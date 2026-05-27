"""
password_hasher.py
==================
Module băm mật khẩu sử dụng SHA-256 kết hợp salt ngẫu nhiên.

Các hàm chính:
    - generate_salt()       : Tạo salt ngẫu nhiên an toàn
    - hash_password()       : Băm mật khẩu kết hợp salt
    - verify_password()     : Xác thực mật khẩu với hash đã lưu
    - validate_password()   : Kiểm tra độ mạnh mật khẩu
    - format_stored_value() : Đóng gói salt + hash để lưu DB
    - parse_stored_value()  : Giải mã chuỗi đã lưu
"""
from __future__ import annotations
import hashlib
import hmac
import os
import re
import secrets
import time
from flask_limiter import Limiter
from dataclasses import dataclass
from typing import Optional, Tuple
from functools import lru_cache


# ─────────────────────────────────────────────
# Cấu hình hằng số
# ─────────────────────────────────────────────

SALT_BYTES    = 32          # Độ dài salt: 32 bytes = 256 bit
HASH_ALG      = "sha256"    # Thuật toán băm
ITERATIONS    = 100000           # Số vòng lặp PBKDF2 (chống brute-force)
SEPARATOR     = "$"         # Ký tự phân cách khi lưu: sha256$<salt>$<hash>
VERSION       = "sha256v2"  # Phiên bản định dạng lưu trữ

PEPPER = os.environ.get("PASSWORD_PEPPER", "default_pepper_key_rotate_in_production")
# Không bao giờ lưu pepper cùng với hash trong database

MAX_FAILED_ATTEMPTS = 5     # Số lần nhập sai tối đa trước khi khóa tài khoản
LOCKOUT_DURATION_SECONDS = 900  # 15 phút khóa sau 5 lần nhập sai
# ─────────────────────────────────────────────
# Kiểu dữ liệu trả về
# ─────────────────────────────────────────────

@dataclass
class HashResult:
    """Kết quả sau khi băm mật khẩu."""
    salt: str           # Salt dạng hex (64 ký tự)
    hash: str           # Hash dạng hex (64 ký tự)
    stored_value: str   # Chuỗi lưu vào DB: "sha256v2$<salt>$<hash>"
    algorithm: str      # Thuật toán sử dụng
    iterations: int     # Số vòng lặp (nếu dùng PBKDF2)

@dataclass
class ValidationResult:
    """Kết quả kiểm tra độ mạnh mật khẩu."""
    is_valid: bool
    errors: list[str]
    strength: str       # "Yếu" / "Trung bình" / "Mạnh"
    score: int          # 0–5


# ─────────────────────────────────────────────
# 1. Tạo salt ngẫu nhiên
# ─────────────────────────────────────────────

def generate_salt(num_bytes: int = SALT_BYTES) -> str:

    """
    Tạo salt ngẫu nhiên an toàn về mặt mật mã.

    Sử dụng os.urandom() — nguồn entropy từ hệ điều hành,
    an toàn hơn random.random() vì không thể đoán trước.

    Args:
        num_bytes: Số byte entropy (mặc định 32 byte = 256 bit)

    Returns:
        Chuỗi hex (64 ký tự nếu num_bytes=32)

    Ví dụ:
        >>> salt = generate_salt()
        >>> len(salt)
        64
    """

    raw_bytes = os.urandom(num_bytes)
    return raw_bytes.hex()


# ─────────────────────────────────────────────
# 2. Băm mật khẩu
# ─────────────────────────────────────────────

def hash_password(password: str, 
    salt: Optional[str] = None,
    iterations: int = ITERATIONS,
    use_pepper: bool = True) -> HashResult:
    """
    Băm mật khẩu bằng SHA-256 kết hợp salt.

    Cách ghép:   SHA-256(salt_hex + password_utf8)
    Mục đích salt:
        - Chống rainbow table: mỗi người dùng có hash khác nhau dù
          cùng mật khẩu, vì salt khác nhau.
        - Chống dictionary attack: attacker phải tính lại hash
          cho từng salt riêng biệt.

    Args:
        password: Mật khẩu dạng chuỗi thuần
        salt:     Chuỗi hex tạo bởi generate_salt()

    Returns:
        HashResult chứa salt, hash, stored_value

    Raises:
        ValueError: Nếu password hoặc salt rỗng
        TypeError:  Nếu password không phải str

    Ví dụ:
        >>> salt = generate_salt()
        >>> result = hash_password("MyPass@2024", salt)
        >>> len(result.hash)
        64
    """

    if not isinstance(password, str):
        raise TypeError(f"password phải là str, nhận được {type(password).__name__}")
    if not password:
        raise ValueError("password không được rỗng")

    if salt is None:
        salt = generate_salt()

    # Ghép salt (hex string) + password (utf-8 bytes)
    if use_pepper:
        combined = (salt + PEPPER + password).encode("utf-8")
    else:
        combined = (salt + password).encode("utf-8")

    derived_key = hashlib.pbkdf2_hmac(
        HASH_ALG,
        combined,
        salt.encode("utf-8"),  # salt làm salt cho PBKDF2
        iterations,
        dklen=32  # 32 bytes = 256 bit
    )
    digest = derived_key.hex()

    stored = format_stored_value(salt, digest)


    return HashResult(
        salt=salt,
        hash=digest,
        stored_value=stored,
        algorithm=f"pbkdf2-{HASH_ALG}",
        iterations=iterations,
    )


# ─────────────────────────────────────────────
# 3. Xác thực mật khẩu
# ─────────────────────────────────────────────

def verify_password(password: str, stored_value: str) -> bool:
    """
    Xác thực mật khẩu người dùng nhập so với hash đã lưu.

    Quy trình:
        1. Giải mã stored_value → lấy salt & hash gốc
        2. Băm lại mật khẩu vừa nhập với salt đó
        3. So sánh bằng hmac.compare_digest() (chống timing attack)

    QUAN TRỌNG: Không dùng == để so sánh hash —
    attacker có thể đo thời gian so sánh từng byte để
    suy ra hash gốc (timing attack).

    Args:
        password:     Mật khẩu người dùng vừa nhập
        stored_value: Chuỗi lưu trong DB ("sha256v1$salt$hash")

    Returns:
        True nếu mật khẩu đúng, False nếu sai

    Ví dụ:
        >>> result = hash_password("MyPass@2024", generate_salt())
        >>> verify_password("MyPass@2024", result.stored_value)
        True
        >>> verify_password("WrongPass", result.stored_value)
        False
    """
    # Mật khẩu rỗng hoặc không phải str → luôn sai, không cần hash
    if not isinstance(password, str) or not password:
        return False

    try:
        salt, original_hash = parse_stored_value(stored_value)
    except ValueError:
        # stored_value bị hỏng → không match
        return False

    # Băm lại mật khẩu nhập vào
    if use_pepper:
        combined = (salt + password + PEPPER).encode("utf-8")
    else:
        combined = (salt + password).encode("utf-8")
    
    candidate = hashlib.pbkdf2_hmac(
        HASH_ALG,
        combined,
        salt.encode("utf-8"),
        iterations,
        dklen=32
    ).hex()

    # So sánh an toàn (constant-time)
    return hmac.compare_digest(
        candidate,
        original_hash

    )


# ─────────────────────────────────────────────
# 4. Định dạng lưu trữ
# ─────────────────────────────────────────────

def format_stored_value( salt: str, 
    hash_hex: str, 
    iterations: int = ITERATIONS,
    use_pepper: bool = True) -> str:
    """
    Đóng gói salt và hash thành chuỗi lưu vào DB.

    Định dạng:  sha256v2$<salt_hex>$<hash_hex>$<iterations>$<use_pepper>
    Ví dụ:      sha256v2$3f2a...c1$e9b4...7d$100000$True

    Lý do lưu chung: Khi đổi thuật toán trong tương lai, có thể
    đọc phiên bản (sha256v2) và xử lý đúng cách.

    Args:
        salt:     Chuỗi hex của salt
        hash_hex: Chuỗi hex của hash
        iterations: Số vòng lặp PBKDF2
        use_pepper: Có sử dụng pepper không

    Returns:
        Chuỗi định dạng "sha256v2$salt$hash$iterations$use_pepper"
    """
    return f"{VERSION}{SEPARATOR}{salt}{SEPARATOR}{hash_hex}"


def parse_stored_value(stored_value: str) -> tuple[str, str, int, bool]:
    """
    Giải mã chuỗi stored_value → (salt, hash).

    Args:
        stored_value: Chuỗi dạng "sha256v2$salt$hash$iterations$use_pepper"

    Returns:
        Tuple (salt_hex, hash_hex, iterations, use_pepper)

    Raises:
        ValueError: Nếu định dạng không hợp lệ
    """
    parts = stored_value.split(SEPARATOR)

    if len(parts) == 3 and parts[0] == "sha256v1":
        version, salt, hash_hex = parts
        return salt, hash_hex, 1, False  # iterations=1, không pepper
    
    # Định dạng mới: sha256v2$salt$iterations$pepper_flag$hash
    if len(parts) == 5 and parts[0] == "sha256v2":
        version, salt, iterations_str, pepper_flag, hash_hex = parts
        iterations = int(iterations_str)
        use_pepper = pepper_flag == "1"
        return salt, hash_hex, iterations, use_pepper
    
    raise ValueError(f"Định dạng stored_value không hợp lệ: '{stored_value}'")


def needs_rehash(stored_value: str) -> bool:
    """
    Kiểm tra xem hash cũ có cần nâng cấp thuật toán không.
    
    Returns:
        True nếu cần rehash (dùng thuật toán cũ hoặc iterations thấp)
    """
    try:
        salt, hash_hex, iterations, use_pepper = parse_stored_value(stored_value)
        # Cần rehash nếu iterations < ITERATIONS hoặc dùng SHA-256 thuần
        return iterations < ITERATIONS
    except ValueError:
        return True  # Định dạng cũ hoặc hỏng → cần rehash



# ─────────────────────────────────────────────
# 5. Kiểm tra độ mạnh mật khẩu
# ─────────────────────────────────────────────

def validate_password(password: str) -> ValidationResult:
    """
    Kiểm tra độ mạnh và tính hợp lệ của mật khẩu.

    Tiêu chí:
        ✓ Tối thiểu 8 ký tự
        ✓ Có chữ hoa (A-Z)
        ✓ Có chữ thường (a-z)
        ✓ Có chữ số (0-9)
        ✓ Có ký tự đặc biệt (!@#$%^&*...)

    Args:
        password: Mật khẩu cần kiểm tra

    Returns:
        ValidationResult với is_valid, errors, strength, score
    """
    errors = []
    score = 0

    checks = [
        (len(password) >= 8,                         "Tối thiểu 8 ký tự"),
        (bool(re.search(r"[A-Z]", password)),         "Có ít nhất 1 chữ hoa (A-Z)"),
        (bool(re.search(r"[a-z]", password)),         "Có ít nhất 1 chữ thường (a-z)"),
        (bool(re.search(r"\d", password)),             "Có ít nhất 1 chữ số (0-9)"),
        (bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
                                                      "Có ít nhất 1 ký tự đặc biệt"),
    ]

    for passed, msg in checks:
        if passed:
            score += 1
        else:
            errors.append(msg)

    # Kiểm tra độ dài tối da chống DOS
    if len(password) > 128:
        error.append("Mat khau khong dai qua 128 ky tu!")
        score = min(score, 4)

    if score <= 2:
        strength = "Yếu"
    elif score <= 4:
        strength = "Trung bình"
    else:
        strength = "Mạnh"

    return ValidationResult(
        is_valid=(len(errors) == 0),
        errors=errors,
        strength=strength,
        score=score,
    )


# ─────────────────────────────────────────────
# 6. Hàm tiện ích tổng hợp (dùng trong register/login)
# ─────────────────────────────────────────────

def register_password(password: str) -> HashResult:
    """
    Hàm tổng hợp dùng khi đăng ký: validate → salt → hash.

    Args:
        password: Mật khẩu người dùng nhập khi đăng ký

    Returns:
        HashResult sẵn sàng lưu vào DB (dùng result.stored_value)

    Raises:
        ValueError: Nếu mật khẩu không đạt yêu cầu
    """
    validation = validate_password(password)
    if not validation.is_valid:
        raise ValueError(
            "Mật khẩu không hợp lệ:\n  - " + "\n  - ".join(validation.errors)
        )

    salt = generate_salt()
    return hash_password(password, salt)

def change_password(
    old_password: str, # mật khẩu cũ
    new_password: str,
    current_stored_value: str) -> PasswordChangeResult: 
    """Đổi mật khẩu an toàn. 
    Args:
        old_password: Mật khẩu cũ
        new_password: Mật khẩu mới
        current_stored_value: Giá trị hash hiện tại trong DB
    
    Returns:
        PasswordChangeResult với kết quả và stored_value mới nếu thành công 
    """
# Xác thực mật khẩu cũ
    if not verify_password(old_password, current_stored_value):
            return PasswordChangeResult(
                success=False,
                message="Mat khau cu khong chinh xac"
            )
    
    # Kiểm tra mật khẩu mới không trùng mật khẩu cũ
    if old_password == new_password:                                    
        return PasswordChangeResult(
            success=False,
            message="Mat khau moi khong đuoc trung voi mat khau cu"
        )
    
    # Validate mật khẩu mới
    validation = validate_password(new_password)
    if not validation.is_valid:
        return PasswordChangeResult(
            success=False,
            message="Mat khau moi khong hop le!: " + ", ".join(validation.errors)
        )
    
    # Tạo hash mới
    new_hash = hash_password(new_password)
    
    return PasswordChangeResult(
        success=True,
        message="Doi mat khau thanh cong",
        new_stored_value=new_hash.stored_value
    )


# ─────────────────────────────────────────────
# 7. Rate limiting helper (cho login)
# ─────────────────────────────────────────────

class RateLimiter:
    """Đơn giản hóa việc rate limiting cho login attempts."""
    
    def __init__(self, max_attempts: int = MAX_FAILED_ATTEMPTS, lockout_seconds: int = LOCKOUT_DURATION_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts = {}  # username -> (failed_count, lockout_until)
    
    def is_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        """Kiểm tra tài khoản có bị khóa không."""
        if username not in self._attempts:
            return False, None
        
        failed_count, lockout_until = self._attempts[username]
        
        if lockout_until and time.time() < lockout_until:
            remaining = int(lockout_until - time.time())
            return True, remaining
        
        # Hết thời gian khóa, reset
        if lockout_until and time.time() >= lockout_until:
            self._attempts[username] = (0, None)
        
        return False, None
    
    def record_failed(self, username: str) -> Tuple[int, Optional[int]]:
        """Ghi nhận lần đăng nhập thất bại."""
        failed_count, lockout_until = self._attempts.get(username, (0, None))
        
        failed_count += 1
        
        if failed_count >= self.max_attempts:
            lockout_until = time.time() + self.lockout_seconds
            self._attempts[username] = (failed_count, lockout_until)
            return failed_count, int(self.lockout_seconds)
        
        self._attempts[username] = (failed_count, None)
        return failed_count, None
    
    def record_success(self, username: str) -> None:
        """Reset failed attempts khi đăng nhập thành công."""
        self._attempts[username] = (0, None)
    
    def reset(self, username: str) -> None:
        """Reset attempts cho username."""
        self._attempts[username] = (0, None)