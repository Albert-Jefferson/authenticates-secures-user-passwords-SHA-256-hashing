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

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass


# ─────────────────────────────────────────────
# Cấu hình hằng số
# ─────────────────────────────────────────────

SALT_BYTES    = 32          # Độ dài salt: 32 bytes = 256 bit
HASH_ALG      = "sha256"    # Thuật toán băm
ITERATIONS    = 1           # Số vòng lặp (mở rộng sang PBKDF2 nếu cần)
SEPARATOR     = "$"         # Ký tự phân cách khi lưu: sha256$<salt>$<hash>
VERSION       = "sha256v1"  # Phiên bản định dạng lưu trữ


# ─────────────────────────────────────────────
# Kiểu dữ liệu trả về
# ─────────────────────────────────────────────

@dataclass
class HashResult:
    """Kết quả sau khi băm mật khẩu."""
    salt: str           # Salt dạng hex (64 ký tự)
    hash: str           # Hash dạng hex (64 ký tự)
    stored_value: str   # Chuỗi lưu vào DB: "sha256v1$<salt>$<hash>"
    algorithm: str      # Thuật toán sử dụng


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

def hash_password(password: str, salt: str) -> HashResult:
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
    if not salt:
        raise ValueError("salt không được rỗng")

    # Ghép salt (hex string) + password (utf-8 bytes)
    combined = (salt + password).encode("utf-8")

    # Tính SHA-256
    digest = hashlib.new(HASH_ALG, combined).hexdigest()

    stored = format_stored_value(salt, digest)

    return HashResult(
        salt=salt,
        hash=digest,
        stored_value=stored,
        algorithm=HASH_ALG,
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
    candidate = hash_password(password, salt)

    # So sánh an toàn (constant-time)
    return hmac.compare_digest(
        candidate.hash.encode("utf-8"),
        original_hash.encode("utf-8"),
    )


# ─────────────────────────────────────────────
# 4. Định dạng lưu trữ
# ─────────────────────────────────────────────

def format_stored_value(salt: str, hash_hex: str) -> str:
    """
    Đóng gói salt và hash thành chuỗi lưu vào DB.

    Định dạng:  sha256v1$<salt_hex>$<hash_hex>
    Ví dụ:      sha256v1$3f2a...c1$e9b4...7d

    Lý do lưu chung: Khi đổi thuật toán trong tương lai, có thể
    đọc phiên bản (sha256v1) và xử lý đúng cách.

    Args:
        salt:     Chuỗi hex của salt
        hash_hex: Chuỗi hex của hash

    Returns:
        Chuỗi định dạng "sha256v1$salt$hash"
    """
    return f"{VERSION}{SEPARATOR}{salt}{SEPARATOR}{hash_hex}"


def parse_stored_value(stored_value: str) -> tuple[str, str]:
    """
    Giải mã chuỗi stored_value → (salt, hash).

    Args:
        stored_value: Chuỗi dạng "sha256v1$salt$hash"

    Returns:
        Tuple (salt_hex, hash_hex)

    Raises:
        ValueError: Nếu định dạng không hợp lệ
    """
    parts = stored_value.split(SEPARATOR)
    if len(parts) != 3:
        raise ValueError(
            f"Định dạng stored_value không hợp lệ. "
            f"Mong đợi: 'version{SEPARATOR}salt{SEPARATOR}hash'. "
            f"Nhận được: '{stored_value}'"
        )
    version, salt, hash_hex = parts
    if version != VERSION:
        raise ValueError(f"Phiên bản không hỗ trợ: '{version}'. Mong đợi: '{VERSION}'")
    return salt, hash_hex


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
