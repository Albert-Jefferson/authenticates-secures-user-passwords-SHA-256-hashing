"""
password_hasher.py
==================
Module xử lý bảo mật mật khẩu cho đề tài:
"Thiết kế hệ thống xác thực và bảo mật mật khẩu người dùng bằng thuật toán băm SHA-256".

Điểm chính:
    - Sinh salt ngẫu nhiên bằng os.urandom().
    - Dùng PBKDF2-HMAC-SHA256: SHA-256 là lõi băm, PBKDF2 lặp nhiều vòng để tăng chi phí brute-force.
    - Hỗ trợ pepper qua biến môi trường PASSWORD_PEPPER.
    - So sánh hash bằng hmac.compare_digest() để giảm rủi ro timing attack.
    - Lưu hash theo định dạng có version để dễ nâng cấp thuật toán về sau.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass
from typing import Optional, Tuple


SALT_BYTES = 32
HASH_ALG = "sha256"
ITERATIONS = 100_000
SEPARATOR = "$"
VERSION = "sha256v2"

# Trong môi trường production, nên cấu hình PASSWORD_PEPPER ở biến môi trường
# và không lưu pepper trong database/source code.
PEPPER = os.environ.get("PASSWORD_PEPPER", "development-pepper-change-in-production")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900


@dataclass
class HashResult:
    """Kết quả sau khi băm mật khẩu."""

    salt: str
    hash: str
    stored_value: str
    algorithm: str
    iterations: int


@dataclass
class ValidationResult:
    """Kết quả kiểm tra độ mạnh mật khẩu."""

    is_valid: bool
    errors: list[str]
    strength: str
    score: int


@dataclass
class PasswordChangeResult:
    """Kết quả đổi mật khẩu."""

    success: bool
    message: str
    new_stored_value: Optional[str] = None


def generate_salt(num_bytes: int = SALT_BYTES) -> str:
    """Tạo salt ngẫu nhiên an toàn bằng nguồn entropy của hệ điều hành."""
    if num_bytes < 16:
        raise ValueError("Salt nên có ít nhất 16 bytes để đảm bảo an toàn")
    return os.urandom(num_bytes).hex()


def _derive_hash(password: str, salt_hex: str, iterations: int, use_pepper: bool) -> str:
    """Sinh khóa dẫn xuất bằng PBKDF2-HMAC-SHA256."""
    if iterations <= 0:
        raise ValueError("iterations phải lớn hơn 0")

    try:
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise ValueError("salt phải là chuỗi hex hợp lệ") from exc

    password_material = password + (PEPPER if use_pepper else "")
    derived_key = hashlib.pbkdf2_hmac(
        HASH_ALG,
        password_material.encode("utf-8"),
        salt_bytes,
        iterations,
        dklen=32,
    )
    return derived_key.hex()


def hash_password(
    password: str,
    salt: Optional[str] = None,
    iterations: int = ITERATIONS,
    use_pepper: bool = True,
) -> HashResult:
    """
    Băm mật khẩu bằng PBKDF2-HMAC-SHA256 kết hợp salt.

    Về bản chất, SHA-256 là hàm băm lõi bên trong HMAC/PBKDF2; PBKDF2 lặp nhiều vòng
    để làm chậm brute-force so với SHA-256 thuần một vòng.
    """
    if not isinstance(password, str):
        raise TypeError(f"password phải là str, nhận được {type(password).__name__}")
    if not password:
        raise ValueError("password không được rỗng")

    if salt is None:
        salt = generate_salt()

    digest = _derive_hash(password, salt, iterations, use_pepper)
    stored = format_stored_value(salt, digest, iterations=iterations, use_pepper=use_pepper)

    return HashResult(
        salt=salt,
        hash=digest,
        stored_value=stored,
        algorithm=f"pbkdf2-hmac-{HASH_ALG}",
        iterations=iterations,
    )


def verify_password(password: str, stored_value: str) -> bool:
    """Xác thực mật khẩu bằng cách băm lại và so sánh constant-time."""
    if not isinstance(password, str) or not password or not stored_value:
        return False

    try:
        salt, original_hash, iterations, use_pepper = parse_stored_value(stored_value)
        candidate = _derive_hash(password, salt, iterations, use_pepper)
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(candidate, original_hash)


def format_stored_value(
    salt: str,
    hash_hex: str,
    iterations: int = ITERATIONS,
    use_pepper: bool = True,
) -> str:
    """
    Đóng gói thông tin hash để lưu database.

    Định dạng hiện tại:
        sha256v2$<salt_hex>$<iterations>$<pepper_flag>$<hash_hex>

    pepper_flag = 1 nếu khi tạo hash có dùng pepper, ngược lại = 0.
    """
    if not salt or not hash_hex:
        raise ValueError("salt và hash_hex không được rỗng")
    pepper_flag = "1" if use_pepper else "0"
    return f"{VERSION}{SEPARATOR}{salt}{SEPARATOR}{iterations}{SEPARATOR}{pepper_flag}{SEPARATOR}{hash_hex}"


def parse_stored_value(stored_value: str) -> tuple[str, str, int, bool]:
    """Giải mã stored_value thành (salt_hex, hash_hex, iterations, use_pepper)."""
    if not isinstance(stored_value, str):
        raise ValueError("stored_value phải là chuỗi")

    parts = stored_value.split(SEPARATOR)

    # Legacy demo format: sha256v1$salt$hash, không pepper, một vòng.
    if len(parts) == 3 and parts[0] == "sha256v1":
        _, salt, hash_hex = parts
        return salt, hash_hex, 1, False

    # Current format: sha256v2$salt$iterations$pepper_flag$hash
    if len(parts) == 5 and parts[0] == VERSION:
        _, salt, iterations_str, pepper_flag, hash_hex = parts
        try:
            iterations = int(iterations_str)
        except ValueError as exc:
            raise ValueError("iterations không hợp lệ") from exc

        if pepper_flag not in {"0", "1"}:
            raise ValueError("pepper_flag không hợp lệ")

        return salt, hash_hex, iterations, pepper_flag == "1"

    raise ValueError(f"Định dạng stored_value không hợp lệ: '{stored_value}'")


def needs_rehash(stored_value: str) -> bool:
    """Kiểm tra hash cũ có cần nâng cấp lên cấu hình hiện tại không."""
    try:
        _salt, _hash_hex, iterations, use_pepper = parse_stored_value(stored_value)
        return iterations < ITERATIONS or not use_pepper
    except ValueError:
        return True


def validate_password(password: str) -> ValidationResult:
    """Kiểm tra độ mạnh mật khẩu theo các tiêu chí phổ biến."""
    errors: list[str] = []
    score = 0

    if not isinstance(password, str):
        return ValidationResult(False, ["Mật khẩu phải là chuỗi"], "Yếu", 0)

    checks = [
        (len(password) >= 8, "Tối thiểu 8 ký tự"),
        (bool(re.search(r"[A-Z]", password)), "Có ít nhất 1 chữ hoa (A-Z)"),
        (bool(re.search(r"[a-z]", password)), "Có ít nhất 1 chữ thường (a-z)"),
        (bool(re.search(r"\d", password)), "Có ít nhất 1 chữ số (0-9)"),
        (bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)), "Có ít nhất 1 ký tự đặc biệt"),
    ]

    for passed, message in checks:
        if passed:
            score += 1
        else:
            errors.append(message)

    if len(password) > 128:
        errors.append("Mật khẩu không được dài quá 128 ký tự")
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


def register_password(password: str) -> HashResult:
    """Validate mật khẩu, sinh salt và trả về hash sẵn sàng lưu database."""
    validation = validate_password(password)
    if not validation.is_valid:
        raise ValueError("Mật khẩu không hợp lệ:\n  - " + "\n  - ".join(validation.errors))
    return hash_password(password)


def change_password(old_password: str, new_password: str, current_stored_value: str) -> PasswordChangeResult:
    """Đổi mật khẩu an toàn: xác thực mật khẩu cũ, validate mật khẩu mới, tạo hash mới."""
    if not verify_password(old_password, current_stored_value):
        return PasswordChangeResult(success=False, message="Mật khẩu cũ không chính xác")

    if old_password == new_password:
        return PasswordChangeResult(success=False, message="Mật khẩu mới không được trùng với mật khẩu cũ")

    validation = validate_password(new_password)
    if not validation.is_valid:
        return PasswordChangeResult(
            success=False,
            message="Mật khẩu mới không hợp lệ: " + ", ".join(validation.errors),
        )

    new_hash = hash_password(new_password)
    return PasswordChangeResult(
        success=True,
        message="Đổi mật khẩu thành công",
        new_stored_value=new_hash.stored_value,
    )


class RateLimiter:
    """Rate limiter đơn giản theo username cho demo đăng nhập."""

    def __init__(self, max_attempts: int = MAX_FAILED_ATTEMPTS, lockout_seconds: int = LOCKOUT_DURATION_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[str, tuple[int, Optional[float]]] = {}

    def is_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        if username not in self._attempts:
            return False, None

        failed_count, lockout_until = self._attempts[username]
        if lockout_until and time.time() < lockout_until:
            return True, int(lockout_until - time.time())

        if lockout_until and time.time() >= lockout_until:
            self._attempts[username] = (0, None)

        return False, None

    def record_failed(self, username: str) -> Tuple[int, Optional[int]]:
        failed_count, _lockout_until = self._attempts.get(username, (0, None))
        failed_count += 1

        if failed_count >= self.max_attempts:
            lockout_until = time.time() + self.lockout_seconds
            self._attempts[username] = (failed_count, lockout_until)
            return failed_count, int(self.lockout_seconds)

        self._attempts[username] = (failed_count, None)
        return failed_count, None

    def record_success(self, username: str) -> None:
        self._attempts[username] = (0, None)

    def reset(self, username: str) -> None:
        self._attempts[username] = (0, None)
