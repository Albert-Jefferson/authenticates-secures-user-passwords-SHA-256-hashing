"""
hash256_salt.py
===============
File minh họa SHA-256 thuần kết hợp salt cho đề tài Mật mã học cơ sở.

Lưu ý: trong hệ thống chính, project đang dùng password_hasher.py với
PBKDF2-HMAC-SHA256 để an toàn hơn trước brute-force. File này giữ lại
để minh họa đúng yêu cầu cơ bản: SHA-256(salt + password).
"""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass


@dataclass
class Hash256Salt:
    """Kết quả sau khi băm mật khẩu bằng SHA-256 + salt."""

    salt: str
    hash: str
    algorithm: str
    store_value: str


@dataclass
class PasswordValidation:
    """Kết quả kiểm tra độ mạnh mật khẩu."""

    valid: bool
    errors: list[str]
    strength: str
    score: int


def generate_salt(length: int = 32) -> str:
    """Tạo salt ngẫu nhiên, mặc định 32 bytes = 64 ký tự hex."""
    if length < 16:
        raise ValueError("Salt nên có ít nhất 16 bytes")
    return os.urandom(length).hex()


def hash_password(password: str, salt: str) -> Hash256Salt:
    """Băm mật khẩu theo công thức SHA-256(salt + password)."""
    if not salt:
        raise ValueError("Không được để trống salt")
    if not password:
        raise ValueError("Không được để trống password")

    salt_password = (salt + password).encode("utf-8")
    digest = hashlib.sha256(salt_password).hexdigest()

    return Hash256Salt(
        salt=salt,
        hash=digest,
        store_value=f"{salt}${digest}",
        algorithm="SHA-256",
    )


def verify_password(password: str, hash_salt: Hash256Salt) -> bool:
    """So sánh hash của mật khẩu nhập vào với hash đã lưu."""
    if not password or not hash_salt:
        return False
    candidate_hash = hash_password(password, hash_salt.salt)
    return hmac.compare_digest(candidate_hash.hash, hash_salt.hash)


def val_password(password: str) -> PasswordValidation:
    """Kiểm tra độ mạnh mật khẩu theo các tiêu chí cơ bản."""
    errors: list[str] = []
    score = 0

    checks = [
        (len(password) >= 8, "Mật khẩu có ít nhất 8 ký tự"),
        (bool(re.search(r"[A-Z]", password)), "Mật khẩu phải có ít nhất 1 chữ cái in hoa"),
        (bool(re.search(r"[a-z]", password)), "Mật khẩu phải có ít nhất 1 chữ cái thường"),
        (bool(re.search(r"[0-9]", password)), "Mật khẩu phải có ít nhất 1 chữ số"),
        (bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)), "Mật khẩu phải có ít nhất 1 ký tự đặc biệt"),
    ]

    for passed, message in checks:
        if passed:
            score += 1
        else:
            errors.append(message)

    if score < 3:
        strength = "Yếu"
    elif score < 5:
        strength = "Trung bình"
    else:
        strength = "Mạnh"

    return PasswordValidation(
        valid=len(errors) == 0,
        errors=errors,
        strength=strength,
        score=score,
    )
