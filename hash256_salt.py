import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass

@dataclass
class Hash256Salt:
    salt: str 
    hash: str
    algorithm: str
    store_value: str

# Kết quả sau khi băm mật khẩu 
# Salt/ Hash : ở dạng hex 64 ký tự (32 byte)
# Chuổi lưu vào database
# algorithm: thuật toán băm được sử dụng (ví dụ: SHA-256)

@dataclass
class val:
    valid: bool
    errors: list[str]
    strength: str
    score: int
# kiểm tra mật khẩu 
# strength: đánh giá mật khẩu mạnh / trung bình / yếu
# score: mức độ mạnh của mật khẩu 

def generate_salt(length: int = 32) -> str:
    raw_bytes = os.urandom(length)
    return raw_bytes.hex()
# Tạo salt ngẫu nhiên có độ dài là 32 bytes
# trả về chuỗi hex 64 ký tự

def hash_password(password: str, salt: str) -> Hash256Salt:
    if not salt:
        raise ValueError("Khong de trong salt")
    if not password:
        raise ValueError("khong de trong password")
    salt_password = (salt + password).encode('utf-8')
    
    digiest = hashlib.sha256(salt_password).hexdigest()

    return Hash256Salt(
        salt = salt,
        hash = digiest,
        store_value = f"{salt}${digiest}",
        algorithm = "SHA-256",
    )
# Hàm băm mật khẩu với salt
# Trả lại kết quả hàm băm dưới dạng Hash256Salt

def verify_password(password: str, hash_salt: Hash256Salt) -> bool:
    candidate_hash = hash_password(password, hash_salt.salt)
    return hmac.compare_digest(candidate_hash.hash, hash_salt.hash)

# Hàm xác minh mật khẩu
# So sánh hash của mật khẩu nhập vào với hash đã lưu trong database

def val_password(password: str) -> val:
    errors = []
    score = 0
    strength = "Yếu"

    if len(password) < 8:
        errors.append("Mat khau co it nhat 8 ky tu")
        if not re.search(r'[A-Z]', password):
            errors.append("Mat khau phai co it nhat 1 chu cai in hoa")
        if not re.search(r'[a-z]', password):
            errors.append("Mat khau phai co it nhat 1 chu cai thuong")
        if not re.search(r'[0-9]', password):
            errors.append("Mat khau phai co it nhat 1 chu so")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Mat khau phai co it nhat 1 ky tu dac biet")
    
# Kiểm tra mật khẩu:
# Có ít nhất 8 ký tự 
# Có ít nhất một chữ in hoa hoặc một chữ thường 
# Phải có ít nhất một ký tự đặt biệt
# Có ít nhất một số từ 0-9

if score < 3:
    strength = "Yếu"
elif score == 3:
    strength = "Trung bình"
else:
    strength = "Mạnh"

# Đánh giá mức độ an toàn của mật khẩu dựa trên điểm số 

return val(
    valid = len(errors) == 0,
    errors = errors,
    strength = strength,
    score = score
)