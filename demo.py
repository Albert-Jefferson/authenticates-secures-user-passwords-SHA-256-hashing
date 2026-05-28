"""
demo.py
=======
Demo chuyên nghiệp cho đề tài:
"Thiết kế hệ thống xác thực và bảo mật mật khẩu người dùng bằng thuật toán băm SHA-256".

Nội dung minh họa:
1. Tạo salt ngẫu nhiên.
2. Băm mật khẩu bằng PBKDF2-HMAC-SHA256.
3. So sánh có salt và không có salt.
4. Kiểm tra mật khẩu không thể khôi phục trực tiếp từ hash.
5. Mô phỏng đăng ký/đăng nhập.
6. Brute-force/dictionary attack đơn giản bằng wordlist.

Chạy:
    python demo.py
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from password_hasher import (
    generate_salt,
    hash_password,
    verify_password,
    validate_password,
    register_password,
)

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GRAY = "\033[90m"
BLUE = "\033[94m"


def banner(title: str) -> None:
    line = "─" * 76
    print(f"\n{CYAN}{BOLD}{line}")
    print(f"  {title}")
    print(f"{line}{RESET}")


def ok(message: str) -> None:
    print(f"  {GREEN}✓{RESET} {message}")


def err(message: str) -> None:
    print(f"  {RED}✗{RESET} {message}")


def info(message: str) -> None:
    print(f"  {GRAY}{message}{RESET}")


def sha256_without_salt(password: str) -> str:
    """SHA-256 thuần, chỉ dùng cho mục đích so sánh học thuật."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_wordlist() -> list[str]:
    """Đọc wordlist demo, nếu không có thì dùng danh sách mặc định."""
    wordlist_path = Path(__file__).with_name("wordlist-demo.txt")
    if wordlist_path.exists():
        return [line.strip() for line in wordlist_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [
        "123456",
        "password",
        "admin",
        "admin123",
        "password123",
        "Qwerty@123",
        "Secure@Pass99",
    ]


# ══════════════════════════════════════════════════════
# 1. Salt ngẫu nhiên
# ══════════════════════════════════════════════════════
banner("1. Tạo salt ngẫu nhiên 256-bit")

salts = [generate_salt() for _ in range(3)]
for index, salt in enumerate(salts, start=1):
    info(f"Salt {index}: {salt}")

ok(f"Mỗi salt dài {len(salts[0])} ký tự hex = 32 bytes = 256 bit entropy")
ok("Các salt khác nhau giúp mỗi user có hash riêng dù dùng cùng mật khẩu")


# ══════════════════════════════════════════════════════
# 2. Băm mật khẩu
# ══════════════════════════════════════════════════════
banner("2. Băm mật khẩu bằng PBKDF2-HMAC-SHA256")

password = "MyPass@2024"
result = hash_password(password)

info(f"Mật khẩu gốc : {YELLOW}{password}{RESET}")
info(f"Salt         : {result.salt}")
info(f"Hash         : {BLUE}{result.hash}{RESET}")
info(f"Stored value : {result.stored_value}")
ok(f"Thuật toán: {result.algorithm}; số vòng lặp: {result.iterations:,}")


# ══════════════════════════════════════════════════════
# 3. So sánh có salt và không có salt
# ══════════════════════════════════════════════════════
banner("3. So sánh khi có salt và không có salt")

shared_password = "Password123!"
plain_hash_1 = sha256_without_salt(shared_password)
plain_hash_2 = sha256_without_salt(shared_password)

print(f"\n  {YELLOW}Không dùng salt - cùng mật khẩu sẽ tạo cùng hash:{RESET}")
info(f"User A hash: {plain_hash_1}")
info(f"User B hash: {plain_hash_2}")
if plain_hash_1 == plain_hash_2:
    err("Hai hash giống nhau → dễ bị nhận diện password trùng và dễ bị rainbow table")

print(f"\n  {YELLOW}Có salt - cùng mật khẩu nhưng salt khác nhau sẽ tạo hash khác nhau:{RESET}")
salted_a = hash_password(shared_password)
salted_b = hash_password(shared_password)
info(f"User A salt: {salted_a.salt}")
info(f"User A hash: {salted_a.hash}")
info(f"User B salt: {salted_b.salt}")
info(f"User B hash: {salted_b.hash}")
if salted_a.hash != salted_b.hash:
    ok("Hash khác nhau → chống reuse/rainbow table hiệu quả hơn")


# ══════════════════════════════════════════════════════
# 4. Kiểm tra độ mạnh mật khẩu
# ══════════════════════════════════════════════════════
banner("4. Kiểm tra độ mạnh mật khẩu")

test_passwords = [
    "abc",
    "mypassword",
    "MyPassword2024",
    "MyPass@2024",
    "VeryStrong@Password2026",
]

for item in test_passwords:
    validation = validate_password(item)
    status = ok if validation.is_valid else err
    status(f"{item!r} → {validation.strength} ({validation.score}/5)")
    for error in validation.errors:
        info(f"  Thiếu: {error}")


# ══════════════════════════════════════════════════════
# 5. Luồng đăng ký/đăng nhập
# ══════════════════════════════════════════════════════
banner("5. Mô phỏng luồng đăng ký → đăng nhập")

username = "nguyenvana"
password = "Secure@Pass99"
user_db: dict[str, str] = {}

try:
    registered = register_password(password)
    user_db[username] = registered.stored_value
    ok(f"Đăng ký thành công user {username!r}")
    info("Database demo chỉ lưu username và stored_value, không lưu password gốc")
    info(f"stored_value: {registered.stored_value}")
except ValueError as exc:
    err(f"Đăng ký thất bại: {exc}")

if verify_password(password, user_db[username]):
    ok("Đăng nhập bằng mật khẩu đúng → thành công")
else:
    err("Đăng nhập bằng mật khẩu đúng → thất bại")

if verify_password("WrongPassword@1", user_db[username]):
    err("Đăng nhập bằng mật khẩu sai → vẫn thành công, đây là lỗi")
else:
    ok("Đăng nhập bằng mật khẩu sai → bị từ chối")


# ══════════════════════════════════════════════════════
# 6. Không khôi phục trực tiếp mật khẩu từ hash
# ══════════════════════════════════════════════════════
banner("6. Kiểm chứng: hash không chứa mật khẩu gốc")

secret = "SuperSecret@1"
secret_hash = register_password(secret)
info(f"Mật khẩu gốc : {YELLOW}{secret}{RESET}")
info(f"Stored value : {secret_hash.stored_value}")

if secret not in secret_hash.stored_value:
    ok("Mật khẩu gốc không xuất hiện trong stored_value")
    ok("Muốn kiểm tra password, hệ thống phải băm lại password nhập vào và so sánh")
else:
    err("Mật khẩu gốc xuất hiện trong stored_value")


# ══════════════════════════════════════════════════════
# 7. Brute-force/dictionary attack đơn giản
# ══════════════════════════════════════════════════════
banner("7. Demo brute-force/dictionary attack bằng wordlist")

wordlist = load_wordlist()
target_password = "Secure@Pass99"
target = register_password(target_password)

info(f"Số mật khẩu trong wordlist: {len(wordlist)}")
info(f"Hash mục tiêu: {target.hash}")
info("Attacker không đảo ngược hash; chỉ có thể thử từng password rồi verify")

start = time.perf_counter()
found = None
attempts = 0
for candidate in wordlist:
    attempts += 1
    if verify_password(candidate, target.stored_value):
        found = candidate
        break
elapsed = time.perf_counter() - start

if found:
    err(f"Tìm thấy mật khẩu trong wordlist sau {attempts} lần thử: {found!r}")
else:
    ok(f"Không tìm thấy mật khẩu trong wordlist sau {attempts} lần thử")
info(f"Thời gian thử: {elapsed:.4f} giây")
ok("Kết luận: mật khẩu mạnh + salt + PBKDF2 nhiều vòng giúp tăng chi phí tấn công")


# ══════════════════════════════════════════════════════
# Tóm tắt
# ══════════════════════════════════════════════════════
banner("Tóm tắt đáp ứng yêu cầu đề tài")

summary = """
  ✓ Đăng ký: username/password → validate → sinh salt → hash → lưu stored_value.
  ✓ Đăng nhập: lấy stored_value → băm lại password nhập vào → so sánh constant-time.
  ✓ Salt: mỗi user có salt riêng, chống rainbow table và hash trùng nhau.
  ✓ SHA-256: dùng làm lõi trong PBKDF2-HMAC-SHA256 để tăng khả năng chống brute-force.
  ✓ Kiểm thử: minh họa no-salt/salt, không khôi phục mật khẩu từ hash, brute-force bằng wordlist.
"""
print(GRAY + summary + RESET)
