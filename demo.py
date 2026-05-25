"""
demo.py
=======
Demo trực quan toàn bộ tính năng của module password_hasher.
Mô phỏng luồng đăng ký và đăng nhập thực tế.

Chạy: python demo.py
"""

import textwrap
from password_hasher import (
    generate_salt,
    hash_password,
    verify_password,
    validate_password,
    register_password,
)

# ─── Màu terminal ───
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GRAY   = "\033[90m"
BLUE   = "\033[94m"


def banner(title: str) -> None:
    line = "─" * 60
    print(f"\n{CYAN}{BOLD}{line}")
    print(f"  {title}")
    print(f"{line}{RESET}")


def ok(msg: str)   -> None: print(f"  {GREEN}✓{RESET} {msg}")
def err(msg: str)  -> None: print(f"  {RED}✗{RESET} {msg}")
def info(msg: str) -> None: print(f"  {GRAY}{msg}{RESET}")


# ══════════════════════════════════════════════════════
# 1. Minh họa tạo salt
# ══════════════════════════════════════════════════════
banner("1. Tạo salt ngẫu nhiên (generate_salt)")

salt1 = generate_salt()
salt2 = generate_salt()
salt3 = generate_salt()

info(f"Salt 1 : {salt1}")
info(f"Salt 2 : {salt2}")
info(f"Salt 3 : {salt3}")
ok(f"Mỗi lần gọi cho kết quả khác nhau (độ dài: {len(salt1)} ký tự = 256-bit entropy)")


# ══════════════════════════════════════════════════════
# 2. Minh họa băm mật khẩu
# ══════════════════════════════════════════════════════
banner("2. Băm mật khẩu SHA-256 + salt (hash_password)")

password = "MyPass@2024"
salt     = generate_salt()
result   = hash_password(password, salt)

info(f"Mật khẩu gốc  : {YELLOW}{password}{RESET}")
info(f"Salt           : {result.salt}")
info(f"Hash SHA-256   : {BLUE}{result.hash}{RESET}")
info(f"Stored value   : {result.stored_value[:40]}...  (lưu vào DB)")
ok(f"Thuật toán: {result.algorithm} | Hash length: {len(result.hash)} ký tự")


# ══════════════════════════════════════════════════════
# 3. Cùng password, salt khác → hash khác (chống rainbow table)
# ══════════════════════════════════════════════════════
banner("3. Tại sao cần salt? (chống Rainbow Table Attack)")

pw = "Password123!"
print(f"\n  {YELLOW}Cùng mật khẩu: \"{pw}\"{RESET}")
print()

for i in range(3):
    s  = generate_salt()
    r  = hash_password(pw, s)
    info(f"User {i+1} → hash: {r.hash[:32]}...")

ok("Ba user cùng mật khẩu nhưng hash hoàn toàn khác nhau!")
info("→ Attacker không thể dùng bảng hash tính sẵn để crack")


# ══════════════════════════════════════════════════════
# 4. Kiểm tra độ mạnh mật khẩu
# ══════════════════════════════════════════════════════
banner("4. Kiểm tra độ mạnh mật khẩu (validate_password)")

test_passwords = [
    ("abc",            "Rất yếu"),
    ("mypassword",     "Chỉ có chữ thường"),
    ("MyPassword2024", "Thiếu ký tự đặc biệt"),
    ("MyPass@2024",    "Hợp lệ - Mạnh"),
]

for pw, desc in test_passwords:
    v = validate_password(pw)
    strength_color = GREEN if v.strength == "Mạnh" else (YELLOW if v.strength == "Trung bình" else RED)
    status = ok if v.is_valid else err
    status(f'"{pw}" [{desc}]')
    print(f"       Điểm: {v.score}/5 | Mức độ: {strength_color}{v.strength}{RESET}")
    if v.errors:
        for e in v.errors:
            print(f"       {RED}→ Thiếu: {e}{RESET}")
    print()


# ══════════════════════════════════════════════════════
# 5. Mô phỏng luồng Đăng ký → Đăng nhập
# ══════════════════════════════════════════════════════
banner("5. Mô phỏng luồng Đăng ký → Đăng nhập")

# --- Đăng ký ---
print(f"\n  {BOLD}[ĐĂNG KÝ]{RESET}")
username  = "nguyenvana"
password  = "Secure@Pass99"

try:
    reg = register_password(password)
    ok(f"Đăng ký thành công cho user: {username}")
    info(f"Lưu vào DB:")
    info(f"  username       = {username}")
    info(f"  stored_value   = {reg.stored_value[:50]}...")

    # Giả lập DB lưu stored_value
    db = {username: reg.stored_value}

except ValueError as e:
    err(f"Đăng ký thất bại: {e}")
    db = {}

# --- Đăng nhập đúng ---
print(f"\n  {BOLD}[ĐĂNG NHẬP - Mật khẩu đúng]{RESET}")
stored = db.get(username)
if stored and verify_password(password, stored):
    ok(f"Xác thực thành công → Đăng nhập cho: {username}")
else:
    err("Sai thông tin đăng nhập")

# --- Đăng nhập sai ---
print(f"\n  {BOLD}[ĐĂNG NHẬP - Mật khẩu sai]{RESET}")
if stored and verify_password("WrongPassword!", stored):
    ok("Xác thực thành công")
else:
    err("Sai thông tin đăng nhập (đúng như mong đợi)")

info("→ Hash không bao giờ bị chuyển ngược về mật khẩu gốc")


# ══════════════════════════════════════════════════════
# 6. Stored value không chứa mật khẩu gốc
# ══════════════════════════════════════════════════════
banner("6. Kiểm chứng bảo mật: stored_value ≠ mật khẩu gốc")

pw  = "SuperSecret@1"
reg = register_password(pw)

print(f"\n  Mật khẩu gốc : {YELLOW}{pw}{RESET}")
print(f"  Stored value :\n    {reg.stored_value}\n")

if pw not in reg.stored_value:
    ok("Mật khẩu gốc KHÔNG xuất hiện trong stored_value")
    ok("Kẻ tấn công lấy được DB cũng không thể biết mật khẩu")
else:
    err("LỖI: mật khẩu xuất hiện trong stored_value!")


# ══════════════════════════════════════════════════════
# Tóm tắt
# ══════════════════════════════════════════════════════
banner("Tóm tắt các hàm trong module")

summary = """
  generate_salt()          → Tạo 32-byte salt ngẫu nhiên, trả về hex string
  hash_password(pw, salt)  → SHA-256(salt+pw), trả về HashResult
  verify_password(pw, sv)  → So sánh constant-time, trả về True/False
  validate_password(pw)    → Kiểm tra độ mạnh, trả về ValidationResult
  register_password(pw)    → Validate + salt + hash trong một bước
  format_stored_value()    → "sha256v1$<salt>$<hash>" để lưu DB
  parse_stored_value()     → Phân tách chuỗi lưu DB thành (salt, hash)
"""
print(GRAY + summary + RESET)
