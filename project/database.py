import sqlite3
import hashlib
import os

DB_NAME = "users.db"

def init_database():
    """Khởi tạo bảng users nếu chưa có."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("[*] Đã khởi tạo database thành công.")

def register_user(username, password):
    """
    Đăng ký người dùng.
    Trả về: (success: bool, message: str)
    """
    # Kiểm tra đầu vào
    if not username or not password:
        return False, "Tên đăng nhập và mật khẩu không được để trống"

    # Tạo salt (16 byte -> 32 ký tự hex)
    salt = os.urandom(16).hex()

    # Băm: SHA-256(password + salt)
    salted_password = password + salt
    password_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', (username, password_hash, salt))
        conn.commit()
        return True, "Đăng ký thành công"
    except sqlite3.IntegrityError:
        return False, "Tên đăng nhập đã tồn tại"
    finally:
        conn.close()

def login_user(username, password):
    """
    Xác thực đăng nhập.
    Trả về: (success: bool, message: str)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False, "Sai tên đăng nhập hoặc mật khẩu"

    db_password_hash, db_salt = row
    input_salted = password + db_salt
    input_hash = hashlib.sha256(input_salted.encode('utf-8')).hexdigest()

    if input_hash == db_password_hash:
        return True, "Đăng nhập thành công"
    else:
        return False, "Sai tên đăng nhập hoặc mật khẩu"

def get_all_users():
    """Lấy danh sách tất cả username (ẩn mật khẩu và salt)"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = [row[0] for row in cursor.fetchall()]
    conn.close()
    return users