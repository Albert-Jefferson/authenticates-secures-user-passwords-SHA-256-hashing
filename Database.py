import sqlite3
import hashlib
import os

DB_NAME = "users.db"

def init_database():
    """
    Khởi tạo cơ sở dữ liệu SQLite và tạo bảng users nếu chưa tồn tại.
    """
    # Kết nối tới database (tự động tạo file nếu chưa có)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tạo bảng theo cấu trúc yêu cầu
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
    print(f"[*] Đã khởi tạo cơ sở dữ liệu '{DB_NAME}' thành công.")

def register_user(username, password):
    """
    Hàm đăng ký người dùng mới: Tạo salt ngẫu nhiên, hash mật khẩu và lưu vào DB.
    """
    # 1. Tạo một đoạn salt ngẫu nhiên bảo mật (16 bytes) dưới dạng chuỗi hex
    salt = os.urandom(16).hex()
    
    # 2. Trộn password với salt và hash bằng thuật toán SHA-256
    # Công thức: SHA-256(password + salt)
    salted_password = password + salt
    password_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    
    # 3. Lưu vào database
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', (username, password_hash, salt))
        
        conn.commit()
        print(f"[+] Đăng ký tài khoản '{username}' thành công!")
    except sqlite3.IntegrityError:
        print(f"[-] Lỗi: Tên đăng nhập '{username}' đã tồn tại!")
    finally:
        conn.close()

def login_user(username, password):
    """
    Hàm kiểm tra đăng nhập.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Lấy thông tin password_hash và salt của username từ DB
    cursor.execute('SELECT password_hash, salt FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        print("[-] Đăng nhập thất bại: Tài khoản không tồn tại.")
        return False
        
    db_password_hash, db_salt = row
    
    # Thực hiện hash lại mật khẩu người dùng vừa nhập với salt lấy từ DB
    input_salted = password + db_salt
    input_hash = hashlib.sha256(input_salted.encode('utf-8')).hexdigest()
    
    # So sánh hai chuỗi hash
    if input_hash == db_password_hash:
        print(f"[+] Đăng nhập thành công! Chào mừng {username}.")
        return True
    else:
        print("[-] Đăng nhập thất bại: Sai mật khẩu.")
        return False

# --- Đoạn code chạy thử nghiệm (Demo) ---
if __name__ == "__main__":
    # Khởi tạo DB ban đầu
    init_database()
    
    print("\n--- THỬ NGHIỆM ĐĂNG KÝ ---")
    register_user("lequocnhi", "MatKhauBaoMat123")
    register_user("lequocnhi", "MatKhauKhac")  # Thử trùng username để test lỗi
    
    print("\n--- THỬ NGHIỆM ĐĂNG NHẬP ---")
    print("Thử đăng nhập sai mật khẩu:")
    login_user("lequocnhi", "SaiMatKhau")
    
    print("\nThử đăng nhập đúng mật khẩu:")
    login_user("lequocnhi", "MatKhauBaoMat123")