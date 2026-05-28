"""
Database.py
===========
Database layer cho hệ thống xác thực.
Tích hợp password_hasher với cơ chế khóa tài khoản.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import json

from password_hasher import (
    verify_password,
    register_password,
    change_password,
    needs_rehash,
    RateLimiter,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS
)

DB_NAME = "users.db"


@contextmanager
def get_db_connection():
    """Context manager cho database connection."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    """Khởi tạo cơ sở dữ liệu với bảng users nâng cấp."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Tạo bảng users với các cột mới
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                stored_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP NULL,
                last_login TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Tạo bảng logs cho sự kiện bảo mật
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        print(f"[*] Đã khởi tạo cơ sở dữ liệu '{DB_NAME}' thành công.")


def log_security_event(username: str, event_type: str, ip_address: str = None, user_agent: str = None, details: dict = None):
    """Ghi log sự kiện bảo mật."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_logs (username, event_type, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            username,
            event_type,
            ip_address,
            user_agent,
            json.dumps(details) if details else None
        ))


def register_user(username: str, password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
    """
    Đăng ký người dùng mới.
    
    Returns:
        Dict với keys: success, message, user_id
    """
    # Validate username
    if not username or len(username) < 3:
        return {
            "success": False,
            "message": "Tên đăng nhập phải có ít nhất 3 ký tự",
            "user_id": None
        }
    
    if not username.isalnum() and not all(c.isalnum() or c == '_' for c in username):
        return {
            "success": False,
            "message": "Tên đăng nhập chỉ chứa chữ cái, số và dấu gạch dưới",
            "user_id": None
        }
    
    try:
        # Tạo hash cho mật khẩu
        hash_result = register_password(password)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, stored_value)
                VALUES (?, ?)
            ''', (username, hash_result.stored_value))
            
            user_id = cursor.lastrowid
            
            log_security_event(username, "REGISTER", ip_address, user_agent, {
                "user_id": user_id,
                "hash_algorithm": hash_result.algorithm,
                "iterations": hash_result.iterations
            })
            
            return {
                "success": True,
                "message": "Đăng ký thành công",
                "user_id": user_id
            }
            
    except sqlite3.IntegrityError:
        log_security_event(username, "REGISTER_FAILED_DUPLICATE", ip_address, user_agent)
        return {
            "success": False,
            "message": "Tên đăng nhập đã tồn tại",
            "user_id": None
        }
    except ValueError as e:
        return {
            "success": False,
            "message": str(e),
            "user_id": None
        }
    except Exception as e:
        log_security_event(username, "REGISTER_ERROR", ip_address, user_agent, {"error": str(e)})
        return {
            "success": False,
            "message": "Lỗi hệ thống, vui lòng thử lại sau",
            "user_id": None
        }


def login_user(username: str, password: str, ip_address: str = None, user_agent: str = None, rate_limiter: RateLimiter = None) -> Dict[str, Any]:
    """
    Đăng nhập với cơ chế khóa tài khoản và logging.
    
    Returns:
        Dict với keys: success, message, token, locked_remaining
    """
    if rate_limiter is None:
        rate_limiter = RateLimiter()
    
    # Kiểm tra rate limiting
    is_locked, remaining = rate_limiter.is_locked(username)
    if is_locked:
        log_security_event(username, "LOGIN_BLOCKED_LOCKED", ip_address, user_agent, {"remaining_seconds": remaining})
        return {
            "success": False,
            "message": f"Tài khoản bị khóa. Vui lòng thử lại sau {remaining} giây",
            "token": None,
            "locked_remaining": remaining
        }
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Lấy thông tin user
            cursor.execute('''
                SELECT id, stored_value, failed_attempts, locked_until, is_active
                FROM users 
                WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            
            if row is None:
                # Không tiết lộ username không tồn tại (chống user enumeration)
                rate_limiter.record_failed(username)
                log_security_event(username, "LOGIN_FAILED_USER_NOT_FOUND", ip_address, user_agent)
                return {
                    "success": False,
                    "message": "Sai thông tin đăng nhập",
                    "token": None,
                    "locked_remaining": None
                }
            
            # Kiểm tra tài khoản active
            if not row["is_active"]:
                log_security_event(username, "LOGIN_BLOCKED_INACTIVE", ip_address, user_agent)
                return {
                    "success": False,
                    "message": "Tài khoản đã bị vô hiệu hóa",
                    "token": None,
                    "locked_remaining": None
                }
            
            # Kiểm tra lock từ database
            if row["locked_until"]:
                locked_until = datetime.fromisoformat(row["locked_until"])
                if datetime.now() < locked_until:
                    remaining = int((locked_until - datetime.now()).total_seconds())
                    log_security_event(username, "LOGIN_BLOCKED_DB_LOCKED", ip_address, user_agent, {"remaining_seconds": remaining})
                    return {
                        "success": False,
                        "message": f"Tài khoản bị khóa. Vui lòng thử lại sau {remaining} giây",
                        "token": None,
                        "locked_remaining": remaining
                    }
            
            # Xác thực mật khẩu
            is_valid = verify_password(password, row["stored_value"])
            
            if not is_valid:
                # Tăng failed_attempts
                new_failed = row["failed_attempts"] + 1
                locked_until = None
                
                if new_failed >= MAX_FAILED_ATTEMPTS:
                    locked_until = datetime.now()
                    # Thêm thời gian khóa
                    from datetime import timedelta
                    locked_until = locked_until + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
                    locked_until_str = locked_until.isoformat()
                else:
                    locked_until_str = None
                
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (new_failed, locked_until_str, username))
                
                rate_limiter.record_failed(username)
                log_security_event(username, "LOGIN_FAILED_WRONG_PASSWORD", ip_address, user_agent, {
                    "failed_attempts": new_failed,
                    "max_attempts": MAX_FAILED_ATTEMPTS
                })
                
                return {
                    "success": False,
                    "message": "Sai thông tin đăng nhập",
                    "token": None,
                    "locked_remaining": None
                }
            
            # Đăng nhập thành công - reset failed attempts
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
            ''', (username,))
            
            rate_limiter.record_success(username)
            
            # Kiểm tra xem có cần rehash không
            if needs_rehash(row["stored_value"]):
                # Rehash với thuật toán mới
                new_hash = register_password(password)
                cursor.execute('''
                    UPDATE users SET stored_value = ? WHERE username = ?
                ''', (new_hash.stored_value, username))
                log_security_event(username, "PASSWORD_REHASHED", ip_address, user_agent)
            
            # Tạo token đơn giản (trong production nên dùng JWT)
            import uuid
            token = str(uuid.uuid4())
            
            log_security_event(username, "LOGIN_SUCCESS", ip_address, user_agent)
            
            return {
                "success": True,
                "message": "Đăng nhập thành công",
                "token": token,
                "locked_remaining": None
            }
            
    except Exception as e:
        log_security_event(username, "LOGIN_ERROR", ip_address, user_agent, {"error": str(e)})
        return {
            "success": False,
            "message": "Lỗi hệ thống, vui lòng thử lại sau",
            "token": None,
            "locked_remaining": None
        }


def change_user_password(username: str, old_password: str, new_password: str, ip_address: str = None) -> Dict[str, Any]:
    """Đổi mật khẩu cho user."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT stored_value FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            
            if row is None:
                return {"success": False, "message": "Người dùng không tồn tại"}
            
            result = change_password(old_password, new_password, row["stored_value"])
            
            if result.success:
                cursor.execute('''
                    UPDATE users SET stored_value = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?
                ''', (result.new_stored_value, username))
                log_security_event(username, "PASSWORD_CHANGED", ip_address)
                return {"success": True, "message": result.message}
            else:
                log_security_event(username, "PASSWORD_CHANGE_FAILED", ip_address, None, {"reason": result.message})
                return {"success": False, "message": result.message}
                
    except Exception as e:
        log_security_event(username, "PASSWORD_CHANGE_ERROR", ip_address, None, {"error": str(e)})
        return {"success": False, "message": "Lỗi hệ thống"}


def get_user_info(username: str) -> Optional[Dict[str, Any]]:
    """Lấy thông tin user (không bao gồm hash mật khẩu)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, created_at, updated_at, failed_attempts, last_login, is_active
            FROM users WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None


def list_users(limit: int = 100) -> list[Dict[str, Any]]:
    """
    Lấy danh sách người dùng phục vụ quản lý/thử nghiệm.

    Không trả về stored_value, salt, hash hoặc thông tin nhạy cảm.
    """
    safe_limit = max(1, min(int(limit), 500))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, created_at, updated_at, failed_attempts, last_login, is_active
            FROM users
            ORDER BY id DESC
            LIMIT ?
        ''', (safe_limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_security_logs(limit: int = 50) -> list[Dict[str, Any]]:
    """Lấy log bảo mật gần nhất để minh họa quá trình thử nghiệm hệ thống."""
    safe_limit = max(1, min(int(limit), 200))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, event_type, ip_address, details, created_at
            FROM security_logs
            ORDER BY id DESC
            LIMIT ?
        ''', (safe_limit,))
        return [dict(row) for row in cursor.fetchall()]


# Khởi tạo database khi import module
if __name__ != "__main__":
    init_database()