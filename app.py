"""
app.py
======
Flask API Backend cho hệ thống xác thực.
Implement các endpoint theo API_endpoint.txt
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
from datetime import datetime
import re

from Database import register_user, login_user, change_user_password, get_user_info, RateLimiter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # Nên dùng biến môi trường

CORS(app)  # Cho phép CORS

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Global rate limiter instance cho login
login_rate_limiter = RateLimiter()

# Store tokens đơn giản (production nên dùng JWT hoặc Redis)
active_tokens = {}  # token -> username, expiry


def validate_username(username: str) -> bool:
    """Validate username format."""
    if not username or len(username) < 3 or len(username) > 50:
        return False
    # Chỉ cho phép chữ cái, số, dấu gạch dưới
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))


def validate_password_request(password: str) -> tuple[bool, str]:
    """Validate password theo yêu cầu."""
    if not password:
        return False, "Mật khẩu không được để trống"
    if len(password) < 8:
        return False, "Mật khẩu phải có ít nhất 8 ký tự"
    return True, ""


@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per minute")  # Giới hạn 10 request/phút
def register():
    """
    Endpoint đăng ký tài khoản mới.
    POST /api/auth/register
    """
    data = request.get_json()
    
    # Kiểm tra request body
    if not data:
        return jsonify({
            "success": False,
            "message": "Request body không hợp lệ"
        }), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # Kiểm tra thiếu field
    if username is None:
        return jsonify({
            "success": False,
            "message": "username là bắt buộc"
        }), 400
    
    if password is None:
        return jsonify({
            "success": False,
            "message": "password là bắt buộc"
        }), 400
    
    # Validate username
    if not validate_username(username):
        return jsonify({
            "success": False,
            "message": "Tên đăng nhập phải có 3-50 ký tự, chỉ chứa chữ cái, số và dấu gạch dưới"
        }), 400
    
    # Validate password
    valid, msg = validate_password_request(password)
    if not valid:
        return jsonify({
            "success": False,
            "message": msg
        }), 400
    
    # Đăng ký user
    result = register_user(
        username=username,
        password=password,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    
    if result["success"]:
        return jsonify({
            "success": True,
            "message": result["message"],
            "user_id": result["user_id"]
        }), 201
    else:
        if "tồn tại" in result["message"]:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 409
        elif "Lỗi hệ thống" in result["message"]:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 500
        else:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 400


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")  # Giới hạn 20 request/phút
def login():
    """
    Endpoint đăng nhập.
    POST /api/auth/login
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "message": "Request body không hợp lệ"
        }), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if username is None or password is None:
        return jsonify({
            "success": False,
            "message": "username và password là bắt buộc"
        }), 400
    
    # Đăng nhập
    result = login_user(
        username=username,
        password=password,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        rate_limiter=login_rate_limiter
    )
    
    if result["success"]:
        # Lưu token (production nên dùng JWT)
        active_tokens[result["token"]] = {
            "username": username,
            "expiry": datetime.now().timestamp() + 3600  # 1 hour
        }
        return jsonify({
            "success": True,
            "message": result["message"],
            "token": result["token"]
        }), 200
    else:
        if "khóa" in result["message"]:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 401
        elif "Lỗi hệ thống" in result["message"]:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 500
        else:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 401


@app.route('/api/auth/change-password', methods=['POST'])
@limiter.limit("5 per minute")
def change_password():
    """
    Endpoint đổi mật khẩu.
    POST /api/auth/change-password
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "message": "Request body không hợp lệ"
        }), 400
    
    # Lấy token từ header
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or token not in active_tokens:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401
    
    token_data = active_tokens[token]
    if token_data["expiry"] < datetime.now().timestamp():
        del active_tokens[token]
        return jsonify({
            "success": False,
            "message": "Token đã hết hạn"
        }), 401
    
    username = token_data["username"]
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({
            "success": False,
            "message": "old_password và new_password là bắt buộc"
        }), 400
    
    # Validate mật khẩu mới
    valid, msg = validate_password_request(new_password)
    if not valid:
        return jsonify({
            "success": False,
            "message": msg
        }), 400
    
    # Đổi mật khẩu
    result = change_user_password(
        username=username,
        old_password=old_password,
        new_password=new_password,
        ip_address=request.remote_addr
    )
    
    if result["success"]:
        return jsonify({
            "success": True,
            "message": result["message"]
        }), 200
    else:
        if "không chính xác" in result["message"]:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 401
        else:
            return jsonify({
                "success": False,
                "message": result["message"]
            }), 400


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout endpoint - xóa token."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in active_tokens:
        del active_tokens[token]
    return jsonify({
        "success": True,
        "message": "Đăng xuất thành công"
    }), 200


@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """Lấy thông tin user hiện tại."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or token not in active_tokens:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401
    
    token_data = active_tokens[token]
    if token_data["expiry"] < datetime.now().timestamp():
        del active_tokens[token]
        return jsonify({
            "success": False,
            "message": "Token đã hết hạn"
        }), 401
    
    user_info = get_user_info(token_data["username"])
    
    if user_info:
        return jsonify({
            "success": True,
            "user": {
                "id": user_info["id"],
                "username": user_info["username"],
                "created_at": user_info["created_at"],
                "last_login": user_info["last_login"]
            }
        }), 200
    
    return jsonify({
        "success": False,
        "message": "User not found"
    }), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    """Xử lý rate limit error."""
    return jsonify({
        "success": False,
        "message": "Quá nhiều request. Vui lòng thử lại sau."
    }), 429


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)