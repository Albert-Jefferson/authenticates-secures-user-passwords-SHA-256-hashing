"""
app.py
======
Flask Web App + REST API cho hệ thống xác thực và bảo mật mật khẩu người dùng
bằng SHA-256/PBKDF2-HMAC-SHA256 kết hợp salt.
"""
from __future__ import annotations

import os
import re
from datetime import datetime

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from Database import (
    RateLimiter,
    change_user_password,
    get_security_logs,
    get_user_info,
    list_users,
    login_user,
    register_user,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-secret-key-change-in-production")

CORS(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

login_rate_limiter = RateLimiter()
active_tokens: dict[str, dict[str, str | float]] = {}


def validate_username(username: str) -> bool:
    """Validate username: 3-50 ký tự, chỉ chữ, số và dấu gạch dưới."""
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))


def validate_password_request(password: str) -> tuple[bool, str]:
    """Validate nhanh ở tầng API; module password_hasher sẽ kiểm tra chi tiết hơn."""
    if not password:
        return False, "Mật khẩu không được để trống"
    if len(password) < 8:
        return False, "Mật khẩu phải có ít nhất 8 ký tự"
    if len(password) > 128:
        return False, "Mật khẩu không được dài quá 128 ký tự"
    return True, ""


def get_authenticated_username() -> tuple[str | None, tuple | None]:
    """Lấy username từ Bearer token và kiểm tra hạn token."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    if not token or token not in active_tokens:
        return None, (jsonify({"success": False, "message": "Unauthorized"}), 401)

    token_data = active_tokens[token]
    if float(token_data["expiry"]) < datetime.now().timestamp():
        del active_tokens[token]
        return None, (jsonify({"success": False, "message": "Token đã hết hạn"}), 401)

    return str(token_data["username"]), None


def serialize_user(user: dict) -> dict:
    """Chuẩn hóa user trả về API, tuyệt đối không trả stored_value/hash/salt."""
    return {
        "id": user["id"],
        "username": user["username"],
        "created_at": user["created_at"],
        "updated_at": user["updated_at"],
        "last_login": user["last_login"],
        "failed_attempts": user["failed_attempts"],
        "is_active": bool(user["is_active"]),
    }


@app.route("/")
def index():
    """Giao diện web demo cho đăng ký, đăng nhập và quản lý thử nghiệm."""
    return render_template("index.html")


@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    """Đăng ký tài khoản mới."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Request body không hợp lệ"}), 400

    username = data.get("username")
    password = data.get("password")

    if username is None:
        return jsonify({"success": False, "message": "username là bắt buộc"}), 400
    if password is None:
        return jsonify({"success": False, "message": "password là bắt buộc"}), 400

    if not validate_username(username):
        return jsonify({
            "success": False,
            "message": "Tên đăng nhập phải có 3-50 ký tự, chỉ chứa chữ cái, số và dấu gạch dưới",
        }), 400

    valid, message = validate_password_request(password)
    if not valid:
        return jsonify({"success": False, "message": message}), 400

    result = register_user(
        username=username,
        password=password,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    if result["success"]:
        return jsonify({
            "success": True,
            "message": result["message"],
            "user_id": result["user_id"],
        }), 201

    if "tồn tại" in result["message"]:
        status_code = 409
    elif "Lỗi hệ thống" in result["message"]:
        status_code = 500
    else:
        status_code = 400

    return jsonify({"success": False, "message": result["message"]}), status_code


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20 per minute")
def login():
    """Đăng nhập và cấp token demo."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Request body không hợp lệ"}), 400

    username = data.get("username")
    password = data.get("password")

    if username is None or password is None:
        return jsonify({"success": False, "message": "username và password là bắt buộc"}), 400

    result = login_user(
        username=username,
        password=password,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        rate_limiter=login_rate_limiter,
    )

    if result["success"]:
        active_tokens[result["token"]] = {
            "username": username,
            "expiry": datetime.now().timestamp() + 3600,
        }
        return jsonify({
            "success": True,
            "message": result["message"],
            "token": result["token"],
            "expires_in": 3600,
        }), 200

    status_code = 500 if "Lỗi hệ thống" in result["message"] else 401
    return jsonify({"success": False, "message": result["message"]}), status_code


@app.route("/api/auth/change-password", methods=["POST"])
@limiter.limit("5 per minute")
def change_password():
    """Đổi mật khẩu cho user đang đăng nhập."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Request body không hợp lệ"}), 400

    username, error_response = get_authenticated_username()
    if error_response:
        return error_response

    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "old_password và new_password là bắt buộc"}), 400

    valid, message = validate_password_request(new_password)
    if not valid:
        return jsonify({"success": False, "message": message}), 400

    result = change_user_password(
        username=username,
        old_password=old_password,
        new_password=new_password,
        ip_address=request.remote_addr,
    )

    if result["success"]:
        return jsonify({"success": True, "message": result["message"]}), 200

    status_code = 401 if "không chính xác" in result["message"] else 400
    return jsonify({"success": False, "message": result["message"]}), status_code


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """Đăng xuất bằng cách xóa token khỏi bộ nhớ demo."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token in active_tokens:
        del active_tokens[token]
    return jsonify({"success": True, "message": "Đăng xuất thành công"}), 200


@app.route("/api/auth/me", methods=["GET"])
def get_current_user():
    """Lấy thông tin user hiện tại, không chứa thông tin nhạy cảm."""
    username, error_response = get_authenticated_username()
    if error_response:
        return error_response

    user_info = get_user_info(username)
    if not user_info:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({"success": True, "user": serialize_user(user_info)}), 200


@app.route("/api/users", methods=["GET"])
def get_users():
    """Danh sách người dùng ẩn hash/salt/stored_value để quản lý thử nghiệm."""
    _username, error_response = get_authenticated_username()
    if error_response:
        return error_response

    limit = request.args.get("limit", 100, type=int)
    return jsonify({
        "success": True,
        "users": [serialize_user(user) for user in list_users(limit=limit)],
    }), 200


@app.route("/api/security-logs", methods=["GET"])
def security_logs():
    """Log bảo mật gần nhất để minh họa thử nghiệm đăng ký/đăng nhập."""
    _username, error_response = get_authenticated_username()
    if error_response:
        return error_response

    limit = request.args.get("limit", 50, type=int)
    return jsonify({"success": True, "logs": get_security_logs(limit=limit)}), 200


@app.errorhandler(429)
def ratelimit_handler(_error):
    """Xử lý rate limit error."""
    return jsonify({"success": False, "message": "Quá nhiều request. Vui lòng thử lại sau."}), 429


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
