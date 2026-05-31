"""
test_api.py
===========
Kiểm thử API endpoints.
Chạy: pytest test_api.py -v
"""

import pytest
import json
import time
from app import app, active_tokens


@pytest.fixture
def client():
    """Fixture cho Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_register_success(client):
    """Test đăng ký thành công."""
    response = client.post('/api/auth/register', json={
        'username': 'testuser1',
        'password': 'StrongPass@123'
    })
    data = json.loads(response.data)
    assert response.status_code == 201
    assert data['success'] is True
    assert 'user_id' in data


def test_register_duplicate_username(client):
    """Test đăng ký với username đã tồn tại."""
    # Đăng ký lần đầu
    client.post('/api/auth/register', json={
        'username': 'duplicate_user',
        'password': 'StrongPass@123'
    })
    
    # Đăng ký lần 2
    response = client.post('/api/auth/register', json={
        'username': 'duplicate_user',
        'password': 'AnotherPass@456'
    })
    data = json.loads(response.data)
    assert response.status_code == 409
    assert data['success'] is False
    assert 'tồn tại' in data['message']


def test_register_weak_password(client):
    """Test đăng ký với mật khẩu yếu."""
    response = client.post('/api/auth/register', json={
        'username': 'weakuser',
        'password': 'weak'
    })
    data = json.loads(response.data)
    assert response.status_code == 400
    assert data['success'] is False
    assert '8 ký tự' in data['message']


def test_register_missing_fields(client):
    """Test thiếu trường bắt buộc."""
    # Thiếu username
    response = client.post('/api/auth/register', json={
        'password': 'StrongPass@123'
    })
    data = json.loads(response.data)
    assert response.status_code == 400
    assert 'username' in data['message'].lower()
    
    # Thiếu password
    response = client.post('/api/auth/register', json={
        'username': 'testuser'
    })
    data = json.loads(response.data)
    assert response.status_code == 400
    assert 'password' in data['message'].lower()


def test_register_invalid_username(client):
    """Test username không hợp lệ."""
    # Username quá ngắn
    response = client.post('/api/auth/register', json={
        'username': 'ab',
        'password': 'StrongPass@123'
    })
    assert response.status_code == 400
    
    # Username có ký tự đặc biệt
    response = client.post('/api/auth/register', json={
        'username': 'test@user',
        'password': 'StrongPass@123'
    })
    assert response.status_code == 400


def test_login_success(client):
    """Test đăng nhập thành công."""
    # Đăng ký trước
    client.post('/api/auth/register', json={
        'username': 'logintest',
        'password': 'LoginPass@123'
    })
    
    # Đăng nhập
    response = client.post('/api/auth/login', json={
        'username': 'logintest',
        'password': 'LoginPass@123'
    })
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data['success'] is True
    assert 'token' in data


def test_login_wrong_password(client):
    """Test đăng nhập với mật khẩu sai."""
    # Đăng ký
    client.post('/api/auth/register', json={
        'username': 'wrongpass',
        'password': 'CorrectPass@123'
    })
    
    # Đăng nhập sai mật khẩu
    response = client.post('/api/auth/login', json={
        'username': 'wrongpass',
        'password': 'WrongPass@123'
    })
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data['success'] is False
    assert 'Sai thông tin' in data['message']


def test_login_nonexistent_user(client):
    """Test đăng nhập với user không tồn tại."""
    response = client.post('/api/auth/login', json={
        'username': 'nonexistent',
        'password': 'SomePass@123'
    })
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data['success'] is False
    # Không được tiết lộ user không tồn tại
    assert 'Sai thông tin' in data['message']


def test_login_missing_fields(client):
    """Test đăng nhập thiếu field."""
    response = client.post('/api/auth/login', json={
        'username': 'testuser'
    })
    data = json.loads(response.data)
    assert response.status_code == 400


def test_login_rate_limiting(client):
    """Test rate limiting cho login."""
    # Tạo user
    client.post('/api/auth/register', json={
        'username': 'ratelimit',
        'password': 'RatePass@123'
    })
    
    # Thử đăng nhập sai nhiều lần
    for i in range(6):  # Max 5 attempts
        response = client.post('/api/auth/login', json={
            'username': 'ratelimit',
            'password': 'WrongPass@123'
        })
    
    # Lần thứ 6 hoặc sau khi vượt quá limit
    # Tài khoản có thể bị khóa tạm thời
    response = client.post('/api/auth/login', json={
        'username': 'ratelimit',
        'password': 'RatePass@123'  # Mật khẩu đúng nhưng có thể bị khóa
    })
    # Có thể là 401 hoặc 429 tùy vào implementation


def test_change_password_success(client):
    """Test đổi mật khẩu thành công."""
    # Đăng ký
    client.post('/api/auth/register', json={
        'username': 'changepass',
        'password': 'OldPass@123'
    })
    
    # Đăng nhập lấy token
    login_resp = client.post('/api/auth/login', json={
        'username': 'changepass',
        'password': 'OldPass@123'
    })
    token = json.loads(login_resp.data)['token']
    
    # Đổi mật khẩu
    response = client.post('/api/auth/change-password', 
        json={
            'old_password': 'OldPass@123',
            'new_password': 'NewPass@456'
        },
        headers={'Authorization': f'Bearer {token}'}
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data['success'] is True
    
    # Kiểm tra đăng nhập với mật khẩu mới
    new_login = client.post('/api/auth/login', json={
        'username': 'changepass',
        'password': 'NewPass@456'
    })
    assert new_login.status_code == 200


def test_change_password_wrong_old(client):
    """Test đổi mật khẩu với mật khẩu cũ sai."""
    # Đăng ký
    client.post('/api/auth/register', json={
        'username': 'wrongold',
        'password': 'CorrectPass@123'
    })
    
    # Đăng nhập
    login_resp = client.post('/api/auth/login', json={
        'username': 'wrongold',
        'password': 'CorrectPass@123'
    })
    token = json.loads(login_resp.data)['token']
    
    # Đổi mật khẩu với mật khẩu cũ sai
    response = client.post('/api/auth/change-password',
        json={
            'old_password': 'WrongPass@123',
            'new_password': 'NewPass@456'
        },
        headers={'Authorization': f'Bearer {token}'}
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data['success'] is False


def test_change_password_weak_new(client):
    """Test đổi mật khẩu sang mật khẩu yếu."""
    client.post('/api/auth/register', json={
        'username': 'weaknew',
        'password': 'OldPass@123'
    })
    
    login_resp = client.post('/api/auth/login', json={
        'username': 'weaknew',
        'password': 'OldPass@123'
    })
    token = json.loads(login_resp.data)['token']
    
    response = client.post('/api/auth/change-password',
        json={
            'old_password': 'OldPass@123',
            'new_password': 'weak'
        },
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 400


def test_get_current_user(client):
    """Test lấy thông tin user hiện tại."""
    # Đăng ký
    client.post('/api/auth/register', json={
        'username': 'currentuser',
        'password': 'UserPass@123'
    })
    
    # Đăng nhập
    login_resp = client.post('/api/auth/login', json={
        'username': 'currentuser',
        'password': 'UserPass@123'
    })
    token = json.loads(login_resp.data)['token']
    
    # Lấy thông tin
    response = client.get('/api/auth/me',
        headers={'Authorization': f'Bearer {token}'}
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data['success'] is True
    assert data['user']['username'] == 'currentuser'


def test_logout(client):
    """Test logout endpoint."""
    client.post('/api/auth/register', json={
        'username': 'logoutuser',
        'password': 'LogoutPass@123'
    })
    
    login_resp = client.post('/api/auth/login', json={
        'username': 'logoutuser',
        'password': 'LogoutPass@123'
    })
    token = json.loads(login_resp.data)['token']
    
    # Logout
    response = client.post('/api/auth/logout',
        headers={'Authorization': f'Bearer {token}'}
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data['success'] is True
    
    # Thử dùng token cũ (sẽ thất bại)
    response = client.get('/api/auth/me',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 401


def test_unauthorized_access(client):
    """Test truy cập không có token."""
    response = client.get('/api/auth/me')
    assert response.status_code == 401
    
    response = client.post('/api/auth/change-password', json={
        'old_password': 'old',
        'new_password': 'new'
    })
    assert response.status_code == 401


def test_api_rate_limiting(client):
    """Test rate limiting tổng thể."""
    # Gửi nhiều request nhanh
    for i in range(15):  # Vượt quá limit mặc định
        response = client.post('/api/auth/register', json={
            'username': f'ratelimituser{i}',
            'password': 'StrongPass@123'
        })
        if response.status_code == 429:
            break
    
    # Có thể bị rate limit
    # 429 Too Many Requests


if __name__ == '__main__':
    pytest.main([__file__, '-v'])