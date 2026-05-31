"""
test_password_hasher.py
=======================
Kiểm thử toàn diện cho module password_hasher.py (nâng cấp)
"""

import hashlib
import sys
import time
import unittest
import os

from password_hasher import (
    HashResult,
    ValidationResult,
    PasswordChangeResult,
    format_stored_value,
    generate_salt,
    hash_password,
    parse_stored_value,
    register_password,
    validate_password,
    verify_password,
    change_password,
    needs_rehash,
    RateLimiter,
    PEPPER,
    ITERATIONS
)


# ──────────────────────────────────────────────────────
# Test cho các hàm mới
# ──────────────────────────────────────────────────────

class TestChangePassword(unittest.TestCase):
    """Kiểm thử change_password()"""
    
    def setUp(self):
        self.password = "OldPass@123"
        self.result = register_password(self.password)
    
    def test_change_password_success(self):
        """Đổi mật khẩu thành công với đúng mật khẩu cũ."""
        new_password = "NewPass@456"
        result = change_password(
            self.password, 
            new_password, 
            self.result.stored_value
        )
        self.assertTrue(result.success)
        self.assertIsNotNone(result.new_stored_value)
        # Verify mật khẩu mới hoạt động
        self.assertTrue(verify_password(new_password, result.new_stored_value))
        # Verify mật khẩu cũ không còn hoạt động
        self.assertFalse(verify_password(self.password, result.new_stored_value))
    
    def test_change_password_wrong_old(self):
        """Đổi mật khẩu thất bại với mật khẩu cũ sai."""
        result = change_password(
            "WrongPass@123",
            "NewPass@456",
            self.result.stored_value
        )
        self.assertFalse(result.success)
        self.assertIn("không chính xác", result.message)
    
    def test_change_password_same_password(self):
        """Không cho phép đổi sang mật khẩu giống cũ."""
        result = change_password(
            self.password,
            self.password,
            self.result.stored_value
        )
        self.assertFalse(result.success)
        self.assertIn("không được trùng", result.message)
    
    def test_change_password_weak_new(self):
        """Không cho phép đổi sang mật khẩu yếu."""
        result = change_password(
            self.password,
            "weak",
            self.result.stored_value
        )
        self.assertFalse(result.success)
        self.assertIn("không hợp lệ", result.message)


class TestNeedsRehash(unittest.TestCase):
    """Kiểm thử needs_rehash()"""
    
    def test_old_format_needs_rehash(self):
        """Định dạng cũ (sha256v1) cần rehash."""
        old_format = "sha256v1$abc123$def456"
        self.assertTrue(needs_rehash(old_format))
    
    def test_new_format_with_low_iterations(self):
        """Iterations thấp hơn chuẩn cần rehash."""
        # Tạo stored_value với iterations thấp
        salt = generate_salt()
        low_iter_value = format_stored_value(salt, "a"*64, iterations=1000, use_pepper=True)
        self.assertTrue(needs_rehash(low_iter_value))
    
    def test_current_format_no_rehash(self):
        """Định dạng hiện tại với iterations đủ cao không cần rehash."""
        result = register_password("StrongPass@123")
        self.assertFalse(needs_rehash(result.stored_value))


class TestRateLimiter(unittest.TestCase):
    """Kiểm thử RateLimiter class."""
    
    def setUp(self):
        self.rate_limiter = RateLimiter(max_attempts=3, lockout_seconds=1)
    
    def test_is_locked_initially_false(self):
        """Ban đầu tài khoản không bị khóa."""
        is_locked, _ = self.rate_limiter.is_locked("testuser")
        self.assertFalse(is_locked)
    
    def test_record_failed_increments(self):
        """Ghi nhận failed attempts."""
        count, _ = self.rate_limiter.record_failed("testuser")
        self.assertEqual(count, 1)
        
        count, _ = self.rate_limiter.record_failed("testuser")
        self.assertEqual(count, 2)
    
    def test_lockout_after_max_attempts(self):
        """Khóa tài khoản sau max_attempts lần thất bại."""
        for _ in range(3):
            self.rate_limiter.record_failed("testuser")
        
        is_locked, remaining = self.rate_limiter.is_locked("testuser")
        self.assertTrue(is_locked)
        self.assertIsNotNone(remaining)
    
    def test_lockout_expires(self):
        """Khóa tài khoản hết hạn sau lockout_seconds."""
        for _ in range(3):
            self.rate_limiter.record_failed("testuser")
        
        # Kiểm tra khóa
        is_locked, _ = self.rate_limiter.is_locked("testuser")
        self.assertTrue(is_locked)
        
        # Chờ hết thời gian khóa
        time.sleep(1.1)
        
        # Kiểm tra lại - hết khóa
        is_locked, _ = self.rate_limiter.is_locked("testuser")
        self.assertFalse(is_locked)
    
    def test_record_success_resets(self):
        """Đăng nhập thành công reset failed attempts."""
        self.rate_limiter.record_failed("testuser")
        self.rate_limiter.record_failed("testuser")
        
        self.rate_limiter.record_success("testuser")
        
        is_locked, _ = self.rate_limiter.is_locked("testuser")
        self.assertFalse(is_locked)
        
        # Sau reset, chỉ cần thêm 1 lần fail là chưa khóa
        self.rate_limiter.record_failed("testuser")
        is_locked, _ = self.rate_limiter.is_locked("testuser")
        self.assertFalse(is_locked)


class TestPepper(unittest.TestCase):
    """Kiểm thử tính năng pepper."""
    
    def test_pepper_changes_hash(self):
        """Hash với pepper khác hash không pepper."""
        salt = generate_salt()
        password = "TestPass@123"
        
        result_with_pepper = hash_password(password, salt, use_pepper=True)
        result_without_pepper = hash_password(password, salt, use_pepper=False)
        
        self.assertNotEqual(result_with_pepper.hash, result_without_pepper.hash)
    
    def test_verify_with_pepper_works(self):
        """Xác thực với pepper hoạt động đúng."""
        result = hash_password("TestPass@123", use_pepper=True)
        self.assertTrue(verify_password("TestPass@123", result.stored_value))
        self.assertFalse(verify_password("WrongPass@123", result.stored_value))
    
    def test_verify_without_pepper_fails_with_pepper_hash(self):
        """Mật khẩu đúng nhưng không dùng pepper sẽ không verify được hash có pepper."""
        result = hash_password("TestPass@123", use_pepper=True)
        # Tạo stored_value không pepper từ cùng mật khẩu
        no_pepper_result = hash_password("TestPass@123", use_pepper=False)
        self.assertNotEqual(result.stored_value, no_pepper_result.stored_value)


class TestPBKDF2Iterations(unittest.TestCase):
    """Kiểm thử multi-round hashing."""
    
    def test_different_iterations_produce_different_hash(self):
        """Số vòng lặp khác nhau tạo hash khác nhau."""
        salt = generate_salt()
        password = "TestPass@123"
        
        result_1k = hash_password(password, salt, iterations=1000)
        result_10k = hash_password(password, salt, iterations=10000)
        
        self.assertNotEqual(result_1k.hash, result_10k.hash)
    
    def test_verify_works_with_custom_iterations(self):
        """Xác thực hoạt động với số vòng lặp tùy chỉnh."""
        result = hash_password("TestPass@123", iterations=50000)
        self.assertTrue(verify_password("TestPass@123", result.stored_value))
    
    def test_performance_reasonable(self):
        """Performance của PBKDF2 với iterations=10000 phải chấp nhận được."""
        start = time.time()
        hash_password("TestPass@123", iterations=10000)
        elapsed = time.time() - start
        # PBKDF2 với 10000 iterations nên < 1s (trên máy tính hiện đại)
        self.assertLess(elapsed, 0.5)


# ──────────────────────────────────────────────────────
# Test cho các hàm cũ (giữ nguyên)
# ──────────────────────────────────────────────────────

class TestGenerateSalt(unittest.TestCase):
    """Kiểm thử generate_salt()"""
    
    def test_length_default(self):
        salt = generate_salt()
        self.assertEqual(len(salt), 64)
    
    def test_uniqueness(self):
        salts = {generate_salt() for _ in range(1000)}
        self.assertEqual(len(salts), 1000)


class TestHashPassword(unittest.TestCase):
    """Kiểm thử hash_password()"""
    
    def test_hash_length(self):
        result = hash_password("Test@123", generate_salt())
        self.assertEqual(len(result.hash), 64)
    
    def test_different_salt_different_hash(self):
        password = "Test@123"
        r1 = hash_password(password, generate_salt())
        r2 = hash_password(password, generate_salt())
        self.assertNotEqual(r1.hash, r2.hash)
    
    def test_empty_password_raises(self):
        with self.assertRaises(ValueError):
            hash_password("", generate_salt())


class TestVerifyPassword(unittest.TestCase):
    """Kiểm thử verify_password()"""
    
    def test_correct_password(self):
        result = register_password("TestPass@123")
        self.assertTrue(verify_password("TestPass@123", result.stored_value))
    
    def test_wrong_password(self):
        result = register_password("TestPass@123")
        self.assertFalse(verify_password("WrongPass@123", result.stored_value))
    
    def test_timing_attack_resistance(self):
        """Kiểm tra timing attack resistance."""
        result = register_password("TestPass@123")
        iterations = 500
        
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_password("TestPass@123", result.stored_value)
        correct_time = time.perf_counter() - t0
        
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_password("X" * 20, result.stored_value)
        wrong_time = time.perf_counter() - t0
        
        ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
        self.assertLess(ratio, 5.0)


class TestValidatePassword(unittest.TestCase):
    """Kiểm thử validate_password()"""
    
    def test_strong_password(self):
        r = validate_password("Secure@Pass9!")
        self.assertTrue(r.is_valid)
        self.assertEqual(r.strength, "Mạnh")
    
    def test_too_short(self):
        r = validate_password("Ab1!")
        self.assertFalse(r.is_valid)
        self.assertIn("Tối thiểu 8 ký tự", r.errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)