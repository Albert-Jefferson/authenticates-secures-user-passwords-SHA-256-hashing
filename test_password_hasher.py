"""
test_password_hasher.py
=======================
Kiểm thử toàn diện cho module password_hasher.py

Chạy: python -m pytest test_password_hasher.py -v
Hoặc: python test_password_hasher.py
"""

import hashlib
import sys
import time
import unittest

from password_hasher import (
    HashResult,
    ValidationResult,
    format_stored_value,
    generate_salt,
    hash_password,
    parse_stored_value,
    register_password,
    validate_password,
    verify_password,
)


# ──────────────────────────────────────────────────────
# TestGenerateSalt
# ──────────────────────────────────────────────────────
class TestGenerateSalt(unittest.TestCase):
    """Kiểm thử generate_salt()"""

    def test_length_default(self):
        """Salt mặc định phải dài 64 ký tự hex (32 bytes × 2)."""
        salt = generate_salt()
        self.assertEqual(len(salt), 64, "Salt phải có 64 ký tự hex")

    def test_length_custom(self):
        """Salt tùy chỉnh số byte."""
        salt = generate_salt(num_bytes=16)
        self.assertEqual(len(salt), 32)

    def test_is_hex_string(self):
        """Salt phải là chuỗi hex hợp lệ."""
        salt = generate_salt()
        try:
            int(salt, 16)
        except ValueError:
            self.fail("Salt không phải chuỗi hex hợp lệ")

    def test_uniqueness(self):
        """Hai lần gọi phải cho salt khác nhau (xác suất collision ≈ 0)."""
        salts = {generate_salt() for _ in range(1000)}
        self.assertEqual(len(salts), 1000, "Salt bị trùng lặp!")

    def test_returns_string(self):
        self.assertIsInstance(generate_salt(), str)


# ──────────────────────────────────────────────────────
# TestHashPassword
# ──────────────────────────────────────────────────────
class TestHashPassword(unittest.TestCase):
    """Kiểm thử hash_password()"""

    def setUp(self):
        self.salt = generate_salt()
        self.password = "SecurePass@2024"

    def test_returns_hash_result(self):
        result = hash_password(self.password, self.salt)
        self.assertIsInstance(result, HashResult)

    def test_hash_length(self):
        """SHA-256 luôn cho output 64 ký tự hex."""
        result = hash_password(self.password, self.salt)
        self.assertEqual(len(result.hash), 64)

    def test_same_input_same_output(self):
        """Cùng password + salt phải cho cùng hash (deterministic)."""
        r1 = hash_password(self.password, self.salt)
        r2 = hash_password(self.password, self.salt)
        self.assertEqual(r1.hash, r2.hash)

    def test_different_salt_different_hash(self):
        """Cùng password nhưng salt khác → hash khác (chống rainbow table)."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        r1 = hash_password(self.password, salt1)
        r2 = hash_password(self.password, salt2)
        self.assertNotEqual(
            r1.hash, r2.hash,
            "Hai salt khác nhau phải tạo ra hai hash khác nhau"
        )

    def test_different_password_different_hash(self):
        """Cùng salt nhưng password khác → hash khác."""
        r1 = hash_password("password1", self.salt)
        r2 = hash_password("password2", self.salt)
        self.assertNotEqual(r1.hash, r2.hash)

    def test_stored_value_format(self):
        """stored_value phải đúng định dạng sha256v1$salt$hash."""
        result = hash_password(self.password, self.salt)
        parts = result.stored_value.split("$")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "sha256v1")
        self.assertEqual(parts[1], self.salt)
        self.assertEqual(parts[2], result.hash)

    def test_algorithm_field(self):
        result = hash_password(self.password, self.salt)
        self.assertEqual(result.algorithm, "sha256")

    def test_empty_password_raises(self):
        with self.assertRaises(ValueError):
            hash_password("", self.salt)

    def test_empty_salt_raises(self):
        with self.assertRaises(ValueError):
            hash_password(self.password, "")

    def test_non_string_password_raises(self):
        with self.assertRaises(TypeError):
            hash_password(12345, self.salt)

    def test_unicode_password(self):
        """Mật khẩu unicode (tiếng Việt) phải hoạt động đúng."""
        result = hash_password("Mậtkhẩu@2024", self.salt)
        self.assertEqual(len(result.hash), 64)

    def test_correctness_against_stdlib(self):
        """Kiểm tra kết quả đúng so với tính tay bằng hashlib."""
        pw   = "TestPassword1!"
        salt = "a" * 64
        expected = hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()
        result = hash_password(pw, salt)
        self.assertEqual(result.hash, expected)


# ──────────────────────────────────────────────────────
# TestVerifyPassword
# ──────────────────────────────────────────────────────
class TestVerifyPassword(unittest.TestCase):
    """Kiểm thử verify_password()"""

    def setUp(self):
        self.password = "MyPass@2024"
        self.salt     = generate_salt()
        self.result   = hash_password(self.password, self.salt)

    def test_correct_password_returns_true(self):
        self.assertTrue(
            verify_password(self.password, self.result.stored_value)
        )

    def test_wrong_password_returns_false(self):
        self.assertFalse(
            verify_password("WrongPassword!", self.result.stored_value)
        )

    def test_empty_password_returns_false(self):
        self.assertFalse(
            verify_password("", self.result.stored_value)
        )

    def test_case_sensitive(self):
        """Phân biệt chữ hoa/thường."""
        self.assertFalse(
            verify_password(self.password.upper(), self.result.stored_value)
        )

    def test_partial_password_returns_false(self):
        self.assertFalse(
            verify_password(self.password[:-1], self.result.stored_value)
        )

    def test_corrupted_stored_value(self):
        """stored_value bị hỏng không được raise exception, chỉ trả False."""
        self.assertFalse(verify_password(self.password, "corrupted_value"))
        self.assertFalse(verify_password(self.password, ""))
        self.assertFalse(verify_password(self.password, "a$b"))

    def test_timing_attack_resistance(self):
        """
        Thời gian so sánh đúng/sai phải gần bằng nhau.
        (Chứng minh hmac.compare_digest hoạt động đúng)
        """
        iterations = 500
        # Đo thời gian verify đúng
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_password(self.password, self.result.stored_value)
        correct_time = time.perf_counter() - t0

        # Đo thời gian verify sai hoàn toàn
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_password("X" * len(self.password), self.result.stored_value)
        wrong_time = time.perf_counter() - t0

        # Hai thời gian không được chênh nhau quá 5× (threshold rộng cho môi trường ảo)
        ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
        self.assertLess(ratio, 5.0, f"Timing ratio quá lớn: {ratio:.2f}x")


# ──────────────────────────────────────────────────────
# TestStoredValue
# ──────────────────────────────────────────────────────
class TestStoredValue(unittest.TestCase):
    """Kiểm thử format_stored_value() và parse_stored_value()"""

    def test_roundtrip(self):
        """format → parse phải khôi phục đúng salt và hash."""
        salt = generate_salt()
        h    = "a" * 64
        stored = format_stored_value(salt, h)
        parsed_salt, parsed_hash = parse_stored_value(stored)
        self.assertEqual(parsed_salt, salt)
        self.assertEqual(parsed_hash, h)

    def test_invalid_format_raises(self):
        with self.assertRaises(ValueError):
            parse_stored_value("noseparator")

    def test_wrong_version_raises(self):
        with self.assertRaises(ValueError):
            parse_stored_value("md5v1$salt$hash")

    def test_too_many_parts_raises(self):
        with self.assertRaises(ValueError):
            parse_stored_value("sha256v1$salt$hash$extra")


# ──────────────────────────────────────────────────────
# TestValidatePassword
# ──────────────────────────────────────────────────────
class TestValidatePassword(unittest.TestCase):
    """Kiểm thử validate_password()"""

    def test_strong_password(self):
        r = validate_password("Secure@Pass9!")
        self.assertTrue(r.is_valid)
        self.assertEqual(r.strength, "Mạnh")
        self.assertEqual(r.score, 5)

    def test_too_short(self):
        r = validate_password("Ab1!")
        self.assertFalse(r.is_valid)
        self.assertIn("Tối thiểu 8 ký tự", r.errors)

    def test_no_uppercase(self):
        r = validate_password("mypass@2024")
        self.assertIn("Có ít nhất 1 chữ hoa (A-Z)", r.errors)

    def test_no_lowercase(self):
        r = validate_password("MYPASS@2024")
        self.assertIn("Có ít nhất 1 chữ thường (a-z)", r.errors)

    def test_no_digit(self):
        r = validate_password("MyPass@!")
        self.assertIn("Có ít nhất 1 chữ số (0-9)", r.errors)

    def test_no_special_char(self):
        r = validate_password("MyPass2024")
        self.assertIn("Có ít nhất 1 ký tự đặc biệt", r.errors)

    def test_weak_password(self):
        r = validate_password("abc")
        self.assertEqual(r.strength, "Yếu")

    def test_medium_password(self):
        r = validate_password("MyPassword2024")   # Thiếu special char
        self.assertEqual(r.strength, "Trung bình")

    def test_returns_validation_result(self):
        self.assertIsInstance(validate_password("test"), ValidationResult)


# ──────────────────────────────────────────────────────
# TestRegisterPassword
# ──────────────────────────────────────────────────────
class TestRegisterPassword(unittest.TestCase):
    """Kiểm thử hàm tổng hợp register_password()"""

    def test_valid_password(self):
        result = register_password("StrongPass@99")
        self.assertIsInstance(result, HashResult)
        self.assertEqual(len(result.hash), 64)
        self.assertEqual(len(result.salt), 64)

    def test_weak_password_raises(self):
        with self.assertRaises(ValueError) as ctx:
            register_password("weak")
        self.assertIn("Mật khẩu không hợp lệ", str(ctx.exception))

    def test_stored_value_can_verify(self):
        """stored_value từ register phải verify được ngay."""
        pw     = "TestReg@2024"
        result = register_password(pw)
        self.assertTrue(verify_password(pw, result.stored_value))


# ──────────────────────────────────────────────────────
# TestIntegration: Luồng đăng ký → đăng nhập đầy đủ
# ──────────────────────────────────────────────────────
class TestIntegration(unittest.TestCase):
    """Kiểm thử luồng nghiệp vụ hoàn chỉnh."""

    def test_register_then_login_success(self):
        password = "Integration@99"
        # Bước 1: Đăng ký — tạo hash lưu DB
        reg  = register_password(password)
        db_stored_value = reg.stored_value   # Giả lập lưu vào DB

        # Bước 2: Đăng nhập — xác thực
        self.assertTrue(verify_password(password, db_stored_value))

    def test_register_then_login_wrong_password(self):
        reg = register_password("Correct@Pass1")
        self.assertFalse(verify_password("Wrong@Pass1", reg.stored_value))

    def test_two_users_same_password_different_hash(self):
        """Hai người dùng cùng mật khẩu phải có hash khác nhau do salt khác."""
        pw = "SamePass@2024"
        r1 = register_password(pw)
        r2 = register_password(pw)
        self.assertNotEqual(r1.salt, r2.salt)
        self.assertNotEqual(r1.hash, r2.hash)
        # Nhưng cả hai đều verify đúng
        self.assertTrue(verify_password(pw, r1.stored_value))
        self.assertTrue(verify_password(pw, r2.stored_value))

    def test_stored_value_not_contain_plain_password(self):
        """stored_value không được chứa mật khẩu gốc."""
        pw  = "SecretPass@1"
        reg = register_password(pw)
        self.assertNotIn(pw, reg.stored_value)


# ──────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────
if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
