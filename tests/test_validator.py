"""Tests for input validator module"""

import unittest
from protection_system.validator import InputValidator


class TestInputValidator(unittest.TestCase):
    """Test cases for InputValidator"""
    
    def test_validate_email_valid(self):
        """Test email validation with valid emails"""
        self.assertTrue(InputValidator.validate_email('test@example.com'))
        self.assertTrue(InputValidator.validate_email('user.name+tag@example.co.uk'))
        self.assertTrue(InputValidator.validate_email('test123@test-domain.com'))
    
    def test_validate_email_invalid(self):
        """Test email validation with invalid emails"""
        self.assertFalse(InputValidator.validate_email('invalid'))
        self.assertFalse(InputValidator.validate_email('@example.com'))
        self.assertFalse(InputValidator.validate_email('test@'))
        self.assertFalse(InputValidator.validate_email(''))
        self.assertFalse(InputValidator.validate_email(None))
    
    def test_validate_username_valid(self):
        """Test username validation with valid usernames"""
        self.assertTrue(InputValidator.validate_username('user123'))
        self.assertTrue(InputValidator.validate_username('test_user'))
        self.assertTrue(InputValidator.validate_username('user-name'))
    
    def test_validate_username_invalid(self):
        """Test username validation with invalid usernames"""
        self.assertFalse(InputValidator.validate_username('ab'))  # Too short
        self.assertFalse(InputValidator.validate_username('a' * 21))  # Too long
        self.assertFalse(InputValidator.validate_username('user@name'))  # Invalid char
        self.assertFalse(InputValidator.validate_username(''))
        self.assertFalse(InputValidator.validate_username(None))
    
    def test_validate_phone_valid(self):
        """Test phone validation with valid phone numbers"""
        self.assertTrue(InputValidator.validate_phone('+1234567890'))
        self.assertTrue(InputValidator.validate_phone('1234567890'))
        self.assertTrue(InputValidator.validate_phone('+441234567890'))
    
    def test_validate_phone_invalid(self):
        """Test phone validation with invalid phone numbers"""
        self.assertFalse(InputValidator.validate_phone('12-34-56'))
        self.assertFalse(InputValidator.validate_phone('abc'))
        self.assertFalse(InputValidator.validate_phone(''))
        self.assertFalse(InputValidator.validate_phone(None))
    
    def test_sanitize_string(self):
        """Test string sanitization"""
        self.assertEqual(InputValidator.sanitize_string('hello\x00world'), 'helloworld')
        self.assertEqual(InputValidator.sanitize_string('test', max_length=2), 'te')
        self.assertEqual(InputValidator.sanitize_string(''), '')
    
    def test_check_sql_injection(self):
        """Test SQL injection detection"""
        self.assertTrue(InputValidator.check_sql_injection("SELECT * FROM users"))
        self.assertTrue(InputValidator.check_sql_injection("'; DROP TABLE users--"))
        self.assertTrue(InputValidator.check_sql_injection("admin' OR '1'='1"))
        self.assertFalse(InputValidator.check_sql_injection("normal text"))
    
    def test_check_xss(self):
        """Test XSS detection"""
        self.assertTrue(InputValidator.check_xss("<script>alert('xss')</script>"))
        self.assertTrue(InputValidator.check_xss("javascript:alert('xss')"))
        self.assertTrue(InputValidator.check_xss('<img onload="alert(1)">'))
        self.assertFalse(InputValidator.check_xss("normal text"))
    
    def test_sanitize_html(self):
        """Test HTML sanitization"""
        self.assertEqual(InputValidator.sanitize_html('<script>'), '&lt;script&gt;')
        self.assertEqual(InputValidator.sanitize_html('a&b'), 'a&amp;b')
        self.assertEqual(InputValidator.sanitize_html('"quoted"'), '&quot;quoted&quot;')
    
    def test_validate_and_sanitize(self):
        """Test combined validation and sanitization"""
        valid, sanitized = InputValidator.validate_and_sanitize("normal text")
        self.assertTrue(valid)
        self.assertEqual(sanitized, "normal text")
        
        valid, sanitized = InputValidator.validate_and_sanitize("SELECT * FROM users")
        self.assertFalse(valid)
        self.assertEqual(sanitized, "")
        
        valid, sanitized = InputValidator.validate_and_sanitize("<script>alert(1)</script>")
        self.assertFalse(valid)
        self.assertEqual(sanitized, "")


if __name__ == '__main__':
    unittest.main()
