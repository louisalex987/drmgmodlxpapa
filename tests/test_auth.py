"""Tests for authentication module"""

import unittest
import time
from protection_system.auth import AuthManager


class TestAuthManager(unittest.TestCase):
    """Test cases for AuthManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.auth = AuthManager()
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "test_password123"
        pwd_hash, salt = AuthManager.hash_password(password)
        
        self.assertIsNotNone(pwd_hash)
        self.assertIsNotNone(salt)
        self.assertEqual(len(pwd_hash), 64)  # SHA-256 produces 64 hex chars
        self.assertEqual(len(salt), 32)  # 16 bytes = 32 hex chars
    
    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "correct_password"
        pwd_hash, salt = AuthManager.hash_password(password)
        
        self.assertTrue(AuthManager.verify_password(password, pwd_hash, salt))
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "correct_password"
        pwd_hash, salt = AuthManager.hash_password(password)
        
        self.assertFalse(AuthManager.verify_password("wrong_password", pwd_hash, salt))
    
    def test_generate_token(self):
        """Test token generation"""
        user_id = "user123"
        token = self.auth.generate_token(user_id)
        
        self.assertIsNotNone(token)
        self.assertIn(token, self.auth.tokens)
        self.assertEqual(self.auth.tokens[token]['user_id'], user_id)
    
    def test_validate_token_valid(self):
        """Test token validation with valid token"""
        user_id = "user123"
        token = self.auth.generate_token(user_id)
        
        validated_user_id = self.auth.validate_token(token)
        self.assertEqual(validated_user_id, user_id)
    
    def test_validate_token_invalid(self):
        """Test token validation with invalid token"""
        validated_user_id = self.auth.validate_token("invalid_token")
        self.assertIsNone(validated_user_id)
    
    def test_validate_token_expired(self):
        """Test token validation with expired token"""
        user_id = "user123"
        token = self.auth.generate_token(user_id, expiry_seconds=1)
        
        time.sleep(1.1)
        validated_user_id = self.auth.validate_token(token)
        self.assertIsNone(validated_user_id)
    
    def test_revoke_token(self):
        """Test token revocation"""
        user_id = "user123"
        token = self.auth.generate_token(user_id)
        
        self.assertTrue(self.auth.revoke_token(token))
        self.assertIsNone(self.auth.validate_token(token))
    
    def test_add_permission(self):
        """Test adding permissions"""
        user_id = "user123"
        permission = "read"
        
        self.auth.add_permission(user_id, permission)
        self.assertTrue(self.auth.has_permission(user_id, permission))
    
    def test_remove_permission(self):
        """Test removing permissions"""
        user_id = "user123"
        permission = "read"
        
        self.auth.add_permission(user_id, permission)
        self.assertTrue(self.auth.remove_permission(user_id, permission))
        self.assertFalse(self.auth.has_permission(user_id, permission))
    
    def test_get_permissions(self):
        """Test getting all permissions"""
        user_id = "user123"
        permissions = {"read", "write", "delete"}
        
        for perm in permissions:
            self.auth.add_permission(user_id, perm)
        
        user_perms = self.auth.get_permissions(user_id)
        self.assertEqual(user_perms, permissions)


if __name__ == '__main__':
    unittest.main()
