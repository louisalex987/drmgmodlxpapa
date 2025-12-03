"""Tests for encryption module"""

import unittest
from protection_system.encryption import EncryptionManager


class TestEncryptionManager(unittest.TestCase):
    """Test cases for EncryptionManager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.encryption = EncryptionManager(key="test_key_123")
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        plaintext = "This is a secret message"
        
        ciphertext = self.encryption.encrypt(plaintext)
        self.assertNotEqual(ciphertext, plaintext)
        
        decrypted = self.encryption.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_different_outputs(self):
        """Test that encryption produces different outputs each time"""
        plaintext = "secret"
        
        ciphertext1 = self.encryption.encrypt(plaintext)
        ciphertext2 = self.encryption.encrypt(plaintext)
        
        # Due to random IV, ciphertexts should be different
        self.assertNotEqual(ciphertext1, ciphertext2)
        
        # But both should decrypt to same plaintext
        self.assertEqual(self.encryption.decrypt(ciphertext1), plaintext)
        self.assertEqual(self.encryption.decrypt(ciphertext2), plaintext)
    
    def test_encrypt_empty_string(self):
        """Test encrypting empty string"""
        plaintext = ""
        
        ciphertext = self.encryption.encrypt(plaintext)
        decrypted = self.encryption.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_long_string(self):
        """Test encrypting long string"""
        plaintext = "A" * 1000
        
        ciphertext = self.encryption.encrypt(plaintext)
        decrypted = self.encryption.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_unicode(self):
        """Test encrypting unicode characters"""
        plaintext = "Hello 世界 🌍"
        
        ciphertext = self.encryption.encrypt(plaintext)
        decrypted = self.encryption.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_decrypt_invalid_ciphertext(self):
        """Test decrypting invalid ciphertext"""
        with self.assertRaises(ValueError):
            self.encryption.decrypt("invalid_base64!")
    
    def test_hash_data(self):
        """Test data hashing"""
        data = "test data"
        hash1 = EncryptionManager.hash_data(data)
        hash2 = EncryptionManager.hash_data(data)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 produces 64 hex chars
    
    def test_verify_hash(self):
        """Test hash verification"""
        data = "test data"
        hash_value = EncryptionManager.hash_data(data)
        
        self.assertTrue(EncryptionManager.verify_hash(data, hash_value))
        self.assertFalse(EncryptionManager.verify_hash("wrong data", hash_value))
    
    def test_generate_new_key(self):
        """Test generating new encryption key"""
        old_key = self.encryption.key
        
        new_key = self.encryption.generate_new_key()
        
        self.assertNotEqual(old_key, new_key)
        self.assertEqual(len(new_key), 64)  # 32 bytes = 64 hex chars
    
    def test_different_keys_produce_different_results(self):
        """Test that different keys produce different encryption results"""
        plaintext = "secret message"
        
        enc1 = EncryptionManager(key="key1")
        enc2 = EncryptionManager(key="key2")
        
        cipher1 = enc1.encrypt(plaintext)
        cipher2 = enc2.encrypt(plaintext)
        
        # Different keys should not be able to decrypt each other's data
        with self.assertRaises(ValueError):
            enc1.decrypt(cipher2)


if __name__ == '__main__':
    unittest.main()
