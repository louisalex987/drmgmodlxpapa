"""
Encryption module
Provides utilities for data encryption and decryption
"""

import base64
import hashlib
import secrets
from typing import Optional


class EncryptionManager:
    """Manages data encryption using XOR cipher with key strengthening"""
    
    def __init__(self, key: Optional[str] = None):
        """
        Initialize EncryptionManager
        
        Args:
            key: Encryption key (generated if not provided)
        """
        self.key = key or secrets.token_hex(32)
        self._derived_key = self._derive_key(self.key)
    
    @staticmethod
    def _derive_key(key: str, iterations: int = 10000) -> bytes:
        """
        Derive a key using multiple rounds of hashing
        
        Args:
            key: Original key
            iterations: Number of hash iterations
            
        Returns:
            Derived key bytes
        """
        derived = key.encode()
        for _ in range(iterations):
            derived = hashlib.sha256(derived).digest()
        return derived
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Base64-encoded encrypted data
        """
        if not isinstance(plaintext, str):
            raise ValueError("Plaintext must be a string")
        
        # Generate a random IV (initialization vector)
        iv = secrets.token_bytes(16)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Expand key to match plaintext length
        plaintext_len = len(plaintext_bytes)
        key_len = len(self._derived_key)
        repeat_count = plaintext_len // key_len + 1
        key_expanded = (self._derived_key * repeat_count)[:plaintext_len]
        
        # XOR encryption
        encrypted = bytes(p ^ k for p, k in zip(plaintext_bytes, key_expanded))
        
        # Prepend IV to encrypted data
        encrypted_with_iv = iv + encrypted
        
        # Encode to base64 for safe transport
        return base64.b64encode(encrypted_with_iv).decode('utf-8')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext data
        
        Args:
            ciphertext: Base64-encoded encrypted data
            
        Returns:
            Decrypted plaintext
        """
        if not isinstance(ciphertext, str):
            raise ValueError("Ciphertext must be a string")
        
        try:
            # Decode from base64
            encrypted_with_iv = base64.b64decode(ciphertext.encode('utf-8'))
            
            # Extract IV and encrypted data
            iv = encrypted_with_iv[:16]
            encrypted = encrypted_with_iv[16:]
            
            # Expand key to match encrypted data length
            encrypted_len = len(encrypted)
            key_len = len(self._derived_key)
            repeat_count = encrypted_len // key_len + 1
            key_expanded = (self._derived_key * repeat_count)[:encrypted_len]
            
            # XOR decryption
            decrypted = bytes(e ^ k for e, k in zip(encrypted, key_expanded))
            
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def hash_data(data: str) -> str:
        """
        Create a SHA-256 hash of data
        
        Args:
            data: Data to hash
            
        Returns:
            Hex-encoded hash
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def verify_hash(data: str, hash_value: str) -> bool:
        """
        Verify data against a hash
        
        Args:
            data: Original data
            hash_value: Hash to verify against
            
        Returns:
            True if hash matches, False otherwise
        """
        return EncryptionManager.hash_data(data) == hash_value
    
    def generate_new_key(self) -> str:
        """
        Generate a new encryption key
        
        Returns:
            New key as hex string
        """
        new_key = secrets.token_hex(32)
        self.key = new_key
        self._derived_key = self._derive_key(new_key)
        return new_key
