"""
Authentication and Authorization module
Provides utilities for password hashing, token generation, and permission management
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional, Dict, Set


class AuthManager:
    """Manages authentication and authorization for users"""
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize AuthManager
        
        Args:
            secret_key: Secret key for token generation (generated if not provided)
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.tokens: Dict[str, Dict] = {}
        self.user_permissions: Dict[str, Set[str]] = {}
    
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
        """
        Hash a password using SHA-256 with salt
        
        Args:
            password: Plain text password
            salt: Salt for hashing (generated if not provided)
            
        Returns:
            Tuple of (hashed_password, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return pwd_hash, salt
    
    @staticmethod
    def verify_password(password: str, hashed_password: str, salt: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored hashed password
            salt: Salt used for hashing
            
        Returns:
            True if password matches, False otherwise
        """
        pwd_hash, _ = AuthManager.hash_password(password, salt)
        return hmac.compare_digest(pwd_hash, hashed_password)
    
    def generate_token(self, user_id: str, expiry_seconds: int = 3600) -> str:
        """
        Generate a secure authentication token
        
        Args:
            user_id: User identifier
            expiry_seconds: Token expiry time in seconds (default 1 hour)
            
        Returns:
            Generated token string
        """
        token = secrets.token_urlsafe(32)
        expiry_time = time.time() + expiry_seconds
        
        self.tokens[token] = {
            'user_id': user_id,
            'expiry': expiry_time
        }
        
        return token
    
    def validate_token(self, token: str) -> Optional[str]:
        """
        Validate an authentication token
        
        Args:
            token: Token to validate
            
        Returns:
            User ID if token is valid, None otherwise
        """
        if token not in self.tokens:
            return None
        
        token_data = self.tokens[token]
        
        # Check if token has expired
        if time.time() > token_data['expiry']:
            del self.tokens[token]
            return None
        
        return token_data['user_id']
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke an authentication token
        
        Args:
            token: Token to revoke
            
        Returns:
            True if token was revoked, False if token didn't exist
        """
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False
    
    def add_permission(self, user_id: str, permission: str) -> None:
        """
        Add a permission to a user
        
        Args:
            user_id: User identifier
            permission: Permission to add
        """
        if user_id not in self.user_permissions:
            self.user_permissions[user_id] = set()
        self.user_permissions[user_id].add(permission)
    
    def remove_permission(self, user_id: str, permission: str) -> bool:
        """
        Remove a permission from a user
        
        Args:
            user_id: User identifier
            permission: Permission to remove
            
        Returns:
            True if permission was removed, False otherwise
        """
        if user_id in self.user_permissions and permission in self.user_permissions[user_id]:
            self.user_permissions[user_id].remove(permission)
            return True
        return False
    
    def has_permission(self, user_id: str, permission: str) -> bool:
        """
        Check if a user has a specific permission
        
        Args:
            user_id: User identifier
            permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        return user_id in self.user_permissions and permission in self.user_permissions[user_id]
    
    def get_permissions(self, user_id: str) -> Set[str]:
        """
        Get all permissions for a user
        
        Args:
            user_id: User identifier
            
        Returns:
            Set of permissions
        """
        return self.user_permissions.get(user_id, set()).copy()
