"""
Protection System - A comprehensive security and protection module
Provides input validation, authentication, rate limiting, and encryption utilities.
"""

__version__ = "1.0.0"
__author__ = "Protection System Team"

from .validator import InputValidator
from .auth import AuthManager
from .rate_limiter import RateLimiter
from .encryption import EncryptionManager
from .security_headers import SecurityHeaders

__all__ = [
    'InputValidator',
    'AuthManager',
    'RateLimiter',
    'EncryptionManager',
    'SecurityHeaders'
]
