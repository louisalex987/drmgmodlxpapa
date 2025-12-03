"""
Input validation and sanitization module
Provides utilities to validate and sanitize user input to prevent injection attacks
"""

import re
from typing import Any, Optional


class InputValidator:
    """Validates and sanitizes user input to prevent security vulnerabilities"""
    
    # Common patterns for validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
    PHONE_PATTERN = re.compile(r'^\+?[1-9]\d{1,14}$')
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|\#|\/\*|\*\/)",
        r"(\bOR\b.{0,20}=|\bAND\b.{0,20}=)",
        r"('.*OR.*'.*=.*'|\".*OR.*\".*=.*\")",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
    ]
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email or not isinstance(email, str):
            return False
        return bool(InputValidator.EMAIL_PATTERN.match(email))
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format (alphanumeric, underscore, hyphen, 3-20 chars)"""
        if not username or not isinstance(username, str):
            return False
        return bool(InputValidator.USERNAME_PATTERN.match(username))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format"""
        if not phone or not isinstance(phone, str):
            return False
        return bool(InputValidator.PHONE_PATTERN.match(phone))
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize string by removing potentially dangerous characters
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length (optional)
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return ""
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Truncate if max_length specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def check_sql_injection(input_str: str) -> bool:
        """
        Check if input contains potential SQL injection patterns
        
        Returns:
            True if potential SQL injection detected, False otherwise
        """
        if not isinstance(input_str, str):
            return False
        
        input_upper = input_str.upper()
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def check_xss(input_str: str) -> bool:
        """
        Check if input contains potential XSS patterns
        
        Returns:
            True if potential XSS detected, False otherwise
        """
        if not isinstance(input_str, str):
            return False
        
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def sanitize_html(input_str: str) -> str:
        """
        Sanitize HTML by escaping special characters
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            HTML-escaped string
        """
        if not isinstance(input_str, str):
            return ""
        
        html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
        }
        
        return "".join(html_escape_table.get(c, c) for c in input_str)
    
    @staticmethod
    def validate_and_sanitize(input_str: str, 
                             max_length: Optional[int] = None,
                             check_sql: bool = True,
                             check_xss: bool = True) -> tuple[bool, str]:
        """
        Validate and sanitize input in one operation
        
        Args:
            input_str: Input string to validate and sanitize
            max_length: Maximum allowed length
            check_sql: Check for SQL injection
            check_xss: Check for XSS
            
        Returns:
            Tuple of (is_valid, sanitized_string)
        """
        if not isinstance(input_str, str):
            return False, ""
        
        # Check for attacks
        if check_sql and InputValidator.check_sql_injection(input_str):
            return False, ""
        
        if check_xss and InputValidator.check_xss(input_str):
            return False, ""
        
        # Sanitize
        sanitized = InputValidator.sanitize_string(input_str, max_length)
        
        return True, sanitized
