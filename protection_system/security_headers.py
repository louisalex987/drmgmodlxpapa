"""
Security headers module
Provides utilities to manage HTTP security headers
"""

from typing import Dict


class SecurityHeaders:
    """Manages HTTP security headers for web applications"""
    
    # Default secure headers
    DEFAULT_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    def __init__(self, custom_headers: Dict[str, str] = None):
        """
        Initialize SecurityHeaders
        
        Args:
            custom_headers: Custom headers to override defaults
        """
        self.headers = self.DEFAULT_HEADERS.copy()
        if custom_headers:
            self.headers.update(custom_headers)
    
    def get_headers(self) -> Dict[str, str]:
        """
        Get all security headers
        
        Returns:
            Dictionary of headers
        """
        return self.headers.copy()
    
    def set_header(self, name: str, value: str) -> None:
        """
        Set a specific header
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers[name] = value
    
    def remove_header(self, name: str) -> bool:
        """
        Remove a specific header
        
        Args:
            name: Header name
            
        Returns:
            True if header was removed, False if it didn't exist
        """
        if name in self.headers:
            del self.headers[name]
            return True
        return False
    
    def get_header(self, name: str) -> str:
        """
        Get a specific header value
        
        Args:
            name: Header name
            
        Returns:
            Header value or empty string if not found
        """
        return self.headers.get(name, '')
    
    def set_csp(self, policy: str) -> None:
        """
        Set Content Security Policy
        
        Args:
            policy: CSP policy string
        """
        self.headers['Content-Security-Policy'] = policy
    
    def set_cors(self, origin: str = '*', methods: str = 'GET, POST', 
                 headers: str = 'Content-Type') -> None:
        """
        Set CORS headers
        
        Args:
            origin: Allowed origins
            methods: Allowed methods
            headers: Allowed headers
        """
        self.headers['Access-Control-Allow-Origin'] = origin
        self.headers['Access-Control-Allow-Methods'] = methods
        self.headers['Access-Control-Allow-Headers'] = headers
    
    def apply_to_response(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """
        Apply security headers to a response headers dictionary
        
        Args:
            response_headers: Existing response headers
            
        Returns:
            Updated response headers
        """
        response_headers.update(self.headers)
        return response_headers
    
    @staticmethod
    def get_strict_headers() -> Dict[str, str]:
        """
        Get a set of strict security headers
        
        Returns:
            Dictionary of strict security headers
        """
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';",
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
        }
