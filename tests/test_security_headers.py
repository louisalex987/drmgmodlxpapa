"""Tests for security headers module"""

import unittest
from protection_system.security_headers import SecurityHeaders


class TestSecurityHeaders(unittest.TestCase):
    """Test cases for SecurityHeaders"""
    
    def test_default_headers(self):
        """Test default security headers"""
        headers_manager = SecurityHeaders()
        headers = headers_manager.get_headers()
        
        self.assertIn('X-Content-Type-Options', headers)
        self.assertIn('X-Frame-Options', headers)
        self.assertIn('X-XSS-Protection', headers)
        self.assertIn('Strict-Transport-Security', headers)
        self.assertIn('Content-Security-Policy', headers)
    
    def test_custom_headers(self):
        """Test custom headers override"""
        custom = {'Custom-Header': 'custom-value'}
        headers_manager = SecurityHeaders(custom_headers=custom)
        headers = headers_manager.get_headers()
        
        self.assertIn('Custom-Header', headers)
        self.assertEqual(headers['Custom-Header'], 'custom-value')
    
    def test_set_header(self):
        """Test setting a header"""
        headers_manager = SecurityHeaders()
        headers_manager.set_header('Test-Header', 'test-value')
        
        self.assertEqual(headers_manager.get_header('Test-Header'), 'test-value')
    
    def test_remove_header(self):
        """Test removing a header"""
        headers_manager = SecurityHeaders()
        
        self.assertTrue(headers_manager.remove_header('X-Frame-Options'))
        self.assertEqual(headers_manager.get_header('X-Frame-Options'), '')
        self.assertFalse(headers_manager.remove_header('Non-Existent-Header'))
    
    def test_get_header(self):
        """Test getting a header value"""
        headers_manager = SecurityHeaders()
        
        value = headers_manager.get_header('X-Frame-Options')
        self.assertEqual(value, 'DENY')
        
        value = headers_manager.get_header('Non-Existent')
        self.assertEqual(value, '')
    
    def test_set_csp(self):
        """Test setting Content Security Policy"""
        headers_manager = SecurityHeaders()
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        
        headers_manager.set_csp(csp)
        self.assertEqual(headers_manager.get_header('Content-Security-Policy'), csp)
    
    def test_set_cors(self):
        """Test setting CORS headers"""
        headers_manager = SecurityHeaders()
        headers_manager.set_cors(
            origin='https://example.com',
            methods='GET, POST, PUT',
            headers='Content-Type, Authorization'
        )
        
        self.assertEqual(
            headers_manager.get_header('Access-Control-Allow-Origin'),
            'https://example.com'
        )
        self.assertEqual(
            headers_manager.get_header('Access-Control-Allow-Methods'),
            'GET, POST, PUT'
        )
        self.assertEqual(
            headers_manager.get_header('Access-Control-Allow-Headers'),
            'Content-Type, Authorization'
        )
    
    def test_apply_to_response(self):
        """Test applying headers to response"""
        headers_manager = SecurityHeaders()
        response_headers = {'Content-Type': 'text/html'}
        
        updated_headers = headers_manager.apply_to_response(response_headers)
        
        self.assertIn('Content-Type', updated_headers)
        self.assertIn('X-Frame-Options', updated_headers)
        self.assertIn('X-Content-Type-Options', updated_headers)
    
    def test_get_strict_headers(self):
        """Test getting strict security headers"""
        strict_headers = SecurityHeaders.get_strict_headers()
        
        self.assertIn('X-Content-Type-Options', strict_headers)
        self.assertIn('X-Frame-Options', strict_headers)
        self.assertIn('Strict-Transport-Security', strict_headers)
        
        # Verify strict HSTS has preload
        self.assertIn('preload', strict_headers['Strict-Transport-Security'])
        
        # Verify strict CSP
        self.assertIn("default-src 'none'", strict_headers['Content-Security-Policy'])


if __name__ == '__main__':
    unittest.main()
