"""Tests for rate limiter module"""

import unittest
import time
from protection_system.rate_limiter import RateLimiter


class TestRateLimiter(unittest.TestCase):
    """Test cases for RateLimiter"""
    
    def test_allow_within_limit(self):
        """Test requests within rate limit"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        identifier = "user123"
        
        for _ in range(5):
            self.assertTrue(limiter.is_allowed(identifier))
    
    def test_deny_over_limit(self):
        """Test requests over rate limit"""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        identifier = "user123"
        
        # Use up the limit
        for _ in range(3):
            self.assertTrue(limiter.is_allowed(identifier))
        
        # This should be denied
        self.assertFalse(limiter.is_allowed(identifier))
    
    def test_window_reset(self):
        """Test rate limit window reset"""
        limiter = RateLimiter(max_requests=2, window_seconds=1)
        identifier = "user123"
        
        # Use up the limit
        self.assertTrue(limiter.is_allowed(identifier))
        self.assertTrue(limiter.is_allowed(identifier))
        self.assertFalse(limiter.is_allowed(identifier))
        
        # Wait for window to reset
        time.sleep(1.1)
        
        # Should be allowed again
        self.assertTrue(limiter.is_allowed(identifier))
    
    def test_get_remaining_requests(self):
        """Test getting remaining request count"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        identifier = "user123"
        
        self.assertEqual(limiter.get_remaining_requests(identifier), 5)
        
        limiter.is_allowed(identifier)
        self.assertEqual(limiter.get_remaining_requests(identifier), 4)
        
        limiter.is_allowed(identifier)
        self.assertEqual(limiter.get_remaining_requests(identifier), 3)
    
    def test_get_reset_time(self):
        """Test getting reset time"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        identifier = "user123"
        
        self.assertIsNone(limiter.get_reset_time(identifier))
        
        limiter.is_allowed(identifier)
        reset_time = limiter.get_reset_time(identifier)
        self.assertIsNotNone(reset_time)
        self.assertGreater(reset_time, time.time())
    
    def test_reset_identifier(self):
        """Test resetting rate limit for identifier"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        identifier = "user123"
        
        limiter.is_allowed(identifier)
        limiter.is_allowed(identifier)
        self.assertFalse(limiter.is_allowed(identifier))
        
        limiter.reset(identifier)
        self.assertTrue(limiter.is_allowed(identifier))
    
    def test_clear_all(self):
        """Test clearing all rate limit data"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        limiter.is_allowed("user1")
        limiter.is_allowed("user2")
        
        limiter.clear_all()
        
        self.assertEqual(limiter.get_remaining_requests("user1"), 2)
        self.assertEqual(limiter.get_remaining_requests("user2"), 2)
    
    def test_multiple_identifiers(self):
        """Test rate limiting with multiple identifiers"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        self.assertTrue(limiter.is_allowed("user1"))
        self.assertTrue(limiter.is_allowed("user1"))
        self.assertFalse(limiter.is_allowed("user1"))
        
        # user2 should have separate limit
        self.assertTrue(limiter.is_allowed("user2"))
        self.assertTrue(limiter.is_allowed("user2"))


if __name__ == '__main__':
    unittest.main()
