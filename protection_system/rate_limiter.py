"""
Rate limiting module
Provides utilities to limit request rates and prevent abuse
"""

import time
from typing import Dict, Optional
from collections import deque


class RateLimiter:
    """Rate limiter using sliding window algorithm"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Initialize RateLimiter
        
        Args:
            max_requests: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request is allowed for the given identifier
        
        Args:
            identifier: Unique identifier (e.g., user ID, IP address)
            
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        current_time = time.time()
        
        # Initialize request queue for new identifier
        if identifier not in self.requests:
            self.requests[identifier] = deque()
        
        request_queue = self.requests[identifier]
        
        # Remove requests outside the time window
        while request_queue and request_queue[0] < current_time - self.window_seconds:
            request_queue.popleft()
        
        # Check if limit is reached
        if len(request_queue) >= self.max_requests:
            return False
        
        # Add current request
        request_queue.append(current_time)
        return True
    
    def get_remaining_requests(self, identifier: str) -> int:
        """
        Get number of remaining requests for identifier
        
        Args:
            identifier: Unique identifier
            
        Returns:
            Number of remaining requests
        """
        if identifier not in self.requests:
            return self.max_requests
        
        current_time = time.time()
        request_queue = self.requests[identifier]
        
        # Clean up old requests
        while request_queue and request_queue[0] < current_time - self.window_seconds:
            request_queue.popleft()
        
        return max(0, self.max_requests - len(request_queue))
    
    def get_reset_time(self, identifier: str) -> Optional[float]:
        """
        Get the time when the rate limit will reset for identifier
        
        Args:
            identifier: Unique identifier
            
        Returns:
            Unix timestamp when limit resets, or None if no requests
        """
        if identifier not in self.requests or not self.requests[identifier]:
            return None
        
        oldest_request = self.requests[identifier][0]
        return oldest_request + self.window_seconds
    
    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for an identifier
        
        Args:
            identifier: Unique identifier
        """
        if identifier in self.requests:
            del self.requests[identifier]
    
    def clear_all(self) -> None:
        """Clear all rate limit data"""
        self.requests.clear()
