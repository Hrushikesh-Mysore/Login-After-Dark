"""
In-Memory Sliding Window Rate Limiter for Login After Dark
Protects authentication endpoints from rapid credential stuffing, brute force, and DoS attacks.
"""

import time
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, current_app

class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 15, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check if request under key is allowed.
        Returns: (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Purge timestamps outside the sliding window
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]

        if len(self.requests[key]) >= self.max_requests:
            oldest = self.requests[key][0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)))
            return False, retry_after

        self.requests[key].append(now)
        return True, 0

    def reset(self, key: str = None):
        """Reset limits for a key or all keys."""
        if key:
            self.requests.pop(key, None)
        else:
            self.requests.clear()

# Global limiter instance: 20 requests per 60 seconds per IP
login_rate_limiter = SlidingWindowRateLimiter(max_requests=25, window_seconds=60)

def rate_limit(limiter: SlidingWindowRateLimiter = login_rate_limiter):
    """Decorator to apply rate limiting to Flask routes."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Skip rate limiting during automated test execution
            if current_app and current_app.config.get("TESTING"):
                return f(*args, **kwargs)

            # Extract client IP
            client_ip = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.remote_addr
                or "127.0.0.1"
            )

            allowed, retry_after = limiter.is_allowed(client_ip)
            if not allowed:
                return jsonify({
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Please wait {retry_after} seconds before trying again.",
                    "retry_after": retry_after
                }), 429

            return f(*args, **kwargs)
        return wrapped
    return decorator
