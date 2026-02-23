"""
Rate Limiting Module

IP-based rate limiting using sliding window algorithm.
Prevents brute force attacks by limiting login attempts per IP address.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from threading import Lock


class RateLimiter:
    """
    IP-based rate limiter using sliding window algorithm.

    Features:
    - In-memory tracking of attempts per IP
    - Sliding window (default: 5 attempts per 5 minutes)
    - Automatic cleanup of old timestamps
    - Thread-safe operations
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed within window
            window_seconds: Time window in seconds (default: 300 = 5 minutes)
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

        # Dictionary mapping IP address to list of attempt timestamps
        self._attempts: Dict[str, List[datetime]] = {}

        # Lock for thread-safe operations
        self._lock = Lock()

    def _clean_old_attempts(self, ip_address: str) -> None:
        """
        Remove timestamps outside the current window.

        Args:
            ip_address: IP address to clean
        """
        if ip_address not in self._attempts:
            return

        cutoff_time = datetime.now() - timedelta(seconds=self.window_seconds)
        self._attempts[ip_address] = [
            timestamp for timestamp in self._attempts[ip_address]
            if timestamp > cutoff_time
        ]

        # Remove IP if no recent attempts
        if not self._attempts[ip_address]:
            del self._attempts[ip_address]

    def check_rate_limit(self, ip_address: str) -> Tuple[bool, int, datetime]:
        """
        Check if IP address has exceeded rate limit.

        Args:
            ip_address: IP address to check

        Returns:
            Tuple of (allowed, attempts_remaining, reset_time)
            - allowed: True if request is allowed, False if rate limited
            - attempts_remaining: Number of attempts remaining
            - reset_time: When the rate limit will reset
        """
        with self._lock:
            # Clean old attempts first
            self._clean_old_attempts(ip_address)

            # Get current attempt count
            current_attempts = len(self._attempts.get(ip_address, []))

            # Calculate reset time
            if ip_address in self._attempts and self._attempts[ip_address]:
                oldest_attempt = min(self._attempts[ip_address])
                reset_time = oldest_attempt + timedelta(seconds=self.window_seconds)
            else:
                reset_time = datetime.now() + timedelta(seconds=self.window_seconds)

            # Check if rate limit exceeded
            if current_attempts >= self.max_attempts:
                return (False, 0, reset_time)

            # Calculate remaining attempts
            attempts_remaining = self.max_attempts - current_attempts

            return (True, attempts_remaining, reset_time)

    def record_attempt(self, ip_address: str) -> None:
        """
        Record a login attempt for an IP address.

        Args:
            ip_address: IP address making the attempt
        """
        with self._lock:
            if ip_address not in self._attempts:
                self._attempts[ip_address] = []

            self._attempts[ip_address].append(datetime.now())

            # Clean old attempts to prevent memory growth
            self._clean_old_attempts(ip_address)

    def reset_ip(self, ip_address: str) -> None:
        """
        Reset rate limit for a specific IP address.

        Args:
            ip_address: IP address to reset
        """
        with self._lock:
            if ip_address in self._attempts:
                del self._attempts[ip_address]

    def get_attempt_count(self, ip_address: str) -> int:
        """
        Get current attempt count for an IP address.

        Args:
            ip_address: IP address to check

        Returns:
            Number of attempts within current window
        """
        with self._lock:
            self._clean_old_attempts(ip_address)
            return len(self._attempts.get(ip_address, []))

    def get_all_stats(self) -> Dict[str, int]:
        """
        Get statistics for all tracked IP addresses.

        Returns:
            Dictionary mapping IP addresses to attempt counts
        """
        with self._lock:
            # Clean all IPs first
            for ip in list(self._attempts.keys()):
                self._clean_old_attempts(ip)

            return {ip: len(attempts) for ip, attempts in self._attempts.items()}
