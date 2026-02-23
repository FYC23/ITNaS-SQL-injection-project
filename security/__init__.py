"""
Security module for SQL injection detection, logging, and rate limiting.

This module provides educational security features for the SQL injection lab:
- Pattern-based SQL injection detection
- JSON-based logging of attack attempts
- IP-based rate limiting
"""

from .detector import detect_sql_injection, SQLInjectionDetector
from .logger import SecurityLogger
from .rate_limiter import RateLimiter

__all__ = [
    'detect_sql_injection',
    'SQLInjectionDetector',
    'SecurityLogger',
    'RateLimiter',
]
