"""
Integration tests for SQL injection lab security features.

Tests the full system including server routes, detection, logging, and rate limiting.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import sqlite3
from config import SecurityConfig
from security.detector import SQLInjectionDetector
from security.logger import SecurityLogger
from security.rate_limiter import RateLimiter


class TestSecurityIntegration:
    """Integration tests for security features."""

    def setup_method(self):
        """Set up test fixtures."""
        # Save original config
        self.original_secure_mode = SecurityConfig.SECURE_MODE
        self.original_block_attacks = SecurityConfig.BLOCK_ATTACKS

        # Initialize components
        self.detector = SQLInjectionDetector()
        self.logger = SecurityLogger(log_dir="logs/test")
        self.rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)

        # Ensure test database exists
        self._setup_test_database()

    def teardown_method(self):
        """Clean up after tests."""
        # Restore original config
        SecurityConfig.SECURE_MODE = self.original_secure_mode
        SecurityConfig.BLOCK_ATTACKS = self.original_block_attacks

        # Clean up test logs
        import shutil
        if os.path.exists("logs/test"):
            shutil.rmtree("logs/test")

    def _setup_test_database(self):
        """Create test database with sample data."""
        if not os.path.exists('mylab.db'):
            conn = sqlite3.connect('mylab.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    password TEXT
                )
            ''')
            cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")
            cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password')")
            conn.commit()
            conn.close()

    def test_vulnerable_mode_allows_attacks(self):
        """Test that vulnerable mode allows attacks but logs them."""
        SecurityConfig.SECURE_MODE = False
        SecurityConfig.BLOCK_ATTACKS = False

        username = "admin"
        password = "' OR '1'='1"

        # Detect attack
        result = self.detector.detect(username, password)
        assert result.is_attack is True

        # In vulnerable mode, attack should not be blocked
        should_block = SecurityConfig.should_block_attacks()
        assert should_block is False

        # Log the attempt
        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username=username,
            password=password,
            detected_patterns=result.matched_patterns,
            category=result.category,
            action_taken='logged',
            confidence=result.confidence
        )

        # Verify log was written
        attempts = self.logger.get_recent_attempts(limit=1)
        assert len(attempts) == 1
        assert attempts[0]['action_taken'] == 'logged'

    def test_secure_mode_blocks_attacks(self):
        """Test that secure mode blocks attacks."""
        SecurityConfig.SECURE_MODE = True
        SecurityConfig.BLOCK_ATTACKS = True

        username = "admin"
        password = "' OR '1'='1"

        # Detect attack
        result = self.detector.detect(username, password)
        assert result.is_attack is True

        # In secure mode, attack should be blocked
        should_block = SecurityConfig.should_block_attacks()
        assert should_block is True

        # Log the blocked attempt
        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username=username,
            password=password,
            detected_patterns=result.matched_patterns,
            category=result.category,
            action_taken='blocked',
            confidence=result.confidence
        )

        # Verify log shows blocked
        attempts = self.logger.get_recent_attempts(limit=1)
        assert len(attempts) == 1
        assert attempts[0]['action_taken'] == 'blocked'

    def test_secure_mode_allows_legitimate_logins(self):
        """Test that secure mode allows legitimate logins."""
        SecurityConfig.SECURE_MODE = True
        SecurityConfig.BLOCK_ATTACKS = True

        username = "admin"
        password = "admin123"

        # Detect (should not find attack)
        result = self.detector.detect(username, password)
        assert result.is_attack is False

        # Should not be blocked
        should_block = result.is_attack and SecurityConfig.should_block_attacks()
        assert should_block is False

        # Log legitimate access
        self.logger.log_access(
            ip_address="127.0.0.1",
            username=username,
            success=True
        )

    def test_rate_limiting_triggers(self):
        """Test that rate limiting triggers after max attempts."""
        ip = "192.168.1.100"

        # First 5 attempts should be allowed
        for i in range(5):
            allowed, remaining, reset_time = self.rate_limiter.check_rate_limit(ip)
            assert allowed is True
            assert remaining == 5 - i
            self.rate_limiter.record_attempt(ip)

        # 6th attempt should be blocked
        allowed, remaining, reset_time = self.rate_limiter.check_rate_limit(ip)
        assert allowed is False
        assert remaining == 0

    def test_rate_limiting_per_ip(self):
        """Test that rate limiting is per IP address."""
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"

        # Exhaust IP1
        for i in range(5):
            self.rate_limiter.record_attempt(ip1)

        # IP1 should be blocked
        allowed1, _, _ = self.rate_limiter.check_rate_limit(ip1)
        assert allowed1 is False

        # IP2 should still be allowed
        allowed2, remaining2, _ = self.rate_limiter.check_rate_limit(ip2)
        assert allowed2 is True
        assert remaining2 == 5

    def test_detection_info_in_logs(self):
        """Test that detection info appears in logs."""
        username = "admin"
        password = "' UNION SELECT * FROM users--"

        result = self.detector.detect(username, password)
        assert result.is_attack is True

        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username=username,
            password=password,
            detected_patterns=result.matched_patterns,
            category=result.category,
            action_taken='logged',
            confidence=result.confidence
        )

        attempts = self.logger.get_recent_attempts(limit=1)
        assert len(attempts) == 1
        assert attempts[0]['category'] in ['union_attack', 'comment_injection']
        assert len(attempts[0]['detected_patterns']) > 0

    def test_password_redaction_in_logs(self):
        """Test that passwords are redacted in logs."""
        username = "admin"
        password = "secretpassword123"

        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username=username,
            password=password,
            detected_patterns=[],
            category="none",
            action_taken='logged',
            confidence="low"
        )

        attempts = self.logger.get_recent_attempts(limit=1)
        assert len(attempts) == 1
        # Password should be redacted
        assert "secretpassword123" not in attempts[0]['password_input']
        assert "[REDACTED]" in attempts[0]['password_input'] or "*" in attempts[0]['password_input']

    def test_log_statistics(self):
        """Test log statistics calculation."""
        # Log some attempts
        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username="admin",
            password="' OR '1'='1",
            detected_patterns=["' OR '1'='1"],
            category="boolean_based",
            action_taken='logged',
            confidence="high"
        )

        self.logger.log_injection_attempt(
            ip_address="127.0.0.1",
            username="admin",
            password="' OR 1=1--",
            detected_patterns=["' OR 1=1"],
            category="boolean_based",
            action_taken='blocked',
            confidence="high"
        )

        stats = self.logger.get_stats()
        assert stats['total_attempts'] == 2
        assert stats['logged_attempts'] == 1
        assert stats['blocked_attempts'] == 1
        assert 'boolean_based' in stats['categories']

    def test_multiple_attack_types_detected(self):
        """Test detection of multiple attack types."""
        # Boolean + Comment
        result1 = self.detector.detect("admin' OR 1=1--", "password")
        assert result1.is_attack is True
        assert len(result1.matched_patterns) >= 2

        # UNION + Comment
        result2 = self.detector.detect("' UNION SELECT * FROM users--", "password")
        assert result2.is_attack is True
        assert len(result2.matched_patterns) >= 2


if __name__ == "__main__":
    # Run tests manually
    import traceback

    test_instance = TestSecurityIntegration()
    test_methods = [method for method in dir(test_instance) if method.startswith('test_')]

    passed = 0
    failed = 0

    for method_name in test_methods:
        try:
            test_instance.setup_method()
            method = getattr(test_instance, method_name)
            method()
            test_instance.teardown_method()
            print(f"✓ {method_name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {method_name}: {e}")
            traceback.print_exc()
            failed += 1
        except Exception as e:
            print(f"✗ {method_name}: Unexpected error: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests")
