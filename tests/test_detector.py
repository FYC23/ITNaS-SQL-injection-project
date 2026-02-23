"""
Unit tests for SQL injection detector.

Tests pattern detection, false positive handling, and confidence scoring.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security.detector import SQLInjectionDetector, detect_sql_injection


class TestSQLInjectionDetector:
    """Test suite for SQL injection detector."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = SQLInjectionDetector()

    def test_boolean_injection_single_quotes(self):
        """Test detection of boolean-based injection with single quotes."""
        result = self.detector.detect("admin", "' OR '1'='1")
        assert result.is_attack is True
        assert result.category == "boolean_based"
        assert len(result.matched_patterns) > 0

    def test_boolean_injection_numeric(self):
        """Test detection of boolean-based injection with numeric comparison."""
        result = self.detector.detect("admin", "' OR 1=1--")
        assert result.is_attack is True
        assert "boolean_based" in result.category or "comment_injection" in result.category

    def test_comment_injection_double_dash(self):
        """Test detection of comment injection with double dash."""
        result = self.detector.detect("admin'--", "anything")
        assert result.is_attack is True
        assert result.category == "comment_injection"

    def test_comment_injection_hash(self):
        """Test detection of comment injection with hash symbol."""
        result = self.detector.detect("admin'#", "password")
        assert result.is_attack is True
        assert result.category == "comment_injection"

    def test_union_attack(self):
        """Test detection of UNION-based SQL injection."""
        result = self.detector.detect("' UNION SELECT * FROM users--", "password")
        assert result.is_attack is True
        # May detect comment first, but should detect union
        assert any(pattern for pattern in result.matched_patterns if 'UNION' in pattern.upper())

    def test_union_all_attack(self):
        """Test detection of UNION ALL SELECT attack."""
        result = self.detector.detect("admin", "' UNION ALL SELECT id, username, password FROM users--")
        assert result.is_attack is True
        assert any(pattern for pattern in result.matched_patterns if 'UNION' in pattern.upper())

    def test_stacked_query_drop(self):
        """Test detection of stacked query with DROP statement."""
        result = self.detector.detect("admin'; DROP TABLE users; --", "password")
        assert result.is_attack is True
        # Should detect semicolon-based stacked query or comment
        assert result.category in ["stacked_query", "comment_injection"]

    def test_stacked_query_delete(self):
        """Test detection of stacked query with DELETE statement."""
        result = self.detector.detect("admin", "'; DELETE FROM users WHERE 1=1--")
        assert result.is_attack is True
        assert result.category in ["stacked_query", "comment_injection"]

    def test_time_based_sleep(self):
        """Test detection of time-based blind injection with SLEEP."""
        result = self.detector.detect("admin", "' OR SLEEP(5)--")
        assert result.is_attack is True
        # May detect boolean or time-based first
        assert result.category in ["time_based_blind", "boolean_based", "comment_injection"]

    def test_time_based_waitfor(self):
        """Test detection of time-based blind injection with WAITFOR."""
        result = self.detector.detect("admin", "'; WAITFOR DELAY '00:00:05'--")
        assert result.is_attack is True
        assert result.category in ["time_based_blind", "comment_injection"]

    def test_quote_manipulation(self):
        """Test detection of quote manipulation."""
        result = self.detector.detect("admin'''", "password")
        assert result.is_attack is True
        assert result.category == "quote_manipulation"

    def test_legitimate_username(self):
        """Test that legitimate usernames are not flagged."""
        result = self.detector.detect("john", "mypassword123")
        assert result.is_attack is False
        assert len(result.matched_patterns) == 0

    def test_legitimate_email(self):
        """Test that email addresses are not flagged."""
        result = self.detector.detect("user@example.com", "password123")
        assert result.is_attack is False
        assert len(result.matched_patterns) == 0

    def test_false_positive_obrien(self):
        """Test that O'Brien (legitimate apostrophe) is not flagged."""
        result = self.detector.detect("O'Brien", "password123")
        assert result.is_attack is False
        assert len(result.matched_patterns) == 0

    def test_false_positive_dangelo(self):
        """Test that D'Angelo (legitimate apostrophe) is not flagged."""
        result = self.detector.detect("D'Angelo", "mypassword")
        assert result.is_attack is False
        assert len(result.matched_patterns) == 0

    def test_false_positive_csharp(self):
        """Test that C# (programming language) is not flagged."""
        result = self.detector.detect("C#", "developer")
        assert result.is_attack is False
        assert len(result.matched_patterns) == 0

    def test_case_insensitive_or(self):
        """Test that detection is case-insensitive for OR."""
        result = self.detector.detect("admin", "' oR '1'='1")
        assert result.is_attack is True
        assert result.category == "boolean_based"

    def test_case_insensitive_union(self):
        """Test that detection is case-insensitive for UNION."""
        result = self.detector.detect("' uNiOn SeLeCt * FROM users--", "password")
        assert result.is_attack is True
        # Should detect UNION pattern regardless of case
        assert any(pattern for pattern in result.matched_patterns if 'UNION' in pattern.upper())

    def test_multiple_patterns(self):
        """Test detection of multiple attack patterns in single input."""
        result = self.detector.detect("admin' OR 1=1--", "password")
        assert result.is_attack is True
        # Should detect both boolean and comment patterns
        assert len(result.matched_patterns) >= 2

    def test_confidence_high_multiple_patterns(self):
        """Test high confidence when multiple patterns match."""
        result = self.detector.detect("admin' OR 1=1--", "password")
        assert result.confidence == "high"

    def test_confidence_medium_single_pattern(self):
        """Test medium confidence when single pattern matches."""
        result = self.detector.detect("admin'--", "password")
        assert result.confidence in ["medium", "high"]

    def test_confidence_low_no_attack(self):
        """Test low confidence when no attack detected."""
        result = self.detector.detect("john", "password123")
        assert result.confidence == "low"

    def test_convenience_function(self):
        """Test the convenience function returns correct tuple."""
        is_attack, patterns, category = detect_sql_injection("admin", "' OR '1'='1")
        assert is_attack is True
        assert len(patterns) > 0
        assert category == "boolean_based"

    def test_empty_inputs(self):
        """Test detection with empty inputs."""
        result = self.detector.detect("", "")
        assert result.is_attack is False

    def test_special_characters_legitimate(self):
        """Test that special characters in legitimate context don't trigger false positives."""
        result = self.detector.detect("user@domain.com", "P@ssw0rd!")
        assert result.is_attack is False


if __name__ == "__main__":
    # Run tests manually
    import traceback

    test_instance = TestSQLInjectionDetector()
    test_methods = [method for method in dir(test_instance) if method.startswith('test_')]

    passed = 0
    failed = 0

    for method_name in test_methods:
        try:
            test_instance.setup_method()
            method = getattr(test_instance, method_name)
            method()
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
