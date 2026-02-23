"""
SQL Injection Detection Module

Pattern-based detection engine that identifies common SQL injection attack patterns.
Designed for educational purposes to demonstrate attack detection techniques.
"""

import re
from typing import Tuple, List
from dataclasses import dataclass


@dataclass
class DetectionResult:
    """Result of SQL injection detection analysis."""
    is_attack: bool
    matched_patterns: List[str]
    category: str
    confidence: str  # 'low', 'medium', 'high'


class SQLInjectionDetector:
    """
    Pattern-based SQL injection detector.

    Detects common SQL injection patterns including:
    - Boolean-based injection
    - Comment injection
    - UNION attacks
    - Stacked queries
    - Time-based blind injection
    - Quote manipulation
    """

    def __init__(self):
        """Initialize detector with compiled regex patterns."""
        # Boolean-based injection patterns
        self.boolean_patterns = [
            re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),
            re.compile(r"'\s*OR\s*1\s*=\s*1", re.IGNORECASE),
            re.compile(r"'\s*OR\s*'a'\s*=\s*'a", re.IGNORECASE),
            re.compile(r"'\s*OR\s*'x'\s*=\s*'x", re.IGNORECASE),
            re.compile(r"'\s*OR\s*1\s*--", re.IGNORECASE),
            re.compile(r"\"\s*OR\s*\"1\"\s*=\s*\"1", re.IGNORECASE),
            re.compile(r"\"\s*OR\s*1\s*=\s*1", re.IGNORECASE),
        ]

        # Comment injection patterns
        self.comment_patterns = [
            re.compile(r"--"),  # SQL comment
            re.compile(r"#"),   # MySQL comment
            re.compile(r"/\*"),  # Multi-line comment start
            re.compile(r"\*/"),  # Multi-line comment end
        ]

        # UNION attack patterns
        self.union_patterns = [
            re.compile(r"UNION\s+SELECT", re.IGNORECASE),
            re.compile(r"UNION\s+ALL\s+SELECT", re.IGNORECASE),
        ]

        # Stacked query patterns
        self.stacked_patterns = [
            re.compile(r";\s*DROP", re.IGNORECASE),
            re.compile(r";\s*DELETE", re.IGNORECASE),
            re.compile(r";\s*UPDATE", re.IGNORECASE),
            re.compile(r";\s*INSERT", re.IGNORECASE),
            re.compile(r";\s*CREATE", re.IGNORECASE),
            re.compile(r";\s*ALTER", re.IGNORECASE),
        ]

        # Time-based blind injection patterns
        self.time_based_patterns = [
            re.compile(r"SLEEP\s*\(", re.IGNORECASE),
            re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
            re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
            re.compile(r"pg_sleep\s*\(", re.IGNORECASE),
        ]

        # Quote manipulation patterns
        self.quote_patterns = [
            re.compile(r"'{2,}"),  # Multiple consecutive quotes
            re.compile(r"\"{2,}"),  # Multiple consecutive double quotes
        ]

    def _is_false_positive(self, text: str) -> bool:
        """
        Check if input is likely a false positive.

        Examples of legitimate inputs:
        - O'Brien (apostrophe in name)
        - user@example.com (email with special chars)
        - C# (programming language)
        """
        # Check for legitimate apostrophe usage (e.g., O'Brien, D'Angelo)
        if re.match(r"^[A-Z]'[A-Z]", text, re.IGNORECASE):
            return True

        # Check for email addresses
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", text):
            return True

        # Check for programming language names (C#, F#)
        if re.match(r"^[A-Z]#$", text, re.IGNORECASE):
            return True

        return False

    def detect(self, username: str, password: str) -> DetectionResult:
        """
        Detect SQL injection patterns in username and password inputs.

        Args:
            username: Username input from login form
            password: Password input from login form

        Returns:
            DetectionResult with detection status, matched patterns, category, and confidence
        """
        combined_input = f"{username} {password}"
        matched_patterns = []
        categories = []

        # Skip detection if input looks like a false positive
        if self._is_false_positive(username) or self._is_false_positive(password):
            return DetectionResult(
                is_attack=False,
                matched_patterns=[],
                category="none",
                confidence="low"
            )

        # Check boolean-based patterns
        for pattern in self.boolean_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("boolean_based")

        # Check comment injection
        for pattern in self.comment_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("comment_injection")

        # Check UNION attacks
        for pattern in self.union_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("union_attack")

        # Check stacked queries
        for pattern in self.stacked_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("stacked_query")

        # Check time-based blind injection
        for pattern in self.time_based_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("time_based_blind")

        # Check quote manipulation
        for pattern in self.quote_patterns:
            if pattern.search(combined_input):
                matched_patterns.append(pattern.pattern)
                categories.append("quote_manipulation")

        # Determine if attack detected
        is_attack = len(matched_patterns) > 0

        # Determine primary category
        category = categories[0] if categories else "none"

        # Determine confidence level
        confidence = self._calculate_confidence(len(matched_patterns), categories)

        return DetectionResult(
            is_attack=is_attack,
            matched_patterns=matched_patterns,
            category=category,
            confidence=confidence
        )

    def _calculate_confidence(self, pattern_count: int, categories: List[str]) -> str:
        """
        Calculate confidence level based on number of patterns matched.

        Args:
            pattern_count: Number of patterns that matched
            categories: List of matched categories

        Returns:
            Confidence level: 'low', 'medium', or 'high'
        """
        if pattern_count == 0:
            return "low"
        elif pattern_count == 1:
            # Single pattern could be coincidence
            return "medium"
        elif pattern_count >= 2 or len(set(categories)) >= 2:
            # Multiple patterns or multiple categories = high confidence
            return "high"
        else:
            return "medium"


# Convenience function for simple detection
def detect_sql_injection(username: str, password: str) -> Tuple[bool, List[str], str]:
    """
    Convenience function for SQL injection detection.

    Args:
        username: Username input from login form
        password: Password input from login form

    Returns:
        Tuple of (is_attack, matched_patterns, category)
    """
    detector = SQLInjectionDetector()
    result = detector.detect(username, password)
    return (result.is_attack, result.matched_patterns, result.category)
