"""
Security Logging Module

JSON-based logging system for tracking SQL injection attempts and legitimate access.
Logs are written in JSON Lines format for easy parsing and analysis.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class SecurityLogger:
    """
    JSON-based security logger for SQL injection attempts and access logs.

    Features:
    - JSON Lines format for easy parsing
    - Separate files for injection attempts and legitimate access
    - Log rotation at 10MB
    - Password redaction for privacy
    """

    def __init__(self, log_dir: str = "logs"):
        """
        Initialize security logger.

        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        self.injection_log = self.log_dir / "injection_attempts.jsonl"
        self.access_log = self.log_dir / "access.log"

        # Maximum log file size before rotation (10MB)
        self.max_log_size = 10 * 1024 * 1024

    def _rotate_if_needed(self, log_file: Path) -> None:
        """
        Rotate log file if it exceeds maximum size.

        Args:
            log_file: Path to log file to check
        """
        if not log_file.exists():
            return

        if log_file.stat().st_size >= self.max_log_size:
            # Rotate: rename current file with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{log_file.stem}_{timestamp}{log_file.suffix}"
            rotated_path = log_file.parent / rotated_name
            log_file.rename(rotated_path)

    def _redact_password(self, password: str) -> str:
        """
        Redact password for logging.

        Args:
            password: Original password

        Returns:
            Redacted password string
        """
        if len(password) <= 2:
            return "[REDACTED]"
        # Show first and last character only
        return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"

    def log_injection_attempt(
        self,
        ip_address: str,
        username: str,
        password: str,
        detected_patterns: List[str],
        category: str,
        action_taken: str,
        user_agent: Optional[str] = None,
        confidence: str = "medium"
    ) -> None:
        """
        Log a SQL injection attempt.

        Args:
            ip_address: Client IP address
            username: Username input (potentially malicious)
            password: Password input (will be redacted)
            detected_patterns: List of matched attack patterns
            category: Attack category (e.g., 'boolean_based')
            action_taken: Action taken ('blocked' or 'logged')
            user_agent: User agent string
            confidence: Detection confidence level
        """
        self._rotate_if_needed(self.injection_log)

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip_address": ip_address,
            "username_input": username[:100],  # Limit length
            "password_input": self._redact_password(password),
            "detected_patterns": detected_patterns[:10],  # Limit array size
            "category": category,
            "confidence": confidence,
            "action_taken": action_taken,
            "user_agent": user_agent or "Unknown"
        }

        with open(self.injection_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

    def log_access(
        self,
        ip_address: str,
        username: str,
        success: bool,
        user_agent: Optional[str] = None
    ) -> None:
        """
        Log a legitimate access attempt.

        Args:
            ip_address: Client IP address
            username: Username used for login
            success: Whether login was successful
            user_agent: User agent string
        """
        self._rotate_if_needed(self.access_log)

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip_address": ip_address,
            "username": username,
            "success": success,
            "user_agent": user_agent or "Unknown"
        }

        with open(self.access_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

    def get_recent_attempts(self, limit: int = 100) -> List[Dict]:
        """
        Get recent injection attempts from log.

        Args:
            limit: Maximum number of attempts to return

        Returns:
            List of log entries (most recent first)
        """
        if not self.injection_log.exists():
            return []

        attempts = []
        with open(self.injection_log, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    attempts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

        # Return most recent first
        return attempts[-limit:][::-1]

    def get_stats(self) -> Dict:
        """
        Get statistics about logged attempts.

        Returns:
            Dictionary with statistics
        """
        if not self.injection_log.exists():
            return {
                "total_attempts": 0,
                "blocked_attempts": 0,
                "logged_attempts": 0,
                "categories": {}
            }

        total = 0
        blocked = 0
        logged = 0
        categories = {}

        with open(self.injection_log, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    total += 1

                    if entry.get("action_taken") == "blocked":
                        blocked += 1
                    else:
                        logged += 1

                    category = entry.get("category", "unknown")
                    categories[category] = categories.get(category, 0) + 1

                except json.JSONDecodeError:
                    continue

        return {
            "total_attempts": total,
            "blocked_attempts": blocked,
            "logged_attempts": logged,
            "categories": categories
        }
