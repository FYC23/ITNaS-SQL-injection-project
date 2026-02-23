"""
Security Configuration

Configuration settings for the SQL injection lab security features.
Toggle between vulnerable and secure modes for educational purposes.
"""


class SecurityConfig:
    """
    Security configuration for SQL injection lab.

    Modes:
    - Vulnerable Mode (SECURE_MODE=False): Allows attacks to succeed for demonstration
    - Secure Mode (SECURE_MODE=True): Blocks attacks using parameterized queries

    All attacks are detected and logged regardless of mode.
    """

    # Core Security Settings
    SECURE_MODE = False  # Toggle: False = vulnerable (educational), True = secure
    DETECTION_ENABLED = True  # Always detect attacks
    BLOCK_ATTACKS = False  # Only block when SECURE_MODE is True
    LOG_ALL_ATTEMPTS = True  # Log both attacks and legitimate attempts

    # Educational Features
    SHOW_EDUCATIONAL_INFO = True  # Show detection info in responses
    SHOW_QUERY_IN_VULNERABLE_MODE = True  # Display executed query

    # Rate Limiting
    MAX_LOGIN_ATTEMPTS = 5  # Maximum attempts per IP
    RATE_LIMIT_WINDOW = 300  # Time window in seconds (5 minutes)

    # Logging
    LOG_DIRECTORY = "logs"
    MAX_LOG_SIZE_MB = 10  # Rotate logs at this size

    @classmethod
    def is_secure_mode(cls) -> bool:
        """Check if secure mode is enabled."""
        return cls.SECURE_MODE

    @classmethod
    def should_block_attacks(cls) -> bool:
        """Check if attacks should be blocked."""
        return cls.SECURE_MODE and cls.BLOCK_ATTACKS

    @classmethod
    def enable_secure_mode(cls) -> None:
        """Enable secure mode (blocks attacks)."""
        cls.SECURE_MODE = True
        cls.BLOCK_ATTACKS = True

    @classmethod
    def enable_vulnerable_mode(cls) -> None:
        """Enable vulnerable mode (allows attacks for education)."""
        cls.SECURE_MODE = False
        cls.BLOCK_ATTACKS = False
