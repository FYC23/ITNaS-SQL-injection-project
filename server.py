from flask import Flask, request, render_template
import sqlite3

from config import SecurityConfig
from security.detector import SQLInjectionDetector
from security.logger import SecurityLogger
from security.rate_limiter import RateLimiter

import argparse
import sys

app = Flask(__name__)

# Initialize security components
detector = SQLInjectionDetector()
logger = SecurityLogger(log_dir=SecurityConfig.LOG_DIRECTORY)
rate_limiter = RateLimiter(
    max_attempts=SecurityConfig.MAX_LOGIN_ATTEMPTS,
    window_seconds=SecurityConfig.RATE_LIMIT_WINDOW
)


def get_client_ip():
    """Get client IP address from request."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def execute_secure_query(username: str, password: str):
    """
    Execute parameterized query - prevents SQL injection.

    Args:
        username: Username input
        password: Password input

    Returns:
        List of matching user records
    """
    conn = sqlite3.connect('mylab.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    results = cursor.fetchall()
    conn.close()
    return results


def execute_vulnerable_query(username: str, password: str):
    """
    Execute string concatenation query - vulnerable to SQL injection.
    Used for educational demonstration.

    Args:
        username: Username input
        password: Password input

    Returns:
        Tuple of (results, query_string)
    """
    conn = sqlite3.connect('mylab.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results, query

@app.route('/')
def home():
    return render_template('main.html', secure_mode=SecurityConfig.is_secure_mode())

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent')

    # Step 1: Check rate limit
    allowed, attempts_remaining, reset_time = rate_limiter.check_rate_limit(client_ip)
    if not allowed:
        return render_template(
            'rate_limited.html',
            reset_time=reset_time,
            max_attempts=SecurityConfig.MAX_LOGIN_ATTEMPTS,
            window_minutes=SecurityConfig.RATE_LIMIT_WINDOW // 60
        )

    # Step 2: Record this attempt
    rate_limiter.record_attempt(client_ip)

    # Step 3: Detect SQL injection patterns (always, regardless of mode)
    detection_result = detector.detect(username, password)

    # Step 4: If attack detected and secure mode enabled, block it
    if detection_result.is_attack and SecurityConfig.is_secure_mode():
        # Log the blocked attempt
        logger.log_injection_attempt(
            ip_address=client_ip,
            username=username,
            password=password,
            detected_patterns=detection_result.matched_patterns,
            category=detection_result.category,
            action_taken='blocked',
            user_agent=user_agent,
            confidence=detection_result.confidence
        )

        return render_template(
            'blocked.html',
            patterns=detection_result.matched_patterns,
            category=detection_result.category,
            username_preview=username[:50],
            password_preview=password[:50],
            username_truncated=len(username) > 50,
            password_truncated=len(password) > 50,
            confidence=detection_result.confidence
        )

    # Step 5: Execute query based on mode
    if SecurityConfig.is_secure_mode():
        # Secure mode: use parameterized query
        results = execute_secure_query(username, password)
        query_to_show = None  # Don't show query in secure mode
    else:
        # Vulnerable mode: use string concatenation (educational)
        results, query_to_show = execute_vulnerable_query(username, password)

    # Step 6: Log the attempt
    if detection_result.is_attack:
        logger.log_injection_attempt(
            ip_address=client_ip,
            username=username,
            password=password,
            detected_patterns=detection_result.matched_patterns,
            category=detection_result.category,
            action_taken='logged',
            user_agent=user_agent,
            confidence=detection_result.confidence
        )
    else:
        logger.log_access(
            ip_address=client_ip,
            username=username,
            success=bool(results),
            user_agent=user_agent
        )

    # Step 7: Render response
    if results:
        return render_template(
            'success.html',
            query=query_to_show,
            results=results,
            attack_detected=detection_result.is_attack,
            patterns=detection_result.matched_patterns,
            category=detection_result.category,
            secure_mode=SecurityConfig.is_secure_mode()
        )
    else:
        return render_template(
            'failed.html',
            query=query_to_show,
            attack_detected=detection_result.is_attack,
            patterns=detection_result.matched_patterns
        )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SQL Injection Lab')
    parser.add_argument('--port', type=int, default=8000, help='Port to run the server on')
    parser.add_argument('--secure-mode', action='store_true', help='Enable secure mode')
    args = parser.parse_args()

    if args.secure_mode:
        SecurityConfig.enable_secure_mode()
    else:
        SecurityConfig.enable_vulnerable_mode()

    app.run(debug=True, host='0.0.0.0', port=args.port)