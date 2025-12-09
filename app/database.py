# app/database.py
"""
Database module for SentinelAuth
Handles rate limiting and login attempt tracking using SQLite.
"""

import sqlite3
import time
from typing import List, Dict, Optional
from flask import g, current_app
import os


DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sentinel_auth.db')


def get_db():
    """
    Get database connection for the current request.
    Stores connection in Flask's g object for request lifecycle.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database schema."""
    # Connect directly instead of using get_db() since we're outside request context
    db = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    # Create login_attempts table for rate limiting
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            user_agent TEXT,
            bot_score INTEGER DEFAULT 0,
            blocked BOOLEAN DEFAULT 0
        )
    ''')

    # Create indexes for login_attempts
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_username_ip
        ON login_attempts (username, ip_address)
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp
        ON login_attempts (timestamp)
    ''')

    # Create fingerprint_history table for tracking fingerprint changes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fingerprint_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            request_count INTEGER DEFAULT 1
        )
    ''')

    # Create indexes for fingerprint_history
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_fingerprint
        ON fingerprint_history (fingerprint)
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_ip
        ON fingerprint_history (ip_address)
    ''')

    db.commit()
    db.close()


def record_login_attempt(db, username: str, ip_address: str,
                         user_agent: str = 'Unknown', bot_score: int = 0,
                         blocked: bool = False) -> int:
    """
    Record a login attempt to the database.

    Args:
        db: Database connection
        username: Attempted username
        ip_address: Client IP address
        user_agent: User agent string (optional)
        bot_score: Calculated bot score
        blocked: Whether attempt was blocked

    Returns:
        ID of the inserted record
    """
    cursor = db.cursor()
    timestamp = int(time.time())

    cursor.execute('''
        INSERT INTO login_attempts
        (username, ip_address, timestamp, user_agent, bot_score, blocked)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, ip_address, timestamp, user_agent, bot_score, int(blocked)))

    db.commit()
    return cursor.lastrowid


def get_login_attempts(db, username: str, ip_address: str,
                       window_seconds: int) -> List[Dict]:
    """
    Get recent login attempts for a username/IP combination.

    Args:
        db: Database connection
        username: Username to check
        ip_address: IP address to check
        window_seconds: Time window in seconds to look back

    Returns:
        List of matching login attempts
    """
    cursor = db.cursor()
    cutoff_time = int(time.time()) - window_seconds

    cursor.execute('''
        SELECT * FROM login_attempts
        WHERE username = ?
        AND ip_address = ?
        AND timestamp >= ?
        ORDER BY timestamp DESC
    ''', (username, ip_address, cutoff_time))

    return [dict(row) for row in cursor.fetchall()]


def record_fingerprint(db, fingerprint: str, ip_address: str) -> None:
    """
    Record or update fingerprint usage.

    Args:
        db: Database connection
        fingerprint: Browser fingerprint hash
        ip_address: Client IP address
    """
    cursor = db.cursor()
    current_time = int(time.time())

    # Check if fingerprint already exists
    cursor.execute('''
        SELECT id, request_count FROM fingerprint_history
        WHERE fingerprint = ? AND ip_address = ?
    ''', (fingerprint, ip_address))

    result = cursor.fetchone()

    if result:
        # Update existing record
        cursor.execute('''
            UPDATE fingerprint_history
            SET last_seen = ?, request_count = request_count + 1
            WHERE id = ?
        ''', (current_time, result['id']))
    else:
        # Insert new record
        cursor.execute('''
            INSERT INTO fingerprint_history
            (fingerprint, ip_address, first_seen, last_seen, request_count)
            VALUES (?, ?, ?, ?, 1)
        ''', (fingerprint, ip_address, current_time, current_time))

    db.commit()


def get_fingerprint_history(db, fingerprint: str) -> Optional[Dict]:
    """
    Get history for a specific fingerprint.

    Args:
        db: Database connection
        fingerprint: Browser fingerprint hash

    Returns:
        Dictionary with fingerprint history or None
    """
    cursor = db.cursor()

    cursor.execute('''
        SELECT * FROM fingerprint_history
        WHERE fingerprint = ?
        ORDER BY last_seen DESC
        LIMIT 1
    ''', (fingerprint,))

    result = cursor.fetchone()
    return dict(result) if result else None


def cleanup_old_records(db, days: int = 7) -> int:
    """
    Clean up records older than specified days.

    Args:
        db: Database connection
        days: Number of days to retain

    Returns:
        Number of records deleted
    """
    cursor = db.cursor()
    cutoff_time = int(time.time()) - (days * 86400)

    cursor.execute('DELETE FROM login_attempts WHERE timestamp < ?', (cutoff_time,))
    deleted_attempts = cursor.rowcount

    cursor.execute('DELETE FROM fingerprint_history WHERE last_seen < ?', (cutoff_time,))
    deleted_fingerprints = cursor.rowcount

    db.commit()

    return deleted_attempts + deleted_fingerprints


def get_statistics(db) -> Dict:
    """
    Get statistics about login attempts and blocks.

    Args:
        db: Database connection

    Returns:
        Dictionary with statistics
    """
    cursor = db.cursor()

    # Total attempts in last 24 hours
    cutoff_24h = int(time.time()) - 86400

    cursor.execute('''
        SELECT
            COUNT(*) as total_attempts,
            SUM(blocked) as blocked_attempts,
            AVG(bot_score) as avg_bot_score
        FROM login_attempts
        WHERE timestamp >= ?
    ''', (cutoff_24h,))

    stats = dict(cursor.fetchone())

    # Unique IPs in last 24 hours
    cursor.execute('''
        SELECT COUNT(DISTINCT ip_address) as unique_ips
        FROM login_attempts
        WHERE timestamp >= ?
    ''', (cutoff_24h,))

    stats.update(cursor.fetchone())

    # Top blocked IPs
    cursor.execute('''
        SELECT ip_address, COUNT(*) as block_count
        FROM login_attempts
        WHERE blocked = 1 AND timestamp >= ?
        GROUP BY ip_address
        ORDER BY block_count DESC
        LIMIT 10
    ''', (cutoff_24h,))

    stats['top_blocked_ips'] = [dict(row) for row in cursor.fetchall()]

    return stats
