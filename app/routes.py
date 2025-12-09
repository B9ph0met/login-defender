# app/routes.py
"""
Flask routes for SentinelAuth
Handles login page display and authentication with anti-bot protection.
"""

from flask import Blueprint, request, render_template, jsonify, session
from app.anti_bot_logic import calculate_bot_score
from app.database import get_db, record_login_attempt, record_fingerprint
import json

bp = Blueprint('main', __name__)


# ========================================
# HOMEPAGE / LOGIN FORM
# ========================================

@bp.route('/')
def index():
    """Serve the login page."""
    return render_template('index.html')


# ========================================
# LOGIN ENDPOINT WITH ANTI-BOT PROTECTION
# ========================================

@bp.route('/login', methods=['POST'])
def login():
    """
    Process login attempt with multi-layered bot detection.

    Expected form fields:
        - username: Login username
        - password: Login password
        - sentinel_timing: Timing behavior score
        - sentinel_headless: Headless detection score
        - sentinel_fingerprint: Browser fingerprint hash
        - sentinel_metadata: JSON timing metadata
    """
    # Get database connection
    db = get_db()

    # Extract form data
    form_data = request.form.to_dict()
    username = form_data.get('username', '')
    password = form_data.get('password', '')

    # Extract client IP address (handle X-Forwarded-For with multiple IPs)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    if ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    # Extract user agent with fallback
    user_agent = request.headers.get('User-Agent') or 'Unknown'

    # Calculate bot score using all defensive layers
    analysis = calculate_bot_score(form_data, session, db)

    # Record fingerprint if present
    fingerprint = form_data.get('sentinel_fingerprint', '')
    if fingerprint:
        record_fingerprint(db, fingerprint, client_ip)

    # Check if request is blocked
    if analysis['blocked']:
        # Record blocked attempt

        record_login_attempt(
            db,
            username=username,
            ip_address=client_ip,
            user_agent=user_agent,
            bot_score=analysis['total_score'],
            blocked=True
        )

        # Return error response
        return render_template('index.html',
                             error=f"Login blocked: {analysis['verdict']}. Please try again later.",
                             analysis=analysis), 403

    # ========================================
    # CREDENTIAL VALIDATION
    # ========================================
    # NOTE: This is a placeholder. In production:
    # 1. Hash passwords with bcrypt/argon2
    # 2. Query user database
    # 3. Implement proper session management
    # 4. Add CSRF protection

    # Placeholder credential check (DO NOT use in production!)
    if username == 'demo' and password == 'password':
        # Successful login
        session['logged_in'] = True
        session['username'] = username

        # Record successful attempt
        record_login_attempt(
            db,
            username=username,
            ip_address=client_ip,
            user_agent=user_agent,
            bot_score=analysis['total_score'],
            blocked=False
        )

        return render_template('success.html',
                             username=username,
                             analysis=analysis)
    else:
        # Invalid credentials
        record_login_attempt(
            db,
            username=username,
            ip_address=client_ip,
            user_agent=user_agent,
            bot_score=analysis['total_score'],
            blocked=False
        )

        return render_template('index.html',
                             error='Invalid username or password.',
                             analysis=analysis), 401


# ========================================
# DEBUG / STATS ENDPOINT (Remove in production!)
# ========================================

@bp.route('/stats')
def stats():
    """
    Display statistics about login attempts and bot detection.
    WARNING: Remove this endpoint in production!
    """
    from app.database import get_statistics

    db = get_db()
    statistics = get_statistics(db)

    return jsonify(statistics)


@bp.route('/debug/analysis', methods=['POST'])
def debug_analysis():
    """
    Debug endpoint to see bot analysis without processing login.
    WARNING: Remove this endpoint in production!
    """
    db = get_db()
    form_data = request.form.to_dict()

    analysis = calculate_bot_score(form_data, session, db)

    return jsonify(analysis)


@bp.route('/reset-db', methods=['POST'])
def reset_database():
    """
    Reset the database by clearing all login attempts and fingerprints.
    WARNING: This is for demo purposes only! Remove in production!
    """
    try:
        db = get_db()
        cursor = db.cursor()

        # Clear all login attempts
        cursor.execute('DELETE FROM login_attempts')

        # Clear all fingerprints
        cursor.execute('DELETE FROM fingerprint_history')

        db.commit()

        # Clear the session as well
        session.clear()

        return jsonify({
            'success': True,
            'message': 'Database reset successfully'
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ========================================
# CLEANUP / TEARDOWN
# ========================================

@bp.teardown_app_request
def teardown_db(exception=None):
    """Close database connection at end of request."""
    from app.database import close_db
    close_db(exception)
