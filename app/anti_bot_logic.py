# app/anti_bot_logic.py
"""
SentinelAuth Anti-Bot Logic
Contains all bot detection and scoring functions for the five defensive layers.
"""

import json
import requests
from flask import current_app, request
from typing import Dict, Tuple


# ========================================
# LAYER 1: BEHAVIORAL TIMING ANALYSIS
# ========================================

def analyze_timing_behavior(timing_score: int, metadata: str) -> Tuple[int, Dict]:
    """
    Analyze user timing behavior to detect automation.

    Args:
        timing_score: Client-calculated timing score
        metadata: JSON string with detailed timing information

    Returns:
        Tuple of (score, details_dict)
    """
    score = timing_score
    details = {'layer': 'timing', 'flags': []}

    try:
        timing_data = json.loads(metadata)

        # Flag 1: Suspiciously fast total interaction
        if timing_data.get('t_load_to_submit', 0) < 800:
            details['flags'].append('fast_submission')
            details['submission_time_ms'] = timing_data.get('t_load_to_submit', 0)

        # Flag 2: No focus event recorded
        if timing_data.get('t_first_focus') is None or timing_data.get('t_first_focus', 0) == 0:
            score += 20
            details['flags'].append('no_focus_event')

        # Flag 3: No typing detected
        if timing_data.get('t_first_key') is None:
            score += 15
            details['flags'].append('no_typing_detected')

        # Flag 4: Unrealistically fast typing
        t_typing = timing_data.get('t_typing_duration')
        if t_typing is not None and t_typing < 150:
            details['flags'].append('fast_typing')

        details['timing_data'] = timing_data

    except (json.JSONDecodeError, TypeError) as e:
        # Invalid metadata is suspicious
        score += 30
        details['flags'].append('invalid_metadata')
        details['error'] = str(e)

    return score, details


# ========================================
# LAYER 2: HEADLESS BROWSER DETECTION
# ========================================

def analyze_headless_signals(headless_score: int) -> Tuple[int, Dict]:
    """
    Analyze headless browser detection signals from client.

    Args:
        headless_score: Client-calculated headless detection score

    Returns:
        Tuple of (score, details_dict)
    """
    details = {
        'layer': 'headless',
        'client_score': headless_score,
        'flags': []
    }

    # High headless score is a strong indicator
    if headless_score >= 100:
        details['flags'].append('webdriver_flag_detected')
    elif headless_score >= 50:
        details['flags'].append('multiple_headless_indicators')
    elif headless_score >= 20:
        details['flags'].append('suspicious_browser_properties')

    return headless_score, details


# ========================================
# LAYER 3: FINGERPRINT VALIDATION
# ========================================

def validate_fingerprint(fingerprint: str, session) -> Tuple[int, Dict]:
    """
    Validate browser fingerprint against session history.

    Args:
        fingerprint: Browser fingerprint hash from client
        session: Flask session object

    Returns:
        Tuple of (score, details_dict)
    """
    score = 0
    details = {
        'layer': 'fingerprint',
        'flags': [],
        'fingerprint': fingerprint
    }

    # Check if fingerprint exists
    if not fingerprint or len(fingerprint) < 5:
        score += 40
        details['flags'].append('missing_or_invalid_fingerprint')
        return score, details

    # Get stored fingerprint from session
    stored_fingerprint = session.get('browser_fingerprint')

    if stored_fingerprint is None:
        # First time seeing this session - store the fingerprint
        session['browser_fingerprint'] = fingerprint
        details['status'] = 'fingerprint_stored'
    elif stored_fingerprint != fingerprint:
        # Fingerprint changed within same session - suspicious
        score += 50
        details['flags'].append('fingerprint_mismatch')
        details['stored_fingerprint'] = stored_fingerprint
    else:
        # Fingerprint matches - good sign
        details['status'] = 'fingerprint_valid'

    return score, details


# ========================================
# LAYER 4: VELOCITY & RATE LIMITING
# ========================================

def check_rate_limit(username: str, ip_address: str, db) -> Tuple[bool, Dict]:
    """
    Check if username/IP combination has exceeded rate limits.

    Args:
        username: Attempted username
        ip_address: Client IP address
        db: Database connection

    Returns:
        Tuple of (is_blocked, details_dict)
    """
    from app.database import get_login_attempts, record_login_attempt

    max_attempts = current_app.config['MAX_LOGIN_ATTEMPTS']
    window_seconds = current_app.config['RATE_LIMIT_WINDOW']

    # Get recent attempts
    attempts = get_login_attempts(db, username, ip_address, window_seconds)

    details = {
        'layer': 'rate_limiting',
        'attempts_count': len(attempts),
        'max_attempts': max_attempts,
        'window_seconds': window_seconds,
        'flags': []
    }

    is_blocked = len(attempts) >= max_attempts

    if is_blocked:
        details['flags'].append('rate_limit_exceeded')
        details['status'] = 'blocked'
    else:
        details['status'] = 'within_limits'

    # Record this attempt
    record_login_attempt(db, username, ip_address)

    return is_blocked, details


# ========================================
# LAYER 5: IP REPUTATION CHECK
# ========================================

def check_ip_reputation(ip_address: str) -> Tuple[int, Dict]:
    """
    Check IP address against reputation service.

    Args:
        ip_address: Client IP address

    Returns:
        Tuple of (score, details_dict)
    """
    score = 0
    details = {
        'layer': 'ip_reputation',
        'ip_address': ip_address,
        'flags': []
    }

    api_key = current_app.config.get('IP_REPUTATION_API_KEY')

    if not api_key:
        # No API key configured - skip check
        details['status'] = 'api_key_not_configured'
        return score, details

    # Placeholder for IP reputation API integration
    # In production, integrate with services like:
    # - IPQualityScore (https://www.ipqualityscore.com/)
    # - AbuseIPDB (https://www.abuseipdb.com/)
    # - MaxMind minFraud

    try:
        # Example API call (uncomment and configure for production)
        # response = requests.get(
        #     f'https://api.ipqualityscore.com/v1/ip/{api_key}/{ip_address}',
        #     timeout=2
        # )
        # data = response.json()
        #
        # if data.get('fraud_score', 0) > 75:
        #     score += 80
        #     details['flags'].append('high_fraud_score')
        # elif data.get('proxy') or data.get('vpn'):
        #     score += 30
        #     details['flags'].append('proxy_or_vpn_detected')

        # Placeholder response for development
        details['status'] = 'placeholder_mode'
        details['note'] = 'Configure IP_REPUTATION_API_KEY in .env for production use'

    except requests.RequestException as e:
        details['status'] = 'api_error'
        details['error'] = str(e)

    return score, details


# ========================================
# MASTER SCORING FUNCTION
# ========================================

def calculate_bot_score(form_data: Dict, session, db) -> Dict:
    """
    Master function to calculate composite bot score from all layers.

    Args:
        form_data: Form data from login request
        session: Flask session object
        db: Database connection

    Returns:
        Dictionary with bot score and detailed analysis
    """
    total_score = 0
    analysis = {
        'layers': {},
        'total_score': 0,
        'verdict': 'unknown',
        'blocked': False
    }

    # Get client IP
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    # Extract sentinel data
    timing_score = int(form_data.get('sentinel_timing', 0))
    headless_score = int(form_data.get('sentinel_headless', 0))
    fingerprint = form_data.get('sentinel_fingerprint', '')
    metadata = form_data.get('sentinel_metadata', '{}')
    username = form_data.get('username', '')

    # Layer 1: Behavioral Timing
    score, details = analyze_timing_behavior(timing_score, metadata)
    total_score += score
    analysis['layers']['timing'] = details

    # Layer 2: Headless Detection
    score, details = analyze_headless_signals(headless_score)
    total_score += score
    analysis['layers']['headless'] = details

    # Layer 3: Fingerprint Validation
    score, details = validate_fingerprint(fingerprint, session)
    total_score += score
    analysis['layers']['fingerprint'] = details

    # Layer 4: Rate Limiting
    is_rate_limited, details = check_rate_limit(username, ip_address, db)
    if is_rate_limited:
        total_score += 100  # Automatic block
    analysis['layers']['rate_limiting'] = details

    # Layer 5: IP Reputation
    score, details = check_ip_reputation(ip_address)
    total_score += score
    analysis['layers']['ip_reputation'] = details

    # Final verdict
    analysis['total_score'] = total_score
    threshold = current_app.config['BOT_SCORE_THRESHOLD']

    if is_rate_limited:
        analysis['verdict'] = 'blocked_rate_limit'
        analysis['blocked'] = True
    elif total_score >= threshold:
        analysis['verdict'] = 'blocked_bot_detected'
        analysis['blocked'] = True
    else:
        analysis['verdict'] = 'passed'
        analysis['blocked'] = False

    return analysis
