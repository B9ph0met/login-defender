#!/usr/bin/env python3
# run.py
"""
SentinelAuth - Main entry point
Multi-layered anti-bot defensive login system
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from app import create_app

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Run the development server
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'

    print("=" * 60)
    print("🛡️  SentinelAuth - Multi-Layered Anti-Bot Login System")
    print("=" * 60)
    print(f"Starting server on http://localhost:{port}")
    print(f"Debug mode: {debug}")
    print("\nDemo credentials:")
    print("  Username: demo")
    print("  Password: password")
    print("\nDefensive Layers Active:")
    print("  ✓ Layer 1: Behavioral Timing Analysis")
    print("  ✓ Layer 2: Headless Browser Detection")
    print("  ✓ Layer 3: Browser Fingerprinting")
    print("  ✓ Layer 4: Velocity & Rate Limiting")
    print("  ✓ Layer 5: IP Reputation Check")
    print("=" * 60)
    print()

    app.run(host='0.0.0.0', port=port, debug=debug)
