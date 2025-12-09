# app/__init__.py
from flask import Flask
import os

def create_app():
    """Application factory pattern for Flask app."""
    app = Flask(__name__,
                static_folder='../static',
                template_folder='../static')

    # Load configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['IP_REPUTATION_API_KEY'] = os.environ.get('IP_REPUTATION_API_KEY', '')

    # Rate limiting configuration
    app.config['MAX_LOGIN_ATTEMPTS'] = 5
    app.config['RATE_LIMIT_WINDOW'] = 300  # 5 minutes in seconds

    # Bot scoring thresholds
    app.config['BOT_SCORE_THRESHOLD'] = 100  # Block if score >= 100 (lowered for testing)

    # Register routes
    from app.routes import bp
    app.register_blueprint(bp)

    # Initialize database
    from app.database import init_db
    init_db()

    return app
