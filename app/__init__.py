from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
import os
import logging
import sys
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# Set logging level early to reduce verbosity
logging.getLogger().setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)
logging.getLogger('sqlalchemy').setLevel(logging.ERROR)
logging.getLogger('werkzeug').setLevel(logging.INFO)  # Allow INFO to show server messages
logging.getLogger('flask.app').setLevel(logging.WARNING)

# Initialize Flask app
module_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(module_dir, '..'))

# Static folder is in app/static
app_static = os.path.join(module_dir, 'static')

# Create necessary directories
instance_path = os.path.join(project_root, 'instance')
os.makedirs(instance_path, exist_ok=True)
os.makedirs(os.path.join(project_root, 'uploads'), exist_ok=True)
os.makedirs(os.path.join(project_root, 'quarantine'), exist_ok=True)

db_path = os.path.join(instance_path, 'app.db')

# Initialize Flask app with correct static folder
app = Flask(__name__, 
           static_folder=app_static,
           static_url_path='/static')

# Load environment variables
load_dotenv()

# Configure database
app.config.update(
    SQLALCHEMY_DATABASE_URI=f'sqlite:///{db_path}',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ECHO=False,  # Disable SQL query logging

    # Gmail SMTP Configuration (much easier than SendGrid!)
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_DEBUG=False,
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'jrao7483@gmail.com'),
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME', 'jrao7483@gmail.com'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', 'your-gmail-app-password-here'),

    # Session and security
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-key-123'),

    # Application settings
    APP_NAME='RansomGuard Pro',
    MAIL_SENDER_NAME='RansomGuard Pro',

    # Ensure test email backend is in Python path
    MAIL_BACKEND='flask_mail.backends.smtp.Mail'
)

# Add project root to Python path
sys.path.append(project_root)

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()

def create_app():
    # Initialize extensions with app
    db.init_app(app)
    mail.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.init_app(app)
    
    # Import models to ensure they are registered with SQLAlchemy
    from . import models
    
    # Create database tables
    with app.app_context():
        try:
            db.create_all()
            logging.warning("Database tables created successfully")
        except Exception as e:
            logging.error(f"Error creating database tables: {e}")
    
    # Import routes after app and db are initialized to avoid circular imports
    from . import routes
    
    return app

# Create app instance
app = create_app()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        from app.models import User
        return User.query.get(int(user_id))
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None
