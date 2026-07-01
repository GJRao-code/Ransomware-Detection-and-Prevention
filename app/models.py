import secrets
import pyotp
import logging
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    organization = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), default='user')
    is_active = db.Column(db.Boolean, default=True)
    email_notifications = db.Column(db.Boolean, default=True)
    
    # Detailed notification preferences
    notify_threat_detection = db.Column(db.Boolean, default=True)
    notify_scan_completion = db.Column(db.Boolean, default=True)
    notify_security_updates = db.Column(db.Boolean, default=False)
    notify_newsletter = db.Column(db.Boolean, default=False)
    notify_desktop_threats = db.Column(db.Boolean, default=True)
    notify_desktop_scan = db.Column(db.Boolean, default=False)
    notify_desktop_system = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Password reset fields
    reset_token = db.Column(db.String(100), nullable=True, unique=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    
    # Two-factor authentication
    otp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    # Avatar
    avatar_path = db.Column(db.String(200), nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def generate_reset_token(self):
        """Generate a password reset token"""
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        return self.reset_token
    
    def verify_reset_token(self, token):
        """Verify if the reset token is valid and not expired"""
        if not self.reset_token or not self.reset_token_expires:
            return False
        
        if datetime.utcnow() > self.reset_token_expires:
            # Clear expired token
            self.reset_token = None
            self.reset_token_expires = None
            return False
            
        return self.reset_token == token
    
    def clear_reset_token(self):
        """Clear the reset token after use"""
        self.reset_token = None
        self.reset_token_expires = None

    def generate_otp_secret(self):
        """Generate a new OTP secret for 2FA"""
        # Use pyotp to generate a proper base32 secret compatible with Google Authenticator
        self.otp_secret = pyotp.random_base32()
        logging.info(f"Generated new OTP secret for user {self.username}: {self.otp_secret}")
        return self.otp_secret

    def verify_otp(self, token):
        """Verify the OTP token"""
        if not self.otp_secret:
            logging.error(f"2FA Verification failed - User: {self.username}, Reason: No secret found")
            return False

        # Allow verification during setup (when 2FA is not enabled) or when 2FA is enabled
        if self.is_2fa_enabled:
            logging.info(f"2FA Verification for enabled user: {self.username}")

        # Try to verify with current secret (should be base32)
        totp = pyotp.TOTP(self.otp_secret)

        # Test with multiple time windows
        for window in range(5):  # Test 0 to 4 (0 to 120 seconds)
            if totp.verify(token, valid_window=window):
                logging.info(f"2FA Verification SUCCESS - User: {self.username}, Token: {token}, Window: {window}")
                return True

        # Debug logging with detailed information
        current_time = datetime.utcnow()
        logging.error(f"2FA Verification FAILED - User: {self.username}")
        logging.error(f"  Secret: '{self.otp_secret}'")
        logging.error(f"  Secret length: {len(self.otp_secret)}")
        logging.error(f"  Is hex: {len(self.otp_secret) == 32 and all(c in '0123456789abcdefABCDEF' for c in self.otp_secret)}")
        logging.error(f"  Is base32: {all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in self.otp_secret)}")
        logging.error(f"  Token received: '{token}'")
        logging.error(f"  Current time: {current_time}")
        logging.error(f"  Server expected code: '{totp.now()}'")

        # Test with current time and nearby times
        for offset in [-60, -30, 0, 30, 60]:  # Test -60 to +60 seconds
            test_time = current_time.timestamp() + offset
            test_totp = pyotp.TOTP(self.otp_secret)
            expected_at_time = test_totp.at(int(test_time))
            logging.error(f"  Time offset {offset}s: Expected '{expected_at_time}', Match: {expected_at_time == token}")

        # Backward compatibility: if current secret looks like hex (old format)
        if len(self.otp_secret) == 32 and all(c in '0123456789abcdefABCDEF' for c in self.otp_secret):
            try:
                logging.error(f"  Detected hex secret, trying backward compatibility")
                totp_hex = pyotp.TOTP(self.otp_secret)
                for window in range(5):
                    if totp_hex.verify(token, valid_window=window):
                        logging.info(f"  Hex secret verification SUCCESS with window {window}")
                        return True
                logging.error(f"  Hex secret verification also FAILED")
            except Exception as e:
                logging.error(f"  Error with hex secret verification: {e}")

        logging.error(f"  All verification attempts exhausted")
        return False

    def get_otp_uri(self):
        """Get the OTP URI for QR code generation"""
        if not self.otp_secret:
            return None

        try:
            totp = pyotp.TOTP(self.otp_secret)
            # Use a simpler account name format that works better with Google Authenticator
            account_name = self.username or self.email.split('@')[0]
            return totp.provisioning_uri(name=account_name, issuer_name="RansomGuardPro")
        except Exception as e:
            logging.error(f"Error generating OTP URI: {e}")
            return None

class ScanSession(db.Model):
    __tablename__ = 'scan_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # 'quick', 'full', 'custom'
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='running')  # 'running', 'completed', 'stopped', 'error'
    files_scanned = db.Column(db.Integer, default=0)
    threats_detected = db.Column(db.Integer, default=0)
    scan_path = db.Column(db.Text, nullable=True)
    progress_percentage = db.Column(db.Float, default=0.0)
    current_file = db.Column(db.Text, nullable=True)
    
    # Relationships
    detected_threats = db.relationship('DetectedThreat', backref='scan_session', lazy=True)

class DetectedThreat(db.Model):
    __tablename__ = 'detected_threats'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(db.Integer, db.ForeignKey('scan_sessions.id'), nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    threat_type = db.Column(db.String(50), nullable=False)  # 'ransomware', 'malware', 'suspicious'
    threat_level = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    confidence_score = db.Column(db.Float, nullable=False)
    detection_method = db.Column(db.String(50), nullable=False)  # 'ml', 'signature', 'behavioral', 'entropy'
    file_hash = db.Column(db.String(64), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=True)
    entropy_score = db.Column(db.Float, nullable=True)
    is_quarantined = db.Column(db.Boolean, default=False)
    quarantine_path = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # 'active', 'quarantined', 'deleted', 'false_positive'

class ThreatAlert(db.Model):
    __tablename__ = 'threat_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.Text, nullable=True)
    process_name = db.Column(db.String(200), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

class SystemHealth(db.Model):
    __tablename__ = 'system_health'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float, nullable=False)
    memory_usage = db.Column(db.Float, nullable=False)
    disk_usage = db.Column(db.Float, nullable=False)
    active_processes = db.Column(db.Integer, nullable=False)
    network_connections = db.Column(db.Integer, nullable=False)
    threat_level = db.Column(db.String(20), default='low')

class HoneypotFile(db.Model):
    __tablename__ = 'honeypot_files'
    
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.Text, nullable=False, unique=True)
    file_name = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)
    is_compromised = db.Column(db.Boolean, default=False)
    original_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=True)

class MLModelMetrics(db.Model):
    __tablename__ = 'ml_model_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(100), nullable=False)
    model_version = db.Column(db.String(50), nullable=False)
    accuracy = db.Column(db.Float, nullable=False)
    precision = db.Column(db.Float, nullable=False)
    recall = db.Column(db.Float, nullable=False)
    f1_score = db.Column(db.Float, nullable=False)
    training_samples = db.Column(db.Integer, nullable=False)
    training_time = db.Column(db.Float, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
