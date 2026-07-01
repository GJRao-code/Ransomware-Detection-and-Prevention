import os
import logging
import json
import threading
import time
from datetime import datetime, timedelta

from flask import render_template, request, redirect, url_for, flash, jsonify, session, Response, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import secrets
import qrcode
import base64
import io
import pyotp

from app import app, db
from app.models import User, ScanSession, DetectedThreat, ThreatAlert, SystemHealth, MLModelMetrics
from app.ml_engine import MLEngine
from app.scanner_engine import ScannerEngine
from app.system_monitor import SystemMonitor
from app.quarantine_manager import QuarantineManager
import atexit


# Initialize engines
ml_engine = MLEngine()
scanner_engine = ScannerEngine()
system_monitor = SystemMonitor()
quarantine_manager = QuarantineManager()

# Ensure background services are stopped gracefully on interpreter exit
def _shutdown_services():
    try:
        logging.info('Shutting down background services...')
        try:
            scanner_engine.shutdown()
        except Exception as e:
            logging.debug(f'Error shutting down scanner engine: {e}')
        try:
            system_monitor.shutdown()
        except Exception:
            pass
    except Exception:
        pass

atexit.register(_shutdown_services)

@app.route("/ml-metrics")
def ml_metrics():
    metrics = MLModelMetrics.query.all()  # get all model metrics
    return render_template("ml_metrics.html", metrics=metrics)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.route("/alerts/list")
def alerts_list():
    user_id = current_user.id  # Flask-Login must be active
    unread_alerts = ThreatAlert.query.filter_by(user_id=user_id, is_read=False).all()
    return render_template("alerts_modal.html", alerts=unread_alerts)


@app.route('/alerts/mark_all_read', methods=['POST'])
@login_required
def alerts_mark_all_read():
    """Mark all unread alerts for the current user as read and return JSON result."""
    try:
        alerts = ThreatAlert.query.filter_by(user_id=current_user.id, is_read=False).all()
        marked = 0
        for a in alerts:
            a.is_read = True
            marked += 1

        if marked:
            db.session.commit()
        else:
            # Nothing to commit but ensure session state is clean
            db.session.rollback()

        return jsonify({'success': True, 'marked': marked})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking alerts read for user {getattr(current_user, 'id', 'unknown')}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email with password reset link
            try:
                from app.email_utils import send_welcome_email
                reset_token = user.generate_reset_token()
                reset_url = url_for('reset_password', token=reset_token, _external=True)
                send_welcome_email(user.email, user.username, reset_url)
                flash('Registration successful! Please check your email to set your password.', 'success')
            except Exception as e:
                logging.error(f"Error sending welcome email: {e}")
                flash('Registration successful! Please log in with your credentials.', 'success')
                
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            logging.error(f"Registration error: {e}")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        login_id = request.form.get('username')  # Can be either username or email
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        if not login_id or not password:
            flash('Username/Email and password are required.', 'error')
            return render_template('login.html')
        
        # Try to find user by username or email
        user = User.query.filter(
            (User.username == login_id) | (User.email == login_id)
        ).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Account is deactivated. Please contact support.', 'error')
                return render_template('login.html')

            # If user has 2FA enabled, require OTP verification before finalizing login
            if getattr(user, 'is_2fa_enabled', False):
                # Store pending user id in session and redirect to the 2FA verification route
                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_remember'] = remember
                flash('Two-Factor Authentication required. Please enter the 6-digit code from your authenticator app.', 'info')
                return redirect(url_for('two_factor'))

            # No 2FA: perform normal login
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()

            next_page = request.args.get('next')
            flash(f'Welcome back, {user.get_full_name()}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    """Handle the two-factor verification step for users with 2FA enabled.

    The login flow will set `session['pre_2fa_user_id']` when username/password
    are valid but the account requires 2FA. This route verifies the OTP and
    completes the login.
    """
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        flash('No pending two-factor authentication session found. Please login again.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        session.pop('pre_2fa_user_id', None)
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        if not token:
            flash('Please enter the 6-digit authentication code.', 'error')
            return render_template('two_factor.html', username=user.username)

        try:
            if user.verify_otp(token):
                # Complete login
                remember = session.pop('pre_2fa_remember', False)
                session.pop('pre_2fa_user_id', None)
                login_user(user, remember=remember)
                session['2fa_verified'] = True
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash('Two-Factor Authentication successful. You are now logged in.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid authentication code. Please try again.', 'error')
        except Exception as e:
            logging.error(f"Error verifying 2FA during login: {e}")
            flash('An error occurred while verifying the code. Please try again.', 'error')

    return render_template('two_factor.html', username=user.username)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password - request reset"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')

        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            token = user.generate_reset_token()
            try:
                db.session.commit()

                # Send password reset email
                from app.email_utils import send_password_reset_email
                reset_url = url_for('reset_password', token=token, _external=True)
                email_sent = send_password_reset_email(user.email, reset_url)

                if email_sent:
                    flash('Password reset instructions have been sent to your email.', 'success')
                    logging.info(f"Password reset email sent to user: {user.username}")
                else:
                    flash('Unable to send email. Please contact support.', 'error')
                    logging.error(f"Failed to send password reset email to user: {user.username}")

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}. Please try again.', 'error')
                logging.error(f"Password reset error: {e}")
        else:
            # For security, don't reveal if email exists or not
            flash('If an account with that email exists, password reset instructions have been sent.', 'success')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Find user by token
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Please fill in all fields.', 'error')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html', token=token)

        try:
            # Update password and clear reset token
            user.set_password(password)
            user.clear_reset_token()
            db.session.commit()

            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            logging.error(f"Password reset error: {e}")

    return render_template('reset_password.html', token=token)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():

    """Main dashboard"""

    # Get recent scan sessions
    recent_scans = ScanSession.query.filter_by(user_id=current_user.id)\
                                   .order_by(ScanSession.start_time.desc())\
                                   .limit(5).all()
    
    # Get threat statistics
    total_threats = DetectedThreat.query.join(ScanSession)\
                                       .filter(ScanSession.user_id == current_user.id)\
                                       .count()
    
    active_threats = DetectedThreat.query.join(ScanSession)\
                                        .filter(ScanSession.user_id == current_user.id)\
                                        .filter(DetectedThreat.status == 'active')\
                                        .count()
    
    quarantined_files = DetectedThreat.query.join(ScanSession)\
                                           .filter(ScanSession.user_id == current_user.id)\
                                           .filter(DetectedThreat.is_quarantined == True)\
                                           .count()
    
    # Get unread alerts
    unread_alerts = ThreatAlert.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    # Get system health
    latest_health = SystemHealth.query.order_by(SystemHealth.timestamp.desc()).first()
    
    # Get ML model metrics
    model_metrics = MLModelMetrics.query.filter_by(is_active=True)\
                                       .order_by(MLModelMetrics.last_updated.desc())\
                                       .all()
    metrics_file = "models/metrics.json"
    rf_accuracy = None
    xgb_accuracy = None

    if os.path.exists(metrics_file):
        with open(metrics_file, "r") as f:
            data = json.load(f)
            rf_accuracy = data.get("random_forest", "N/A")
            xgb_accuracy = data.get("xgboost", "N/A")


    
    
    return render_template('dashboard.html',
                         recent_scans=recent_scans,
                         total_threats=total_threats,
                         active_threats=active_threats,
                         quarantined_files=quarantined_files,
                         unread_alerts=unread_alerts,
                         system_health=latest_health,
                         model_metrics=model_metrics,
                         rf_accuracy=rf_accuracy,
                         xgb_accuracy=xgb_accuracy
                         )

@app.route('/scan')
@login_required
def scan():
    """Scan interface"""
    return render_template('scan.html')

@app.route('/debug_scan')
@login_required
def debug_scan():
    """Debug endpoint to test scanning functionality"""
    try:
        # Create a test scan session
        scan_session = ScanSession(
            user_id=current_user.id,
            scan_type='quick',
            scan_path=None
        )
        db.session.add(scan_session)
        db.session.commit()

        # Start scan in background
        thread = threading.Thread(target=scanner_engine.start_scan,
                                args=(scan_session.id, 'quick', None))
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'scan_id': scan_session.id,
            'message': 'Debug scan started successfully'
        })

    except Exception as e:
        logging.error(f"Debug scan error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new scan"""
    scan_type = request.form.get('scan_type', 'quick')
    scan_path = request.form.get('scan_path', '')

    if scan_type == 'custom' and not scan_path:
        # Return JSON error for AJAX requests
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            return jsonify({'success': False, 'message': 'Please specify a path for custom scan.'}), 400
        else:
            flash('Please specify a path for custom scan.', 'error')
            return redirect(url_for('scan'))

    # Create scan session
    scan_session = ScanSession(
        user_id=current_user.id,
        scan_type=scan_type,
        scan_path=scan_path if scan_type == 'custom' else None
    )
    db.session.add(scan_session)
    db.session.commit()

    # Start scan in background thread
    try:
        thread = threading.Thread(target=scanner_engine.start_scan,
                                args=(scan_session.id, scan_type, scan_path))
        thread.daemon = True
        thread.start()

        # Check if this is an AJAX request (Content-Type header indicates form-encoded data)
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            # Return JSON for AJAX requests
            return jsonify({
                'success': True,
                'scan_id': scan_session.id,
                'message': 'Scan started successfully'
            })
        else:
            # Redirect for form submissions
            session['current_scan_id'] = scan_session.id
            flash('Scan started successfully!', 'success')
            return redirect(url_for('scan_progress', scan_id=scan_session.id))

    except Exception as e:
        logging.error(f"Error starting scan thread: {e}")

        # Return JSON error for AJAX requests
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            return jsonify({'success': False, 'message': 'Failed to start scan. Please try again.'}), 500
        else:
            flash('Failed to start scan. Please try again.', 'error')
            db.session.rollback()
            return redirect(url_for('scan'))

@app.route('/scan_progress/<int:scan_id>')
@login_required
def scan_progress(scan_id):
    """Scan progress page"""
    try:
        scan_session = ScanSession.query.get_or_404(scan_id)
        if scan_session.user_id != current_user.id:
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all threats for this scan (use detected_at instead of timestamp)
        try:
            threats = DetectedThreat.query.filter_by(scan_session_id=scan_id).order_by(DetectedThreat.detected_at.desc()).all()
        except Exception as e:
            app.logger.warning(f"Error fetching threats: {e}")
            threats = []
        
        # Calculate progress percentage (use existing progress_percentage or default to 0)
        progress = 0
        if hasattr(scan_session, 'progress_percentage') and scan_session.progress_percentage is not None:
            progress = min(100, max(0, float(scan_session.progress_percentage)))
        elif scan_session.files_scanned and scan_session.files_scanned > 0:
            # If no progress_percentage but files_scanned exists, show a small progress
            progress = min(5, max(0, scan_session.files_scanned * 0.01))

        # Get current file being scanned
        current_file = getattr(scan_session, 'current_file', None) or "Starting scan..."
        
        # Prepare context with safe defaults
        context = {
            'scan_session': scan_session,
            'threats': threats,
            'progress': progress,
            'show_progress': True,
            'current_file': current_file,
            'files_scanned': getattr(scan_session, 'files_scanned', 0) or 0,
            'total_files': max(1, getattr(scan_session, 'files_scanned', 0) or 1),  # Avoid division by zero
            'threats_detected': getattr(scan_session, 'threats_detected', 0) or 0,
            'scan_status': getattr(scan_session, 'status', 'running')
        }
        
        return render_template('scan.html', **context)
        
    except Exception as e:
        app.logger.error(f"Error in scan_progress: {str(e)}", exc_info=True)
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading scan progress: {str(e)}. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/get_scan_threats/<int:scan_id>')
@login_required
def get_scan_threats(scan_id):
    """Get all threats for a scan"""
    try:
        scan_session = ScanSession.query.get_or_404(scan_id)
        if scan_session.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        threats = DetectedThreat.query.filter_by(scan_session_id=scan_id).order_by(DetectedThreat.detected_at.desc()).all()
        
        threats_data = [{
            'id': t.id,
            'file_path': t.file_path,
            'threat_type': t.threat_type,
            'threat_level': t.threat_level,
            'confidence': t.confidence_score,
            'detection_method': t.detection_method,
            'detected_at': t.detected_at.isoformat() if t.detected_at else None,
            'is_quarantined': t.is_quarantined
        } for t in threats]
        
        return jsonify({'threats': threats_data})
    except Exception as e:
        app.logger.error(f"Error getting scan threats: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/quarantine_threat/<int:threat_id>', methods=['POST'])
@login_required
def quarantine_threat(threat_id):
    """Quarantine a specific threat"""
    try:
        threat = DetectedThreat.query.get_or_404(threat_id)
        scan_session = ScanSession.query.get(threat.scan_session_id)
        
        if scan_session.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        if threat.is_quarantined:
            return jsonify({'message': 'Threat already quarantined', 'already_quarantined': True})
        
        # Quarantine the file
        if quarantine_manager.quarantine_file(threat.file_path, threat):
            threat.is_quarantined = True
            threat.status = 'quarantined'
            db.session.commit()
            return jsonify({'message': 'Threat quarantined successfully', 'success': True})
        else:
            return jsonify({'error': 'Failed to quarantine threat'}), 500
    
    except Exception as e:
        app.logger.error(f"Error quarantining threat: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/bulk_quarantine/<int:scan_id>', methods=['POST'])
@login_required
def bulk_quarantine(scan_id):
    """Quarantine all threats from a scan"""
    try:
        scan_session = ScanSession.query.get_or_404(scan_id)
        if scan_session.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        threats = DetectedThreat.query.filter_by(scan_session_id=scan_id, is_quarantined=False).all()
        quarantined_count = 0
        failed_count = 0
        
        for threat in threats:
            try:
                if quarantine_manager.quarantine_file(threat.file_path, threat):
                    threat.is_quarantined = True
                    threat.status = 'quarantined'
                    quarantined_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                app.logger.warning(f"Failed to quarantine threat {threat.id}: {e}")
                failed_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Quarantined {quarantined_count} threats',
            'quarantined': quarantined_count,
            'failed': failed_count
        })
    
    except Exception as e:
        app.logger.error(f"Error in bulk quarantine: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/scan_events/<int:scan_id>')
@login_required
def scan_events(scan_id):
    """Server-sent events for real-time scan updates"""
    scan_session = ScanSession.query.get_or_404(scan_id)
    if scan_session.user_id != current_user.id:
        return "Access denied", 403
    
    def generate():
        try:
            consecutive_errors = 0
            max_consecutive_errors = 10
            wait_count = 0
            max_wait = 5  # Wait up to 5 seconds for scan to start
            
            while True:
                try:
                    # Re-query the scan session to get fresh data
                    # Use app_context and read all attributes immediately while session is active
                    scan_session = None
                    scan_data = {}
                    try:
                        with app.app_context():
                            # Fresh query - read all attributes immediately before session closes
                            scan_session = ScanSession.query.filter_by(id=scan_id).first()
                            if scan_session:
                                # Read all attributes while the session is active
                                scan_data = {
                                    'progress_percentage': scan_session.progress_percentage,
                                    'files_scanned': scan_session.files_scanned,
                                    'threats_detected': scan_session.threats_detected,
                                    'current_file': scan_session.current_file,
                                    'status': scan_session.status,
                                    'end_time': scan_session.end_time
                                }
                                # Close session after reading data
                                db.session.close()
                    except Exception as query_error:
                        # If query fails, log it with full traceback
                        import traceback
                        error_trace = traceback.format_exc()
                        app.logger.error(f"Database query error in scan_events for scan {scan_id}: {query_error}\n{error_trace}")
                        
                        # Try to recover with app context
                        try:
                            with app.app_context():
                                db.session.rollback()
                                scan_session = ScanSession.query.filter_by(id=scan_id).first()
                                if scan_session:
                                    scan_data = {
                                        'progress_percentage': scan_session.progress_percentage,
                                        'files_scanned': scan_session.files_scanned,
                                        'threats_detected': scan_session.threats_detected,
                                        'current_file': scan_session.current_file,
                                        'status': scan_session.status,
                                        'end_time': scan_session.end_time
                                    }
                                db.session.close()
                        except Exception as retry_error:
                            app.logger.error(f"Retry query also failed for scan {scan_id}: {retry_error}")
                            scan_session = None
                            scan_data = {}
                    
                    if not scan_session:
                        # Scan session not found
                        wait_count += 1
                        if wait_count < max_wait:
                            # Wait a bit more - scan might be starting
                            time.sleep(1)
                            continue
                        else:
                            # Scan session not found after waiting, send error and exit
                            error_data = {
                                'type': 'error',
                                'message': 'Scan session not found'
                            }
                            yield f"data: {json.dumps(error_data)}\n\n"
                            break
                    
                    # Reset error counter and wait count on successful query
                    consecutive_errors = 0
                    wait_count = 0
                    
                    # Use data from scan_data dict (already read from session)
                    # This avoids DetachedInstanceError
                    progress_percentage = scan_data.get('progress_percentage')
                    if progress_percentage is not None:
                        try:
                            progress_pct = min(100, max(0, float(progress_percentage)))
                        except (ValueError, TypeError):
                            progress_pct = 0
                    else:
                        # Fallback: use a simple progress based on files_scanned
                        files_scanned_val = scan_data.get('files_scanned', 0) or 0
                        progress_pct = min(5, max(0, files_scanned_val * 0.01)) if files_scanned_val else 0
                    
                    # Safely get all attributes from scan_data
                    files_scanned = scan_data.get('files_scanned', 0) or 0
                    threats_detected = scan_data.get('threats_detected', 0) or 0
                    current_file = scan_data.get('current_file') or 'Starting scan...'
                    status = scan_data.get('status') or 'running'
                    
                    data = {
                        'type': 'progress',
                        'progress_percentage': progress_pct,
                        'progress': progress_pct,
                        'files_scanned': files_scanned,
                        'threats_detected': threats_detected,
                        'current_file': current_file,
                        'status': status
                    }
                    
                    yield f"data: {json.dumps(data)}\n\n"
                    
                    # Check if scan is complete
                    if status in ['completed', 'stopped', 'error']:
                        # Send completion event
                        end_time = scan_data.get('end_time')
                        completion_data = {
                            'type': 'complete',
                            'status': status,
                            'total_files': files_scanned,
                            'total_threats': threats_detected,
                            'end_time': end_time.isoformat() if end_time else None
                        }
                        yield f"data: {json.dumps(completion_data)}\n\n"
                        break
                    
                    time.sleep(1)
                    
                except Exception as e:
                    consecutive_errors += 1
                    # Log the error with more details
                    import traceback
                    error_details = traceback.format_exc()
                    app.logger.error(f"Error in scan_events generator for scan {scan_id}: {e}\n{error_details}")
                    
                    # Try to clean up the database session
                    try:
                        db.session.rollback()
                        db.session.close()
                    except:
                        pass
                    
                    # If we have too many consecutive errors, stop trying
                    if consecutive_errors >= max_consecutive_errors:
                        error_data = {
                            'type': 'error',
                            'message': f'Too many errors. Scan may have been deleted or corrupted.'
                        }
                        yield f"data: {json.dumps(error_data)}\n\n"
                        break
                    
                    # For temporary errors, send a minimal progress update to keep connection alive
                    # instead of sending error events
                    if consecutive_errors < 3:
                        # First few errors: send minimal progress update to keep connection alive
                        minimal_data = {
                            'type': 'progress',
                            'progress_percentage': 0,
                            'progress': 0,
                            'files_scanned': 0,
                            'threats_detected': 0,
                            'current_file': 'Starting scan...',
                            'status': 'running'
                        }
                        yield f"data: {json.dumps(minimal_data)}\n\n"
                        time.sleep(2)
                        continue
                    else:
                        # After 3 errors: send error event but keep trying
                        error_data = {
                            'type': 'error',
                            'message': 'Error fetching scan data'
                        }
                        yield f"data: {json.dumps(error_data)}\n\n"
                        time.sleep(2)  # Wait a bit longer before retrying
                    
        except GeneratorExit:
            # Client disconnected, clean up
            pass
        except Exception as e:
            import traceback
            app.logger.error(f"Fatal error in scan_events generator for scan {scan_id}: {e}\n{traceback.format_exc()}")
    
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'  # Disable buffering for nginx
    return response

@app.route('/quarantine')
@login_required
def quarantine():
    """Quarantine management page"""
    quarantined_threats = DetectedThreat.query.join(ScanSession)\
                                             .filter(ScanSession.user_id == current_user.id)\
                                             .filter(DetectedThreat.is_quarantined == True)\
                                             .order_by(DetectedThreat.detected_at.desc())\
                                             .all()
    
    return render_template('quarantine.html', quarantined_threats=quarantined_threats)

@app.route('/quarantine_action/<int:threat_id>/<action>')
@login_required
def quarantine_action(threat_id, action):
    """Handle quarantine actions (restore, delete)"""
    threat = DetectedThreat.query.get_or_404(threat_id)
    scan_session = ScanSession.query.get(threat.scan_session_id)
    
    if scan_session.user_id != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('quarantine'))
    
    try:
        if action == 'restore':
            if quarantine_manager.restore_file(threat):
                threat.is_quarantined = False
                threat.status = 'active'
                db.session.commit()
                flash('File restored successfully.', 'success')
            else:
                flash('Failed to restore file.', 'error')
        
        elif action == 'delete':
            if quarantine_manager.delete_quarantined_file(threat):
                threat.status = 'deleted'
                db.session.commit()
                flash('File deleted permanently.', 'success')
            else:
                flash('Failed to delete file.', 'error')
        
        elif action == 'whitelist':
            threat.status = 'false_positive'
            db.session.commit()
            flash('File marked as false positive.', 'info')
    
    except Exception as e:
        flash('An error occurred while processing the request.', 'error')
        logging.error(f"Quarantine action error: {e}")
    
    return redirect(url_for('quarantine'))

@app.route('/quarantine_bulk_action', methods=['POST'])
@login_required
def quarantine_bulk_action():
    """Handle bulk quarantine actions - memory efficient"""
    try:
        data = request.get_json()
        action = data.get('action')
        threat_ids = data.get('threat_ids', [])
        
        if not action or not threat_ids:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        # Limit to prevent memory issues
        if len(threat_ids) > 1000:
            return jsonify({'success': False, 'message': 'Too many files selected (max 1000)'}), 400
        
        success_count = 0
        failed_count = 0
        
        # Process one at a time to minimize memory usage
        for threat_id in threat_ids:
            try:
                threat = DetectedThreat.query.get(threat_id)
                if not threat:
                    failed_count += 1
                    continue
                
                # Verify ownership
                scan_session = ScanSession.query.get(threat.scan_session_id)
                if scan_session.user_id != current_user.id:
                    failed_count += 1
                    continue
                
                # Perform action
                if action == 'restore':
                    if quarantine_manager.restore_file(threat):
                        threat.is_quarantined = False
                        threat.status = 'active'
                        success_count += 1
                    else:
                        failed_count += 1
                
                elif action == 'delete':
                    if quarantine_manager.delete_quarantined_file(threat):
                        threat.status = 'deleted'
                        success_count += 1
                    else:
                        failed_count += 1
                
                elif action == 'whitelist':
                    threat.status = 'false_positive'
                    threat.is_quarantined = False
                    success_count += 1
                
                # Commit after each file to prevent large transactions
                db.session.commit()
                
            except Exception as e:
                logging.error(f"Error processing threat {threat_id}: {e}")
                db.session.rollback()
                failed_count += 1
        
        message = f'Successfully processed {success_count} file(s).'
        if failed_count > 0:
            message += f' {failed_count} file(s) failed.'
        
        return jsonify({
            'success': True,
            'message': message,
            'success_count': success_count,
            'failed_count': failed_count
        })
    
    except Exception as e:
        logging.error(f"Bulk action error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/account')
@login_required
def account():
    """Account management page"""
    return render_template('account.html')

@app.route('/update_account', methods=['POST'])
@login_required
def update_account():
    """Update account information"""
    try:
        current_user.first_name = request.form.get('first_name', '')
        current_user.last_name = request.form.get('last_name', '')
        current_user.email = request.form.get('email', current_user.email)
        current_user.phone = request.form.get('phone', '')
        current_user.organization = request.form.get('organization', '')
        current_user.email_notifications = bool(request.form.get('email_notifications'))
        
        # Check if email is already taken by another user
        existing_user = User.query.filter_by(email=current_user.email)\
                                 .filter(User.id != current_user.id).first()
        if existing_user:
            flash('Email is already registered to another account.', 'error')
            return redirect(url_for('account'))
        
        db.session.commit()
        flash('Account updated successfully!', 'success')
    
    except Exception as e:
        db.session.rollback()
        flash('Failed to update account.', 'error')
        logging.error(f"Account update error: {e}")
    
    return redirect(url_for('account'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('account'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('account'))
    
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('account'))
    
    try:
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to change password.', 'error')
        logging.error(f"Password change error: {e}")
    
    return redirect(url_for('account'))

@app.route('/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    """Update notification preferences"""
    try:
        data = request.get_json()
        
        # Update email notification preferences
        current_user.notify_threat_detection = data.get('emailThreats', True)
        current_user.notify_scan_completion = data.get('emailScan', True)
        current_user.notify_security_updates = data.get('emailSecurity', False)
        current_user.notify_newsletter = data.get('emailNewsletter', False)
        
        # Update desktop notification preferences
        current_user.notify_desktop_threats = data.get('desktopThreats', True)
        current_user.notify_desktop_scan = data.get('desktopScan', False)
        current_user.notify_desktop_system = data.get('desktopSystem', True)
        
        # Update general email_notifications flag
        current_user.email_notifications = (
            current_user.notify_threat_detection or 
            current_user.notify_scan_completion or 
            current_user.notify_security_updates or 
            current_user.notify_newsletter
        )
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Notification settings saved successfully!'})
    
    except Exception as e:
        db.session.rollback()
        logging.error(f"Notification update error: {e}")
        return jsonify({'success': False, 'message': 'Failed to save notification settings'}), 500

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    """Upload and update user avatar"""
    try:
        if 'avatar' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400

        file = request.files['avatar']

        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400

        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        if '.' not in file.filename or \
           file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return jsonify({'success': False, 'message': 'Invalid file type. Only images are allowed.'}), 400

        # Validate file size (max 5MB)
        if file.content_length > 5 * 1024 * 1024:
            return jsonify({'success': False, 'message': 'File size must be less than 5MB.'}), 400

        # Generate secure filename
        filename = secure_filename(f"{current_user.id}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")

        # Ensure uploads/avatars directory exists
        avatar_dir = os.path.join(app.root_path, 'static', 'uploads', 'avatars')
        os.makedirs(avatar_dir, exist_ok=True)

        # Save file
        file_path = os.path.join(avatar_dir, filename)
        file.save(file_path)

        # Delete old avatar if exists
        if current_user.avatar_path:
            old_avatar_path = os.path.join(app.root_path, 'static', 'uploads', 'avatars', current_user.avatar_path)
            if os.path.exists(old_avatar_path):
                try:
                    os.remove(old_avatar_path)
                except Exception as e:
                    logging.warning(f"Failed to delete old avatar: {e}")

        # Update user avatar path in database
        current_user.avatar_path = filename
        db.session.commit()

        # Generate avatar URL
        avatar_url = url_for('static', filename=f'uploads/avatars/{filename}')

        return jsonify({
            'success': True,
            'message': 'Avatar updated successfully',
            'avatar_url': avatar_url
        })

    except Exception as e:
        db.session.rollback()
        logging.error(f"Avatar upload error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while uploading the avatar'}), 500

@app.route('/export_activity_log')
@login_required
def export_activity_log():
    """Export user activity log as CSV"""
    try:
        from io import BytesIO, StringIO
        import csv
        from datetime import datetime
        
        # Get user's scan sessions
        scan_sessions = ScanSession.query.filter_by(user_id=current_user.id)\
            .order_by(ScanSession.start_time.desc()).all()
        
        # Create CSV
        csv_buffer = StringIO()
        writer = csv.writer(csv_buffer)
        
        # Header
        writer.writerow(['Activity Log for ' + current_user.username])
        writer.writerow(['Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        writer.writerow(['Date', 'Time', 'Activity', 'Details', 'Status'])
        
        # Add scan activities
        for scan in scan_sessions:
            date = scan.start_time.strftime('%Y-%m-%d') if scan.start_time else 'N/A'
            time = scan.start_time.strftime('%H:%M:%S') if scan.start_time else 'N/A'
            activity = f'{scan.scan_type.upper()} Scan' if scan.scan_type else 'Scan'
            details = f'{scan.files_scanned or 0} files scanned, {scan.threats_detected or 0} threats found'
            status = scan.status.upper()
            
            writer.writerow([date, time, activity, details, status])
        
        # Add login activity (if last_login exists)
        if current_user.last_login:
            date = current_user.last_login.strftime('%Y-%m-%d')
            time = current_user.last_login.strftime('%H:%M:%S')
            writer.writerow([date, time, 'Login', 'User logged in', 'SUCCESS'])
        
        # Add account creation
        if current_user.created_at:
            date = current_user.created_at.strftime('%Y-%m-%d')
            time = current_user.created_at.strftime('%H:%M:%S')
            writer.writerow([date, time, 'Account Created', 'User account registered', 'SUCCESS'])
        
        # Convert to bytes
        output = BytesIO()
        output.write(csv_buffer.getvalue().encode('utf-8'))
        output.seek(0)
        
        filename = f'activity_log_{current_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Error exporting activity log: {e}")
        return "Error exporting activity log", 500

@app.route('/analytics')
@login_required
def analytics():
    """Analytics and metrics page"""
    # Get user's scan statistics
    user_scans = ScanSession.query.filter_by(user_id=current_user.id).all()
    user_threats = DetectedThreat.query.join(ScanSession)\
                                      .filter(ScanSession.user_id == current_user.id)\
                                      .all()
    
    # Get ML model metrics
    model_metrics = MLModelMetrics.query.filter_by(is_active=True)\
                                       .order_by(MLModelMetrics.last_updated.desc())\
                                       .all()
    
    # Get system health data
    health_data = SystemHealth.query.order_by(SystemHealth.timestamp.desc())\
                                   .limit(24).all()
    
    return render_template('analytics.html',
                         user_scans=user_scans,
                         user_threats=user_threats,
                         model_metrics=model_metrics,
                         health_data=health_data)

@app.route('/api/chart_data/<chart_type>')
@login_required
def chart_data(chart_type):
    """API endpoint for chart data"""
    try:
        if chart_type == 'threat_timeline':
            # Get threat detection timeline
            threats = DetectedThreat.query.join(ScanSession)\
                                         .filter(ScanSession.user_id == current_user.id)\
                                         .order_by(DetectedThreat.detected_at)\
                                         .all()
            
            data = {}
            for threat in threats:
                date = threat.detected_at.strftime('%Y-%m-%d')
                if date not in data:
                    data[date] = {'ransomware': 0, 'malware': 0, 'suspicious': 0}
                data[date][threat.threat_type] += 1
            
            return jsonify(data)
        
        elif chart_type == 'model_accuracy':
            # Get model accuracy metrics
            metrics = MLModelMetrics.query.filter_by(is_active=True)\
                                         .order_by(MLModelMetrics.last_updated.desc())\
                                         .all()
            
            data = []
            for metric in metrics:
                data.append({
                    'model': metric.model_name,
                    'accuracy': metric.accuracy,
                    'precision': metric.precision,
                    'recall': metric.recall,
                    'f1_score': metric.f1_score
                })
            
            return jsonify(data)
        
        elif chart_type == 'system_health':
            # Get system health metrics
            health_data = SystemHealth.query.order_by(SystemHealth.timestamp.desc())\
                                           .limit(24).all()
            
            data = []
            for health in reversed(health_data):
                data.append({
                    'timestamp': health.timestamp.strftime('%H:%M'),
                    'cpu': health.cpu_usage,
                    'memory': health.memory_usage,
                    'disk': health.disk_usage
                })
            
            return jsonify(data)
        
        elif chart_type == 'threat_distribution':
            # Get threat type distribution
            threats = DetectedThreat.query.join(ScanSession)\
                                         .filter(ScanSession.user_id == current_user.id)\
                                         .all()
            
            distribution = {}
            for threat in threats:
                threat_type = threat.threat_type
                if threat_type not in distribution:
                    distribution[threat_type] = 0
                distribution[threat_type] += 1
            
            return jsonify(distribution)
        
        else:
            return jsonify({'error': 'Invalid chart type'}), 400
    
    except Exception as e:
        logging.error(f"Chart data error: {e}")
        return jsonify({'error': 'Failed to fetch chart data'}), 500

@app.route('/api/system_status')
@login_required
def system_status():
    """API endpoint for real-time system status"""
    try:
        # Get latest system health
        health = SystemHealth.query.order_by(SystemHealth.timestamp.desc()).first()
        
        # Get active scan count
        active_scans = ScanSession.query.filter_by(status='running').count()
        
        # Get recent threats
        recent_threats = DetectedThreat.query.join(ScanSession)\
                                           .filter(ScanSession.user_id == current_user.id)\
                                           .filter(DetectedThreat.detected_at >= datetime.utcnow().replace(hour=0, minute=0, second=0))\
                                           .count()
        
        return jsonify({
            'cpu_usage': health.cpu_usage if health else 0,
            'memory_usage': health.memory_usage if health else 0,
            'disk_usage': health.disk_usage if health else 0,
            'threat_level': health.threat_level if health else 'low',
            'active_scans': active_scans,
            'recent_threats': recent_threats
        })
    
    except Exception as e:
        logging.error(f"System status error: {e}")
        return jsonify({'error': 'Failed to fetch system status'}), 500
# 2FA Routes
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Setup 2FA for the user"""
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate':
            try:
                # Generate OTP secret
                secret = current_user.generate_otp_secret()
                logging.info(f"Generated secret for user {current_user.username}: {secret}")

                # Commit to database
                db.session.commit()
                logging.info(f"Secret committed to database for user {current_user.username}")

                # Verify the secret was saved correctly
                db.session.refresh(current_user)
                logging.info(f"Database secret after refresh: {current_user.otp_secret}")

                # Generate QR code server-side
                otp_uri = current_user.get_otp_uri()
                if not otp_uri:
                    logging.error(f"Failed to generate OTP URI for user {current_user.username}")
                    return jsonify({'success': False, 'message': 'Failed to generate OTP URI'})

                logging.info(f"Generated OTP URI: {otp_uri}")

                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(otp_uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")

                # Convert to base64
                img_buffer = io.BytesIO()
                img.save(img_buffer, format='PNG')
                img_str = base64.b64encode(img_buffer.getvalue()).decode()

                logging.info(f"Generated QR code for user {current_user.username}")

                return jsonify({
                    'success': True,
                    'secret': secret,
                    'qr_code': f'data:image/png;base64,{img_str}'
                })
            except Exception as e:
                logging.error(f"Error generating 2FA secret: {e}")
                db.session.rollback()
                return jsonify({'success': False, 'message': f'Failed to generate QR code: {str(e)}'})
        elif action == 'verify':
            try:
                token = request.form.get('token')
                logging.info(f"Verification attempt - User: {current_user.username}, Token: {token}")
                logging.info(f"Current user secret: {current_user.otp_secret}")
                logging.info(f"Current user 2FA enabled: {current_user.is_2fa_enabled}")

                if current_user.verify_otp(token):
                    current_user.is_2fa_enabled = True
                    db.session.commit()
                    logging.info(f"2FA enabled successfully for user {current_user.username}")
                    flash('2FA has been enabled successfully!', 'success')
                    return jsonify({'success': True})
                else:
                    logging.error(f"Verification failed - User: {current_user.username}, Token: {token}, Secret: {current_user.otp_secret}")
                    return jsonify({'success': False, 'message': 'Invalid verification code'})
            except Exception as e:
                logging.error(f"Error verifying 2FA token: {e}")
                return jsonify({'success': False, 'message': 'Error verifying token'})
        elif action == 'debug':
            # Debug endpoint to get current expected code (available during 2FA setup)
            try:
                if current_user.otp_secret:
                    totp = pyotp.TOTP(current_user.otp_secret)
                    expected_code = totp.now()
                    logging.info(f"Debug - User: {current_user.username}, Expected code: {expected_code}")
                    return jsonify({
                        'success': True,
                        'expected_code': expected_code,
                        'secret': current_user.otp_secret,
                        'secret_length': len(current_user.otp_secret),
                        'is_hex': len(current_user.otp_secret) == 32 and all(c in '0123456789abcdefABCDEF' for c in current_user.otp_secret),
                        'is_base32': all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in current_user.otp_secret),
                        'timestamp': datetime.utcnow().isoformat(),
                        'is_2fa_enabled': current_user.is_2fa_enabled,
                        'user_id': current_user.id
                    })
                else:
                    logging.error(f"Debug - No OTP secret found for user {current_user.username}")
                    return jsonify({
                        'success': False,
                        'message': 'No OTP secret found. Generate a QR code first.',
                        'user_id': current_user.id if current_user.is_authenticated else None,
                        'is_authenticated': current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False
                    })
            except Exception as e:
                logging.error(f"Error in debug endpoint: {e}")
                import traceback
                logging.error(f"Debug endpoint traceback: {traceback.format_exc()}")
                return jsonify({
                    'success': False,
                    'message': f'Debug error: {str(e)}',
                    'user_id': getattr(current_user, 'id', None),
                    'is_authenticated': getattr(current_user, 'is_authenticated', False)
                })
        elif action == 'disable':
            try:
                current_user.is_2fa_enabled = False
                current_user.otp_secret = None
                db.session.commit()
                flash('2FA has been disabled.', 'success')
                return jsonify({'success': True})
            except Exception as e:
                logging.error(f"Error disabling 2FA: {e}")
                return jsonify({'success': False, 'message': 'Error disabling 2FA'})
    return render_template('setup_2fa.html')

@app.route('/verify_2fa', methods=['POST'])
@login_required
def verify_2fa():
    """Verify 2FA token"""
    token = request.form.get('token')
    if current_user.verify_otp(token):
        session['2fa_verified'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid token'})

# Error handlers
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Background task to update system health
def update_system_health():
    """Background task to monitor system health"""
    while True:
        try:
            with app.app_context():
                health_data = system_monitor.get_system_health()
                health = SystemHealth(**health_data)
                db.session.add(health)
                db.session.commit()
        except Exception as e:
            logging.error(f"System health update error: {e}")
        
        time.sleep(60)  # Update every minute

# Start background health monitoring
health_thread = threading.Thread(target=update_system_health)
health_thread.daemon = True
health_thread.start()

@app.route('/export_report/<report_type>')
@login_required
def export_report(report_type):
    """Export scan reports in various formats"""
    try:
        from io import BytesIO
        import csv
        from datetime import datetime
        
        # Get scan sessions and threats
        scan_sessions = ScanSession.query.filter_by(user_id=current_user.id).order_by(ScanSession.start_time.desc()).limit(100).all()
        
        # Generate report data
        report_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'user': current_user.username,
            'total_scans': len(scan_sessions),
            'total_threats': sum(s.threats_detected for s in scan_sessions if s.threats_detected),
            'scans': []
        }
        
        for scan in scan_sessions:
            threats = DetectedThreat.query.filter_by(scan_session_id=scan.id).all()
            scan_info = {
                'id': scan.id,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'status': scan.status,
                'files_scanned': scan.files_scanned or 0,
                'threats_detected': scan.threats_detected or 0,
                'threats': [{
                    'file_path': t.file_path,
                    'threat_type': t.threat_type,
                    'threat_level': t.threat_level,
                    'confidence': t.confidence_score,
                    'detected_at': t.detected_at.isoformat() if t.detected_at else None
                } for t in threats]
            }
            report_data['scans'].append(scan_info)
        
        # Generate file based on report type
        if report_type == 'comprehensive':
            # Human-readable text format with summary
            from io import StringIO
            report_text = StringIO()
            
            report_text.write("=" * 80 + "\n")
            report_text.write("RANSOMGUARD PRO - COMPREHENSIVE SECURITY REPORT\n")
            report_text.write("=" * 80 + "\n\n")
            report_text.write(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            report_text.write(f"User: {current_user.username}\n")
            report_text.write(f"Total Scans: {report_data['total_scans']}\n")
            report_text.write(f"Total Threats Detected: {report_data['total_threats']}\n")
            report_text.write("\n" + "-" * 80 + "\n\n")
            
            for idx, scan in enumerate(report_data['scans'], 1):
                report_text.write(f"SCAN #{idx} (ID: {scan['id']})\n")
                report_text.write("-" * 80 + "\n")
                report_text.write(f"  Start Time: {scan['start_time'] or 'N/A'}\n")
                report_text.write(f"  End Time: {scan['end_time'] or 'N/A'}\n")
                report_text.write(f"  Status: {scan['status'].upper()}\n")
                report_text.write(f"  Files Scanned: {scan['files_scanned']:,}\n")
                report_text.write(f"  Threats Detected: {scan['threats_detected']}\n\n")
                
                if scan['threats']:
                    report_text.write(f"  DETECTED THREATS ({len(scan['threats'])}):\n")
                    for threat_idx, threat in enumerate(scan['threats'], 1):
                        report_text.write(f"\n  Threat #{threat_idx}:\n")
                        report_text.write(f"    File Path: {threat['file_path']}\n")
                        report_text.write(f"    Threat Type: {threat['threat_type'].upper()}\n")
                        report_text.write(f"    Threat Level: {threat['threat_level'].upper()}\n")
                        report_text.write(f"    Confidence: {threat['confidence']:.1%}\n")
                        report_text.write(f"    Detected At: {threat['detected_at'] or 'N/A'}\n")
                    report_text.write("\n")
                else:
                    report_text.write("  No threats detected in this scan.\n\n")
                
                report_text.write("\n")
            
            report_text.write("=" * 80 + "\n")
            report_text.write("END OF REPORT\n")
            report_text.write("=" * 80 + "\n")
            
            output = BytesIO()
            output.write(report_text.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'ransomguard_comprehensive_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
            mimetype = 'text/plain'
            
        elif report_type == 'executive':
            # CSV format - executive summary
            from io import StringIO
            csv_buffer = StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(['Scan ID', 'Date', 'Status', 'Files Scanned', 'Threats Found'])
            for scan in scan_sessions:
                date_str = scan.start_time.strftime('%Y-%m-%d %H:%M') if scan.start_time else 'N/A'
                writer.writerow([
                    scan.id,
                    date_str,
                    scan.status,
                    scan.files_scanned or 0,
                    scan.threats_detected or 0
                ])
            output = BytesIO()
            output.write(csv_buffer.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'ransomguard_executive_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            mimetype = 'text/csv'
            
        elif report_type == 'technical':
            # CSV format - technical details with all threats
            from io import StringIO
            csv_buffer = StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(['Scan ID', 'Threat ID', 'File Path', 'Threat Type', 'Level', 'Confidence', 'Detection Method', 'Detected At'])
            for scan in scan_sessions:
                threats = DetectedThreat.query.filter_by(scan_session_id=scan.id).all()
                for threat in threats:
                    date_str = threat.detected_at.strftime('%Y-%m-%d %H:%M:%S') if threat.detected_at else 'N/A'
                    writer.writerow([
                        scan.id,
                        threat.id,
                        threat.file_path,
                        threat.threat_type,
                        threat.threat_level,
                        f"{threat.confidence_score:.2%}",
                        threat.detection_method,
                        date_str
                    ])
            output = BytesIO()
            output.write(csv_buffer.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'ransomguard_technical_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            mimetype = 'text/csv'
        else:
            # Return error as plain text instead of redirect
            return f"Error: Invalid report type '{report_type}'. Valid types: comprehensive, executive, technical", 400
        
        return send_file(
            output,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Error exporting report: {e}", exc_info=True)
        # Return error as plain text instead of redirect
        return f"Error exporting report: {str(e)}", 500

@app.route('/export_report/scan')
@login_required
def export_scan_results():
    """Export latest scan results in various formats (PDF, Excel, CSV, JSON)"""
    try:
        from io import BytesIO
        import csv
        import json as json_module
        from datetime import datetime
        
        # Get format from query parameter
        export_format = request.args.get('format', 'pdf').lower()
        
        # Get the most recent scan for this user
        latest_scan = ScanSession.query.filter_by(user_id=current_user.id).order_by(ScanSession.start_time.desc()).first()
        
        if not latest_scan:
            flash('No scan data available to export', 'warning')
            return redirect(url_for('scan'))
        
        # Get threats for this scan
        threats = DetectedThreat.query.filter_by(scan_session_id=latest_scan.id).all()
        
        # Prepare data
        scan_data = {
            'scan_id': latest_scan.id,
            'start_time': latest_scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if latest_scan.start_time else 'N/A',
            'end_time': latest_scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if latest_scan.end_time else 'N/A',
            'status': latest_scan.status,
            'files_scanned': latest_scan.files_scanned or 0,
            'threats_detected': latest_scan.threats_detected or 0,
            'scan_type': latest_scan.scan_type or 'quick',
            'threats': [{
                'file_path': t.file_path,
                'threat_type': t.threat_type,
                'threat_level': t.threat_level,
                'confidence': f"{t.confidence_score:.1%}",
                'detection_method': t.detection_method,
                'detected_at': t.detected_at.strftime('%Y-%m-%d %H:%M:%S') if t.detected_at else 'N/A',
                'is_quarantined': t.is_quarantined
            } for t in threats]
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if export_format == 'json':
            # JSON export
            output = BytesIO()
            output.write(json_module.dumps(scan_data, indent=2).encode('utf-8'))
            output.seek(0)
            filename = f'scan_results_{timestamp}.json'
            mimetype = 'application/json'
            
        elif export_format == 'csv':
            # CSV export
            from io import StringIO
            csv_buffer = StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(['File Path', 'Threat Type', 'Threat Level', 'Confidence', 'Detection Method', 'Detected At', 'Quarantined'])
            for threat in scan_data['threats']:
                writer.writerow([
                    threat['file_path'],
                    threat['threat_type'],
                    threat['threat_level'],
                    threat['confidence'],
                    threat['detection_method'],
                    threat['detected_at'],
                    'Yes' if threat['is_quarantined'] else 'No'
                ])
            output = BytesIO()
            output.write(csv_buffer.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'scan_results_{timestamp}.csv'
            mimetype = 'text/csv'
            
        elif export_format == 'excel':
            # Excel export (using CSV format with .xlsx extension for simplicity)
            from io import StringIO
            csv_buffer = StringIO()
            writer = csv.writer(csv_buffer)
            # Header
            writer.writerow(['RANSOMGUARD SCAN REPORT'])
            writer.writerow([f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
            writer.writerow([f'Scan ID: {scan_data["scan_id"]}'])
            writer.writerow([f'Files Scanned: {scan_data["files_scanned"]:,}'])
            writer.writerow([f'Threats Detected: {scan_data["threats_detected"]}'])
            writer.writerow([])
            writer.writerow(['File Path', 'Threat Type', 'Threat Level', 'Confidence', 'Detection Method', 'Detected At', 'Quarantined'])
            for threat in scan_data['threats']:
                writer.writerow([
                    threat['file_path'],
                    threat['threat_type'],
                    threat['threat_level'],
                    threat['confidence'],
                    threat['detection_method'],
                    threat['detected_at'],
                    'Yes' if threat['is_quarantined'] else 'No'
                ])
            output = BytesIO()
            output.write(csv_buffer.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'scan_results_{timestamp}.csv'  # Excel can open CSV files
            mimetype = 'text/csv'
            
        elif export_format == 'pdf':
            # PDF export (simple text-based format)
            from io import StringIO
            pdf_text = StringIO()
            pdf_text.write("=" * 80 + "\n")
            pdf_text.write("RANSOMGUARD PRO - SCAN REPORT\n")
            pdf_text.write("=" * 80 + "\n\n")
            pdf_text.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            pdf_text.write(f"Scan ID: {scan_data['scan_id']}\n")
            pdf_text.write(f"Scan Type: {scan_data['scan_type'].upper()}\n")
            pdf_text.write(f"Start Time: {scan_data['start_time']}\n")
            pdf_text.write(f"End Time: {scan_data['end_time']}\n")
            pdf_text.write(f"Status: {scan_data['status'].upper()}\n")
            pdf_text.write(f"Files Scanned: {scan_data['files_scanned']:,}\n")
            pdf_text.write(f"Threats Detected: {scan_data['threats_detected']}\n")
            pdf_text.write("\n" + "-" * 80 + "\n\n")
            
            if scan_data['threats']:
                pdf_text.write(f"DETECTED THREATS ({len(scan_data['threats'])}):\n\n")
                for idx, threat in enumerate(scan_data['threats'], 1):
                    pdf_text.write(f"Threat #{idx}:\n")
                    pdf_text.write(f"  File: {threat['file_path']}\n")
                    pdf_text.write(f"  Type: {threat['threat_type'].upper()}\n")
                    pdf_text.write(f"  Level: {threat['threat_level'].upper()}\n")
                    pdf_text.write(f"  Confidence: {threat['confidence']}\n")
                    pdf_text.write(f"  Method: {threat['detection_method']}\n")
                    pdf_text.write(f"  Detected: {threat['detected_at']}\n")
                    pdf_text.write(f"  Quarantined: {'Yes' if threat['is_quarantined'] else 'No'}\n")
                    pdf_text.write("\n")
            else:
                pdf_text.write("No threats detected. Your system is clean!\n\n")
            
            pdf_text.write("=" * 80 + "\n")
            pdf_text.write("END OF REPORT\n")
            pdf_text.write("=" * 80 + "\n")
            
            output = BytesIO()
            output.write(pdf_text.getvalue().encode('utf-8'))
            output.seek(0)
            filename = f'scan_results_{timestamp}.txt'  # Text format for PDF
            mimetype = 'text/plain'
        else:
            # Return error as plain text instead of redirect
            return f"Error: Invalid export format '{export_format}'. Valid formats: pdf, excel, csv, json", 400
        
        return send_file(
            output,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Error exporting scan results: {e}", exc_info=True)
        # Return error as plain text instead of redirect
        return f"Error exporting scan results: {str(e)}", 500

@app.route('/stop_scan/<int:scan_id>', methods=['POST'])
@login_required
def stop_scan(scan_id):
    """Stop a running scan"""
    try:
        scan = ScanSession.query.get_or_404(scan_id)
        
        # Check if the scan belongs to the current user
        if scan.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403

        # Check if the scan is actually running
        if scan.status not in ['queued', 'scanning', 'running']:
            return jsonify({'error': 'Scan is not running'}), 400

        # Update scan status
        scan.status = 'stopped'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        
        # Notify any connected clients
        return jsonify({
            'success': True,
            'message': 'Scan stopped successfully',
            'scan_id': scan_id
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error stopping scan {scan_id}: {e}")
        return jsonify({'error': f'Failed to stop scan: {str(e)}'}), 500


@app.route('/export_scan_report/<int:scan_id>')
@login_required
def export_scan_report(scan_id):
    """Export detailed report for a specific scan"""
    try:
        from io import BytesIO
        from datetime import datetime
        
        scan_session = ScanSession.query.get_or_404(scan_id)
        if scan_session.user_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        threats = DetectedThreat.query.filter_by(scan_session_id=scan_id).all()
        
        report_data = {
            'scan_id': scan_id,
            'generated_at': datetime.utcnow().isoformat(),
            'scan_info': {
                'start_time': scan_session.start_time.isoformat() if scan_session.start_time else None,
                'end_time': scan_session.end_time.isoformat() if scan_session.end_time else None,
                'status': scan_session.status,
                'files_scanned': scan_session.files_scanned or 0,
                'threats_detected': scan_session.threats_detected or 0,
                'scan_type': scan_session.scan_type
            },
            'threats': [{
                'file_path': t.file_path,
                'threat_type': t.threat_type,
                'threat_level': t.threat_level,
                'confidence': t.confidence_score,
                'detection_method': t.detection_method,
                'detected_at': t.detected_at.isoformat() if t.detected_at else None,
                'is_quarantined': t.is_quarantined
            } for t in threats]
        }
        
        output = BytesIO()
        output.write(json.dumps(report_data, indent=2).encode('utf-8'))
        output.seek(0)
        filename = f'ransomguard_scan_{scan_id}_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Error exporting scan report: {e}", exc_info=True)
        flash(f'Error exporting scan report: {str(e)}', 'error')
        return redirect(url_for('scan_progress', scan_id=scan_id))

@app.route("/alerts/mark_all_read", methods=["POST"])
@login_required
def mark_all_read():
    ThreatAlert.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    flash("All alerts marked as read.", "success")
    return redirect(url_for("dashboard"))