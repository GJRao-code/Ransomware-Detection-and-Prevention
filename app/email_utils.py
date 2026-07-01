import os
import logging
from flask import current_app, render_template, has_app_context
from flask_mail import Message

def get_app_config(key, default=None):
    """Helper to get config from Flask app if available, or environment variables"""
    if has_app_context():
        return current_app.config.get(key, os.getenv(key, default))
    return os.getenv(key, default)

def send_email(subject, sender, recipients, text_body=None, html_body=None, template_name=None, template_vars=None):
    """Send email using Flask-Mail with Gmail SMTP"""
    try:
        if not sender:
            sender = get_app_config('MAIL_DEFAULT_SENDER', 'jrao7483@gmail.com')
        if not sender or not recipients:
            logging.error("Sender or recipients cannot be None or empty")
            return False

        logging.info(f"Attempting to send email to: {recipients}")
        logging.info(f"Using sender: {sender}")

        if template_name:
            if not template_vars:
                template_vars = {}

            template_vars.update({
                'app_name': get_app_config('APP_NAME', 'RansomGuard Pro'),
                'support_email': get_app_config('MAIL_DEFAULT_SENDER', 'jrao7483@gmail.com'),
                'current_year': 2025
            })

            if not text_body and has_app_context():
                try:
                    text_body = render_template(f'emails/{template_name}.txt', **template_vars)
                except Exception as e:
                    logging.warning(f"Could not render text template: {e}")
                    text_body = "Email content could not be loaded."

            if not html_body and has_app_context():
                try:
                    html_body = render_template(f'emails/{template_name}.html', **template_vars)
                except Exception as e:
                    logging.warning(f"Could not render HTML template: {e}")
                    html_body = None

            if not text_body:
                text_body = f"Security Alert for {template_vars.get('username', 'User')}\n\n{template_vars.get('alert_details', 'No details available')}"

        if not text_body and not html_body:
            text_body = "Default email content: No body provided."

        # Send email using direct SMTP (more reliable than Flask-Mail)
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Create message
        if html_body:
            msg = MIMEMultipart('alternative')
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
        else:
            msg = MIMEText(text_body, 'plain')

        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipients if isinstance(recipients, str) else ', '.join(recipients)

        # Send email via Gmail SMTP
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(current_app.config.get('MAIL_USERNAME'),
                        current_app.config.get('MAIL_PASSWORD'))
            server.sendmail(sender, recipients if isinstance(recipients, str) else recipients, msg.as_string())
            server.quit()

            logging.info(f"Email sent successfully to {recipients}")
            return True

        except Exception as e:
            logging.error(f"Gmail SMTP error: {str(e)}")
            raise e

    except Exception as e:
        logging.error(f"Error sending email: {str(e)}", exc_info=True)
        return False

def send_email_fallback(subject, sender, recipients, text_body=None, html_body=None, template_name=None, template_vars=None):
    """Fallback email method for development - prints to console"""
    print("\n" + "="*60)
    print("DEVELOPMENT EMAIL FALLBACK")
    print("="*60)
    print(f"From: {sender}")
    print(f"To: {recipients}")
    print(f"Subject: {subject}")
    print("-"*60)
    print("Email Body:")
    print("-"*60)
    if text_body:
        print(text_body)
    if html_body:
        print("\nHTML Body:")
        print(html_body)
    print("="*60)
    print("This is a development fallback. Configure Gmail to send real emails.")
    print("="*60 + "\n")
    return True

def send_password_reset_email(email, reset_url):
    """Send password reset email"""
    subject = "RansomGuard Pro - Password Reset Request"
    sender = get_app_config('MAIL_DEFAULT_SENDER', 'jrao7483@gmail.com')

    return send_email(
        subject=subject,
        sender=sender,
        recipients=email,
        template_name='reset_password',
        template_vars={
            'reset_url': reset_url,
            'username': email.split('@')[0] if '@' in email else 'User'
        }
    )

def send_welcome_email(email, username, reset_url):
    """Send welcome email to new users"""
    subject = "Welcome to RansomGuard Pro - Set Your Password"
    sender = get_app_config('MAIL_DEFAULT_SENDER', 'noreply@ransomguardpro.com')
    
    return send_email(
        subject=subject,
        sender=sender,
        recipients=email,
        template_name='welcome',
        template_vars={
            'username': username,
            'reset_url': reset_url
        }
    )

def send_security_alert(email, username, alert_details):
    """Send security alert email"""
    subject = "Security Alert - Suspicious Activity Detected"
    sender = get_app_config('MAIL_DEFAULT_SENDER', 'noreply@ransomguardpro.com')
    
    return send_email(
        subject=subject,
        sender=sender,
        recipients=email,
        template_name='security_alert',
        template_vars={
            'username': username,
            'alert_details': alert_details
        }
    )