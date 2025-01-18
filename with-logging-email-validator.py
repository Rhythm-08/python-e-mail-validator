import logging
from flask import Flask, request, jsonify
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import smtplib
import time
from functools import lru_cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Setup Flask app and Limiter
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

# Setup logging
logging.basicConfig(
    filename="email_validation.log",  # Log file name
    level=logging.INFO,  # Log level (INFO for general logs)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
    datefmt="%Y-%m-%d %H:%M:%S"  # Date format
)
logger = logging.getLogger()

@lru_cache(maxsize=1000)
def validate_email_address(email):
    """Validates the email syntax and checks the domain for MX records."""
    try:
        # Validate email syntax
        v = validate_email(email)
        email = v["email"]  # Normalized email
        domain = email.split('@')[1]

        # Check if the domain has MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            logger.warning(f"Invalid email (no MX records): {email}")
            return {"status": "invalid", "reason": "No MX records found for the domain."}

        logger.info(f"Valid email syntax and MX records: {email}")
        return {"status": "valid", "email": email, "reason": "Valid email address."}
    except EmailNotValidError as e:
        logger.error(f"Invalid email syntax: {email} - {str(e)}")
        return {"status": "invalid", "reason": f"Invalid email syntax: {str(e)}"}
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain does not exist: {email}")
        return {"status": "invalid", "reason": "Domain does not exist."}
    except Exception as e:
        logger.error(f"Unexpected error while validating email {email}: {str(e)}")
        return {"status": "invalid", "reason": f"Unexpected error: {str(e)}"}

def smtp_check(email):
    """Performs SMTP validation to check if the recipient email exists."""
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)

        # Connect to the mail server
        server = smtplib.SMTP(mx_record)
        server.set_debuglevel(0)
        server.helo()
        server.mail('test@example.com')  # Sender email
        code, message = server.rcpt(email)  # Recipient email
        server.quit()

        if code == 250:
            logger.info(f"SMTP validation passed for email: {email}")
            return {"status": "valid", "reason": "SMTP check passed."}
        else:
            logger.warning(f"SMTP error for email {email}: {message.decode()}")
            return {"status": "invalid", "reason": f"SMTP error: {message.decode()}"}
    except Exception as e:
        logger.error(f"SMTP validation failed for email {email}: {str(e)}")
        return {"status": "invalid", "reason": f"SMTP validation error: {str(e)}"}

def categorize_email(email):
    """Categorizes the email into valid, invalid, disposable, or accept-all."""
    try:
        domain = email.split('@')[1]
        # Check for disposable email domains first
        disposable_domains = ["mailinator.com", "10minutemail.com", "dispostable.com", "yopmail.com"]  # Added yopmail.com
        if domain in disposable_domains:
            logger.info(f"Disposable email domain detected: {email}")
            return {"status": "disposable", "email": email, "reason": "Disposable email domain."}

        # Check if domain is accept-all
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_record = str(mx_records[0].exchange)
            server = smtplib.SMTP(mx_record)
            server.set_debuglevel(0)
            server.helo()
            server.mail('test@example.com')
            code, _ = server.rcpt('test@' + domain)
            server.quit()

            if code == 250:
                logger.info(f"Accept-all domain detected: {email}")
                return {"status": "accept-all", "email": email, "reason": "Accept-all domain."}
        except Exception as e:
            logger.warning(f"SMTP check failed for {email}: {str(e)}")

        # If it passes both disposable and accept-all checks, it's valid
        logger.info(f"Valid email domain detected: {email}")
        return {"status": "valid", "email": email, "reason": "Valid email address."}

    except Exception as e:
        logger.error(f"Error categorizing email {email}: {str(e)}")

    logger.info(f"Unknown email status: {email}")
    return {"status": "unknown", "email": email, "reason": "Unable to categorize the email."}

@app.route('/validate', methods=['POST'])
@limiter.limit("10 per second")
def validate():
    """API endpoint to validate an email address."""
    data = request.json
    email = data.get("email")
    if not email:
        logger.error("Email is required in the request.")
        return jsonify({"error": "Email is required"}), 400

    # Step 1: Syntax and domain validation
    syntax_result = validate_email_address(email)
    if syntax_result['status'] != "valid":
        logger.info(f"Email validation failed: {email} - {syntax_result['reason']}")
        return jsonify(syntax_result)

    # Step 2: Categorize email
    category_result = categorize_email(email)
    logger.info(f"Email categorization result: {email} - {category_result['reason']}")
    return jsonify(category_result)

@app.route('/validate_bulk', methods=['POST'])
@limiter.limit("5 per second")
def validate_bulk():
    """API endpoint to validate multiple email addresses in bulk."""
    data = request.json
    emails = data.get("emails")
    if not emails or not isinstance(emails, list):
        logger.error("A list of emails is required.")
        return jsonify({"error": "A list of emails is required"}), 400

    results = {"valid": [], "invalid": [], "disposable": [], "accept-all": [], "unknown": []}
    for email in emails:
        # Add a small delay to avoid triggering rate limits or being flagged
        time.sleep(0.1)  # 100ms delay

        # Step 1: Syntax and domain validation
        syntax_result = validate_email_address(email)
        if syntax_result['status'] != "valid":
            logger.info(f"Bulk validation failed for {email}: {syntax_result['reason']}")
            results["invalid"].append({"email": email, "reason": syntax_result['reason']})
            continue

        # Step 2: Categorize email
        category_result = categorize_email(email)
        logger.info(f"Bulk validation result for {email}: {category_result['reason']}")
        results[category_result['status']].append({"email": category_result['email'], "reason": category_result['reason']})

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
