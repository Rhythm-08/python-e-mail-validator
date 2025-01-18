from flask import Flask, request, jsonify
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import smtplib
import time
from functools import lru_cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

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
            return {"status": "invalid", "reason": "No MX records found for the domain."}

        return {"status": "valid", "email": email}
    except EmailNotValidError as e:
        return {"status": "invalid", "reason": str(e)}
    except dns.resolver.NXDOMAIN:
        return {"status": "invalid", "reason": "Domain does not exist."}
    except Exception as e:
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
            return {"status": "valid"}
        else:
            return {"status": "invalid", "reason": message.decode()}
    except Exception as e:
        return {"status": "invalid", "reason": f"SMTP validation error: {str(e)}"}

def categorize_email(email):
    """Categorizes the email into valid, invalid, disposable, or accept-all."""
    try:
        domain = email.split('@')[1]
        # Check for disposable email domains
        disposable_domains = ["mailinator.com", "10minutemail.com", "dispostable.com"]  # Extend this list
        if domain in disposable_domains:
            return {"status": "disposable", "email": email}

        # Check if domain is accept-all
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        server = smtplib.SMTP(mx_record)
        server.helo()
        server.mail('test@example.com')
        code, _ = server.rcpt('test@' + domain)
        server.quit()

        if code == 250:
            return {"status": "accept-all", "email": email}
    except Exception:
        pass

    return {"status": "unknown", "email": email}

@app.route('/validate', methods=['POST'])
@limiter.limit("10 per second")
def validate():
    """API endpoint to validate an email address."""
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Step 1: Syntax and domain validation
    syntax_result = validate_email_address(email)
    if syntax_result['status'] != "valid":
        return jsonify(syntax_result)

    # Step 2: Categorize email
    category_result = categorize_email(email)
    return jsonify(category_result)

@app.route('/validate_bulk', methods=['POST'])
@limiter.limit("5 per second")
def validate_bulk():
    """API endpoint to validate multiple email addresses in bulk."""
    data = request.json
    emails = data.get("emails")
    if not emails or not isinstance(emails, list):
        return jsonify({"error": "A list of emails is required"}), 400

    results = {"valid": [], "invalid": [], "disposable": [], "accept-all": [], "unknown": []}
    for email in emails:
        # Add a small delay to avoid triggering rate limits or being flagged
        time.sleep(0.1)  # 100ms delay

        # Step 1: Syntax and domain validation
        syntax_result = validate_email_address(email)
        if syntax_result['status'] != "valid":
            results["invalid"].append({"email": email, "reason": syntax_result['reason']})
            continue

        # Step 2: Categorize email
        category_result = categorize_email(email)
        results[category_result['status']].append(category_result)

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
