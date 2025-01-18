from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError
import logging
from flask import Flask, request, jsonify

# Flask App Setup
app = Flask(__name__)

# Logger Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Caching for DNS and Results
dns_cache = {}

def validate_email_syntax(email):
    """Validate email syntax."""
    try:
        result = validate_email(email)
        return {"status": "valid", "email": result["email"], "reason": "Valid syntax."}
    except EmailNotValidError as e:
        return {"status": "invalid", "email": email, "reason": str(e)}

def check_disposable(email):
    """Check if the email belongs to a disposable domain."""
    disposable_domains = {"mailinator.com", "10minutemail.com", "yopmail.com", "dispostable.com"}
    domain = email.split('@')[1]
    if domain in disposable_domains:
        return {"status": "disposable", "email": email, "reason": "Disposable email domain."}
    return None

def check_domain_mx(domain):
    """Check if the domain has valid MX records."""
    if domain in dns_cache:
        return dns_cache[domain]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
        dns_cache[domain] = mx_host
        return mx_host
    except Exception as e:
        dns_cache[domain] = None
        logger.warning(f"MX record lookup failed for {domain}: {str(e)}")
        return None

def smtp_check(email, mx_host):
    """Perform SMTP validation for the email."""
    try:
        server = smtplib.SMTP(mx_host, timeout=5)
        server.helo()
        server.mail('test@example.com')
        code, message = server.rcpt(email)
        server.quit()

        if code == 250:
            return {
                "status": "valid",
                "email": email,
                "reason": "SMTP validation successful.",
                "message": message.decode()  # Decode the SMTP server's response
            }
        return {
            "status": "invalid",
            "email": email,
            "reason": "SMTP validation failed.",
            "message": message.decode()  # Decode the SMTP server's response
        }
    except Exception as e:
        logger.warning(f"SMTP validation error for {email}: {str(e)}")
        return {
            "status": "unknown",
            "email": email,
            "reason": "SMTP validation error.",
            "message": str(e)  # Include the exception message
        }

def validate_single_email(email):
    """Validate a single email."""
    syntax_result = validate_email_syntax(email)
    if syntax_result["status"] != "valid":
        return syntax_result

    disposable_result = check_disposable(email)
    if disposable_result:
        return disposable_result

    domain = email.split('@')[1]
    mx_host = check_domain_mx(domain)
    if not mx_host:
        return {"status": "invalid", "email": email, "reason": "No MX records found.", "message": "Domain has no MX records."}

    smtp_result = smtp_check(email, mx_host)
    return smtp_result

@app.route('/validate_bulk', methods=['POST'])
def validate_bulk():
    """Bulk email validation endpoint."""
    data = request.json
    emails = data.get("emails")
    if not emails or not isinstance(emails, list):
        return jsonify({"error": "A list of emails is required"}), 400

    results = {"valid": [], "invalid": [], "disposable": [], "unknown": []}

    # Use ThreadPoolExecutor for parallel validation
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_email = {executor.submit(validate_single_email, email): email for email in emails}
        for future in as_completed(future_to_email):
            email = future_to_email[future]
            try:
                result = future.result()
                logger.info(f"Validation result for {email}: {result}")
                results[result["status"]].append(result)
            except Exception as e:
                logger.error(f"Error validating email {email}: {str(e)}")
                results["unknown"].append({"email": email, "reason": "Validation error.", "message": str(e)})

    return jsonify(results)

@app.route('/validate', methods=['POST'])
def validate_single():
    """Validate a single email."""
    data = request.json
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    result = validate_single_email(email)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
