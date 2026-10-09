import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-safe-secret-key")

# Standard configuration via Environment Variables
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SENDER_NAME = os.environ.get("SENDER_NAME", "Support Team")

# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/send-transactional", methods=["POST"])
def send_transactional():
    data = request.get_json(silent=True) or {}
    
    recipient = str(data.get("recipient", "")).strip().lower()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    is_html = bool(data.get("is_html", False))

    # Basic Validation
    if not recipient or "@" not in recipient:
        return jsonify({"success": False, "message": "Valid recipient email is required."}), 400
    if not subject or not body:
        return jsonify({"success": False, "message": "Subject and body are required."}), 400
    if not SMTP_USER or not SMTP_PASS:
        return jsonify({"success": False, "message": "SMTP credentials not configured on server."}), 500

    try:
        # Construct RFC-compliant Email Message
        msg = MIMEMultipart("alternative")
        msg["From"] = formataddr((SENDER_NAME, SMTP_USER))
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        
        domain = SMTP_USER.split("@")[-1] if "@" in SMTP_USER else "domain.com"
        msg["Message-ID"] = make_msgid(domain=domain)

        content_type = "html" if is_html else "plain"
        msg.attach(MIMEText(body, content_type, "utf-8"))

        # Connect using SSL (Port 465)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient], msg.as_string())

        return jsonify({
            "success": True, 
            "message": "Email sent successfully to inbox.",
            "recipient": recipient
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({"success": False, "message": "SMTP Authentication failed. Check credentials."}), 401
    except Exception as exc:
        return jsonify({"success": False, "message": f"Server error: {str(exc)}"}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Transactional Mailer"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
