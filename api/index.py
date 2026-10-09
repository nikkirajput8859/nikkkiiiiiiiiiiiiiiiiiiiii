import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# Root directory path definition for Vercel
BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-safe-secret-key")

# Standard configuration via Environment Variables
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SENDER_NAME = os.environ.get("SENDER_NAME", "Support Team")

# Authentication Check Helper
def is_authenticated():
    return session.get("authenticated") is True

# =========================================================
# ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        password = str(request.form.get("password", ""))
        configured_password = os.environ.get("LOGIN_PASSWORD", "")

        if not configured_password:
            error = "LOGIN_PASSWORD environment variable is not configured."
        elif password == configured_password:
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not is_authenticated():
        return redirect(url_for("login"))

    return render_template("index.html")

@app.route("/send-transactional", methods=["POST"])
def send_transactional():
    if not is_authenticated():
        return jsonify({"success": False, "message": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    recipient = str(data.get("recipient", "")).strip().lower()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    is_html = bool(data.get("is_html", False))

    if not recipient or "@" not in recipient:
        return jsonify({"success": False, "message": "Valid recipient email is required."}), 400
    if not subject or not body:
        return jsonify({"success": False, "message": "Subject and body are required."}), 400
    if not SMTP_USER or not SMTP_PASS:
        return jsonify({"success": False, "message": "SMTP credentials not configured on server."}), 500

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = formataddr((SENDER_NAME, SMTP_USER))
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        
        domain = SMTP_USER.split("@")[-1] if "@" in SMTP_USER else "domain.com"
        msg["Message-ID"] = make_msgid(domain=domain)

        content_type = "html" if is_html else "plain"
        msg.attach(MIMEText(body, content_type, "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [recipient], msg.as_string())

        return jsonify({
            "success": True, 
            "message": "Email dispatched successfully.",
            "recipient": recipient
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({"success": False, "message": "SMTP Authentication failed. Check credentials."}), 401
    except Exception as exc:
        return jsonify({"success": False, "message": f"Server error: {str(exc)}"}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Flask Mailer"})

# WSGI export for Vercel
app_obj = app
