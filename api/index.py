from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, Response,
    stream_with_context
)
import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import random
import time
import html

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid, formatdate
from pathlib import Path

# Vercel Serverless Path Configuration
BASE_DIR = Path(__file__).resolve().parent.parent

templates_path = BASE_DIR / "templates"
static_path = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_path) if templates_path.exists() else "templates",
    static_folder=str(static_path) if static_path.exists() else "static",
    static_url_path="/static"
)

application = app
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-change-me")

# Batch limit reduced to stay within Vercel's 10-second timeout limit
MAX_RECIPIENTS = 15
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

def valid_email(value):
    if not value or not isinstance(value, str):
        return False
    return bool(EMAIL_RE.fullmatch(value.strip()))

def authenticated():
    return session.get("authenticated") is True

def strip_html_tags(html_text):
    """HTML content se plain text fallback banata hai taaki spam filters pass ho sakein."""
    if not html_text:
        return ""
    text = re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html_text, flags=re.IGNORECASE)
    text = re.sub(r'<script[^>]*>[\s\S]*?</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    return text.strip()

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")

def expand_spintax(text):
    if not text:
        return ""
    def replace_match(match):
        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]
        if not options:
            return ""
        return random.choice(options)
    
    prev = None
    while prev != text:
        prev = text
        text = SPINTAX_RE.sub(replace_match, text)
    return text

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return True, None

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed."
    except Exception:
        return True, None  # Prevent complete failure if turnstile API is slow

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        password = str(request.form.get("password", ""))
        configured_password = os.environ.get("LOGIN_PASSWORD", "admin123")

        if secrets.compare_digest(password, configured_password):
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
    if not authenticated():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", "")
    )

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required."}), 200

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip().replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "") or data.get("cf-turnstile-response", "")).strip()

    if not sender_name or not valid_email(gmail) or not app_password or not subject or not body.strip():
        return jsonify({"success": False, "message": "All fields are required and must be valid."}), 200

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 200

    clean_recipients = []
    for item in recipients:
        email = str(item).strip().lower()
        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 200

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    verified, verify_error = verify_turnstile(turnstile_token, client_ip)
    if not verified:
        return jsonify({"success": False, "message": verify_error}), 200

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0
        remaining = total

        yield json.dumps({
            "type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total
        }) + "\n"

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=10) as server:
                server.login(gmail, app_password)

                for index, recipient in enumerate(clean_recipients):
                    try:
                        final_subject = expand_spintax(subject)
                        final_body = expand_spintax(body)

                        domain = gmail.split("@")[-1] if "@" in gmail else "gmail.com"

                        if is_html:
                            message = MIMEMultipart("alternative")
