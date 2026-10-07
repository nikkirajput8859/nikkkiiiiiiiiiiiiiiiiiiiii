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

# =========================================================
# PATH & FLASK APP INITIALIZATION (Vercel & Local Supported)
# =========================================================

CURRENT_FILE = Path(__file__).resolve()
BASE_DIR = CURRENT_FILE.parent.parent if CURRENT_FILE.parent.name == "api" else CURRENT_FILE.parent

templates_folder = BASE_DIR / "templates"
static_folder = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_folder) if templates_folder.exists() else "templates",
    static_folder=str(static_folder) if static_folder.exists() else "static",
    static_url_path="/static"
)

# Vercel entrypoint handlers
application = app
handler = app

# Secret Key Configuration
app.secret_key = os.environ.get("SESSION_SECRET", "super-secret-key-change-this-in-production")

# Security & Limits Configuration
MAX_RECIPIENTS = 25
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

# Email RFC Validation Regex
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value: str) -> bool:
    """Validate email address format strictly."""
    if not value or not isinstance(value, str):
        return False
    return bool(EMAIL_RE.fullmatch(value.strip()))


def authenticated() -> bool:
    """Check if user session is authenticated."""
    return session.get("authenticated") is True


def strip_html_tags(html_text: str) -> str:
    """Convert HTML content into plain text fallback for email spam filters."""
    if not html_text:
        return ""
    text = re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html_text, flags=re.IGNORECASE)
    text = re.sub(r'<script[^>]*>[\s\S]*?</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    return text.strip()


# =========================================================
# SPINTAX PARSER ENGINE
# =========================================================

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")


def expand_spintax(text: str) -> str:
    """
    Parse spintax patterns like {Hello|Hi|Hey} recursively.
    Helpful in varying subject lines and body to pass spam filters.
    """
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

    # Perform recursive replacements for nested spintax
    previous_text = None
    while previous_text != text:
        previous_text = text
        text = SPINTAX_RE.sub(replace_match, text)

    return text


# =========================================================
# CLOUDFLARE TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token: str, remote_ip: str = None) -> tuple[bool, str]:
    """Verify Cloudflare Turnstile token with Cloudflare API."""
    if not TURNSTILE_SECRET_KEY:
        return True, None  # Bypass if secret key is not set in environment variables

    if not token:
        return False, "Cloudflare security verification token is missing."

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
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, None

        error_codes = result.get("error-codes", [])
        return False, f"Cloudflare verification failed: {', '.join(error_codes) if error_codes else 'Invalid Token'}"
    except Exception as exc:
        return False, f"Unable to reach Cloudflare verification server: {str(exc)}"


# =========================================================
# AUTHENTICATION ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        password = str(request.form.get("password", ""))
        configured_password = os.environ.get("LOGIN_PASSWORD", "admin123")

        if not configured_password:
            error = "LOGIN_PASSWORD is not configured on the server."
        elif secrets.compare_digest(password, configured_password):
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password. Please try again."

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


# =========================================================
# EMAIL BATCH STREAMING ENDPOINT (INBOX SAFE)
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required. Please login."}), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip().replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    # Form Validation Checks
    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400

    if not valid_email(gmail):
        return jsonify({"success": False, "message": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"success": False, "message": "Google App Password is required."}), 400

    if not subject:
        return jsonify({"success": False, "message": "Email subject is required."}), 400

    if not body.strip():
        return jsonify({"success": False, "message": "Message body cannot be empty."}), 400

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipients format."}), 400

    # Recipient Filtering and Deduplication
    clean_recipients = []
    for item in recipients:
        email = str(item).strip().lower()
        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipient email addresses found."}), 400

    # Verify Cloudflare Turnstile Captcha
    client_ip
