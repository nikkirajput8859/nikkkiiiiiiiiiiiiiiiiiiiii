import json
import os
import re
import secrets
import smtplib
import ssl
import time
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)

# =========================================================
# APP CONFIGURATION & PATH RESOLUTION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

templates_path = BASE_DIR / "templates"
static_path = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_path) if templates_path.exists() else "templates",
    static_folder=str(static_path) if static_path.exists() else "static",
    static_url_path="/static",
)

handler = app
application = app

# =========================================================
# ENVIRONMENT VARIABLES & SESSIONS
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip() or secrets.token_hex(32)
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip() or os.environ.get("ADMIN_PASSWORD", "admin123").strip()

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

# =========================================================
# MAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Preserved execution delay
SEND_DELAY_SECONDS = 1.8

# =========================================================
# VALIDATION & HELPER FUNCTIONS
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 254:
        return False
    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:max_length]


# =========================================================
# PERSONALIZATION & TEMPLATES
# =========================================================

def personalize_template(template, recipient):
    result = str(template or "")
    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(recipient.get("ref_code", "") or ""),
    }
    for placeholder, value in values.items():
        result = result.replace(placeholder, value)
    return result


def html_to_plain_text(html):
    text = str(html or "")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"</div\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.strip()


# =========================================================
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return True, None

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# =========================================================
# AUTH ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(request.form.get("password", ""))

    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 401

    session.clear()
