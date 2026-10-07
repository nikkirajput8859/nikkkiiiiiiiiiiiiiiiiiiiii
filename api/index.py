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

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid, formatdate
from pathlib import Path

# Safe path handling for Vercel Serverless environment
BASE_DIR = Path(__file__).resolve().parent.parent

templates_path = BASE_DIR / "templates"
static_path = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_path) if templates_path.exists() else "templates",
    static_folder=str(static_path) if static_path.exists() else "static",
    static_url_path="/static"
)

# Vercel entry point definitions (Fixes Vercel build error)
application = app
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-change-me")

MAX_RECIPIENTS = 25
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

def valid_email(value):
    return bool(EMAIL_RE.fullmatch(value.strip()))

def authenticated():
    return session.get("authenticated") is True

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")

def expand_spintax(text):
    def replace_match(match):
        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]
        if len(options) < 2:
            return match.group(0)
        return random.choice(options)
    return SPINTAX_RE.sub(replace_match, text)

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
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed."
    except Exception:
        return False, "Unable to verify Cloudflare."

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
        return jsonify({"success": False, "message": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name or not valid_email(gmail) or not app_password or not subject or not body.strip():
        return jsonify({"success": False, "message": "All fields are required and must be valid."}), 400

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    clean_recipients = []
    for item in recipients:
        email = str(item).strip().lower()
        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get("X-Forwarded-For", request.remote_addr)
    )

    if not verified:
        return jsonify({"success": False, "message": verify_error}), 403

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
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=15) as server:
                server.login(gmail, app_password)

                for index, recipient in enumerate(clean_recipients):
                    try:
                        final_subject = expand_spintax(subject)
                        final_body = expand_spintax(body)

                        message = MIMEMultipart("alternative") if is_html else MIMEText(final_body, "plain", "utf-8")
                        message["Subject"] = final_subject
                        message["From"] = formataddr((sender_name, gmail))
                        message["To"] = recipient
                        
                        message["Message-ID"] = make_msgid(domain=gmail.split('@')[1])
                        message["Date"] = formatdate(localtime=True)
                        message["Reply-To"] = gmail

                        if is_html:
                            part1 = MIMEText("Please view this email in an HTML compatible client.", "plain", "utf-8")
                            part2 = MIMEText(final_body, "html", "utf-8")
                            message.attach(part1)
                            message.attach(part2)

                        server.sendmail(gmail, [recipient], message.as_string())

                        sent_count += 1
                        remaining -= 1

                        yield json.dumps({
                            "type": "progress", "email": recipient, "result": "sent",
                            "total": total, "sent": sent_count, "failed": failed_count, "remaining": remaining
                        }) + "\n"

                        if index < len(clean_recipients) - 1:
                            time.sleep(random.uniform(1.5, 3.5))

                    except Exception as exc:
                        failed_count += 1
                        remaining -= 1
                        yield json.dumps({
                            "type": "progress", "email": recipient, "result": "failed", "error": str(exc),
                            "total": total, "sent": sent_count, "failed": failed_count, "remaining": remaining
                        }) + "\n"

        except smtplib.SMTPAuthenticationError:
            yield json.dumps({"type": "error", "message": "Gmail authentication failed. Check App Password."}) + "\n"
            return
        except Exception as exc:
            yield json.dumps({"type": "error", "message": f"Server error: {str(exc)}"}) + "\n"
            return

        yield json.dumps({
            "type": "complete", "success": True, "message": "Sending complete.",
            "total": total, "sent": sent_count, "failed": failed_count, "remaining": remaining
        }) + "\n"

    return Response(generate(), content_type="application/x-ndjson; charset=utf-8", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Secure Mail Console"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
