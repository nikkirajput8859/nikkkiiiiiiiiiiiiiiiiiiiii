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
# PATH & FLASK APP INITIALIZATION
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

application = app
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "super-secret-key-change-this")

MAX_RECIPIENTS = 25
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    return bool(EMAIL_RE.fullmatch(value.strip()))


def authenticated() -> bool:
    return session.get("authenticated") is True


def strip_html_tags(html_text: str) -> str:
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

    previous_text = None
    while previous_text != text:
        previous_text = text
        text = SPINTAX_RE.sub(replace_match, text)

    return text


# =========================================================
# CLOUDFLARE TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token: str, remote_ip: str = None) -> tuple[bool, str]:
    if not TURNSTILE_SECRET_KEY:
        return True, None

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
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."
    except Exception:
        return True, None  # Fallback to prevent blocking if Turnstile API times out


# =========================================================
# ROUTES
# =========================================================

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


# =========================================================
# EMAIL BATCH STREAMING ENDPOINT (INBOX SAFE & VERCEL FIXED)
# =========================================================

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

    # Pre-validation checks
    validation_error = None
    if not sender_name:
        validation_error = "Sender Name is required."
    elif not valid_email(gmail):
        validation_error = "Enter a valid Gmail address."
    elif not app_password:
        validation_error = "Google App Password is required."
    elif not subject:
        validation_error = "Email subject is required."
    elif not body.strip():
        validation_error = "Message body is required."

    clean_recipients = []
    if isinstance(recipients, list):
        for item in recipients:
            email = str(item).strip().lower()
            if valid_email(email) and email not in clean_recipients:
                clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not validation_error and not clean_recipients:
        validation_error = "No valid recipient email address provided."

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    verified, verify_err = verify_turnstile(turnstile_token, client_ip)
    if not verified and not validation_error:
        validation_error = verify_err

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        
        # If pre-validation failed, yield error event and stop
        if validation_error:
            yield json.dumps({
                "type": "error",
                "message": validation_error,
                "total": total,
                "sent": 0,
                "failed": 0,
                "remaining": total
            }) + "\n"
            return

        sent_count = 0
        failed_count = 0
        remaining = total

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total
        }) + "\n"

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=12) as server:
                server.login(gmail, app_password)

                for index, recipient in enumerate(clean_recipients):
                    try:
                        final_subject = expand_spintax(subject)
                        final_body = expand_spintax(body)

                        if is_html:
                            message = MIMEMultipart("alternative")
                            plain_text_fallback = strip_html_tags(final_body)
                            
                            part_plain = MIMEText(plain_text_fallback, "plain", "utf-8")
                            part_html = MIMEText(final_body, "html", "utf-8")
                            
                            message.attach(part_plain)
                            message.attach(part_html)
                        else:
                            message = MIMEText(final_body, "plain", "utf-8")

                        domain = gmail.split("@")[-1] if "@" in gmail else "gmail.com"
                        
                        message["Subject"] = final_subject
                        message["From"] = formataddr((sender_name, gmail))
                        message["To"] = recipient
                        message["Reply-To"] = gmail
                        message["Message-ID"] = make_msgid(domain=domain)
                        message["Date"] = formatdate(localtime=True)
                        message["X-Mailer"] = "Secure Mail Console v2.0"
                        message["MIME-Version"] = "1.0"

                        server.sendmail(gmail, [recipient], message.as_string())

                        sent_count += 1
                        remaining -= 1

                        yield json.dumps({
                            "type": "progress",
                            "email": recipient,
                            "result": "sent",
                            "total": total,
                            "sent": sent_count,
                            "failed": failed_count,
                            "remaining": remaining
                        }) + "\n"

                        # Optimized delay to prevent Vercel Serverless Function Timeout
                        if index < len(clean_recipients) - 1:
                            time.sleep(1.0)

                    except Exception as send_err:
                        failed_count += 1
                        remaining -= 1

                        yield json.dumps({
                            "type": "progress",
                            "email": recipient,
                            "result": "failed",
                            "error": str(send_err),
                            "total": total,
                            "sent": sent_count,
                            "failed": failed_count,
                            "remaining": remaining
                        }) + "\n"

        except smtplib.SMTPAuthenticationError:
            yield json.dumps({
                "type": "error",
                "message": "Gmail authentication failed. Check App Password.",
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": remaining
            }) + "\n"
            return

        except Exception as conn_err:
            yield json.dumps({
                "type": "error",
                "message": f"SMTP Connection error: {str(conn_err)}",
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": remaining
            }) + "\n"
            return

        yield json.dumps({
            "type": "complete",
            "success": True,
            "message": "Batch process complete.",
            "total": total,
            "sent": sent_count,
            "failed": failed_count,
            "remaining": remaining
        }) + "\n"

    return Response(
        generate(),
        status=200,
        content_type="application/x-ndjson; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Secure Mail Console"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
