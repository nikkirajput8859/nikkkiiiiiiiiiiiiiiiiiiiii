from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session
)
import smtplib
import ssl
import re
import os
import json
import secrets
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid, formatdate
from pathlib import Path

# Base Path Setup
BASE_DIR = Path(__file__).resolve().parent.parent

templates_path = BASE_DIR / "templates"
static_path = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(templates_path) if templates_path.exists() else "templates",
    static_folder=str(static_path) if static_path.exists() else "static",
    static_url_path="/static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-12345")

MAX_RECIPIENTS = 15
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def valid_email(value):
    if not value or not isinstance(value, str):
        return False
    return bool(EMAIL_RE.fullmatch(value.strip()))


def authenticated():
    return session.get("authenticated") is True


SPINTAX_RE = re.compile(r"\{([^{}]+)\}")


def expand_spintax(text):
    if not text:
        return ""

    def replace_match(match):
        options = [opt.strip() for opt in match.group(1).split("|") if opt.strip()]
        return random.choice(options) if options else ""

    prev = None
    while prev != text:
        prev = text
        text = SPINTAX_RE.sub(replace_match, text)
    return text


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
    app_password = str(data.get("app_password", "")).strip().replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])

    if not sender_name or not valid_email(gmail) or not app_password or not subject or not body.strip():
        return jsonify({"success": False, "message": "Sabhi fields bharne zaruri hain."}), 400

    clean_recipients = []
    if isinstance(recipients, list):
        for item in recipients:
            email = str(item).strip().lower()
            if valid_email(email) and email not in clean_recipients:
                clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "Koi valid recipient email nahi milis."}), 400

    sent_count = 0
    failed_count = 0

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=8) as server:
            server.login(gmail, app_password)

            for recipient in clean_recipients:
                try:
                    final_subject = expand_spintax(subject)
                    final_body = expand_spintax(body)

                    if is_html:
                        message = MIMEMultipart("alternative")
                        message.attach(MIMEText(final_body, "html", "utf-8"))
                    else:
                        message = MIMEText(final_body, "plain", "utf-8")

                    domain = gmail.split("@")[-1] if "@" in gmail else "gmail.com"
                    message["Subject"] = final_subject
                    message["From"] = formataddr((sender_name, gmail))
                    message["To"] = recipient
                    message["Reply-To"] = gmail
                    message["Message-ID"] = make_msgid(domain=domain)
                    message["Date"] = formatdate(localtime=True)

                    server.sendmail(gmail, [recipient], message.as_string())
                    sent_count += 1
                except Exception:
                    failed_count += 1

        return jsonify({
            "success": True,
            "message": "Emails sent successfully.",
            "total": len(clean_recipients),
            "sent": sent_count,
            "failed": failed
