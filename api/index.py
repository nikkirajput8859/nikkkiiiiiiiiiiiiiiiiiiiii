import os
import re
import json
import hmac
import html
import time
from pathlib import Path
from datetime import timedelta
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, Response
import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app
application = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
FROM_EMAIL = os.environ.get("FROM_EMAIL", "").strip()  # jaise hello@tumharadomain.com

if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set SESSION_SECRET to a random value of at least 32 characters.")
if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")
if not RESEND_API_KEY:
    raise RuntimeError("Set RESEND_API_KEY in Vercel.")
if not FROM_EMAIL:
    raise RuntimeError("Set FROM_EMAIL in Vercel. Example: hello@yourdomain.com")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)

MAX_RECIPIENTS = 25
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")

def clean(value, limit=250):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]

def valid_email(value):
    return isinstance(value, str) and len(value.strip()) <= 254 and bool(EMAIL_RE.fullmatch(value.strip()))

def logged_in():
    return session.get("authenticated") is True

def error(message, status=400):
    return jsonify({"success": False, "message": message}), status

def event_line(data):
    return json.dumps(data, ensure_ascii=False) + "\n"

def html_to_text(value):
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]*>", " ", value)
    return re.sub(r"\n{3,}", "\n\n", html.unescape(value)).strip()

def normalize_recipient(item):
    if isinstance(item, str):
        item = {"email": item}
    if not isinstance(item, dict):
        return None
    address = str(item.get("email", "")).strip().lower()
    if not valid_email(address):
        return None
    return {
        "email": address,
        **{k: clean(item.get(k, ""), 150) for k in ("name", "hi", "hello", "thanks", "ref_code")},
    }

def personalize(value, recipient):
    result = str(value or "")
    for key in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        result = result.replace("{{" + key + "}}", recipient.get(key, ""))
    return result

def send_via_resend(to_email, sender_name, subject, body, is_html, recipient):
    # Resend Batch API - SPF/DKIM/DMARC auto pass hota hai
    payload = {
        "from": f"{sender_name} <{FROM_EMAIL}>",
        "to": [to_email],
        "reply_to": FROM_EMAIL,
        "subject": clean(personalize(subject, recipient), 250),
        "html": personalize(body, recipient) if is_html else None,
        "text": html_to_text(personalize(body, recipient)) if is_html else personalize(body, recipient),
        "headers": {
            "List-Unsubscribe": f"<mailto:{FROM_EMAIL}?subject=unsubscribe>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None)
    if not hmac.compare_digest(str(request.form.get("password", "")), LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password."), 401
    session.clear()
    session.permanent = True
    session["authenticated"] = True
    return redirect(url_for("login"))

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "smtp": "Resend API - INBOX MODE", "max_recipients": MAX_RECIPIENTS, "from": FROM_EMAIL})

@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)

@app.route("/sw.js")
def sw():
    return Response("", mimetype="application/javascript")

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({"success": False, "message": "Please log in again.", "login_required": True}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Invalid JSON request.")

    sender_name = clean(data.get("sender_name", ""))
    subject = clean(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

    if not sender_name:
        return error("Enter a sender name.")
    if not subject or not body.strip():
        return error("Subject and body are required.")
    if len(body) > 100_000:
        return error("Email body is too large.")
    if not isinstance(incoming, list):
        return error("Recipients must be a list.")
    if data.get("consent_confirmed") is not True:
        return error("Confirm recipients have permission to receive this email.")

    recipients, seen, invalid = [], set(), 0
    for item in incoming:
        r = normalize_recipient(item)
        if not r:
            invalid += 1
        elif r["email"] not in seen:
            seen.add(r["email"])
            recipients.append(r)

    if not recipients:
        return error("No valid recipients found.")
    if len(recipients) > MAX_RECIPIENTS:
        return error(f"Maximum {MAX_RECIPIENTS} unique recipients per batch.")

    def generate():
        total, sent, failed = len(recipients), 0, 0
        yield event_line({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total, "invalid_skipped": invalid})
        # Resend Batch - 25 mail ek sath, fast
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=5) as pool:
            jobs = {pool.submit(send_via_resend, r["email"], sender_name, subject, body, is_html, r): r for r in recipients}
            for future in as_completed(jobs):
                r = jobs[future]
                try:
                    future.result()
                    sent += 1
                    item = {"type": "progress", "recipient": r["email"], "result": "sent"}
                except Exception as exc:
                    failed += 1
                    item = {"type": "progress", "recipient": r["email"], "result": "failed", "error": str(exc)[:200]}
                item.update({"total": total, "sent": sent, "failed": failed, "remaining": total - sent - failed})
                yield event_line(item)
        yield event_line({"type": "complete", "success": failed == 0, "message": "Batch sending finished.", "total": total, "sent": sent, "failed": failed, "remaining": 0})

    response = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    response.headers["Cache-Control"] = "no-store, no-cache, no-transform"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
