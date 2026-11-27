import os
import re
import ssl
import json
import hmac
import html
import time
import random
import string
import smtplib
import urllib.request
from pathlib import Path
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, Response
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app
application = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip() or "change-this-to-any-long-random-secret-1234567890"
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip() or "1234"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
FROM_EMAIL = os.environ.get("FROM_EMAIL", "").strip()

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)

SMTP_HOST, SMTP_PORT, SMTP_TIMEOUT = "smtp.gmail.com", 465, 30
MAX_RECIPIENTS = 25
MAX_WORKERS = 3
SEND_DELAY_RANGE = (0.35, 0.75)
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def clean(v, limit=250):
    return str(v or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def valid_email(v):
    return isinstance(v, str) and len(v.strip()) <= 254 and bool(EMAIL_RE.fullmatch(v.strip()))


def logged_in():
    return session.get("authenticated") is True


def error(msg, status=400):
    return jsonify({"success": False, "message": msg}), status


def event_line(d):
    return json.dumps(d, ensure_ascii=False) + "\n"


def html_to_text(v):
    v = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", v)
    v = re.sub(r"(?i)</\s*(p|div|li|h[1-6])\s*>", "\n", v)
    v = re.sub(r"<[^>]*>", " ", v)
    return re.sub(r"\n{3,}", "\n\n", html.unescape(v)).strip()


def generate_ref_code(length=8):
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(random.choices(alphabet, k=length))
    return f"REF-{suffix}"


def derive_name_from_email(address):
    local_part = address.split("@", 1)[0]
    cleaned = re.sub(r"[._-]+", " ", local_part).strip()
    return cleaned.title() if cleaned else "Member"


def normalize_recipient(item):
    if isinstance(item, str):
        item = {"email": item}
    if not isinstance(item, dict):
        return None
    addr = str(item.get("email", "")).strip().lower()
    if not valid_email(addr):
        return None

    provided_ref = clean(item.get("ref_code", ""), 40)
    ref_code = provided_ref if provided_ref else generate_ref_code()
    name = clean(item.get("name", ""), 150) or derive_name_from_email(addr)

    return {
        "email": addr,
        "name": name,
        "hi": clean(item.get("hi", ""), 150) or "Hi",
        "hello": clean(item.get("hello", ""), 150) or "Hello",
        "thanks": clean(item.get("thanks", ""), 150) or "Thanks",
        "ref_code": ref_code,
    }


def personalize(v, r):
    res = str(v or "")
    for k in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        res = res.replace("{{" + k + "}}", str(r.get(k, "")))
    return res


def build_personalized_content(body, is_html, r):
    rendered = personalize(body, r)
    ref_code = r["ref_code"]
    has_ref_placeholder = "{{ref_code}}" in str(body or "")

    if is_html:
        final_html = rendered
        if not has_ref_placeholder:
            footer_html = (
                f'<p style="margin-top:16px;font-size:12px;color:#64748b;">'
                f'Reference ID: <strong>{html.escape(ref_code)}</strong></p>'
            )
            final_html = f"{rendered}\n{footer_html}"
        plain_text = html_to_text(final_html) or f"Reference ID: {ref_code}"
        return plain_text, final_html

    final_text = rendered
    if not has_ref_placeholder:
        final_text = f"{rendered}\n\nReference ID: {ref_code}"
    return final_text, None


def send_via_resend(to_email, sender_name, subject, body, is_html, r):
    plain_text, html_body = build_personalized_content(body, is_html, r)
    payload = {
        "from": f"{clean(sender_name, 200)} <{FROM_EMAIL}>",
        "to": [to_email],
        "reply_to": FROM_EMAIL,
        "subject": clean(personalize(subject, r), 250),
        "text": plain_text,
        "headers": {"X-Ref-Code": r["ref_code"]},
    }
    if is_html and html_body:
        payload["html"] = html_body

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_gmail_batch(gmail, password, sender_name, subject, body, is_html, recipients):
    results = []
    ctx = ssl.create_default_context()
    clean_password = re.sub(r"\s+", "", password)
    domain_part = gmail.split("@", 1)[1] if "@" in gmail else "gmail.com"

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=SMTP_TIMEOUT) as smtp:
        smtp.ehlo()
        smtp.login(gmail, clean_password)

        for r in recipients:
            try:
                time.sleep(random.uniform(*SEND_DELAY_RANGE))
                plain_text, html_body = build_personalized_content(body, is_html, r)

                msg = EmailMessage()
                msg["Subject"] = clean(personalize(subject, r), 250)
                msg["From"] = formataddr((clean(sender_name, 200), gmail))
                msg["To"] = r["email"]
                msg["Reply-To"] = gmail
                msg["Date"] = formatdate(localtime=True)
                msg["Message-ID"] = make_msgid(domain=domain_part)
                msg["X-Ref-Code"] = r["ref_code"]

                if is_html and html_body:
                    msg.set_content(plain_text)
                    msg.add_alternative(html_body, subtype="html")
                else:
                    msg.set_content(plain_text)

                refused = smtp.send_message(msg, from_addr=gmail, to_addrs=[r["email"]])
                if refused:
                    results.append((r, False, "Recipient refused by SMTP server."))
                else:
                    results.append((r, True, None))
            except Exception as exc:
                results.append((r, False, str(exc)[:200]))

    return results


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
    return redirect(url_for("home"))


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
    mode = "Resend API" if RESEND_API_KEY and FROM_EMAIL else "Gmail SMTP"
    return jsonify({
        "status": "ok",
        "mode": mode,
        "max_recipients": MAX_RECIPIENTS,
        "workers": MAX_WORKERS,
    })


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
    gmail = clean(data.get("gmail", ""), 254).lower()
    password = str(data.get("app_password", "")).strip()
    subject = clean(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])
    use_resend = bool(RESEND_API_KEY and FROM_EMAIL)

    if not sender_name or not subject or not body.strip():
        return error("Sender name, subject and body are required.")
    if not use_resend and (not valid_email(gmail) or not gmail.endswith("@gmail.com") or not password):
        return error("Enter valid @gmail.com and App Password, or setup Resend in Vercel.")
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
        yield event_line({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "invalid_skipped": invalid,
        })

        try:
            if use_resend:
                with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as pool:
                    jobs = {
                        pool.submit(send_via_resend, r["email"], sender_name, subject, body, is_html, r): r
                        for r in recipients
                    }
                    for future in as_completed(jobs):
                        r = jobs[future]
                        try:
                            future.result()
                            sent += 1
                            item = {
                                "type": "progress",
                                "recipient": r["email"],
                                "ref_code": r["ref_code"],
                                "result": "sent",
                            }
                        except Exception as exc:
                            failed += 1
                            item = {
                                "type": "progress",
                                "recipient": r["email"],
                                "ref_code": r["ref_code"],
                                "result": "failed",
                                "error": str(exc)[:200],
                            }
                        item.update({
                            "total": total,
                            "sent": sent,
                            "failed": failed,
                            "remaining": total - sent - failed,
                        })
                        yield event_line(item)
            else:
                batch_results = send_gmail_batch(gmail, password, sender_name, subject, body, is_html, recipients)
                for r, ok, err_msg in batch_results:
                    if ok:
                        sent += 1
                        item = {
                            "type": "progress",
                            "recipient": r["email"],
                            "ref_code": r["ref_code"],
                            "result": "sent",
                        }
                    else:
                        failed += 1
                        item = {
                            "type": "progress",
                            "recipient": r["email"],
                            "ref_code": r["ref_code"],
                            "result": "failed",
                            "error": err_msg or "Failed to send.",
                        }
                    item.update({
                        "total": total,
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed,
                    })
                    yield event_line(item)
        except smtplib.SMTPAuthenticationError:
            yield event_line({
                "type": "error",
                "message": "Gmail authentication failed. Check your Gmail address and 16-character App Password.",
            })
            return
        except Exception as exc:
            yield event_line({"type": "error", "message": f"Error: {str(exc)[:200]}"})
            return

        yield event_line({
            "type": "complete",
            "success": failed == 0,
            "message": "Batch sending finished.",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
        })

    resp = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    resp.headers["Cache-Control"] = "no-store, no-cache, no-transform"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
