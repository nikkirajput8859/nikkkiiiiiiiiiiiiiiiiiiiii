import os
import re
import json
import time
import random
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, Response, session, redirect, url_for, stream_with_context

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super_secret_key_123")

# Cloudflare Turnstile Keys (अपनी Keys यहाँ डालें या Environment Variable का उपयोग करें)
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "YOUR_TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "YOUR_TURNSTILE_SECRET_KEY")


def parse_spintax(text):
    """
    Spintax parser: {hi|hello|hey} जैसे फॉर्मेट को रैंडमली रिप्लेस करता है।
    """
    if not text:
        return ""
    pattern = r'\{([^{}]*)\}'
    while re.search(pattern, text):
        text = re.sub(pattern, lambda m: random.choice(m.group(1).split('|')), text)
    return text


def verify_turnstile(token, remote_ip=None):
    """
    Cloudflare Turnstile token को वैलिडेट करने के लिए फ़ंक्शन।
    """
    if not TURNSTILE_SECRET_KEY or TURNSTILE_SECRET_KEY == "YOUR_TURNSTILE_SECRET_KEY":
        return True  # यदि Turnstile सेट नहीं है तो स्किप करें

    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        return result.get("success", False)
    except Exception:
        return False


@app.route('/')
def index():
    return render_template('index.html', turnstile_site_key=TURNSTILE_SITE_KEY)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/send-batch', methods=['POST'])
def send_batch():
    data = request.get_json() or {}

    sender_name = data.get("sender_name", "").strip()
    gmail = data.get("gmail", "").strip()
    app_password = data.get("app_password", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")
    is_html = data.get("is_html", False)
    recipients = data.get("recipients", [])
    turnstile_token = data.get("turnstile_token", "")

    @stream_with_context
    def generate():
        # 1. Validation
        if not sender_name or not gmail or not app_password or not subject or not body or not recipients:
            yield json.dumps({
                "type": "error",
                "message": "सभी आवश्यक फ़ील्ड भरें।",
                "total": len(recipients),
                "sent": 0,
                "failed": len(recipients),
                "remaining": 0
            }) + "\n"
            return

        # 2. Turnstile Verification
        if TURNSTILE_SECRET_KEY and TURNSTILE_SECRET_KEY != "YOUR_TURNSTILE_SECRET_KEY":
            if not verify_turnstile(turnstile_token, request.remote_addr):
                yield json.dumps({
                    "type": "error",
                    "message": "Cloudflare सुरक्षा सत्यापन विफल रहा।",
                    "total": len(recipients),
                    "sent": 0,
                    "failed": len(recipients),
                    "remaining": 0
                }) + "\n"
                return

        total = len(recipients)
        sent = 0
        failed = 0
        remaining = total

        # Start Event
        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": remaining
        }) + "\n"

        # 3. Process & Send Emails
        for recipient in recipients:
            try:
                # Spintax apply करें
                final_subject = parse_spintax(subject)
                final_body = parse_spintax(body)

                # Email Object तैयार करें
                msg = MIMEMultipart()
                msg['From'] = f"{sender_name} <{gmail}>"
                msg['To'] = recipient
                msg['Subject'] = final_subject

                mime_type = 'html' if is_html else 'plain'
                msg.attach(MIMEText(final_body, mime_type, 'utf-8'))

                # SMTP Gmail सेंडिंग
                with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as server:
                    server.starttls()
                    server.login(gmail, app_password)
                    server.send_message(msg)

                sent += 1
            except Exception as e:
                failed += 1

            remaining = total - (sent + failed)

            # Progress Event
            yield json.dumps({
                "type": "progress",
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": remaining
            }) + "\n"

            # Spam Prevention delay (1 second)
            time.sleep(1)

        # Complete Event
        yield json.dumps({
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
            "message": "ईमेल भेजने की प्रक्रिया पूरी हो गई है।"
        }) + "\n"

    return Response(generate(), mimetype='application/x-ndjson')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
