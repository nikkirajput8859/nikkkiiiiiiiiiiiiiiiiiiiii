import os
import re
import random
import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
import urllib.request
import urllib.parse
from flask import Flask, render_template, request, response_class, redirect, url_for, session

# Dynamic absolute path handling for Vercel Serverless environment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

if not os.path.exists(TEMPLATE_DIR):
    TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
if not os.path.exists(STATIC_DIR):
    STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "secure_mail_console_secret_key_2026")

APP_PASSWORD = os.environ.get("APP_PASSWORD", "admin123")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

def spin_text(text):
    if not text:
        return ""
    pattern = re.compile(r'\{([^{}]+)\}')
    while True:
        match = pattern.search(text)
        if not match:
            break
        options = match.group(1).split('|')
        replacement = random.choice(options)
        text = text[:match.start()] + replacement + text[match.end():]
    return text

def verify_turnstile(token, ip):
    if not TURNSTILE_SECRET_KEY:
        return True
    if not token:
        return False
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = urllib.parse.urlencode({
        'secret': TURNSTILE_SECRET_KEY,
        'response': token,
        'remoteip': ip
    }).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result.get('success', False)
    except Exception:
        return False

def strip_html(html):
    text = re.sub(r'<br\s*/?>', '\n', html, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return text.strip()

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if pwd == APP_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('index'))
        else:
            error = "Invalid password. Access denied."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('index.html', turnstile_site_key=TURNSTILE_SITE_KEY)

@app.route('/send-batch', methods=['POST'])
def send_batch():
    if not session.get('authenticated'):
        return json.dumps({"type": "error", "message": "Unauthorized"}), 401, {'Content-Type': 'application/json'}

    payload = request.get_json() or {}
    sender_name = payload.get('sender_name', '').strip()
    gmail = payload.get('gmail', '').strip()
    app_password = payload.get('app_password', '').strip()
    subject = payload.get('subject', '').strip()
    body = payload.get('body', '')
    is_html = payload.get('is_html', False)
    recipients = payload.get('recipients', [])
    turnstile_token = payload.get('turnstile_token', '')

    client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
    if TURNSTILE_SECRET_KEY and not verify_turnstile(turnstile_token, client_ip):
        return json.dumps({"type": "error", "message": "Cloudflare Turnstile verification failed."}), 400, {'Content-Type': 'application/json'}

    if not all([sender_name, gmail, app_password, subject, body, recipients]):
        return json.dumps({"type": "error", "message": "All fields are required."}), 400, {'Content-Type': 'application/json'}

    def generate_events():
        total = len(recipients)
        sent = 0
        failed = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}) + "\n"

        server = None
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=12)
            server.login(gmail, app_password)
        except Exception as e:
            yield json.dumps({"type": "error", "message": f"SMTP Authentication failed: {str(e)}", "total": total, "sent": 0, "failed": total, "remaining": 0}) + "\n"
            return

        for index, recipient in enumerate(recipients):
            try:
                msg = MIMEMultipart('alternative')
                curr_subject = spin_text(subject)
                curr_body = spin_text(body)

                msg['From'] = f"{sender_name} <{gmail}>"
                msg['To'] = recipient
                msg['Subject'] = curr_subject
                msg['Date'] = formatdate(localtime=True)
                msg['Message-ID'] = make_msgid(domain=gmail.split('@')[-1] if '@' in gmail else 'gmail.com')
                msg['X-Mailer'] = 'SecureMailConsole/2.0'

                if is_html:
                    plain_fallback = strip_html(curr_body)
                    msg.attach(MIMEText(plain_fallback, 'plain', 'utf-8'))
                    msg.attach(MIMEText(curr_body, 'html', 'utf-8'))
                else:
                    msg.attach(MIMEText(curr_body, 'plain', 'utf-8'))

                server.send_message(msg)
                sent += 1
            except Exception:
                failed += 1

            remaining = total - (sent + failed)
            yield json.dumps({"type": "progress", "total": total, "sent": sent, "failed": failed, "remaining": remaining}) + "\n"

            if index < total - 1:
                time.sleep(random.uniform(1.0, 2.0))

        try:
            server.quit()
        except Exception:
            pass

        yield json.dumps({"type": "complete", "total": total, "sent": sent, "failed": failed, "remaining": 0, "message": "All emails processed successfully."}) + "\n"

    return response_class(generate_events(), mimetype='application/x-ndjson')

if __name__ == '__main__':
    app.run(debug=True)
