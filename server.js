const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const GATE_PASSWORD = process.env.GATE_PASSWORD || 'admin123';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || '';

// Rate limiter for authentication
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login attempts. Try again later.' }
});

app.post('/api/auth', loginLimiter, (req, res) => {
    const { password } = req.body;
    if (password === GATE_PASSWORD) {
        return res.json({ success: true, token: Buffer.from(GATE_PASSWORD).toString('base64') });
    }
    return res.status(401).json({ success: false, message: 'Incorrect password' });
});

// Helper functions for safe parsing & spintax
function parseSpintax(text) {
    if (!text) return '';
    let spun = String(text);
    const regex = /\{([^{}]+)\}/g;
    while (regex.test(spun)) {
        spun = spun.replace(regex, (match, choices) => {
            const options = choices.split('|');
            return options[Math.floor(Math.random() * options.length)];
        });
    }
    return spun;
}

function stripHtml(html) {
    if (!html) return '';
    return html.replace(/<[^>]*>?/gm, '').replace(/\s+/g, ' ').trim();
}

function extractCleanEmail(input) {
    if (!input) return '';
    const match = String(input).match(/<([^>]+)>/);
    const email = match ? match[1] : input;
    return email.trim().toLowerCase();
}

async function verifyTurnstile(token) {
    if (!TURNSTILE_SECRET || TURNSTILE_SECRET.startsWith('1x00000000')) return true;
    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token)}`
        });
        const data = await response.json();
        return data.success;
    } catch (e) {
        return false;
    }
}

app.post('/api/send-stream', async (req, res) => {
    const { senderName, email, appPassword, subject, body, recipients, cfToken, authToken } = req.body;

    // Authentication Check
    if (authToken !== Buffer.from(GATE_PASSWORD).toString('base64')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // Turnstile Check
    const isHuman = await verifyTurnstile(cfToken);
    if (!isHuman) {
        return res.status(400).json({ error: 'Captcha validation failed' });
    }

    if (!email || !appPassword || !recipients || !Array.isArray(recipients) || recipients.length === 0) {
        return res.status(400).json({ error: 'Missing required parameters' });
    }

    const cleanSenderEmail = extractCleanEmail(email);
    const safeSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
    const cleanAppPassword = appPassword.replace(/\s+/g, '').trim();

    // SSE Headers Setup
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');

    let isClientConnected = true;
    req.on('close', () => {
        isClientConnected = false;
    });

    const sendSSE = (data) => {
        if (isClientConnected) {
            res.write(`data: ${JSON.stringify(data)}\n\n`);
        }
    };

    // Nodemailer Connection Pool (6 Parallel Connections)
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // STARTTLS safe handshake
        requireTLS: true,
        pool: true,
        maxConnections: 6, // 6 parallel connections pool
        maxMessages: Infinity,
        auth: {
            user: cleanSenderEmail,
            pass: cleanAppPassword
        }
    });

    try {
        await transporter.verify();
    } catch (error) {
        sendSSE({ type: 'fatal_error', message: 'SMTP Auth Failed. Check Gmail & App Password.' });
        return res.end();
    }

    const total = recipients.length;
    let sentCount = 0;
    let failedCount = 0;

    sendSSE({ type: 'start', total });

    const BATCH_SIZE = 6; // एक साथ 6 ईमेल सेंड करने की स्पीड

    for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
        if (!isClientConnected) break;

        const batch = recipients.slice(i, i + BATCH_SIZE);

        const batchPromises = batch.map(async (recipientRaw) => {
            const recipientEmail = extractCleanEmail(recipientRaw);
            if (!recipientEmail) return null;

            const dynamicSubject = parseSpintax(subject);
            const dynamicBody = parseSpintax(body);

            // INLINE WRAPPER WITH EXACT FONT SIZE 10pt (NO REF ID)
            const formattedHtml = `
                <div style="font-family: Arial, Helvetica, sans-serif; font-size: 10pt; line-height: 1.4; color: #222222; -webkit-text-size-adjust: none; -ms-text-size-adjust: 100%;">
                    <!-- Main Body Container (Font Size 10pt) -->
                    <div style="font-family: Arial, Helvetica, sans-serif; font-size: 10pt; line-height: 1.4; color: #222222;">
                        ${dynamicBody}
                    </div>
                </div>
            `;

            const plainText = stripHtml(dynamicBody);

            const mailOptions = {
                from: safeSenderName ? `"${safeSenderName}" <${cleanSenderEmail}>` : cleanSenderEmail,
                to: recipientEmail,
                replyTo: cleanSenderEmail,
                subject: dynamicSubject || 'No Subject',
                text: plainText,
                html: formattedHtml
            };

            try {
                await transporter.sendMail(mailOptions);
                return { recipient: recipientEmail, success: true };
            } catch (err) {
                return { recipient: recipientEmail, success: false, error: err.message };
            }
        });

        // 6 पैरेलल ईमेल निष्पादित करें
        const results = await Promise.all(batchPromises);

        results.forEach((resResult) => {
            if (!resResult) return;

            if (resResult.success) {
                sentCount++;
                sendSSE({ type: 'progress', status: 'sent', recipient: resResult.recipient, sentCount, failedCount });
            } else {
                failedCount++;
                sendSSE({ type: 'progress', status: 'failed', recipient: resResult.recipient, error: resResult.error, sentCount, failedCount });
            }
        });

        // 6 ईमेल भेजने के बाद 1 से 2 सेकंड (1000ms - 2000ms) का डायनामिक रैंडम डिले
        if (i + BATCH_SIZE < recipients.length && isClientConnected) {
            const randomDelay = Math.floor(Math.random() * 1000) + 1000;
            await new Promise((resolve) => setTimeout(resolve, randomDelay));
        }
    }

    transporter.close();
    sendSSE({ type: 'complete', sentCount, failedCount, total });
    res.end();
});

app.listen(PORT, () => {
    console.log(`Server running safely on port ${PORT}`);
});
