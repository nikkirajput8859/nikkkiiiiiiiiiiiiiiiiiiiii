const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const GATE_PASSWORD = process.env.GATE_PASSWORD || 'admin123';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || '';

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

function parseSpintax(text) {
    if (!text) return '';
    return text.replace(/\{([^{}]+)\}/g, (match, choices) => {
        const options = choices.split('|');
        return options[Math.floor(Math.random() * options.length)];
    });
}

function stripHtml(html) {
    return html.replace(/<[^>]*>?/gm, '').replace(/\s+/g, ' ').trim();
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

    if (authToken !== Buffer.from(GATE_PASSWORD).toString('base64')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const isHuman = await verifyTurnstile(cfToken);
    if (!isHuman) {
        return res.status(400).json({ error: 'Captcha validation failed' });
    }

    if (!email || !appPassword || !recipients || !Array.isArray(recipients) || recipients.length === 0) {
        return res.status(400).json({ error: 'Missing parameters' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendSSE = (data) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Standard High-Inbox Connection via Port 587 (STARTTLS) with 6 connections pool
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // STARTTLS safe handshake
        requireTLS: true,
        pool: true,
        maxConnections: 6, // 6 parallel connections
        maxMessages: Infinity,
        auth: {
            user: email.trim(),
            pass: appPassword.replace(/\s+/g, '').trim()
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

    const BATCH_SIZE = 6; // एक साथ 6 ईमेल भेजने का फ़िक्स सेटअप

    for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
        const batch = recipients.slice(i, i + BATCH_SIZE);

        const batchPromises = batch.map(async (recipientRaw) => {
            const recipient = recipientRaw.trim();
            if (!recipient) return null;

            const dynamicSubject = parseSpintax(subject);
            let dynamicBody = parseSpintax(body);

            // 1. UNIQUE REFERENCE CODE GENERATOR (For Inbox Delivery)
            const refCode = 'REF-' + Math.floor(100000 + Math.random() * 900000);
            
            // 2. EMBED REFERENCE CODE IN HTML & TEXT TEMPLATE
            const htmlWithRef = `
                <div>${dynamicBody}</div>
                <br><br>
                <div style="font-size: 11px; color: #888888; border-top: 1px solid #eeeeee; padding-top: 8px;">
                    Reference ID: <b>${refCode}</b>
                </div>
            `;
            
            const plainText = stripHtml(dynamicBody) + `\n\n[Ref ID: ${refCode}]`;

            const mailOptions = {
                from: `"${senderName.replace(/["\r\n]/g, '').trim()}" <${email.trim()}>`,
                to: recipient,
                replyTo: email.trim(),
                subject: dynamicSubject,
                text: plainText,
                html: htmlWithRef
            };

            try {
                await transporter.sendMail(mailOptions);
                return { recipient, success: true };
            } catch (err) {
                return { recipient, success: false, error: err.message };
            }
        });

        // Executing 6 emails concurrently
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

        // 6 ईमेल सेंड करने के बाद 1 से 2 सेकंड का रैंडम गैप (1000ms से 2000ms)
        if (i + BATCH_SIZE < recipients.length) {
            const randomDelay = Math.floor(Math.random() * 1000) + 1000;
            await new Promise((resolve) => setTimeout(resolve, randomDelay));
        }
    }

    transporter.close();
    sendSSE({ type: 'complete', sentCount, failedCount, total });
    res.end();
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
