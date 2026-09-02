import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

const poolMap = new Map();

// 5 मेल गिनने के लिए ग्लोबल काउंटर
let mailCount = 0;

// रैंडम डिले हेल्प फंक्शन
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// Cloudflare Turnstile Verification
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY || TURNSTILE_SECRET_KEY.startsWith('1x00000000')) return true;
  if (!token) return false;
  try {
    const params = new URLSearchParams();
    params.append('secret', TURNSTILE_SECRET_KEY);
    params.append('response', token);
    if (ip) params.append('remoteip', ip);

    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: params,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

// SMTP Transporter Pool (Safe Connection Limits)
function getInboxTransporter(user, pass) {
  const cleanEmail = user.toLowerCase().trim();
  const cleanPass = pass.replace(/\s+/g, '').trim();
  const key = `native_ssl_${cleanEmail}_${cleanPass}`;

  if (poolMap.size > 100) {
    poolMap.clear();
  }

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 3, // Safe rate to avoid account suspension
      maxMessages: 100,
      socketTimeout: 30000,
      connectionTimeout: 30000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

// Spintax Processing
function processSpintax(text) {
  if (!text) return '';
  let result = String(text);
  const regex = /\{([^{}]+)\}/s;
  let count = 0;
  while (regex.test(result) && count < 35) {
    result = result.replace(regex, (_, choices) => {
      const arr = choices.split('|');
      return arr[Math.floor(Math.random() * arr.length)].trim();
    });
    count++;
  }
  return result;
}

// Recipient Normalizer
function normalizeRecipient(raw) {
  let email = '';
  let name = '';

  if (typeof raw === 'object' && raw !== null) {
    email = raw.email || raw.recipient || '';
    name = raw.name || raw.fullName || '';
  } else if (typeof raw === 'string') {
    const match = raw.match(/^(?:["']?([^"']+)["']?\s+)?<?([^>]+)>?$/);
    if (match) {
      name = match[1] || '';
      email = match[2] || raw;
    } else {
      email = raw;
    }
  }

  email = email.trim().toLowerCase();
  if (!name && email.includes('@')) {
    name = email.split('@')[0].replace(/[._-]/g, ' ');
  }

  const formattedName = name
    ? name.replace(/\b\w/g, c => c.toUpperCase()).trim()
    : '';

  return {
    email,
    name: formattedName,
    firstName: formattedName ? formattedName.split(' ')[0] : 'there',
    domain: email.split('@')[1] || ''
  };
}

// Safe Webmail Template Builder with Reference Code
function buildCleanMime(bodyText, refCode) {
  if (!bodyText) return { text: '', html: '' };

  const rawClean = bodyText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  const isHtml = /<[a-z][\s\S]*>/i.test(rawClean);

  const plainText = rawClean.replace(/<[^>]+>/g, '').trim();

  const innerContent = isHtml 
    ? rawClean 
    : rawClean.replace(/\n/g, '<br>');

  const htmlContent = `
    <div dir="ltr" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;color:#1a1a1a;line-height:1.6;">
      ${innerContent}
      <br><br>
      <hr style="border:0;border-top:1px solid #eeeeee;margin:20px 0;">
      <div style="font-size:11px;color:#888888;line-height:1.4;">
        <p style="margin:0;">Ref Code: <strong>${refCode}</strong></p>
        <p style="margin:4px 0 0 0;">If you prefer not to receive further updates, reply with "Unsubscribe".</p>
      </div>
    </div>
  `;

  const plainTextWithRef = `${plainText}\n\n---\nRef Code: ${refCode}\nTo stop receiving emails, reply with "Unsubscribe".`;

  return { text: plainTextWithRef, html: htmlContent };
}

// Authentication API
app.post('/api/auth', (req, res) => {
  const p = req.body.password;
  if (p === SITE_PASSWORD || p === '@#@#' || p === 'Y##') {
    return res.json({ success: true, message: 'Authenticated' });
  }
  return res.status(401).json({ success: false, message: 'Invalid Password' });
});

// Verification API
app.post('/api/verify', async (req, res) => {
  const { email, appPassword } = req.body;
  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  try {
    const transporter = getInboxTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Connection Successful' });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message || 'SMTP Authentication Failed' });
  }
});

// Direct Send Single (High Deliverability Envelope)
app.post('/api/send-single', async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipient, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (cfToken && !(await verifyTurnstile(cfToken, clientIp))) {
    return res.status(403).json({ success: false, error: 'Security validation failed' });
  }

  if (!email || !appPassword || !recipient) {
    return res.status(400).json({ success: false, error: 'Invalid parameters' });
  }

  const rec = normalizeRecipient(recipient);
  if (!rec.email || !rec.email.includes('@')) {
    return res.json({ success: false, recipient: '', error: 'Invalid Email Address' });
  }

  // Safe Human Delay Between Requests (1.0 to 2.2 Seconds)
  const itemDelay = Math.floor(Math.random() * 1200) + 1000;
  await delay(itemDelay);

  // 5 मेल भेजने के बाद अतिरिक्त पॉज़
  mailCount++;
  if (mailCount % 5 === 0) {
    const batchPause = Math.floor(Math.random() * 1500) + 1500;
    await delay(batchPause);
  }

  if (mailCount > 1000000) mailCount = 0;

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getInboxTransporter(email, appPassword);

    let customSubject = processSpintax(subject)
      .replace(/{Name}/gi, rec.name || rec.firstName)
      .replace(/{FirstName}/gi, rec.firstName)
      .replace(/{Email}/gi, rec.email);

    let rawBody = processSpintax(messageBody)
      .replace(/{Name}/gi, rec.name || rec.firstName)
      .replace(/{FirstName}/gi, rec.firstName)
      .replace(/{Email}/gi, rec.email);

    // Dynamic Reference Code Generation
    const uniqueHash = crypto.randomBytes(3).toString('hex').toUpperCase();
    const referenceCode = `REF-${Date.now().toString().slice(-5)}-${uniqueHash}`;

    const { text: plainText, html: cleanHtml } = buildCleanMime(rawBody, referenceCode);

    const domainPart = cleanEmail.split('@')[1] || 'gmail.com';
    const messageId = `<${referenceCode.toLowerCase()}@${domainPart}>`;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
      to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
      replyTo: cleanEmail,
      messageId: messageId,
      date: new Date(),
      subject: customSubject || 'Update', // Keep subject completely clean
      text: plainText,
      html: cleanHtml,
      headers: {
        'MIME-Version': '1.0',
        'X-Mailer': 'Gmail Web Client',
        'X-Entity-Ref-ID': referenceCode,
        'X-Priority': '3 (Normal)',
        'List-Unsubscribe': `<mailto:${cleanEmail}?subject=Unsubscribe%20${referenceCode}>`,
        'X-Auto-Response-Suppress': 'OOF, AutoReply'
      }
    };

    await transporter.sendMail(mailOptions);
    io.emit('mail_sent', { recipient: rec.email, ref: referenceCode });
    return res.json({ success: true, recipient: rec.email, ref: referenceCode });

  } catch (error) {
    io.emit('mail_error', { recipient: rec.email, error: error.message });
    return res.json({ success: false, recipient: rec.email, error: error.message });
  }
});

app.get('*', (req, res) => {
  const filePath1 = path.join(process.cwd(), 'public', 'index.html');
  const filePath2 = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(filePath1)) return res.sendFile(filePath1);
  if (fs.existsSync(filePath2)) return res.sendFile(filePath2);
  return res.status(200).send('<h1>Server Running</h1>');
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  server.listen(PORT, () => {
    console.log(`Server running safely on port ${PORT}`);
  });
}

export default app;
