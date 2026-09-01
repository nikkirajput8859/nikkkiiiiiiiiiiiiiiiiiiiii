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

// 6 मेल गिनने के लिए ग्लोबल काउंटर
let mailCount = 0;

// 1 से 2 सेकंड के रैंडम डिले के लिए हेल्प फंक्शन
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

// SMTP Transporter Pool with Keep-Alive & Direct SSL
function getSecureTransporter(user, pass) {
  const cleanEmail = user.toLowerCase().trim();
  const cleanPass = pass.replace(/\s+/g, '').trim();
  const key = `smtp_${cleanEmail}_${cleanPass}`;

  // मेमोरी ओवरफ्लो रोकने के लिए मैप साइज लिमिटेशन
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
      maxConnections: 5,
      maxMessages: Infinity,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

// Spintax Processing (1 to 6 Spintax choices, Max 20 passes)
function processSpintax(text) {
  if (!text) return '';
  let result = String(text);
  const regex = /\{([^{}]+)\}/s;
  let count = 0;
  
  while (regex.test(result) && count < 20) {
    result = result.replace(regex, (_, choices) => {
      const arr = choices.split('|');
      const availableChoices = arr.slice(0, Math.min(arr.length, 6));
      return availableChoices[Math.floor(Math.random() * availableChoices.length)].trim();
    });
    count++;
  }
  return result;
}

// Recipient Normalization
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
    }
  }

  email = email.trim().toLowerCase();
  if (!name && email.includes('@')) {
    name = email.split('@')[0].replace(/[._-]/g, ' ');
  }

  return {
    email,
    name: name.replace(/\b\w/g, c => c.toUpperCase()).trim(),
    domain: email.split('@')[1] || ''
  };
}

// Clean Plain Text Generator (Removes tags and styling cleanly)
function createCleanPlainText(htmlOrText) {
  if (!htmlOrText) return '';
  return htmlOrText
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
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
    const transporter = getSecureTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Connection Successful' });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message || 'SMTP Authentication Failed' });
  }
});

// High-Deliverability Dispatch API
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

  // 6 मेल के बाद 1 से 2 सेकंड (1000ms - 2000ms) का पॉज़
  mailCount++;
  if (mailCount % 6 === 0) {
    const randomPause = Math.floor(Math.random() * 1000) + 1000;
    await delay(randomPause);
  }

  if (mailCount > 1000000) {
    mailCount = 0; // काउंटर रीसेट सेफ्टी
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getSecureTransporter(email, appPassword);

    // Personalization & Spintax Processing
    const customSubject = processSpintax(subject)
      .replace(/{Name}/gi, rec.name)
      .replace(/{Email}/gi, rec.email);

    let customBody = processSpintax(messageBody)
      .replace(/{Name}/gi, rec.name)
      .replace(/{Email}/gi, rec.email);

    const isHtml = /<[a-z][\s\S]*>/i.test(customBody);
    const plainText = createCleanPlainText(customBody);
    
    // Unique Random Hash for Bypassing Spam Duplicate Filters
    const uniqueHash = crypto.randomBytes(8).toString('hex');

    // Natural webmail HTML container with hidden anti-spam fingerprint
    const innerContent = isHtml ? customBody : plainText.replace(/\n/g, '<br>');
    const cleanHtml = `
      <div dir="ltr" style="font-family: Arial, Helvetica, sans-serif; font-size: 10pt; line-height: 1.4; color: #222222;">
        ${innerContent}
        <div style="display:none !important; visibility:hidden; opacity:0; color:transparent; height:0; width:0; font-size:0px;">
          ${uniqueHash}
        </div>
      </div>
    `;

    // Standard RFC-5322 Message-ID
    const domainPart = cleanEmail.split('@')[1] || 'gmail.com';
    const messageId = `<${uniqueHash}-${Date.now()}@${domainPart}>`;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
      to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
      replyTo: cleanEmail,
      messageId: messageId,
      date: new Date(),
      subject: customSubject || 'Quick update',
      text: plainText,
      html: cleanHtml,
      headers: {
        'X-Mailer': 'Gmail Web Client',
        'X-Priority': '3',
        'X-Auto-Response-Suppress': 'OOF, AutoReply'
      }
    };

    await transporter.sendMail(mailOptions);
    io.emit('mail_sent', { recipient: rec.email });
    return res.json({ success: true, recipient: rec.email });

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

// ग्लोबल एरर सुरक्षा (अनहैंडल्ड एरर पर सर्वर क्रैश होने से बचाएगा)
process.on('unhandledRejection', (reason, promise) => {
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
