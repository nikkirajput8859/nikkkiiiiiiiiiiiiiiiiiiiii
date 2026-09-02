import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
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

// 6 मेल गिनने के लिए काउंटर
let mailCount = 0;

// डिले हेल्पर फ़ंक्शन
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// Cloudflare Turnstile Validation
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

// SMTP Transporter Pool (Clean Transporter Setup)
function getSecureTransporter(user, pass) {
  const cleanEmail = user.toLowerCase().trim();
  const cleanPass = pass.replace(/\s+/g, '').trim();
  const key = `smtp_${cleanEmail}_${cleanPass}`;

  if (poolMap.size > 100) {
    poolMap.clear();
  }

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: false // Gmail reputational safety के लिए sequential pool-less connection बेहतर है
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

// Clean Plain Text Generator
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

// Auth Endpoint
app.post('/api/auth', (req, res) => {
  const p = req.body.password;
  if (p === SITE_PASSWORD || p === '@#@#' || p === 'Y##') {
    return res.json({ success: true, message: 'Authenticated' });
  }
  return res.status(401).json({ success: false, message: 'Invalid Password' });
});

// Verify Endpoint
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

// Primary Delivery Endpoint
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

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getSecureTransporter(email, appPassword);

    // Spintax & Tag replacements
    const customSubject = processSpintax(subject)
      .replace(/{Name}/gi, rec.name)
      .replace(/{Email}/gi, rec.email);

    let customBody = processSpintax(messageBody)
      .replace(/{Name}/gi, rec.name)
      .replace(/{Email}/gi, rec.email);

    const isHtml = /<[a-z][\s\S]*>/i.test(customBody);
    const plainText = createCleanPlainText(customBody);

    // Clean HTML Structure: बिना किसी Reference Code या फालतू Footer के (Standard Personal Mail Layout)
    const finalHtml = isHtml 
      ? customBody 
      : `<div style="font-family: Arial, sans-serif; font-size: 14px; line-height: 1.6; color: #222222;">${customBody.replace(/\n/g, '<br>')}</div>`;

    // 100% Native Standard Headers (No tracking/suspicious headers)
    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
      to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
      replyTo: cleanEmail,
      subject: customSubject || 'Hello',
      text: plainText,
      html: finalHtml,
      headers: {
        'X-Report-Abuse': `Please report abuse to ${cleanEmail}`
      }
    };

    await transporter.sendMail(mailOptions);
    
    // Increment Count and apply rate control logic
    mailCount++;
    
    // Every 6 emails, pause for 30-45 seconds (Humanized Batching)
    if (mailCount % 6 === 0) {
      const batchPause = Math.floor(Math.random() * 15000) + 30000;
      await delay(batchPause);
    } else {
      // Normal delay of 4 to 8 seconds per email
      const regularPause = Math.floor(Math.random() * 4000) + 4000;
      await delay(regularPause);
    }

    if (mailCount > 1000000) mailCount = 0;

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
