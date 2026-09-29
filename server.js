import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const activeJobs = new Map();
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Helper: 2 से 5 सेकंड का रैंडम डिले (Spam Detection से बचने के लिए)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const getRandomDelay = (min = 2000, max = 5000) => Math.floor(Math.random() * (max - min + 1)) + min;

// Helper: HTML से टेक्स्ट में कन्वर्ट करना (Dual Version के लिए)
function stripHtml(html) {
  if (!html) return '';
  return html.replace(/<[^>]*>?/gm, '').trim();
}

async function verifyTurnstileToken(token, remoteIp) {
  if (!token || TURNSTILE_SECRET_KEY.startsWith('1x0000000000000000000000000000000AA')) {
    return true;
  }

  try {
    const formData = new URLSearchParams();
    formData.append('secret', TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    if (remoteIp) formData.append('remoteip', remoteIp);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const outcome = await result.json();
    return outcome.success === true;
  } catch (error) {
    return false;
  }
}

function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // TLS
      requireTLS: true,
      auth: { user: cleanEmail, pass: cleanPass },
      pool: true,
      maxConnections: 1, // Gmail रिस्ट्रिक्शन से बचने के लिए
      maxMessages: 50,
      rateLimit: 1 // दर नियंत्रित रखें
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

function parseRecipientData(input) {
  if (!input) return { email: '', name: '', firstName: '', domain: '' };

  let email = '';
  let rawName = '';

  if (typeof input === 'object' && input !== null) {
    email = String(input.email || input.recipient || '').trim();
    rawName = String(input.name || input.fullName || '').trim();
  } else if (typeof input === 'string') {
    const str = input.trim();
    const angleMatch = str.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      rawName = angleMatch[1] ? angleMatch[1].trim() : '';
      email = angleMatch[2].trim();
    } else if (str.includes(',')) {
      const parts = str.split(',');
      if (parts[0]?.includes('@')) {
        email = parts[0].trim();
        rawName = parts[1]?.trim() || '';
      } else {
        rawName = parts[0].trim();
        email = parts[1]?.trim() || '';
      }
    } else {
      email = str;
    }
  }

  const cleanEmail = email.toLowerCase();
  const domain = cleanEmail.includes('@') ? cleanEmail.split('@')[1] : '';

  return {
    email: cleanEmail,
    name: rawName,
    firstName: rawName ? rawName.split(' ')[0] : '',
    domain
  };
}

function parseSpintax(text) {
  if (!text) return '';
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 30) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|');
      const pick = options[Math.floor(Math.random() * options.length)];
      return pick ? pick.trim() : '';
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '').trim();
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);

  const displayName = recipient.name || recipient.firstName || 'there';
  const displayFirstName = recipient.firstName || displayName || 'there';

  content = content.replace(/{Name}/gi, displayName);
  content = content.replace(/{FirstName}/gi, displayFirstName);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return content;
}

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized' });
});

app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');

  const { jobId, email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Request Data' })}\n\n`);
    res.end();
    return;
  }

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile Verification Failed' })}\n\n`);
      res.end();
      return;
    }
  }

  const currentJobId = jobId || Date.now().toString();
  activeJobs.set(currentJobId, { stopRequested: false });

  req.on('close', () => {
    activeJobs.delete(currentJobId);
  });

  const transporter = getTransporter(email, appPassword);

  for (let i = 0; i < recipients.length; i++) {
    if (activeJobs.get(currentJobId)?.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const recipient = parseRecipientData(recipients[i]);
    if (!recipient.email) {
      res.write(`data: ${JSON.stringify({ success: false, recipient: '', error: 'Invalid Email Format' })}\n\n`);
      continue;
    }

    try {
      const personalizedSubject = personalizeContent(subject, recipient);
      let personalizedBody = personalizeContent(messageBody, recipient);
      const isHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

      // 1. हर ईमेल में यूनिक आइडेंटिफ़ायर (Signature) जोड़ना
      const uniqueMsgId = crypto.randomBytes(8).toString('hex');
      const uniqueNum = Math.floor(100000 + Math.random() * 900000);
      const timestamp = new Date().toISOString();

      // इनबॉक्स डिलीवरी बढ़ाने के लिए नीचे यूनिक फुटर जोड़ा जाता है
      const uniqueFooterHtml = `<br/><br/><div style="font-size: 10px; color: #888888; opacity: 0.6; display: none !important;">Ref: ${uniqueMsgId}-${uniqueNum} | ${timestamp}</div>`;
      const uniqueFooterText = `\n\n[Ref Code: ${uniqueMsgId}-${uniqueNum}]`;

      let finalHtml = '';
      let finalText = '';

      if (isHtml) {
        finalHtml = personalizedBody + uniqueFooterHtml;
        finalText = stripHtml(personalizedBody) + uniqueFooterText;
      } else {
        finalHtml = `<div style="font-family: sans-serif; font-size: 14px; line-height: 1.5; color: #333333;">${personalizedBody.replace(/\n/g, '<br>')}${uniqueFooterHtml}</div>`;
        finalText = personalizedBody + uniqueFooterText;
      }

      // 2. इनबॉक्स डिलीवरी वाले सुरक्षित ईमेल हेडर सेटिंग्स
      const mailOptions = {
        from: senderName ? `"${senderName.replace(/"/g, '')}" <${email}>` : email,
        to: recipient.name ? `"${recipient.name.replace(/"/g, '')}" <${recipient.email}>` : recipient.email,
        subject: personalizedSubject || 'Important Update',
        text: finalText,
        html: finalHtml,
        headers: {
          'X-Mailer': 'Secure Console v2.0',
          'X-Priority': '3',
          'X-MSMail-Priority': 'Normal',
          'Message-ID': `<${uniqueMsgId}.${Date.now()}@gmail.com>`,
          'List-Unsubscribe': `<mailto:${email}?subject=unsubscribe>`
        }
      };

      const info = await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient: recipient.email, id: info.messageId })}\n\n`);

      // 3. स्पैम फ़िल्टर से बचने के लिए 2.5s से 5s का डिले (Throttling Delay)
      if (i < recipients.length - 1) {
        const delay = getRandomDelay(2500, 5000);
        await sleep(delay);
      }

    } catch (err) {
      res.write(`data: ${JSON.stringify({ success: false, recipient: recipient.email, error: err.message })}\n\n`);
      // त्रुटि आने पर भी 2 सेकंड रुकें
      await sleep(2000);
    }
  }

  activeJobs.delete(currentJobId);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  const { jobId } = req.body;
  if (jobId && activeJobs.has(jobId)) {
    activeJobs.get(jobId).stopRequested = true;
    return res.json({ success: true, message: 'Stop signal sent successfully' });
  }
  return res.status(404).json({ success: false, message: 'Job not found' });
});

app.listen(PORT, () => {
  console.log(`Server running safely on port ${PORT}`);
});

export default app;
