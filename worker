import nodemailer from 'nodemailer';
import { parentPort, workerData } from 'worker_threads';

/* Worker Task Execution */
async function runTask() {
  if (!workerData) {
    if (parentPort) parentPort.postMessage({ success: false, error: "No worker data provided" });
    return;
  }

  const { email, appPassword, recipient, subject, messageBody, senderName } = workerData;

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: email, pass: appPassword }
    });

    const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
      to: recipient,
      subject: subject,
      text: messageBody
    };

    const info = await transporter.sendMail(mailOptions);
    
    if (parentPort) {
      parentPort.postMessage({ success: true, recipient, messageId: info.messageId });
    }
  } catch (error) {
    if (parentPort) {
      parentPort.postMessage({ success: false, recipient, error: error.message });
    }
  }
}

runTask();
