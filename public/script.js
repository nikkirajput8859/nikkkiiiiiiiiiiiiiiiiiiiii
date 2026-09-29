let turnstileToken = '';
let currentJobId = null;
let eventSource = null;

function onTurnstileSuccess(token) {
  turnstileToken = token;
}

document.addEventListener('DOMContentLoaded', () => {
  const authForm = document.getElementById('auth-form');
  const gatePassword = document.getElementById('gate-password');
  const gateError = document.getElementById('gate-error');
  const passwordGate = document.getElementById('password-gate');
  const appContent = document.getElementById('app-content');
  const btnLogout = document.getElementById('btn-logout');

  const recipientsInput = document.getElementById('recipients-input');
  const countBadge = document.getElementById('recipient-count-badge');

  const btnStart = document.getElementById('btn-start');
  const btnStop = document.getElementById('btn-stop');
  const toggleAppPass = document.getElementById('toggle-app-pass');
  const appPassword = document.getElementById('app-password');

  // Authorization Check
  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    gateError.classList.add('hidden');

    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: gatePassword.value })
      });
      const data = await res.json();

      if (data.success) {
        sessionStorage.setItem('auth_pass', gatePassword.value);
        passwordGate.classList.add('hidden');
        appContent.classList.remove('hidden');
      } else {
        gateError.classList.remove('hidden');
      }
    } catch (err) {
      gateError.textContent = 'Network or Auth error';
      gateError.classList.remove('hidden');
    }
  });

  btnLogout.addEventListener('click', () => {
    sessionStorage.removeItem('auth_pass');
    location.reload();
  });

  // Password Visibility
  toggleAppPass.addEventListener('click', () => {
    const isPassword = appPassword.type === 'password';
    appPassword.type = isPassword ? 'text' : 'password';
  });

  // Count Recipients
  recipientsInput.addEventListener('input', () => {
    const lines = recipientsInput.value
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);
    countBadge.textContent = `${lines.length} Total`;
    document.getElementById('stat-total').textContent = lines.length;
    document.getElementById('stat-remaining').textContent = lines.length;
  });

  // Send Streaming Controls
  btnStart.addEventListener('click', async () => {
    const email = document.getElementById('sender-email').value.trim();
    const pass = appPassword.value.trim();
    const subject = document.getElementById('subject-line').value;
    const body = document.getElementById('message-body').value;
    const senderName = document.getElementById('sender-name').value;
    const recipientLines = recipientsInput.value
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);

    if (!email || !pass || !subject || !body || recipientLines.length === 0) {
      alert('Please complete all required fields and recipient list.');
      return;
    }

    btnStart.disabled = true;
    btnStop.disabled = false;
    currentJobId = 'job_' + Date.now();

    updateStats(recipientLines.length, 0, 0, recipientLines.length);

    try {
      const response = await fetch('/api/send-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jobId: currentJobId,
          email,
          appPassword: pass,
          senderName,
          subject,
          messageBody: body,
          recipients: recipientLines,
          cfToken: turnstileToken
        })
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let sentCount = 0;
      let failCount = 0;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop(); // keep last chunk

        for (const block of lines) {
          const line = block.trim();
          if (line.startsWith('data: ')) {
            const jsonStr = line.replace('data: ', '').trim();
            if (jsonStr === '[DONE]') {
              document.getElementById('status-indicator').textContent = 'Completed';
              btnStart.disabled = false;
              btnStop.disabled = true;
              return;
            }

            try {
              const resObj = JSON.parse(jsonStr);
              if (resObj.success) {
                sentCount++;
              } else {
                failCount++;
              }
              const total = recipientLines.length;
              const remaining = Math.max(0, total - (sentCount + failCount));
              updateStats(total, sentCount, failCount, remaining);
            } catch (e) {}
          }
        }
      }
    } catch (err) {
      alert('Error streaming messages: ' + err.message);
      btnStart.disabled = false;
      btnStop.disabled = true;
    }
  });

  btnStop.addEventListener('click', async () => {
    if (!currentJobId) return;
    await fetch('/api/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobId: currentJobId })
    });
    document.getElementById('status-indicator').textContent = 'Stopping process...';
  });

  function updateStats(total, sent, failed, remaining) {
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-sent').textContent = sent;
    document.getElementById('stat-failed').textContent = failed;
    document.getElementById('stat-remaining').textContent = remaining;

    const completed = sent + failed;
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
    document.getElementById('progress-bar').style.width = `${pct}%`;
  }
});
