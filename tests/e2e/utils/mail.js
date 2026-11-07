// Mailpit (compose.dev.yml) catches every mail of the E2E stack; its API lets tests read them.
const MAILPIT_URL = process.env.MAILPIT_URL || 'http://127.0.0.1:18025';

async function listMails() {
  const resp = await fetch(`${MAILPIT_URL}/api/v1/messages?limit=500`);
  if (!resp.ok) throw new Error(`mailpit -> ${resp.status}`);
  return (await resp.json()).messages || [];
}

/**
 * Wait until a mail matches (to: address, subject: substring or RegExp, text: substring of the body).
 * Newest mails are checked first. Resolves to {id, to, subject, text}.
 */
async function waitForMail({ to, subject, text }, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const candidates = (await listMails()).filter((m) => (!to || m.To.some((r) => r.Address === to))
      && (!subject || (subject instanceof RegExp ? subject.test(m.Subject) : m.Subject.includes(subject))));
    for (const match of candidates) {
      const full = await (await fetch(`${MAILPIT_URL}/api/v1/message/${match.ID}`)).json();
      if (!text || (full.Text || '').includes(text)) {
        return { id: match.ID, to: match.To.map((r) => r.Address), subject: match.Subject, text: full.Text || '' };
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`no mail to ${to} with subject ${subject}${text ? ' containing ' + text : ''}`);
}

/** All mails to an address. */
async function mailsTo(address) {
  return (await listMails()).filter((m) => m.To.some((r) => r.Address === address));
}

module.exports = { listMails, waitForMail, mailsTo };
