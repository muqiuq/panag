// Shared helpers for PANAG pages (no build step, no dependencies). Loaded on every page by footer.php.
// Data from the server or the router is only ever inserted as text (el(), textContent) – never as HTML.
(function () {
  const BASE_PATH = document.body.dataset.basePath || '';
  const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || document.body.dataset.csrfToken || '';

  /** Call api.php?f=<action>. POST when a body is given (or post=true). Resolves to the JSON payload plus httpStatus. */
  async function api(action, body, post) {
    const isPost = post || body !== undefined;
    let resp;
    try {
      resp = await fetch(`${BASE_PATH}/api.php?f=${encodeURIComponent(action)}`, {
        method: isPost ? 'POST' : 'GET',
        headers: isPost ? { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN } : {},
        body: isPost ? JSON.stringify(body || {}) : undefined,
      });
    } catch (e) {
      return { status: false, message: 'Network error – is PANAG reachable?', httpStatus: 0 };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      data = { status: false, message: `Request failed (HTTP ${resp.status}).` };
    }
    data.httpStatus = resp.status;
    return data;
  }

  /** Create an element: el('span', {class: 'badge'}, 'text', childNode, ...). Text is never parsed as HTML. */
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([key, value]) => {
      if (value === null || value === undefined || value === false) return;
      if (key === 'class') node.className = value;
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    });
    children.flat().forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  /** Replace the content of container with a Bootstrap alert. */
  function showAlert(container, ok, message) {
    if (!container) return;
    container.replaceChildren(el('div', { class: `alert ${ok ? 'alert-success' : 'alert-danger'}`, role: 'alert' }, message || (ok ? 'Done.' : 'Request failed.')));
  }

  /** Short-lived notification (bottom right). Errors stay longer and are announced assertively. */
  function toast(message, ok = true) {
    let area = document.getElementById('toastArea');
    if (!area) {
      area = el('div', { id: 'toastArea', class: 'toast-area', 'data-testid': 'toasts' });
      document.body.append(area);
    }
    const close = el('button', { type: 'button', class: 'btn-close btn-close-white ms-auto', 'aria-label': 'Close' });
    const item = el('div', { class: `toast show align-items-center border-0 text-bg-${ok ? 'success' : 'danger'}`, role: ok ? 'status' : 'alert', 'aria-live': ok ? 'polite' : 'assertive' },
      el('div', { class: 'd-flex align-items-start gap-2 p-2' }, el('div', { class: 'toast-body p-1' }, message || (ok ? 'Done.' : 'Request failed.')), close));
    const remove = () => item.remove();
    close.addEventListener('click', remove);
    area.append(item);
    setTimeout(remove, ok ? 5000 : 10000);
  }

  /** Disable a button and show a small spinner while a request runs. */
  function busy(button, on) {
    if (!button) return;
    button.disabled = on;
    button.classList.toggle('is-busy', on);
    button.setAttribute('aria-busy', on ? 'true' : 'false');
  }

  /** Mirrors format_duration_human() in src/durations.php: "1 h 30 min", "15 min", "40 s". */
  function formatDuration(seconds) {
    const s = Math.max(0, Math.round(seconds));
    if (s < 60) return `${s} s`;
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return [h ? `${h} h` : '', m ? `${m} min` : ''].filter(Boolean).join(' ');
  }

  function formatClock(unixSeconds) {
    const d = new Date(unixSeconds * 1000);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }

  /** "1 h left" right after a 1 h grant: rounds up to whole minutes (seconds only below one minute). */
  function formatLeft(seconds) {
    return seconds < 60 ? formatDuration(seconds) : formatDuration(Math.ceil(seconds / 60) * 60);
  }

  /**
   * Remember when entries (from current_access_view()) arrived. Remaining times are then counted down
   * from the router's remaining_sec, independent of a skewed browser clock.
   */
  function stampEntries(entries) {
    const now = Date.now();
    (entries || []).forEach((e) => { if (e.received_ms === undefined) e.received_ms = now; });
    return entries || [];
  }

  /** Seconds left of an entry (null = permanent). */
  function remainingSeconds(entry) {
    if (entry.remaining_sec === null || entry.remaining_sec === undefined) return null;
    const elapsed = entry.received_ms === undefined ? 0 : Math.floor((Date.now() - entry.received_ms) / 1000);
    return Math.max(0, entry.remaining_sec - elapsed);
  }

  /** Local clock time when the entry ends ("16:45"), '' for permanent entries. */
  function untilClock(entry) {
    const left = remainingSeconds(entry);
    return left === null ? '' : formatClock(Math.floor(Date.now() / 1000) + left);
  }

  /** RouterOS shows single hosts without "/32". */
  function normalizeAddress(address) {
    return String(address || '').trim().replace(/\/32$/, '');
  }

  /** Active entries changed (grant, extend, revoke, refresh): keeps dashboard, palette etc. in sync. */
  function accessChanged(entries) {
    if (Array.isArray(entries)) document.dispatchEvent(new CustomEvent('panag:access', { detail: { entries: stampEntries(entries) } }));
  }

  // Confirmation for forms/buttons with data-confirm (replaces inline onsubmit/onclick handlers).
  document.addEventListener('submit', (event) => {
    const message = event.submitter?.dataset.confirm || event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  window.Panag = {
    api, el, showAlert, toast, busy, formatDuration, formatLeft, formatClock, stampEntries, remainingSeconds, untilClock,
    normalizeAddress, accessChanged, BASE_PATH, CSRF_TOKEN,
  };
})();
