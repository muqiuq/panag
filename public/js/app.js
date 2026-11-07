// Shared helpers for PANAG pages (no build step, no dependencies).
(function () {
  const BASE_PATH = document.body.dataset.basePath || '';
  const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || document.body.dataset.csrfToken || '';

  /** Call api.php?f=<action>. POST when a body is given (or post=true). Resolves to the JSON payload. */
  async function api(action, body, post) {
    const isPost = post || body !== undefined;
    const resp = await fetch(`${BASE_PATH}/api.php?f=${encodeURIComponent(action)}`, {
      method: isPost ? 'POST' : 'GET',
      headers: isPost ? { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN } : {},
      body: isPost ? JSON.stringify(body || {}) : undefined,
    });
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      data = { status: false, message: `Request failed (HTTP ${resp.status}).` };
    }
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

  window.Panag = { api, el, showAlert, BASE_PATH, CSRF_TOKEN };
})();
