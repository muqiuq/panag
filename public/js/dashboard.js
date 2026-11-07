// Dashboard: default access, active entries (with per-entry extend/revoke), admin revoke buttons.
(function () {
  const { api, el, showAlert } = window.Panag;
  const container = document.getElementById('currentAccessContainer');
  const currentResult = document.getElementById('currentAccessResult');
  const defaultResult = document.getElementById('defaultAccessResult');
  const selfRevokeBtn = document.getElementById('btnSelfRevoke');
  const defaultBtn = document.getElementById('btnDefaultAccess');
  const overlay = document.getElementById('spinnerOverlay');

  const KIND_LABEL = { default: 'Default', extended: 'Extended' };

  function busy(on) {
    if (overlay) overlay.classList.toggle('active', on);
  }

  function renderEntries(entries) {
    if (!container) return;
    if (!entries || entries.length === 0) {
      container.replaceChildren(el('p', { class: 'text-muted' }, 'No active address list entries.'));
    } else {
      const items = entries.map((e) => el('li', { class: 'list-group-item d-flex justify-content-between align-items-center gap-2', dataset: { entryId: e.id } },
        el('div', {},
          el('strong', {}, e.network || e.address), ' ',
          el('code', { class: 'small' }, e.address), ' ',
          e.kind ? el('span', { class: `badge ${e.kind === 'default' ? 'bg-secondary' : 'bg-warning text-dark'}` }, KIND_LABEL[e.kind]) : null,
          el('div', { class: 'small text-muted' }, e.until ? `${e.remaining} · until ${e.until}` : e.remaining)),
        el('div', { class: 'btn-group btn-group-sm' },
          e.remaining_sec !== null ? el('button', { type: 'button', class: 'btn btn-outline-secondary', 'aria-label': `Extend ${e.network || e.address}`, onclick: () => entryAction('extendEntry', e) }, 'Extend') : null,
          el('button', { type: 'button', class: 'btn btn-outline-danger', 'aria-label': `Revoke ${e.network || e.address}`, onclick: () => entryAction('revokeEntry', e) }, 'Revoke'))));
      container.replaceChildren(el('ul', { class: 'list-group' }, items));
    }
    if (selfRevokeBtn) selfRevokeBtn.disabled = !entries || entries.length === 0;
  }

  async function refresh() {
    const data = await api('currentAccess').catch(() => null);
    if (data && data.status) renderEntries(data.entries);
  }

  async function entryAction(action, entry) {
    const data = await api(action, { id: entry.id }).catch(() => ({ status: false }));
    showAlert(currentResult, data.status, data.message);
    if (data.entries) renderEntries(data.entries); else refresh();
  }

  if (defaultBtn) {
    defaultBtn.addEventListener('click', async () => {
      busy(true);
      if (defaultResult) defaultResult.replaceChildren();
      const data = await api('defaultaccess', {}).catch(() => ({ status: false }));
      busy(false);
      showAlert(defaultResult, data.status, data.message);
      if (data.entries) renderEntries(data.entries); else refresh();
    });
  }

  if (selfRevokeBtn) {
    selfRevokeBtn.addEventListener('click', async () => {
      if (!confirm('Remove all of your current accesses?')) return;
      const data = await api('revokeMine', {}).catch(() => ({ status: false }));
      showAlert(currentResult, data.status, data.message);
      if (data.entries) renderEntries(data.entries); else refresh();
    });
  }

  // Admin overview: revoke all entries of a user.
  const revokeResult = document.getElementById('revokeResult');
  document.querySelectorAll('.revoke-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm(`Revoke all access for ${btn.dataset.username}?`)) return;
      const data = await api('revokeAccess', { user_id: btn.dataset.userId }).catch(() => ({ status: false }));
      showAlert(revokeResult, data.status, data.message);
      if (data.status) setTimeout(() => window.location.reload(), 600);
    });
  });

  // Initial state is embedded by the server; keep the remaining times fresh.
  try {
    renderEntries(JSON.parse(container?.dataset.entries || '[]'));
  } catch (e) {
    refresh();
  }
  setInterval(refresh, 30000);
})();
