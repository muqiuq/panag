// Dashboard: default access, active entries (extend/revoke per entry), all networks (grant per row).
// The command palette (palette.js) grants too; both stay in sync through the "panag:access" event.
(function () {
  const { api, el, toast, busy, formatLeft, remainingSeconds, untilClock, normalizeAddress, accessChanged } = window.Panag;
  const activeTable = document.getElementById('activeAccessTable');
  const networksTable = document.getElementById('networksTable');
  const selfRevokeBtn = document.getElementById('btnSelfRevoke');
  const defaultBtn = document.getElementById('btnDefaultAccess');
  const KIND_LABEL = { default: 'Default', extended: 'Extended' };
  const PERMANENT_SORT = '999999999';
  let entries = [];

  function entryRow(e) {
    const left = remainingSeconds(e);
    const name = e.network || e.address;
    const now = Math.floor(Date.now() / 1000);
    return el('tr', { dataset: { entryId: e.id } },
      el('td', {}, el('strong', {}, name)),
      el('td', {}, el('code', {}, e.address)),
      el('td', {}, e.kind ? el('span', { class: `badge ${e.kind === 'default' ? 'text-bg-secondary' : 'text-bg-warning'}` }, KIND_LABEL[e.kind]) : '–'),
      el('td', { 'data-sort-value': left === null ? PERMANENT_SORT : String(left) }, left === null ? 'permanent' : `${formatLeft(left)} left`),
      el('td', { 'data-sort-value': left === null ? PERMANENT_SORT : String(now + left) }, untilClock(e)),
      el('td', { class: 'text-end text-nowrap' },
        el('div', { class: 'btn-group btn-group-sm' },
          left !== null ? el('button', { type: 'button', class: 'btn btn-outline-secondary', 'data-entry-action': 'extendEntry', 'aria-label': `Extend ${name}` }, 'Extend') : null,
          el('button', { type: 'button', class: 'btn btn-outline-danger', 'data-entry-action': 'revokeEntry', 'aria-label': `Revoke ${name}` }, 'Revoke'))));
  }

  function renderActive() {
    if (!activeTable) return;
    const body = activeTable.tBodies[0];
    if (entries.length === 0) {
      body.replaceChildren(el('tr', {}, el('td', { colspan: 6, class: 'text-muted' }, 'No active address list entries.')));
    } else {
      body.replaceChildren(...entries.map(entryRow));
    }
    window.PanagTableSort.refresh(activeTable);
    if (selfRevokeBtn) selfRevokeBtn.disabled = entries.length === 0;
  }

  function renderNetworkStatus() {
    if (!networksTable) return;
    const byAddress = new Map(entries.map((e) => [normalizeAddress(e.address), e]));
    networksTable.querySelectorAll('tbody tr[data-address]').forEach((row) => {
      const entry = byAddress.get(normalizeAddress(row.dataset.address));
      const cell = row.querySelector('[data-status]');
      const left = entry ? remainingSeconds(entry) : null;
      cell.dataset.sortValue = entry ? (left === null ? PERMANENT_SORT : String(left)) : '';
      cell.replaceChildren(entry ? el('span', { class: 'badge text-bg-success' }, left === null ? 'active' : `active, ${formatLeft(left)} left`) : '');
    });
  }

  document.addEventListener('panag:access', (event) => {
    entries = event.detail.entries;
    renderActive();
    renderNetworkStatus();
  });

  async function refresh() {
    const data = await api('currentAccess');
    if (data.status) accessChanged(data.entries);
  }

  async function call(button, action, body) {
    busy(button, true);
    const data = await api(action, body);
    busy(button, false);
    toast(data.message, data.status);
    if (data.entries) accessChanged(data.entries); else refresh();
    return data;
  }

  activeTable?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-entry-action]');
    if (button) call(button, button.dataset.entryAction, { id: button.closest('tr').dataset.entryId });
  });

  networksTable?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-grant]');
    if (button) call(button, 'grantNetwork', { network_id: Number(button.dataset.grant) });
  });

  defaultBtn?.addEventListener('click', () => call(defaultBtn, 'defaultaccess', {}));

  selfRevokeBtn?.addEventListener('click', () => {
    if (window.confirm('Remove all of your current accesses?')) call(selfRevokeBtn, 'revokeMine', {});
  });

  // Initial state is embedded by the server; keep the remaining times fresh.
  let initial = [];
  try {
    initial = JSON.parse(activeTable?.dataset.entries || '[]');
  } catch (e) {
    refresh();
  }
  accessChanged(initial);
  setInterval(refresh, 30000);
})();
