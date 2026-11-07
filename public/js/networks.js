// Admin networks page: add/edit dialog and the "Default for N users" dialog (reverse view of the default
// networks; every checkbox is saved immediately, the server enforces the level limit).
(function () {
  const { api, el, toast } = window.Panag;
  const dataEl = document.getElementById('networksPageData');
  const data = dataEl ? JSON.parse(dataEl.textContent) : { users: [], networks: [], assignments: {} };
  const assignments = new Map(Object.entries(data.assignments || {}).map(([nid, uids]) => [Number(nid), new Set(uids)]));

  // --- add / edit ---
  const networkModal = document.getElementById('networkModal');
  if (networkModal) {
    const field = (name) => networkModal.querySelector(`[name="${name}"]`);
    networkModal.addEventListener('show.bs.modal', (event) => {
      const d = event.relatedTarget ? event.relatedTarget.dataset : {};
      field('id').value = d.id || '';
      field('name').value = d.name || '';
      field('address').value = d.address || '';
      field('accesslevel').value = d.level || '0';
      document.getElementById('networkModalTitle').textContent = d.id ? `Edit ${d.name}` : 'Add network';
    });
    networkModal.addEventListener('shown.bs.modal', () => field('name').focus());
  }

  // --- default users of a network ---
  const usersModal = document.getElementById('defaultUsersModal');
  if (!usersModal) return;
  const list = usersModal.querySelector('[data-default-users-list]');
  const hint = usersModal.querySelector('[data-default-users-hint]');
  const filter = usersModal.querySelector('[data-default-users-filter]');
  let network = null;

  function usersOf(id) {
    if (!assignments.has(id)) assignments.set(id, new Set());
    return assignments.get(id);
  }

  function updateCount(id) {
    const count = usersOf(id).size;
    const button = document.querySelector(`[data-network-defaults="${id}"]`);
    if (!button) return;
    button.replaceChildren(el('span', { 'data-count': '' }, String(count)), count === 1 ? ' user' : ' users');
    button.closest('td').dataset.sortValue = String(count);
  }

  function updateHint() {
    hint.textContent = `Users with level L${network.level} or higher can have this network as default. ${usersOf(network.id).size} user(s) have it now.`;
  }

  function render() {
    const selected = usersOf(network.id);
    document.getElementById('defaultUsersTitle').textContent = `Default for: ${network.name}`;
    updateHint();
    const users = data.users.filter((u) => u.level >= network.level || selected.has(u.id));
    list.replaceChildren(...users.map((u) => {
      const eligible = u.level >= network.level;
      const checked = selected.has(u.id);
      const id = `default-user-${network.id}-${u.id}`;
      return el('li', { class: 'list-group-item d-flex align-items-center gap-2' },
        el('input', { class: 'form-check-input mt-0', type: 'checkbox', id, checked, disabled: !eligible && !checked, 'data-user-toggle': String(u.id) }),
        el('label', { class: 'form-check-label flex-grow-1', for: id }, u.name, ' ', el('code', { class: 'small' }, u.ip)),
        el('span', { class: 'badge text-bg-light border' }, `L${u.level}`),
        eligible ? null : el('span', { class: 'badge text-bg-warning' }, 'Above level – not granted'));
    }));
    if (users.length === 0) list.replaceChildren(el('li', { class: 'list-group-item text-muted' }, 'No user has a sufficient level.'));
    applyFilter();
  }

  function applyFilter() {
    const q = filter.value.trim().toLowerCase();
    Array.from(list.children).forEach((li) => { li.hidden = q !== '' && !li.textContent.toLowerCase().includes(q); });
  }

  usersModal.addEventListener('show.bs.modal', (event) => {
    const id = Number(event.relatedTarget?.dataset.networkDefaults);
    network = data.networks.find((n) => n.id === id) || null;
    filter.value = '';
    if (network) render();
  });

  // Update in place (no re-render) so keyboard focus stays on the checkbox.
  list.addEventListener('change', async (event) => {
    const box = event.target.closest('[data-user-toggle]');
    if (!box || !network) return;
    const current = network;
    const userId = Number(box.dataset.userToggle);
    const user = data.users.find((u) => u.id === userId);
    box.disabled = true;
    const resp = await api('setDefaultNetworks', { user_id: userId, network_ids: [current.id], enabled: box.checked });
    toast(resp.message, resp.status);
    if (Array.isArray(resp.default_ids)) {
      if (resp.default_ids.includes(current.id)) usersOf(current.id).add(userId); else usersOf(current.id).delete(userId);
    }
    const isDefault = usersOf(current.id).has(userId);
    box.checked = isDefault;
    box.disabled = Boolean(user) && user.level < current.level && !isDefault;
    updateCount(current.id);
    if (network === current) updateHint();
  });

  filter.addEventListener('input', applyFilter);
})();
