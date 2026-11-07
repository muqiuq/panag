// Admin matrix (admin/matrix.php): toggle default networks per cell, filter users (rows) and networks (columns).
(function () {
  const { api, toast } = window.Panag;
  const table = document.getElementById('matrixTable');
  if (!table) return;

  function paint(button, selected) {
    const eligible = button.dataset.eligible === '1';
    button.setAttribute('aria-pressed', selected ? 'true' : 'false');
    button.textContent = selected ? (eligible ? '✓' : '!') : (eligible ? '' : '–');
    button.disabled = !eligible && !selected;
    button.classList.toggle('is-invalid', selected && !eligible);
    button.closest('td').dataset.sortValue = selected ? '1' : '0';
  }

  table.addEventListener('click', async (event) => {
    const button = event.target.closest('.matrix-toggle');
    if (!button || button.disabled) return;
    const userId = Number(button.dataset.userId);
    const enabled = button.getAttribute('aria-pressed') !== 'true';
    button.disabled = true;
    const resp = await api('setDefaultNetworks', { user_id: userId, network_ids: [Number(button.dataset.networkId)], enabled });
    button.disabled = false;
    toast(resp.message, resp.status);
    if (Array.isArray(resp.default_ids)) {
      const stored = new Set(resp.default_ids);
      table.querySelectorAll(`.matrix-toggle[data-user-id="${userId}"]`).forEach((b) => paint(b, stored.has(Number(b.dataset.networkId))));
    } else {
      paint(button, !enabled);
    }
  });

  const matches = (el, q) => q === '' || (el.dataset.filterText || '').toLowerCase().includes(q);

  document.querySelector('[data-matrix-filter="users"]')?.addEventListener('input', (event) => {
    const q = event.target.value.trim().toLowerCase();
    Array.from(table.tBodies[0].rows).forEach((row) => { row.hidden = !matches(row, q); });
  });

  document.querySelector('[data-matrix-filter="networks"]')?.addEventListener('input', (event) => {
    const q = event.target.value.trim().toLowerCase();
    table.querySelectorAll('thead [data-network-col]').forEach((th) => {
      const hide = !matches(th, q);
      th.hidden = hide;
      Array.from(table.tBodies[0].rows).forEach((row) => { row.cells[th.cellIndex].hidden = hide; });
    });
  });
})();
