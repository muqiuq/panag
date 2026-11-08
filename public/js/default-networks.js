// Default networks editor (src/views/partials/default_networks_editor.php): admin user page and the
// profile of superusers/admins. Every switch is saved immediately; the server enforces permissions and
// the level limit and answers with the stored list, which is then shown.
(function () {
  const { api, toast, busy } = window.Panag;

  document.querySelectorAll('[data-default-networks]').forEach((root) => {
    const userId = Number(root.dataset.userId);
    const table = root.querySelector('table');
    const search = root.querySelector('[data-dn-search]');
    const onlySelected = root.querySelector('[data-dn-only-selected]');
    const showAll = root.querySelector('[data-dn-show-all]');
    const summary = root.querySelector('[data-dn-summary]');
    const empty = root.querySelector('[data-dn-empty]');
    const rows = () => Array.from(table.tBodies[0].rows);
    const isSelected = (row) => row.dataset.selected === '1';
    const isEligible = (row) => row.dataset.eligible === '1';
    // Sensitive networks are shown but can never be added (single grants only).
    const canAdd = (row) => isEligible(row) && row.dataset.sensitive !== '1';

    function applyFilters() {
      const q = (search?.value || '').trim().toLowerCase();
      let visible = 0;
      rows().forEach((row) => {
        const show = (isEligible(row) || isSelected(row) || Boolean(showAll?.checked))
          && (!onlySelected?.checked || isSelected(row))
          && (q === '' || row.textContent.toLowerCase().includes(q));
        row.hidden = !show;
        if (show) visible++;
      });
      if (empty) empty.hidden = visible > 0;
      if (summary) {
        const count = rows().filter(isSelected).length;
        const invalid = rows().filter((r) => isSelected(r) && !isEligible(r)).length;
        summary.textContent = `${count} selected` + (invalid ? ` · ${invalid} above level (not granted)` : '');
      }
    }

    function showRow(row, selected) {
      row.dataset.selected = selected ? '1' : '0';
      row.cells[0].dataset.sortValue = selected ? '1' : '0';
      const toggle = row.querySelector('[data-dn-toggle]');
      toggle.checked = selected;
      // Networks above the level can only be removed, never added.
      toggle.disabled = !canAdd(row) && !selected;
      const warning = row.querySelector('[data-dn-invalid]');
      if (warning) warning.hidden = !(selected && !isEligible(row));
    }

    async function save(ids, enabled, control) {
      busy(control, true);
      const resp = await api('setDefaultNetworks', { user_id: userId, network_ids: ids, enabled });
      busy(control, false);
      toast(resp.message, resp.status);
      const stored = Array.isArray(resp.default_ids) ? new Set(resp.default_ids) : null;
      rows().forEach((row) => {
        const id = Number(row.dataset.networkId);
        // Without an answer (e.g. 403), undo the optimistic change of the clicked switch.
        showRow(row, stored ? stored.has(id) : (ids.includes(id) ? !enabled : isSelected(row)));
      });
      applyFilters();
      window.PanagTableSort.refresh(table);
    }

    table.addEventListener('change', (event) => {
      const toggle = event.target.closest('[data-dn-toggle]');
      if (toggle) save([Number(toggle.closest('tr').dataset.networkId)], toggle.checked, toggle);
    });

    root.querySelectorAll('[data-dn-bulk]').forEach((button) => button.addEventListener('click', () => {
      const enable = button.dataset.dnBulk === 'all';
      const ids = rows()
        .filter((row) => !row.hidden && (enable ? canAdd(row) && !isSelected(row) : isSelected(row)))
        .map((row) => Number(row.dataset.networkId));
      if (ids.length === 0) {
        toast('Nothing to change.', true);
        return;
      }
      save(ids, enable, button);
    }));

    [search, onlySelected, showAll].forEach((control) => control?.addEventListener('input', applyFilters));
    rows().forEach((row) => showRow(row, isSelected(row)));
    applyFilters();
  });
})();
