// Sortable tables (no dependencies).
//
//   <table data-sortable id="networks">        id is used to remember the order (localStorage)
//     <th data-sort="text|number|ip|none">     default text; "none" = not sortable
//     <td data-sort-value="1730000000">        optional raw value (timestamps, seconds, bytes, flags)
//   <input data-table-filter="networks">       optional: hides rows not containing the typed text
//
// Clicking a header (a <button>, so it works with the keyboard) sorts ascending, then descending; the
// active header gets aria-sort. Empty values always sort last. Rows with a colspan cell ("No entries")
// stay at the end. Tables whose rows are rendered by JavaScript call PanagTableSort.refresh(table).
(function () {
  const STORE_PREFIX = 'panag.sort.';

  function ipKey(value) {
    const m = String(value).match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?/);
    return m ? [+m[1], +m[2], +m[3], +m[4], m[5] === undefined ? 32 : +m[5]] : null;
  }

  function numberKey(value) {
    const m = String(value).replace(/'/g, '').match(/-?\d+(?:\.\d+)?/);
    return m ? parseFloat(m[0]) : null;
  }

  function key(type, value) {
    if (value === '') return null;
    if (type === 'number') return numberKey(value);
    if (type === 'ip') return ipKey(value);
    return value;
  }

  function compareKeys(type, a, b) {
    if (type === 'number') return a - b;
    if (type === 'ip') {
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
      return 0;
    }
    return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
  }

  function cellValue(row, index) {
    const cell = row.cells[index];
    if (!cell) return '';
    return (cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent).trim();
  }

  function headerCells(table) {
    const row = table.tHead && table.tHead.rows[0];
    return row ? Array.from(row.cells) : [];
  }

  function headerKey(th) {
    return th.dataset.sortKey || th.textContent.trim();
  }

  function isFixedRow(row) {
    return row.querySelector('[colspan]') !== null;
  }

  function sortBy(table, index, dir) {
    const th = headerCells(table)[index];
    if (!th) return;
    const type = th.dataset.sort || 'text';
    Array.from(table.tBodies).forEach((tbody) => {
      const rows = Array.from(tbody.rows);
      const fixed = rows.filter(isFixedRow);
      const decorated = rows.filter((r) => !isFixedRow(r)).map((row, i) => ({ row, i, k: key(type, cellValue(row, index)) }));
      decorated.sort((a, b) => {
        if (a.k === null || b.k === null) {
          return a.k === b.k ? a.i - b.i : (a.k === null ? 1 : -1);
        }
        const c = compareKeys(type, a.k, b.k);
        return (dir === 'asc' ? c : -c) || a.i - b.i;
      });
      tbody.append(...decorated.map((d) => d.row), ...fixed);
    });
    headerCells(table).forEach((cell) => {
      if (cell === th) cell.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
      else cell.removeAttribute('aria-sort');
    });
    table.dataset.sortIndex = String(index);
    table.dataset.sortDir = dir;
  }

  function save(table, th, dir) {
    if (!table.id) return;
    try {
      localStorage.setItem(STORE_PREFIX + table.id, JSON.stringify({ key: headerKey(th), dir }));
    } catch (e) { /* storage unavailable – sorting still works for this page view */ }
  }

  function restore(table) {
    if (!table.id) return;
    let stored = null;
    try {
      stored = JSON.parse(localStorage.getItem(STORE_PREFIX + table.id) || 'null');
    } catch (e) { /* ignore */ }
    if (!stored) return;
    const th = headerCells(table).find((cell) => cell.dataset.sort !== 'none' && headerKey(cell) === stored.key);
    if (th) sortBy(table, th.cellIndex, stored.dir === 'desc' ? 'desc' : 'asc');
  }

  function applyFilter(table) {
    const query = (table.dataset.filter || '').toLowerCase();
    Array.from(table.tBodies).forEach((tbody) => {
      Array.from(tbody.rows).forEach((row) => {
        if (!isFixedRow(row)) row.classList.toggle('filtered-out', query !== '' && !row.textContent.toLowerCase().includes(query));
      });
    });
  }

  function setup(table) {
    if (table.dataset.sortReady) return;
    table.dataset.sortReady = '1';
    headerCells(table).forEach((th) => {
      if (th.dataset.sort === 'none') return;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'sort-btn';
      button.append(...Array.from(th.childNodes));
      th.append(button);
      button.addEventListener('click', () => {
        const dir = th.getAttribute('aria-sort') === 'ascending' ? 'desc' : 'asc';
        sortBy(table, th.cellIndex, dir);
        save(table, th, dir);
      });
    });
    restore(table);
  }

  /** Re-apply the current order and filter after rows were (re-)rendered. */
  function refresh(table) {
    if (!table) return;
    setup(table);
    if (table.dataset.sortIndex !== undefined) sortBy(table, +table.dataset.sortIndex, table.dataset.sortDir || 'asc');
    applyFilter(table);
  }

  document.querySelectorAll('table[data-sortable]').forEach(setup);
  document.querySelectorAll('[data-table-filter]').forEach((input) => {
    const table = document.getElementById(input.dataset.tableFilter);
    if (!table) return;
    input.addEventListener('input', () => {
      table.dataset.filter = input.value.trim();
      applyFilter(table);
    });
  });

  window.PanagTableSort = { setup, refresh, sortBy };
})();
