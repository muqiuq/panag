// Command palette: grant networks by typing – on the dashboard as a prominent field, on every page via
// "/" or Ctrl/Cmd+K as an overlay.
//
// Keyboard model (WAI-ARIA combobox with a listbox popup):
//   typing          the result list opens and filters live; nothing is selected yet
//   Enter or ↓      selects the first result – Enter never grants straight away, so a stray Enter is harmless
//   ↑ / ↓, hover    move the selection
//   Enter, click    run the selected result (grant or extend a network, run a command, open a page)
//   Esc             close the list (overlay: close the overlay)
//
// A single network is always granted with the user's extended duration. A trailing duration overrides it
// within the limits: "vpn 2h", "dc 1:30", "office 45m". Searching for an IP finds the network containing it.
(function () {
  if (document.body.dataset.palette !== 'on' || !window.Panag) return;
  const { api, el, toast, formatDuration, formatLeft, stampEntries, remainingSeconds, normalizeAddress, accessChanged, BASE_PATH } = window.Panag;

  // --- data ------------------------------------------------------------------------------------

  let data = null;
  let loadedAt = 0;
  let pending = null;
  let entries = [];
  const listeners = new Set(); // re-render open lists when data changes

  function load(force) {
    if (!force && data && Date.now() - loadedAt < 60000) return Promise.resolve(data);
    if (!pending) {
      pending = api('palette').then((resp) => {
        pending = null;
        if (resp.status) {
          data = resp;
          loadedAt = Date.now();
          entries = stampEntries(resp.entries);
          listeners.forEach((fn) => fn());
        }
        return data;
      });
    }
    return pending;
  }

  document.addEventListener('panag:access', (event) => {
    entries = event.detail.entries;
    listeners.forEach((fn) => fn());
  });

  // The dashboard embeds the data (no extra request – every router call costs CPU on small devices).
  const embedded = document.getElementById('paletteData');
  if (embedded) {
    try {
      data = JSON.parse(embedded.textContent);
      loadedAt = Date.now();
      entries = stampEntries(data.entries);
    } catch (e) { /* loaded on demand instead */ }
  }

  function activeEntry(network) {
    const address = normalizeAddress(network.address);
    return entries.find((e) => normalizeAddress(e.address) === address) || null;
  }

  // --- matching --------------------------------------------------------------------------------

  /** Mirrors parse_duration_input() for the forms a user types after a network name. */
  function parseDuration(token) {
    let m;
    if ((m = token.match(/^(\d{1,2}):([0-5]\d)$/))) return (+m[1]) * 3600 + (+m[2]) * 60;
    if ((m = token.match(/^(?:(\d{1,2})h)?(?:(\d{1,4})m(?:in)?)?$/)) && (m[1] || m[2])) return (+(m[1] || 0)) * 3600 + (+(m[2] || 0)) * 60;
    return null;
  }

  /** "dc 2h" → {text: "dc", duration: 7200, durationText: "2h"}. Bare numbers are never durations. */
  function parseQuery(raw) {
    const text = String(raw).trim().toLowerCase().replace(/\s+/g, ' ');
    const parts = text.split(' ');
    if (parts.length > 1) {
      const last = parts[parts.length - 1];
      const seconds = /[:hm]/.test(last) ? parseDuration(last) : null;
      if (seconds !== null) return { text: parts.slice(0, -1).join(' '), duration: seconds, durationText: last };
    }
    return { text, duration: null, durationText: '' };
  }

  function ipToInt(value) {
    const m = String(value).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m || m.slice(1).some((o) => +o > 255)) return null;
    return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + (+m[4]);
  }

  function prefixLength(cidr) {
    const bits = String(cidr).split('/')[1];
    if (bits === undefined) return 32;
    return /^\d{1,2}$/.test(bits) ? Number(bits) : NaN; // malformed ("10.0.0.0/") never matches
  }

  function cidrContains(cidr, ip) {
    const base = ipToInt(String(cidr).split('/')[0]);
    const bits = prefixLength(cidr);
    if (base === null || !(bits >= 0 && bits <= 32)) return false;
    if (bits === 0) return true;
    const mask = (~((1 << (32 - bits)) - 1)) >>> 0;
    return ((base & mask) >>> 0) === ((ip & mask) >>> 0);
  }

  function textScore(haystack, q) {
    if (!q) return 0;
    if (haystack === q) return 100;
    if (haystack.startsWith(q)) return 90;
    if (haystack.split(/[\s\-_/.()]+/).some((w) => w.startsWith(q))) return 75;
    if (haystack.includes(q)) return 55;
    const tokens = q.split(' ');
    if (tokens.length > 1 && tokens.every((t) => haystack.includes(t))) return 45;
    return 0;
  }

  /** Letters in order from a word start, e.g. "dc" → "Datacenter". Weak, so real matches always win. */
  function fuzzyScore(haystack, q) {
    if (q.length < 2 || q.includes(' ')) return 0;
    for (let start = 0; start < haystack.length; start++) {
      if (haystack[start] !== q[0] || (start > 0 && !/[\s\-_/.()]/.test(haystack[start - 1]))) continue;
      let j = 1;
      for (let i = start + 1; i < haystack.length && j < q.length; i++) {
        if (haystack[i] === q[j]) j++;
      }
      if (j === q.length) return 25;
    }
    return 0;
  }

  function scoreNetwork(network, q) {
    const ip = ipToInt(q);
    const address = network.address.toLowerCase();
    if (ip !== null) {
      // most specific network first
      return cidrContains(network.address, ip) ? 95 + prefixLength(network.address) / 100 : (address.startsWith(q) ? 80 : 0);
    }
    const name = network.name.toLowerCase();
    return Math.max(textScore(name, q), address.startsWith(q) ? 80 : 0, address.includes(q) ? 50 : 0, fuzzyScore(name, q));
  }

  function search(raw, showAll) {
    const q = parseQuery(raw);
    if (!data || (!q.text && !showAll)) return { q, items: [] };
    const items = [];
    data.networks.forEach((network) => {
      const score = q.text ? scoreNetwork(network, q.text) : 60;
      if (score > 0) items.push({ type: 'network', network, score: score + (network.is_default ? 0.5 : 0), label: network.name });
    });
    if (q.duration === null) {
      data.commands.forEach((command) => {
        const score = q.text ? Math.max(textScore(command.label.toLowerCase(), q.text), textScore(command.keywords, q.text) * 0.8) : 20;
        if (score > 0) items.push({ type: 'command', command, score: score - 5, label: command.label });
      });
      if (q.text) {
        data.users.forEach((user) => {
          const score = Math.max(textScore(user.name.toLowerCase(), q.text), user.ip.startsWith(q.text) ? 80 : 0);
          if (score > 0) items.push({ type: 'user', user, score: score - 10, label: user.name });
        });
      }
    }
    items.sort((a, b) => b.score - a.score || a.label.localeCompare(b.label, undefined, { numeric: true }));
    return { q, items: items.slice(0, 15) };
  }

  // --- rendering -------------------------------------------------------------------------------

  function durationProblem(seconds) {
    if (seconds === null) return null;
    if (seconds < data.durations.min) return `at least ${formatDuration(data.durations.min)}`;
    if (seconds > data.durations.max_extended) return `at most ${formatDuration(data.durations.max_extended)}`;
    return null;
  }

  function renderOption(item, id, q) {
    const option = (main, meta) => el('li', { role: 'option', id, class: 'palette-option', 'aria-selected': 'false' },
      el('span', { class: 'palette-main' }, main), el('span', { class: 'palette-meta' }, meta));

    if (item.type === 'network') {
      const n = item.network;
      const entry = activeEntry(n);
      const left = entry ? remainingSeconds(entry) : null;
      const duration = q.duration ?? data.durations.extended;
      const problem = durationProblem(q.duration);
      return option(
        [el('span', { class: 'palette-label' }, n.name), ' ', el('code', { class: 'palette-sub' }, n.address),
          n.is_default ? el('span', { class: 'badge text-bg-secondary ms-2' }, 'Default') : null],
        [entry ? el('span', { class: 'palette-status' }, left === null ? 'active, permanent' : `active, ${formatLeft(left)} left`) : null,
          el('span', { class: problem ? 'palette-hint text-danger' : 'palette-hint' },
            problem ? `Duration must be ${problem}` : `${entry ? 'Extend' : 'Grant'} · ${formatDuration(duration)}`)]);
    }
    if (item.type === 'user') {
      const u = item.user;
      return option([el('span', { class: 'palette-label' }, `User: ${u.name}`), ' ', el('code', { class: 'palette-sub' }, u.ip)],
        el('span', { class: 'palette-hint' }, `Open user · ${u.role}`));
    }
    const c = item.command;
    return option(el('span', { class: 'palette-label' }, c.label), el('span', { class: 'palette-hint' }, c.hint || ''));
  }

  // --- actions ---------------------------------------------------------------------------------

  /** @return {Promise<{ok: boolean, message?: string, navigating?: boolean}>} */
  async function run(item, q) {
    if (item.type === 'user' || (item.type === 'command' && item.command.path)) {
      window.location.href = `${BASE_PATH}/${(item.user || item.command).path}`;
      return { ok: false, navigating: true };
    }
    let resp;
    if (item.type === 'network') {
      const body = { network_id: item.network.id };
      if (q.duration !== null) body.duration = q.durationText;
      resp = await api('grantNetwork', body);
    } else {
      resp = await api(item.command.api, item.command.body || {});
    }
    if (resp.status && resp.theme) window.Panag.applyTheme(resp.theme, resp.dark);
    toast(resp.message, resp.status);
    if (resp.entries) accessChanged(resp.entries);
    return { ok: Boolean(resp.status), message: resp.message };
  }

  // Last pointer position, document-wide (capture phase: updated before the list's own listener runs).
  let pointer = '';
  document.addEventListener('mousemove', (event) => { pointer = `${event.clientX},${event.clientY}`; }, true);

  // --- combobox --------------------------------------------------------------------------------

  let instance = 0;

  /** Wire an <input> + <ul> pair as combobox. opts.overlay: Esc is left to the <dialog>. */
  function combobox(input, list, opts) {
    const id = list.id || `palette-list-${++instance}`;
    list.id = id;
    const status = el('div', { class: 'visually-hidden', role: 'status', 'aria-live': 'polite' });
    const empty = el('div', { class: 'palette-empty', hidden: true }, 'No matching network or command.');
    // In the overlay, toasts are covered by the modal dialog – errors are shown inside it as well.
    const error = el('div', { class: 'palette-error', role: 'alert', hidden: true });
    list.after(empty, status);
    if (opts.overlay) status.after(error);
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-expanded', 'false');
    input.setAttribute('aria-controls', id);
    input.setAttribute('autocomplete', 'off');
    input.setAttribute('spellcheck', 'false');
    list.setAttribute('role', 'listbox');

    let items = [];
    let query = parseQuery('');
    let active = -1;
    let open = false;
    let showAll = false;
    let running = false;
    // Hover only selects after a real pointer movement: a list appearing (or scrolling) under a resting
    // pointer must not select anything, otherwise the first Enter would grant straight away.
    // null = pointer position unknown, the first sighting only becomes the reference.
    let pointerAnchor = null;

    function setOpen(value) {
      open = value;
      list.hidden = !value;
      input.setAttribute('aria-expanded', value ? 'true' : 'false');
      if (!value) {
        empty.hidden = true;
        active = -1;
        input.removeAttribute('aria-activedescendant');
      }
    }

    function render() {
      if (!input.value.trim() && !showAll) {
        setOpen(false);
        return;
      }
      if (!data) load(); // renders again via listeners once loaded
      const keep = active >= 0 && items[active] ? items[active] : null;
      ({ q: query, items } = search(input.value, showAll));
      pointerAnchor = pointer || null;
      // Keep the selection only while the same result is still listed (data refresh), never after typing.
      active = keep ? items.findIndex((i) => i.type === keep.type && i.label === keep.label) : -1;
      list.replaceChildren(...items.map((item, i) => renderOption(item, `${id}-opt-${i}`, query)));
      setOpen(true);
      empty.hidden = items.length > 0 || !data;
      list.hidden = items.length === 0;
      status.textContent = data ? `${items.length} result${items.length === 1 ? '' : 's'}` : 'Loading…';
      highlight();
    }

    function highlight() {
      Array.from(list.children).forEach((option, i) => {
        option.setAttribute('aria-selected', i === active ? 'true' : 'false');
        option.classList.toggle('active', i === active);
      });
      const current = list.children[active];
      if (current) {
        input.setAttribute('aria-activedescendant', current.id);
        current.scrollIntoView({ block: 'nearest' });
      } else {
        input.removeAttribute('aria-activedescendant');
      }
    }

    function select(index) {
      if (!items.length) return;
      active = Math.max(0, Math.min(items.length - 1, index));
      pointerAnchor = pointer || null;
      highlight();
    }

    async function execute(index) {
      const item = items[index];
      if (!item || running) return;
      running = true;
      input.setAttribute('aria-busy', 'true');
      list.classList.add('is-running');
      let result = { ok: false };
      try {
        result = await run(item, query);
      } finally {
        running = false;
        input.removeAttribute('aria-busy');
        list.classList.remove('is-running');
      }
      if (result.navigating) return;
      if (!result.ok) {
        // Keep the query so it can be corrected (e.g. "vpn 20h" → "vpn 2h").
        error.textContent = result.message || 'Request failed.';
        error.hidden = false;
        input.focus();
        return;
      }
      error.hidden = true;
      input.value = '';
      showAll = false;
      setOpen(false);
      if (opts.onDone) opts.onDone(); else input.focus();
    }

    input.addEventListener('input', () => {
      error.hidden = true;
      showAll = false;
      active = -1;
      render();
    });
    input.addEventListener('focus', () => load());
    input.addEventListener('blur', () => {
      if (!opts.overlay) setTimeout(() => { if (document.activeElement !== input) setOpen(false); }, 150);
    });
    input.addEventListener('keydown', (event) => {
      if (event.isComposing) return;
      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          if (!open) {
            showAll = !input.value.trim();
            render();
            select(0);
          } else {
            select(active + 1);
          }
          break;
        case 'ArrowUp':
          event.preventDefault();
          if (open) select(active - 1);
          break;
        case 'Enter':
          event.preventDefault();
          if (open && active >= 0) {
            execute(active);
          } else if (input.value.trim() || showAll) {
            // first Enter only selects – see the keyboard model above
            if (!open) render();
            select(0);
          }
          break;
        case 'Escape':
          if (opts.overlay) return; // the dialog closes itself
          if (open) {
            event.preventDefault();
            setOpen(false);
          } else if (input.value) {
            event.preventDefault();
            input.value = '';
          }
          break;
        case 'Tab':
          setOpen(false);
          break;
        default:
      }
    });

    // Mouse: hover selects, click runs. mousedown must not steal the focus from the input.
    list.addEventListener('mousedown', (event) => event.preventDefault());
    list.addEventListener('mousemove', (event) => {
      if (pointerAnchor === null) {
        pointerAnchor = pointer;
        return;
      }
      if (pointer === pointerAnchor) return;
      const option = event.target.closest('[role="option"]');
      const index = option ? Array.prototype.indexOf.call(list.children, option) : -1;
      if (index >= 0 && index !== active) select(index);
    });
    list.addEventListener('click', (event) => {
      const option = event.target.closest('[role="option"]');
      if (option) execute(Array.prototype.indexOf.call(list.children, option));
    });

    listeners.add(() => { if (open) render(); });
    setOpen(false);
    return {
      reset() {
        error.hidden = true;
        input.value = '';
        showAll = false;
        setOpen(false);
      },
    };
  }

  // --- placement: dashboard field or overlay ---------------------------------------------------

  const inlineInput = document.getElementById('paletteInput');
  if (inlineInput) combobox(inlineInput, document.getElementById('paletteList'), {});

  let dialog = null;
  let overlay = null;

  function openOverlay() {
    if (!dialog) {
      const input = el('input', { type: 'text', class: 'form-control form-control-lg', 'aria-label': 'Search networks and commands', placeholder: 'Network, IP or command – e.g. "vpn", "10.10.0.5", "dc 2h"' });
      const list = el('ul', { class: 'palette-list list-unstyled mb-0', id: 'paletteOverlayList' });
      dialog = el('dialog', { class: 'palette-dialog', 'aria-label': 'Command palette', 'data-testid': 'palette-dialog' },
        el('div', { class: 'palette-box' }, input, list,
          el('div', { class: 'palette-footer' }, '↑↓ select · Enter run · Esc close')));
      document.body.append(dialog);
      overlay = combobox(input, list, { overlay: true, onDone: () => dialog.close() });
      dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
      dialog.addEventListener('close', () => overlay.reset());
    }
    load();
    if (!dialog.open) dialog.showModal();
    dialog.querySelector('input').focus();
  }

  function openPalette() {
    if (inlineInput) {
      inlineInput.scrollIntoView({ block: 'center' });
      inlineInput.focus();
      inlineInput.select();
    } else {
      openOverlay();
    }
  }

  document.addEventListener('keydown', (event) => {
    if ((event.key === 'k' || event.key === 'K') && (event.ctrlKey || event.metaKey) && !event.altKey) {
      event.preventDefault();
      openPalette();
      return;
    }
    const target = event.target instanceof Element ? event.target : null;
    const typing = target && target.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"]');
    if (event.key === '/' && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      openPalette();
    }
  });
  document.querySelectorAll('[data-palette-open]').forEach((button) => button.addEventListener('click', openPalette));

  window.PanagPalette = { open: openPalette };
})();
