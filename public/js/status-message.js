// Dashboard: the own status message for today (max. 100 characters, cleared at 03:00). Updates the
// "Status today" list (non-admins) or the users overview (admins) in place.
(function () {
  const { api, el, toast, busy } = window.Panag;
  const form = document.querySelector('[data-status-form]');
  if (!form) return;
  const input = form.querySelector('input[name="message"]');
  const counter = form.querySelector('[data-status-count]');
  const clear = form.querySelector('[data-status-clear]');
  const submit = form.querySelector('button[type="submit"]');

  const updateCount = () => { counter.textContent = String([...input.value].length); };
  input.addEventListener('input', updateCount);

  function show(userId, username, message, time) {
    const overviewCell = document.querySelector(`[data-status-of="${userId}"]`);
    if (overviewCell) overviewCell.textContent = message || '';
    const list = document.querySelector('[data-status-list]');
    if (!list) return;
    let item = list.querySelector(`[data-status-user="${userId}"]`);
    if (!message) {
      if (item) item.remove();
    } else {
      if (!item) {
        item = el('li', { 'data-status-user': String(userId) },
          el('strong', {}, username), ' ',
          el('span', { class: 'status-message', 'data-status-text': '' }), ' ',
          el('span', { class: 'text-muted small text-nowrap', 'data-status-time': '' }));
      }
      item.querySelector('[data-status-text]').textContent = message;
      item.querySelector('[data-status-time]').textContent = `since ${time}`;
      list.prepend(item); // newest first
    }
    const none = document.querySelector('[data-status-none]');
    if (none) none.hidden = list.children.length > 0;
  }

  async function save(message, control) {
    busy(control, true);
    const data = await api('setStatusMessage', { message });
    busy(control, false);
    toast(data.message, data.status);
    if (!data.status) return;
    input.value = data.status_message || '';
    updateCount();
    clear.disabled = !data.status_message;
    const now = new Date();
    show(data.user_id, data.username, data.status_message, `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`);
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    save(input.value, submit);
  });
  clear.addEventListener('click', () => save('', clear));
})();
