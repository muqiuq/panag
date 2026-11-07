// Profile: duration presets and a live "valid until" hint.
(function () {
  /** Mirrors parse_duration_input() in src/durations.php (subset: h:mm, h:mm:ss, minutes, 1h30m). */
  function parseDuration(value) {
    const v = String(value).toLowerCase().replace(/\s+/g, '');
    let m;
    if ((m = v.match(/^(\d{1,3}):([0-5]\d)$/))) return (+m[1]) * 3600 + (+m[2]) * 60;
    if ((m = v.match(/^(\d{1,3}):([0-5]\d):([0-5]\d)$/))) return (+m[1]) * 3600 + (+m[2]) * 60 + (+m[3]);
    if ((m = v.match(/^\d{1,5}$/))) return (+v) * 60;
    if (v && (m = v.match(/^(?:(\d{1,3})h)?(?:(\d{1,5})m(?:in)?)?(?:(\d{1,6})s)?$/))) return (+(m[1] || 0)) * 3600 + (+(m[2] || 0)) * 60 + (+(m[3] || 0));
    return null;
  }

  document.querySelectorAll('[data-duration-field]').forEach((field) => {
    const input = field.querySelector('input');
    const until = field.querySelector('[data-until]');
    const update = () => {
      const seconds = parseDuration(input.value);
      if (!until) return;
      if (seconds === null) {
        until.textContent = ' · invalid';
        return;
      }
      const t = new Date(Date.now() + seconds * 1000);
      until.textContent = ` · valid until approx. ${t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    };
    field.querySelectorAll('[data-preset]').forEach((btn) => btn.addEventListener('click', () => {
      input.value = btn.dataset.preset;
      update();
      input.focus();
    }));
    input.addEventListener('input', update);
    update();
  });
})();
