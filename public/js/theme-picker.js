// Profile → Theme: selecting a tile previews the theme on the whole page right away; "Save theme" keeps it.
(function () {
  const form = document.querySelector('[data-theme-picker]');
  if (!form) return;
  const note = form.querySelector('[data-theme-preview-note]');
  const saved = form.dataset.savedTheme;
  form.addEventListener('change', (event) => {
    const input = event.target;
    if (input.name !== 'theme') return;
    window.Panag.applyTheme(input.value, input.dataset.dark === '1');
    if (note) note.hidden = input.value === saved;
  });
})();
