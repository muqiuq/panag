// Admin user page (admin/user.php): tabs that follow the URL hash, OTP secret reveal.
(function () {
  const { api, toast, busy } = window.Panag;

  // #account, #networks, #durations, #otp – reloads and redirects (PRG) keep the tab.
  const tabButtons = Array.from(document.querySelectorAll('[data-user-tabs] [data-hash]'));
  function showTabFromHash() {
    const button = tabButtons.find((b) => b.dataset.hash === window.location.hash.slice(1));
    if (button && window.bootstrap) window.bootstrap.Tab.getOrCreateInstance(button).show();
  }
  tabButtons.forEach((button) => button.addEventListener('shown.bs.tab', () => {
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#${button.dataset.hash}`);
  }));
  window.addEventListener('hashchange', showTabFromHash);
  showTabFromHash();

  // The secret is fetched (and logged) only on request.
  const reveal = document.querySelector('[data-otp-reveal]');
  const output = document.querySelector('[data-otp-output]');
  if (!reveal || !output) return;
  const secretEl = output.querySelector('[data-otp-secret]');
  const qrEl = output.querySelector('[data-otp-qr]');

  reveal.addEventListener('click', async () => {
    busy(reveal, true);
    const data = await api('revealOtp', { user_id: Number(reveal.dataset.otpReveal) });
    busy(reveal, false);
    if (!data.status) {
      toast(data.message, false);
      return;
    }
    secretEl.textContent = data.secret;
    window.PanagOtp.renderQr(qrEl, data.uri);
    output.hidden = false;
    reveal.hidden = true;
  });

  output.querySelector('[data-otp-hide]')?.addEventListener('click', () => {
    secretEl.textContent = '';
    qrEl.replaceChildren();
    output.hidden = true;
    reveal.hidden = false;
    reveal.focus();
  });
})();
