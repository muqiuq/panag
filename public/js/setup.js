// Initial setup (setup.php): QR code of the entered OTP secret.
(function () {
  const button = document.getElementById('showQrBtn');
  const secretInput = document.getElementById('otpSecretSetup');
  const nameInput = document.getElementById('setup-username-display');
  const modalEl = document.getElementById('qrModal');
  if (!button || !secretInput || !modalEl || !window.bootstrap) return;
  const modal = new window.bootstrap.Modal(modalEl);

  button.addEventListener('click', () => {
    const secret = secretInput.value.trim();
    if (!secret) return;
    const { issuer, digits, period, account } = button.dataset;
    document.getElementById('qrTitle').textContent = `OTP for ${nameInput?.value.trim() || 'Admin'} (${account})`;
    window.PanagOtp.renderQr(document.getElementById('qrBody'), window.PanagOtp.provisioningUri({ issuer, account, secret, digits, period }));
    modal.show();
  });
})();
