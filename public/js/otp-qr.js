// OTP QR codes for authenticator apps (needs js/kjua.min.js): admin user page and setup.
(function () {
  function provisioningUri({ issuer, account, secret, digits, period }) {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&digits=${digits}&period=${period}`;
  }

  /** kjua 0.1.1 renders "image" (an <img> with a data: URL, allowed by the CSP) or "canvas" – no SVG. */
  function renderQr(container, uri) {
    const img = window.kjua({ text: uri, size: 220, quiet: 2, ecLevel: 'M', render: 'image' });
    img.alt = 'QR code for the authenticator app';
    container.replaceChildren(img);
  }

  window.PanagOtp = { provisioningUri, renderQr };
})();
