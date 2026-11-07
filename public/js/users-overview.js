// Users overview (admin dashboard, status page): revoke all entries of a user.
(function () {
  const { api, toast, busy } = window.Panag;
  document.querySelectorAll('[data-revoke-all]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!window.confirm(`Revoke all access of ${button.dataset.username}?`)) return;
      busy(button, true);
      const data = await api('revokeAccess', { user_id: Number(button.dataset.revokeAll) });
      busy(button, false);
      toast(data.message, data.status);
      if (data.status) setTimeout(() => window.location.reload(), 800);
    });
  });
})();
