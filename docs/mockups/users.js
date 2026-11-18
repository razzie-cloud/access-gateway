/* Browser-local proposal. Only authored HTMX receipts are requested. */
(() => {
  const users = document.querySelector('#users');
  const dialog = document.querySelector('#disable-user-dialog');
  if (!users || !dialog) return;
  let pending = null;
  const revoked = new Set();
  const confirm = dialog.querySelector('[data-confirm-disable-user]');
  const closeDialog = () => {
    const input = pending;
    pending = null;
    dialog.close();
    input?.focus({ preventScroll: true });
  };
  const notice = message => {
    const node = document.createElement('div');
    node.className = 'notice';
    node.textContent = message + ' Sample change only; reload restores all users and sessions.';
    document.querySelector('#users-feedback').replaceChildren(node);
  };
  const updateSwitch = (input, enabled) => {
    input.checked = enabled;
    input.closest('label').querySelector('[data-user-status]').textContent = enabled ? 'On' : 'Off';
  };
  const removeRevokedSessions = () => {
    const panel = document.querySelector('#sessions');
    panel.querySelectorAll('[data-gateway-session]').forEach(row => {
      if (revoked.has(row.dataset.account)) row.remove();
    });
    const count = panel.querySelectorAll('[data-gateway-session]').length;
    panel.querySelector('[data-gateway-count]').textContent = count;
    if (!count && !panel.querySelector('.activity-empty')) {
      const empty = document.createElement('p');
      empty.className = 'activity-empty';
      empty.textContent = 'No active sessions for this selection.';
      panel.querySelector('.overflow-auto').after(empty);
    }
  };
  users.addEventListener('change', event => {
    const input = event.target.closest('[data-user-switch]');
    if (!input || input.disabled) return;
    if (pending) {
      input.checked = input.closest('label').querySelector('[data-user-status]').textContent === 'On';
      return;
    }
    // Keep the committed state until the local receipt has loaded.
    const enabling = input.checked;
    updateSwitch(input, !enabling);
    pending = input;
    if (enabling) {
      input.disabled = true;
      htmx.ajax('GET', '/access-gateway/docs/mockups/fragments/user-enabled.html', { target: '#user-enable-receipt' }).catch(() => {});
      return;
    }
    dialog.querySelector('[data-disable-username]').textContent = input.dataset.userSwitch;
    dialog.querySelector('[data-disable-error]').textContent = '';
    dialog.showModal();
    dialog.querySelector('[data-cancel-disable-user]').focus();
  });
  dialog.querySelector('[data-cancel-disable-user]').addEventListener('click', closeDialog);
  dialog.addEventListener('cancel', event => {
    event.preventDefault();
    if (!confirm.classList.contains('htmx-request')) closeDialog();
  });
  document.addEventListener('htmx:afterSwap', event => {
    const target = event.detail.target;
    if (target.id === 'sessions') removeRevokedSessions();
    if (target.id === 'user-disable-receipt' && pending) {
      const input = pending;
      updateSwitch(input, false);
      revoked.add(input.dataset.userSwitch);
      removeRevokedSessions();
      notice(`${input.dataset.userSwitch} disabled. All their gateway and app sessions were deleted. Further login attempts are blocked until re-enabled.`);
      closeDialog();
    }
    if (target.id === 'user-enable-receipt' && pending) {
      const input = pending;
      updateSwitch(input, true);
      input.disabled = false;
      pending = null;
      notice(`${input.dataset.userSwitch} enabled. They can sign in again; deleted sessions are not restored.`);
      input.focus({ preventScroll: true });
    }
  });
  const failed = event => {
    if (event.detail.elt === confirm) {
      dialog.querySelector('[data-disable-error]').textContent = 'The sample action could not load. The user is still enabled. Try again or cancel.';
    } else if (event.detail.target?.id === 'user-enable-receipt' && pending) {
      pending.disabled = false;
      notice('The sample action could not load. The user is still disabled. Try again.');
      pending.focus({ preventScroll: true });
      pending = null;
    }
  };
  document.addEventListener('htmx:responseError', failed);
  document.addEventListener('htmx:sendError', failed);
})();
