/* Local sample behavior only. Mutation receipts are authored HTMX fixtures. */
(() => {
  const table = document.querySelector('.sessions-table tbody');
  const initialRows = table.innerHTML;
  const feedback = document.querySelector('#sessions-feedback');
  const dialog = document.querySelector('#delete-gateway-dialog');
  let pendingGateway = null;
  const updateCount = () => {
    const count = table.querySelectorAll('[data-gateway-session]').length;
    document.querySelectorAll('[data-gateway-count]').forEach(node => { node.textContent = count; });
  };
  const notice = text => {
    const node = document.createElement('div');
    node.className = 'notice';
    node.textContent = text + ' Sample change only.';
    feedback.replaceChildren(node);
  };
  document.addEventListener('change', event => {
    if (!event.target.matches('[data-app-session]')) return;
    const row = event.target.closest('tr');
    const count = row.querySelectorAll('[data-app-session]:checked').length;
    row.querySelector('.delete-apps').disabled = count === 0;
    row.querySelector('[data-selection-count]').textContent = count ? `(${count})` : '';
  });
  document.addEventListener('click', event => {
    const trash = event.target.closest('[data-delete-gateway]');
    if (trash && !trash.disabled) {
      pendingGateway = trash.closest('tr');
      dialog.querySelector('[data-dialog-session]').textContent = pendingGateway.dataset.sessionName;
      dialog.querySelector('[data-dialog-account]').textContent = pendingGateway.dataset.account;
      const count = pendingGateway.querySelectorAll('[data-app-session]').length;
      dialog.querySelector('[data-dialog-apps]').textContent = count ? `all ${count} of its app sessions` : 'the gateway login';
      dialog.showModal();
      dialog.querySelector('[data-cancel-delete]').focus();
    }
    if (event.target.closest('[data-cancel-delete]')) dialog.close();
    if (event.target.closest('[data-reset-sessions]')) {
      table.innerHTML = initialRows;
      htmx.process(table);
      updateCount();
      notice('Sample sessions restored.');
    }
  });
  document.addEventListener('htmx:afterSwap', event => {
    const target = event.detail.target;
    if (target.matches('.apps-cell')) {
      // Remove the selected sample records from this row, keeping its gateway.
      const selected = target.querySelectorAll('[data-app-session]:checked');
      const count = selected.length;
      selected.forEach(input => input.closest('.app-chip').remove());
      target.querySelector('[data-sample-receipt]')?.remove();
      const button = target.querySelector('.delete-apps');
      button.disabled = true;
      target.querySelector('[data-selection-count]').textContent = '';
      if (!target.querySelector('[data-app-session]')) {
        const empty = document.createElement('span');
        empty.className = 'muted no-apps';
        empty.textContent = 'No app sessions';
        empty.tabIndex = -1;
        target.replaceChildren(empty);
        empty.focus();
      } else {
        target.querySelector('[data-app-session]').focus();
      }
      notice(`${count} app session${count === 1 ? '' : 's'} deleted. The gateway session is still active.`);
    }
    if (target.id === 'delete-receipt' && pendingGateway) {
      const name = pendingGateway.dataset.sessionName;
      const next = pendingGateway.nextElementSibling || pendingGateway.previousElementSibling;
      dialog.close();
      pendingGateway.remove();
      pendingGateway = null;
      updateCount();
      next?.querySelector('[data-delete-gateway]:not(:disabled), [data-app-session]:not(:disabled)')?.focus();
      notice(`Gateway session for ${name} and its app sessions deleted.`);
    }
  });
})();
