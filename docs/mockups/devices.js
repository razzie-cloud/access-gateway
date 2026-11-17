/* Mockup-only state. HTMX fetches local receipts without sending draft values. */
(() => {
  const dialog = document.querySelector('#delete-device-dialog');
  let pendingDevice = null;
  const notice = text => {
    const node = document.createElement('div');
    node.className = 'notice';
    node.textContent = text + ' Sample change only; Refresh restores the fixtures.';
    document.querySelector('#devices-feedback').replaceChildren(node);
  };
  const finishEditing = row => {
    row.querySelector('.device-rename').hidden = true;
    row.querySelector('.device-name-line').hidden = false;
    row.querySelector('[data-edit-device]').focus({ preventScroll: true });
  };
  const cancelEditing = row => {
    row.querySelector('input').value = row.querySelector('[data-device-name]').textContent;
    row.querySelector('input').setCustomValidity('');
    finishEditing(row);
  };
  document.addEventListener('click', event => {
    const edit = event.target.closest('[data-edit-device]');
    if (edit) {
      const row = edit.closest('.device-row');
      const input = row.querySelector('input');
      input.value = row.querySelector('[data-device-name]').textContent;
      input.setCustomValidity('');
      row.querySelector('.device-name-line').hidden = true;
      row.querySelector('.device-rename').hidden = false;
      input.focus();
      input.select();
    }
    const cancel = event.target.closest('[data-cancel-rename]');
    if (cancel) cancelEditing(cancel.closest('.device-row'));
    const trash = event.target.closest('[data-delete-device]');
    if (trash && !trash.disabled) {
      pendingDevice = trash.closest('.device-row');
      dialog.querySelector('[data-dialog-device]').textContent = pendingDevice.querySelector('[data-device-name]').textContent;
      dialog.showModal();
      dialog.querySelector('[data-cancel-device-delete]').focus();
    }
    if (event.target.closest('[data-cancel-device-delete]')) dialog.close();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && event.target.closest('.device-rename')) {
      event.preventDefault();
      cancelEditing(event.target.closest('.device-row'));
    }
  });
  document.addEventListener('input', event => {
    if (!event.target.matches('.device-rename input')) return;
    const value = event.target.value.trim();
    event.target.setCustomValidity(!value ? 'Enter a device name.' : /[\u0000-\u001f\u007f-\u009f]/u.test(value) ? 'Use a name without control characters.' : '');
  });
  document.addEventListener('htmx:afterSwap', event => {
    const target = event.detail.target;
    if (target.matches('.device-receipt')) {
      const row = target.closest('.device-row');
      const name = row.querySelector('input').value.trim();
      row.querySelector('[data-device-name]').textContent = name;
      row.querySelector('[data-edit-device]').setAttribute('aria-label', `Rename ${name}`);
      row.querySelector('[data-delete-device]').setAttribute('aria-label', `Remove ${name}`);
      row.querySelector('.device-rename').setAttribute('aria-label', `Rename ${name}`);
      target.replaceChildren();
      finishEditing(row);
      notice(`Device renamed to “${name}”.`);
    }
    if (target.id === 'device-delete-receipt' && pendingDevice) {
      const name = pendingDevice.querySelector('[data-device-name]').textContent;
      const next = pendingDevice.nextElementSibling?.matches('.device-row') ? pendingDevice.nextElementSibling : pendingDevice.previousElementSibling;
      dialog.close();
      pendingDevice.remove();
      pendingDevice = null;
      const count = document.querySelectorAll('#devices .device-row').length;
      document.querySelector('#devices [data-device-count]').textContent = count;
      (next?.querySelector('[data-edit-device]') || document.querySelector('#devices [data-scope-refresh]')).focus({ preventScroll: true });
      if (!count) {
        const empty = document.createElement('p');
        empty.className = 'devices-empty';
        empty.textContent = 'No registered devices in this sample. Refresh to restore them.';
        document.querySelector('#devices .card-caption').before(empty);
      }
      notice(`Device “${name}” removed.`);
    }
  });
  const failedRename = event => {
    if (event.detail.elt.closest('.device-rename')) notice('The sample rename could not load. Your draft is still here; try again.');
  };
  document.addEventListener('htmx:responseError', failedRename);
  document.addEventListener('htmx:sendError', failedRename);
})();
