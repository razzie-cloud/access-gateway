"use strict";

// HTMX owns account views and forms. WebAuthn requires this small browser API bridge.
const status = (message) => { document.getElementById("status").textContent = message; };
const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), c => c.charCodeAt(0)).buffer;
const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Delegation also covers registration links inserted or replaced by HTMX.
document.addEventListener("click", async event => {
  const button = event.target.closest("[data-copy-registration-link]");
  if (!button) return;
  const result = button.closest(".registration-result");
  const input = result.querySelector("#registration-link");
  const feedback = result.querySelector("[data-copy-feedback]");
  try {
    await navigator.clipboard.writeText(input.value);
    feedback.textContent = "Registration link copied.";
  } catch {
    input.focus();
    input.select();
    feedback.textContent = "Unable to copy automatically. Copy the selected link manually.";
  }
});

async function api(path, body) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

// Tokens stay out of request URLs, access logs, referrers and HTMX history snapshots.
const tokenInput = document.getElementById("link-token");
let invitationReady;
function applyInvitation(details) {
  const label = document.getElementById("invitation-username");
  if (label) {
    label.hidden = !details.newUser;
    label.querySelector("input").disabled = !details.newUser;
  }
  const choices = document.getElementById("registration-choices");
  if (choices) choices.hidden = details.newUser;
  if (details.newUser) {
    document.getElementById("enrollment-description").textContent = "Choose your username and create your first passkey to join Razzie Cloud.";
    document.getElementById("registration-help").textContent = "Your first passkey is required to create an account. One-time login is available for existing accounts.";
  }
}
function prepareInvitation() {
  if (!/^[a-f0-9]{64}$/.test(tokenInput.value)) return Promise.reject(new Error("Open a complete registration link, or ask for a new one."));
  if (!invitationReady) {
    invitationReady = api("/api/register/link", { linkToken: tokenInput.value }).catch(error => {
      invitationReady = null;
      throw error;
    });
  }
  return invitationReady.then(details => { applyInvitation(details); return details; });
}

// HTMX swaps only the action controls. The surrounding form retains the token;
// mode selection never consumes it or transmits it in a GET request.
document.addEventListener("htmx:afterSwap", async event => {
  if (!tokenInput || event.detail.target.id !== "enrollment-options") return;
  try {
    const details = await prepareInvitation();
    const options = document.getElementById("enrollment-options");
    if (details.newUser && options.dataset.registrationMode === "login") {
      document.getElementById("registration-choices").hidden = true;
      status("Create your first passkey to set up your account.");
      return;
    }
    document.getElementById("registration-submit").disabled = false;
    status("");
    (document.getElementById("device-name") || document.getElementById("registration-submit")).focus();
  } catch (error) { status(error.message); }
});
if (tokenInput) {
  tokenInput.value = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  if (!/^[a-f0-9]{64}$/.test(tokenInput.value)) {
    document.querySelector("#device-registration button").disabled = true;
    status("Open a complete registration link, or ask for a new one.");
  } else {
    prepareInvitation().catch(error => status(error.message)).finally(() => {
      document.querySelector("#device-registration button").disabled = false;
    });
  }
}

async function passkeyCeremony(mode, body, credentialID) {
  const options = await api(`/api/${mode}/begin`, body);
  options.publicKey.challenge = decode(options.publicKey.challenge);
  if (mode === "register") options.publicKey.user.id = decode(options.publicKey.user.id);
  for (const field of ["excludeCredentials", "allowCredentials"]) {
    if (options.publicKey[field]) options.publicKey[field] = options.publicKey[field].map(c => ({ ...c, id: decode(c.id) }));
  }
  if (credentialID) {
    // Prove possession of the passkey just enrolled, even on a browser that
    // already has other passkeys. Never fall back to an empty allowlist.
    options.publicKey.allowCredentials = (options.publicKey.allowCredentials || []).filter(c => encode(c.id) === credentialID);
    if (!options.publicKey.allowCredentials.length) throw new Error("The new passkey is unavailable. Open the account page to sign in.");
  }
  status(mode === "register" ? "Complete the passkey prompt on your device." : "Complete the passkey prompt to sign in.");
  const credential = mode === "register" ? await navigator.credentials.create(options) : await navigator.credentials.get(options);
  if (!credential) throw new Error("No credential was returned. You can try again.");
  const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
  if (mode === "register") response.attestationObject = encode(credential.response.attestationObject);
  else {
    response.authenticatorData = encode(credential.response.authenticatorData);
    response.signature = encode(credential.response.signature);
    response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
  }
  const result = await api(`/api/${mode}/finish`, { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() });
  return { result, credentialID: encode(credential.rawId) };
}

// A canceled sign-in retries login without reusing a consumed enrollment link.
const pendingSignIns = new WeakMap();
document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-webauthn]");
  if (!form) return;
  event.preventDefault();
  if (form.getAttribute("aria-busy") === "true") return;
  const button = form.querySelector("button");
  button.disabled = true;
  form.setAttribute("aria-busy", "true");
  const choices = document.getElementById("registration-choices");
  if (choices) { choices.open = false; choices.hidden = true; }
  try {
    const linkLogin = tokenInput && document.getElementById("enrollment-options")?.dataset.registrationMode === "login";
    if (linkLogin) {
      const details = await prepareInvitation();
      if (details.newUser) throw new Error("Create your first passkey to set up your account.");
      await api("/api/login/link", { linkToken: tokenInput.value });
      tokenInput.value = "";
      location.replace("/");
      return;
    }
    if (!window.PublicKeyCredential) throw new Error("Passkeys require a supported browser and HTTPS (or localhost).");
    const mode = form.dataset.webauthn;
    if (!pendingSignIns.has(form)) {
      if (tokenInput) await prepareInvitation();
      const completed = await passkeyCeremony(mode, Object.fromEntries(new FormData(form)));
      if (mode === "register") {
        pendingSignIns.set(form, { username: completed.result.username, credentialID: completed.credentialID });
        // Enrollment is durable even if the following login is canceled.
        for (const name of ["linkToken", "token"]) {
          const input = form.elements.namedItem(name);
          if (input) input.value = "";
        }
        for (const input of form.querySelectorAll("input, select, textarea")) input.disabled = true;
        button.textContent = "Sign in with your new passkey";
        if (choices) choices.hidden = true;
      }
    }
    const pending = pendingSignIns.get(form);
    if (pending) await passkeyCeremony("login", { username: pending.username }, pending.credentialID);
    if (location.pathname === "/auth/authorize") {
      location.reload();
      return;
    }
    if (tokenInput) {
      tokenInput.value = "";
      location.replace("/");
      return;
    }
    status("Signed in.");
    pendingSignIns.delete(form);
    htmx.trigger(document.body, "reloadState");
  } catch (error) {
    status(pendingSignIns.has(form) ? `Passkey registered. Sign-in did not complete: ${error.message} Choose “Sign in with your new passkey” to retry.` : error.message);
  }
  finally {
    button.disabled = false;
    form.removeAttribute("aria-busy");
    if (choices && !pendingSignIns.has(form) && tokenInput?.value) {
      // A failed operation retains the token and lets the user retry or change
      // modes. Invitations continue to hide the existing-account alternative.
      prepareInvitation().catch(() => {});
    }
  }
});

// Display server-rendered validation and authorization errors in the form's target.
document.addEventListener("htmx:beforeSwap", (event) => {
  if ([400, 401, 403, 404, 405, 409, 413, 415, 429, 500, 503].includes(event.detail.xhr.status)) {
    event.detail.shouldSwap = true;
    event.detail.isError = false;
  }
});
document.addEventListener("htmx:responseError", () => status("The request failed. Please try again."));
document.addEventListener("htmx:sendError", () => status("Unable to reach the gateway. Please try again."));

// Replacing a panel removes its focused Refresh button. Restore keyboard focus
// without moving the page or taking focus back after the user moves elsewhere.
const refreshFocus = new WeakSet();
const registrationRequests = new WeakMap();
document.addEventListener("htmx:beforeRequest", event => {
  const source = event.detail.elt;
  const registrationForm = source.closest("#device-registration");
  if (registrationForm) {
    if (registrationForm.getAttribute("aria-busy") === "true") {
      event.preventDefault();
      return;
    }
    registrationRequests.set(event.detail.xhr, registrationForm);
    registrationForm.setAttribute("aria-busy", "true");
    document.getElementById("registration-submit").disabled = true;
  }
  if (source.matches("[data-activity-refresh]") && document.activeElement === source) {
    refreshFocus.add(event.detail.xhr);
  }
});
document.addEventListener("htmx:afterRequest", event => {
  const form = registrationRequests.get(event.detail.xhr);
  if (!form) return;
  registrationRequests.delete(event.detail.xhr);
  form.removeAttribute("aria-busy");
  document.getElementById("registration-submit").disabled = false;
});
document.addEventListener("htmx:afterSettle", event => {
  if (!refreshFocus.has(event.detail.xhr)) return;
  refreshFocus.delete(event.detail.xhr);
  if (document.activeElement === document.body) {
    document.getElementById(event.detail.requestConfig.elt.id)?.focus({ preventScroll: true });
  }
});

// Device editors keep real HTMX forms and server validation. Only presentation,
// confirmation and focus are handled here, including rows inserted by HTMX.
(() => {
  let confirmation;
  const requests = new WeakMap();
  const swaps = new WeakMap();
  function edit(row, open) {
    row.querySelector(".device-name-line").hidden = open;
    row.querySelector(".device-rename").hidden = !open;
  }
  function cancel(row) {
    if (row.querySelector(".device-rename").classList.contains("htmx-request")) return;
    const input = row.querySelector('[name="device_name"]');
    input.value = input.defaultValue;
    edit(row, false);
    row.querySelector("[data-edit-device]").focus({ preventScroll: true });
  }
  document.addEventListener("click", event => {
    const pencil = event.target.closest("[data-edit-device]");
    if (pencil) {
      const row = pencil.closest(".device-row");
      edit(row, true);
      const input = row.querySelector('[name="device_name"]');
      input.focus({ preventScroll: true });
      input.select();
    }
    const button = event.target.closest("[data-cancel-device-rename]");
    if (button) cancel(button.closest(".device-row"));
    if (!event.target.closest("[data-confirm-device-delete], [data-cancel-device-delete]")) return;
    const pending = confirmation;
    confirmation = null;
    event.target.closest("dialog").close();
    if (event.target.closest("[data-confirm-device-delete]") && pending?.form.isConnected) {
      pending.form.querySelector("button").focus({ preventScroll: true });
      pending.issue(true);
    }
  });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || !event.target.closest(".device-rename")) return;
    event.preventDefault();
    cancel(event.target.closest(".device-row"));
  });
  document.addEventListener("htmx:confirm", event => {
    const form = event.detail.elt.closest("[data-device-remove]");
    if (!form) return;
    const dialog = document.getElementById("delete-device-dialog");
    if (!dialog) return;
    event.preventDefault();
    confirmation = { form, issue: event.detail.issueRequest };
    dialog.querySelector("[data-remove-device-name]").textContent = form.dataset.deviceName;
    dialog.showModal();
    dialog.querySelector("[data-cancel-device-delete]").focus();
  });
  document.addEventListener("close", event => {
    if (event.target.id === "delete-device-dialog" && !event.target.open) confirmation = null;
  }, true);
  document.addEventListener("htmx:beforeRequest", event => {
    const form = event.detail.elt.closest(".device-rename, [data-device-remove]");
    if (!form) return;
    const row = form.closest(".device-row");
    requests.set(event.detail.xhr, {
      row: row.id,
      next: row.nextElementSibling?.id || row.previousElementSibling?.id,
      focus: form.contains(document.activeElement)
    });
  });
  document.addEventListener("htmx:beforeSwap", event => {
    if (event.detail.target.id !== "activity-data" || !event.detail.shouldSwap) return;
    const saved = event.detail.xhr.status === 200 && event.detail.requestConfig.elt.closest(".device-rename")?.closest(".device-row").id;
    const drafts = [...document.querySelectorAll('.device-rename:not([hidden])')]
      .filter(form => form.closest(".device-row").id !== saved)
      .map(form => ({ row: form.closest(".device-row").id, value: form.querySelector('[name="device_name"]').value }));
    const active = document.activeElement;
    swaps.set(event.detail.xhr, {
      drafts,
      row: active.closest(".device-row")?.id,
      input: active.matches('[name="device_name"]'),
      start: active.selectionStart,
      end: active.selectionEnd
    });
  });
  document.addEventListener("htmx:afterSwap", event => {
    const swap = swaps.get(event.detail.xhr);
    if (!swap) return;
    for (const draft of swap.drafts) {
      const row = document.getElementById(draft.row);
      if (!row) continue;
      row.querySelector('[name="device_name"]').value = draft.value;
      edit(row, true);
    }
  });
  document.addEventListener("htmx:afterSettle", event => {
    const request = requests.get(event.detail.xhr);
    const swap = swaps.get(event.detail.xhr);
    requests.delete(event.detail.xhr);
    swaps.delete(event.detail.xhr);
    if (document.activeElement !== document.body) return;
    const row = document.getElementById(swap?.row || request?.row);
    if ((swap?.input || request?.focus) && row?.querySelector('.device-rename:not([hidden])')) {
      const input = row.querySelector('[name="device_name"]');
      input.focus({ preventScroll: true });
      if (swap?.input) input.setSelectionRange(swap.start, swap.end);
    } else if (request?.focus) {
      (row?.querySelector("[data-edit-device]") || document.getElementById(request.next)?.querySelector("[data-edit-device]") || document.getElementById("refresh-devices"))?.focus({ preventScroll: true });
    }
  });
})();

// HTMX submits real session forms; this bridge supplies selection state, native
// confirmation and focus after the server refreshes the activity group.
(() => {
  let confirmation;
  const requests = new WeakMap();
  function updateSelection(form) {
    const button = form.querySelector(".delete-apps");
    if (!button) return;
    const count = form.querySelectorAll('input[name="session_id"]:checked').length;
    button.disabled = count === 0;
    form.querySelector("[data-selection-count]").textContent = count ? `(${count})` : "";
  }
  document.addEventListener("change", event => {
    const form = event.target.closest(".session-app-form");
    if (form) updateSelection(form);
  });
  document.addEventListener("htmx:confirm", event => {
    const form = event.detail.elt.closest("[data-gateway-delete]");
    if (!form) return;
    const dialog = document.getElementById("delete-session-dialog");
    if (!dialog) return; // Retain HTMX's built-in confirmation fallback.
    event.preventDefault();
    confirmation = { form, issue: event.detail.issueRequest };
    dialog.querySelector("[data-delete-device]").textContent = form.dataset.deviceName;
    dialog.querySelector("[data-delete-account]").textContent = form.dataset.username;
    const count = Number(form.dataset.appCount);
    dialog.querySelector("[data-delete-apps]").textContent = count ? `all ${count} of its app sessions` : "the gateway login";
    dialog.showModal();
    dialog.querySelector("[data-cancel-session-delete]").focus();
  });
  document.addEventListener("click", event => {
    if (!event.target.closest("[data-confirm-session-delete], [data-cancel-session-delete]")) return;
    const pending = confirmation;
    confirmation = null;
    event.target.closest("dialog").close();
    if (event.target.closest("[data-confirm-session-delete]") && pending?.form.isConnected) pending.issue(true);
  });
  document.addEventListener("close", event => {
    // close is queued: a quick reopen may already own a new confirmation.
    if (event.target.id === "delete-session-dialog" && !event.target.open) confirmation = null;
  }, true);
  document.addEventListener("htmx:beforeRequest", event => {
    const form = event.detail.elt.closest(".session-app-form, [data-gateway-delete]");
    if (!form || !form.contains(document.activeElement)) return;
    const row = form.closest("[data-gateway-session]");
    requests.set(event.detail.xhr, { row: row.id, next: row.nextElementSibling?.id, apps: form.matches(".session-app-form") });
  });
  document.addEventListener("htmx:afterSettle", event => {
    event.detail.target.querySelectorAll?.(".session-app-form").forEach(updateSelection);
    const focus = requests.get(event.detail.xhr);
    requests.delete(event.detail.xhr);
    if (!focus || document.activeElement !== document.body) return;
    const row = document.getElementById(focus.row) || document.getElementById(focus.next);
    const target = (focus.apps && row?.querySelector('input[type="checkbox"]:not(:disabled)')) || row?.querySelector(".session-trash:not(:disabled)") || row || document.getElementById("refresh-sessions");
    target?.focus({ preventScroll: true });
  });
})();

// Orient navigation within long pages and after server-rendered HTMX updates.
(() => {
  let highlighted, timeout;
  function hashTarget() {
    try {
      const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      return target?.matches("[data-navigation-target]") ? target : null;
    } catch { return null; }
  }
  function highlight(target) {
    clearTimeout(timeout);
    highlighted?.classList.remove("navigation-highlight");
    highlighted = null;
    if (!target) return;
    // Restart the cue when the same navigation link is activated again.
    void target.offsetWidth;
    target.classList.add("navigation-highlight");
    highlighted = target;
    timeout = setTimeout(() => {
      target.classList.remove("navigation-highlight");
      highlighted = null;
    }, 1500);
  }
  document.addEventListener("DOMContentLoaded", () => {
    highlight(hashTarget());
  });
  window.addEventListener("hashchange", () => highlight(hashTarget()));
  document.addEventListener("click", event => {
    const link = event.target.closest("a[href]");
    if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || (link.target && link.target !== "_self")) return;
    if (link.origin === location.origin && link.pathname === location.pathname && link.search === location.search && link.hash && link.hash === location.hash) highlight(hashTarget());
  });
  document.addEventListener("htmx:afterSettle", event => {
    const updated = event.detail.target || event.detail.elt;
    if (!(updated instanceof Element)) return;
    const target = hashTarget();
    if (!target || !updated.contains(target)) return;
    // A fragment target may not exist until the activity panel has loaded.
    target.scrollIntoView({ block: "start", behavior: "auto" });
    highlight(target);
  });
})();

// Filters replace only their list; keep keyboard focus at its new disclosure.
(() => {
  const requests = new WeakMap();
  document.addEventListener("htmx:beforeRequest", event => {
    const source = event.detail.elt;
    if (source.matches("[data-activity-filter]") && source.contains(document.activeElement)) {
      requests.set(event.detail.xhr, source.closest(".user-filter").querySelector("summary").id);
    }
  });
  document.addEventListener("htmx:afterSettle", event => {
    const id = requests.get(event.detail.xhr);
    requests.delete(event.detail.xhr);
    if (id && document.activeElement === document.body) {
      document.getElementById(id)?.focus({ preventScroll: true });
    }
  });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    document.querySelectorAll(".user-filter[open]").forEach(menu => {
      menu.open = false;
      menu.querySelector("summary").focus();
    });
  });
  document.addEventListener("click", event => {
    document.querySelectorAll(".user-filter[open]").forEach(menu => {
      if (!menu.contains(event.target)) menu.open = false;
    });
  });
})();
