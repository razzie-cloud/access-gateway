"use strict";

// HTMX owns account views and forms. WebAuthn requires this small browser API bridge.
const status = (message) => { document.getElementById("status").textContent = message; };
const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), c => c.charCodeAt(0)).buffer;
const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function api(path, body) {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

// Tokens stay out of request URLs, access logs, referrers and HTMX history snapshots.
const tokenInput = document.getElementById("link-token");
if (tokenInput) {
  tokenInput.value = location.hash.slice(1);
  history.replaceState(null, "", location.pathname);
  if (!/^[a-f0-9]{64}$/.test(tokenInput.value)) {
    document.querySelector("#device-registration button").disabled = true;
    status("Open a complete registration link, or ask for a new one.");
  }
}

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-webauthn]");
  if (!form) return;
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  form.setAttribute("aria-busy", "true");
  try {
    if (!window.PublicKeyCredential) throw new Error("Passkeys require a supported browser and HTTPS (or localhost).");
    const mode = form.dataset.webauthn;
    const options = await api(`/api/${mode}/begin`, Object.fromEntries(new FormData(form)));
    options.publicKey.challenge = decode(options.publicKey.challenge);
    if (mode === "register") options.publicKey.user.id = decode(options.publicKey.user.id);
    for (const field of ["excludeCredentials", "allowCredentials"]) {
      if (options.publicKey[field]) options.publicKey[field] = options.publicKey[field].map(c => ({ ...c, id: decode(c.id) }));
    }
    status("Complete the passkey prompt on your device.");
    const credential = mode === "register" ? await navigator.credentials.create(options) : await navigator.credentials.get(options);
    if (!credential) throw new Error("No credential was returned. You can try again.");
    const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
    if (mode === "register") response.attestationObject = encode(credential.response.attestationObject);
    else {
      response.authenticatorData = encode(credential.response.authenticatorData);
      response.signature = encode(credential.response.signature);
      response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
    }
    await api(`/api/${mode}/finish`, { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() });
    if (mode === "login" && location.pathname === "/auth/authorize") {
      location.reload();
      return;
    }
    if (tokenInput) {
      tokenInput.value = "";
      location.replace("/");
      return;
    }
    status(mode === "register" ? "Passkey registered. Sign in to continue." : "Signed in.");
    htmx.trigger(document.body, "reloadState");
  } catch (error) { status(error.message); }
  finally { button.disabled = false; form.removeAttribute("aria-busy"); }
});

// Display server-rendered validation and authorization errors in the form's target.
document.addEventListener("htmx:beforeSwap", (event) => {
  if ([400, 401, 403, 404, 409, 503].includes(event.detail.xhr.status)) {
    event.detail.shouldSwap = true;
    event.detail.isError = false;
  }
});
document.addEventListener("htmx:responseError", () => status("The request failed. Please try again."));
document.addEventListener("htmx:sendError", () => status("Unable to reach the gateway. Please try again."));
