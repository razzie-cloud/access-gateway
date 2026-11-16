"use strict";

// Serve the repository over loopback HTTP and open tests/passkey-flow.html.
// Runs the production bridge with fake API/authenticator responses, without
// accounts, credentials, dependencies or changes to the production bundle.
(async () => {
  const output = document.getElementById("results");
  const source = await (await fetch("../internal/web/static/app.js")).text();
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  const equal = (got, expected) => assert(JSON.stringify(got) === JSON.stringify(expected), `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)}`);
  const buffer = value => Uint8Array.from(atob(value), c => c.charCodeAt(0)).buffer;

  function fixture({ mode = "register", invite = true, pathname = "/register", fail, missingKey = false, nullCredential = false, newUser = false, linkLogin = false, noPublicKey = false } = {}) {
    const events = {}, calls = [], prompts = [], navigations = [], refreshes = [];
    const message = { textContent: "" }, button = { disabled: false, textContent: "Create passkey" };
    const inputs = Object.fromEntries(Object.entries({ username: "untrusted-form-name", deviceName: "Phone", token: "bootstrap-secret", linkToken: "" }).map(([name, value]) => [name, { name, value, disabled: false }]));
    inputs.username.disabled = invite;
    inputs.token.disabled = invite;
    const usernameLabel = { hidden: true, querySelector: () => inputs.username };
    const description = { textContent: "Existing account" };
    const help = { textContent: "" };
    const choices = { hidden: true, open: false };
    const options = { dataset: { registrationMode: linkLogin ? "login" : "enroll" } };
    const attributes = new Map();
    const form = {
      dataset: { webauthn: mode }, elements: { namedItem: name => inputs[name] },
      querySelector: () => button, querySelectorAll: () => Object.values(inputs),
      setAttribute: (name, value) => attributes.set(name, value),
      getAttribute: name => attributes.get(name), removeAttribute: name => attributes.delete(name),
    };
    const mockDocument = {
      body: {}, addEventListener: (name, callback) => { events[name] = callback; },
      getElementById: id => id === "status" ? message : id === "link-token" && invite ? inputs.linkToken : id === "invitation-username" ? usernameLabel : id === "enrollment-description" ? description : id === "registration-help" ? help : id === "registration-choices" && invite ? choices : id === "enrollment-options" && invite ? options : null,
      querySelector: () => button,
    };
    const mockLocation = {
      hash: "#" + "a".repeat(64), pathname,
      replace: value => navigations.push(value), reload: () => navigations.push("reload"),
    };
    let failure = fail;
    async function mockFetch(path, options) {
      calls.push({ path, body: JSON.parse(options.body) });
      equal(options.headers.Accept, "application/json");
      if (failure === path) { failure = null; return { ok: false, json: async () => ({ error: "simulated failure" }) }; }
      let data = { ok: true };
      if (path === "/api/register/link") data = { newUser };
      if (path.endsWith("/begin")) {
        data = { publicKey: { challenge: "Y2hhbGxlbmdl", user: { id: "dXNlcg" },
          allowCredentials: ["b2xk", ...(missingKey ? [] : ["bmV3"]), "ZGVjb3k"].map(id => ({ type: "public-key", id })),
        } };
      }
      if (path === "/api/register/finish") data.username = "token-bound-account";
      return { ok: true, json: async () => data };
    }
    function credential() {
      return { id: "bmV3", rawId: buffer("bmV3"), type: "public-key",
        response: { clientDataJSON: buffer("YQ=="), attestationObject: buffer("Yg=="), authenticatorData: buffer("Yw=="), signature: buffer("ZA=="), userHandle: null },
        getClientExtensionResults: () => ({ rk: true }) };
    }
    const navigator = { credentials: {
      create: async () => { prompts.push("create"); return credential(); },
      get: async options => {
        prompts.push("get");
        if (mode === "register") {
          equal(options.publicKey.allowCredentials.map(c => btoa(String.fromCharCode(...new Uint8Array(c.id)))).map(c => c.replace(/=+$/, "")), ["bmV3"]);
          assert(Object.values(inputs).every(input => input.disabled), "Enrollment fields must not block login retry validation");
          equal(inputs.token.value, "");
          equal(inputs.linkToken.value, "");
        }
        if (failure === "prompt") { failure = null; throw new Error("Canceled"); }
        if (nullCredential) return null;
        return credential();
      },
    } };
    new Function("document", "window", "navigator", "location", "history", "fetch", "FormData", "htmx", source)(
      mockDocument, { PublicKeyCredential: noPublicKey ? undefined : function () {}, addEventListener() {} }, navigator, mockLocation,
      { replaceState() {} }, mockFetch,
      class { constructor() { return Object.entries(inputs).filter(([, input]) => !input.disabled).map(([name, input]) => [name, input.value]); } },
      { trigger: (_, name) => refreshes.push(name) },
    );
    return { calls, prompts, navigations, refreshes, message, button, inputs, attributes, usernameLabel, description, choices,
      submit: () => events.submit({ target: { closest: () => form }, preventDefault() {} }),
    };
  }

  const paths = test => test.calls.map(call => call.path).filter(path => path !== "/api/register/link");
  const registrationAndLogin = ["/api/register/begin", "/api/register/finish", "/api/login/begin", "/api/login/finish"];
  const tests = {
    async "one-time link login works without WebAuthn and sends only its token"() {
      const test = fixture({ linkLogin: true, noPublicKey: true });
      await test.submit();
      equal(paths(test), ["/api/login/link"]);
      equal(test.calls.find(call => call.path === "/api/login/link").body, { linkToken: "a".repeat(64) });
      equal(test.prompts, []);
      equal(test.navigations, ["/"]);
      equal(test.inputs.linkToken.value, "");
    },
    async "one-time link login failure keeps the link available for retry"() {
      const test = fixture({ linkLogin: true, fail: "/api/login/link" });
      await test.submit();
      equal(test.navigations, []);
      equal(test.inputs.linkToken.value, "a".repeat(64));
      await test.submit();
      equal(paths(test), ["/api/login/link", "/api/login/link"]);
      equal(test.prompts, []);
      equal(test.navigations, ["/"]);
    },
    async "new-user invitations cannot use one-time login"() {
      const test = fixture({ linkLogin: true, newUser: true });
      await test.submit();
      equal(paths(test), []);
      equal(test.prompts, []);
      equal(test.navigations, []);
      equal(test.inputs.linkToken.value, "a".repeat(64));
      assert(test.choices.hidden, "New-user invitations must hide login alternative");
    },
    async "new-user invitation asks for a username before enrollment"() {
      const test = fixture({ newUser: true });
      await test.submit();
      equal(test.usernameLabel.hidden, false);
      equal(test.calls.find(call => call.path === "/api/register/begin").body.username, "untrusted-form-name");
      assert(test.description.textContent.includes("Choose your username"), "Explain account creation");
      equal(test.navigations, ["/"]);
    },
    async "existing-account invitation omits the username"() {
      const test = fixture();
      await test.submit();
      equal(test.usernameLabel.hidden, true);
      assert(!("username" in test.calls.find(call => call.path === "/api/register/begin").body), "Existing account cannot be overridden");
    },
    async "failed invitation lookup retries without opening a passkey prompt"() {
      const test = fixture({ fail: "/api/register/link" });
      await test.submit();
      equal(test.prompts, []);
      await test.submit();
      equal(test.prompts, ["create", "get"]);
    },
    async "invitation enrolls and signs in before navigating"() {
      const test = fixture();
      await test.submit();
      equal(paths(test), registrationAndLogin);
      equal(test.calls.find(call => call.path === "/api/login/begin").body, { username: "token-bound-account" });
      equal(test.prompts, ["create", "get"]);
      equal(test.navigations, ["/"]);
      equal(test.button.disabled, false);
    },
    async "bootstrap signs in and refreshes the account"() {
      const test = fixture({ invite: false, pathname: "/" });
      await test.submit();
      equal(paths(test), registrationAndLogin);
      equal(test.message.textContent, "Signed in.");
      equal(test.refreshes, ["reloadState"]);
    },
    async "bootstrap resumes pending SSO after signing in"() {
      const test = fixture({ invite: false, pathname: "/auth/authorize" });
      await test.submit();
      equal(test.navigations, ["reload"]);
    },
    async "canceled assertion retries login without repeating enrollment"() {
      const test = fixture({ fail: "prompt" });
      await test.submit();
      equal(test.navigations, []);
      assert(test.message.textContent.startsWith("Passkey registered."), "Preserve enrollment success");
      equal(test.button.textContent, "Sign in with your new passkey");
      await test.submit();
      equal(paths(test), [...registrationAndLogin.slice(0, 3), ...registrationAndLogin.slice(2)]);
      equal(test.navigations, ["/"]);
    },
    async "login API failures retry without repeating enrollment"() {
      for (const fail of ["/api/login/begin", "/api/login/finish"]) {
        const test = fixture({ fail });
        await test.submit();
        equal(test.navigations, []);
        assert(test.message.textContent.startsWith("Passkey registered."), "Enrollment stays successful");
        await test.submit();
        equal(paths(test).filter(path => path.startsWith("/api/register/")), registrationAndLogin.slice(0, 2));
        equal(test.navigations, ["/"]);
      }
    },
    async "registration failure never starts login or clears the link"() {
      const test = fixture({ fail: "/api/register/finish" });
      await test.submit();
      equal(paths(test), registrationAndLogin.slice(0, 2));
      equal(test.navigations, []);
      equal(test.inputs.linkToken.value, "a".repeat(64));
      equal(test.message.textContent, "simulated failure");
      assert(!test.inputs.deviceName.disabled && !test.inputs.linkToken.disabled, "Registration remains retryable");
    },
    async "missing new passkey never opens an unrestricted assertion"() {
      const test = fixture({ missingKey: true });
      await test.submit();
      equal(test.prompts, ["create"]);
      equal(test.navigations, []);
      assert(test.message.textContent.includes("unavailable"), "Explain the unavailable credential");
    },
    async "empty assertion result never navigates or reports signed in"() {
      const test = fixture({ nullCredential: true });
      await test.submit();
      equal(paths(test), registrationAndLogin.slice(0, 3));
      equal(test.navigations, []);
      assert(test.message.textContent.startsWith("Passkey registered."), "Keep a sign-in retry");
    },
    async "ordinary login still refreshes the account and resumes SSO"() {
      for (const pathname of ["/", "/auth/authorize"]) {
        const test = fixture({ mode: "login", invite: false, pathname });
        await test.submit();
        equal(paths(test), registrationAndLogin.slice(2));
        equal(test.calls[0].body.username, "untrusted-form-name");
        equal(test.navigations, pathname === "/" ? [] : ["reload"]);
        equal(test.refreshes, pathname === "/" ? ["reloadState"] : []);
      }
    },
    async "duplicate submission does not start concurrent ceremonies"() {
      const test = fixture();
      await Promise.all([test.submit(), test.submit()]);
      equal(paths(test), registrationAndLogin);
      equal(test.attributes.has("aria-busy"), false);
    },
  };
  const results = [];
  for (const [name, test] of Object.entries(tests)) {
    try { await test(); results.push(`PASS ${name}`); }
    catch (error) { results.push(`FAIL ${name}: ${error.stack}`); }
  }
  output.textContent = results.join("\n");
  document.title = results.every(line => line.startsWith("PASS")) ? "PASS" : "FAIL";
})().catch(error => { document.getElementById("results").textContent = `FAIL ${error.stack}`; document.title = "FAIL"; });
