# Access Gateway design concept

Serve the **Razzie Cloud parent directory** with
`go run scripts/serve.go`, then open
<http://127.0.0.1:8765/access-gateway/docs/mockups/index.html>.

| Screen | File | Review focus |
| --- | --- | --- |
| Administrator overview | [index.html](index.html) | Devices and sessions beside enrollment/user creation |
| Passkey sign-in | [login.html](login.html) | Two-column entry screen and clear primary action |
| Device enrollment | [register.html](register.html) | Device naming and a separate return to sign-in |
| Administrator access denied | [admin-denied.html](admin-denied.html) | Centered branded 403 page on a protected app hostname |

[Account screenshot](index-desktop.png) · [Sign-in screenshot](login-desktop.png)

## Dark-mode screenshots

Open [the dark preview](dark/index.html), or use **Dark mode** in any preview's
top bar. **Light mode** returns to the same screen. Dark pages use the same PicoCSS
and HTMX assets, with navy surfaces and gold actions in `dark.css`.

| Screen | Screenshot |
| --- | --- |
| Administrator overview | [Dark image](dark/index-desktop.png) |
| Passkey sign-in | [Dark image](dark/login-desktop.png) |
| Device enrollment | [Dark image](dark/register-desktop.png) |
| Administrator access denied | [Dark image](dark/admin-denied-desktop.png) |

Try **Refresh**, a device's **Manage** disclosure, **Generate registration link**,
**Create user**, or the sign-in/enrollment forms. Actions fetch sample HTML
fragments. Current-browser sessions and devices with live sessions keep their
protected/disabled actions. No WebAuthn API is invoked, no valid bearer link is
generated, and no service API is contacted. Bootstrap and non-admin variants are
outside this initial screen set.

Assets are referenced directly from `../../internal/web/static/`. `mockup.css`
adds layout and Pico variable overrides. `fragments/` contains HTMX fixtures.
Production templates now implement this layout and automatically follow the
browser's light/dark preference. These mockup pages remain separate fixtures with
simulated interactions; service forms use the live HTMX and WebAuthn flows.

## Administrator access denied

Open [the light preview](http://127.0.0.1:8765/access-gateway/docs/mockups/admin-denied.html)
or [the dark preview](http://127.0.0.1:8765/access-gateway/docs/mockups/dark/admin-denied.html).
Screenshots: [light desktop](admin-denied-desktop.png),
[light mobile](admin-denied-mobile.png), [dark desktop](dark/admin-denied-desktop.png),
[dark mobile](dark/admin-denied-mobile.png).

This concept replaces the plain-text administrator-role denial with a centered
logo, 403 badge, explanation and two exits. Cloud home links to
`https://razzie.cloud/`; account management links to `https://auth.razzie.cloud/`.
These are real navigation destinations; the concept does not implement a role
request, account switch or sign-out action.

Every asset and navigation URL in these two pages is absolute. Preview assets
and theme links use the loopback gateway stand-in `http://127.0.0.1:8765`.
Keep the preview server on that port; opening the HTML through another server
then demonstrates the protected-app origin case. The explicit preview CSP permits
assets from that stand-in without relying on the document's hostname.
For implementation, derive gateway asset/account URLs from configured `ORIGIN`
and the home link from `LANDING_ORIGIN`, and make the response CSP permit those
specific asset sources. Do not derive them from incoming Host/forwarded headers.
Retain HTTP 403 and the existing authorization behavior. The reviewed concept
is now implemented in the production forward-auth admin denial, using the
existing embedded stylesheet and automatic browser light/dark preference.
These previews remain separate static fixtures.

The production gateway now reuses this layout for its other errors, with
status-specific headings, explanations and guidance. It negotiates JSON for
clients requesting it, while browser navigation gets HTML and `/ui/*` HTMX
requests retain inline error fragments. See [error responses](../reference.md#error-responses)
for format selection, absolute URLs and the shared error-page CSP. The static
mockups continue to show the reviewed administrator-denial example.

Production verification passed `go build ./...`, `go vet ./...`, `go test ./...`
and `go test -race ./...` with disposable loopback PostgreSQL/Redis backends.
A temporary harness exercised the real admin check and production response in
Chromium: both themes, all four widths below, different page/asset hostnames,
HTTP 403, CSP, loaded assets, headings/overflow, keyboard focus and intercepted
exit links. No unexpected browser/network errors were observed; production
desktop/mobile screenshots were visually reviewed. No deployment or physical
passkey workflow was exercised.

Chromium verification covered both themes at 320, 390, 768 and 1440 pixels,
from both the asset origin and a second origin returning HTTP 403 (16 layout
cases). Checks covered loaded assets, absolute references, one heading, horizontal
overflow, keyboard focus, theme round trips and both exit destinations (intercepted
locally). No page/CSP errors, failed requests or unexpected failed responses were
observed. Desktop/mobile screenshots were saved for both themes. Static mockups
only; Go checks and live authentication were not run.

See [the coordinated design notes](../../../docs/frontend-mockups.md) in the
parent checkout for scope and verification details.
