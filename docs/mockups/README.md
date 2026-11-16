# Access Gateway design concept

Serve the **Razzie Cloud parent directory** with
`go run scripts/serve.go`, then open
<http://127.0.0.1:8765/access-gateway/docs/mockups/index.html>.

| Screen | File | Review focus |
| --- | --- | --- |
| Administrator overview | [index.html](index.html) | Devices and sessions beside enrollment/user creation |
| Passkey sign-in | [login.html](login.html) | Two-column entry screen and clear primary action |
| Registration link | [register.html](register.html) | Enrollment by default, with one-time login in a Pico split-button dropdown |
| New-user invitation | [register-invitation.html](register-invitation.html) | Username and first passkey required to create an account |
| Administrator access denied | [admin-denied.html](admin-denied.html) | Centered branded 403 page on a protected app hostname |

[Account screenshot](index-desktop.png) · [Sign-in screenshot](login-desktop.png)

## Registration link: one-time login proposal

Open [the light preview](register.html) or [the dark preview](dark/register.html).
The existing **Create passkey on this device** action stays the default. Its
attached native dropdown sits inside a PicoCSS `role="group"` and offers
**Create a passkey** and **Sign in once**. Selecting the latter replaces the
device-name form with an explanation and a **Sign in once** action. Selection
alone does not consume the link. The dropdown also lets the recipient return
to enrollment. Enrollment still requires a device name; one-time login does not.

The proposed login consumes the same existing-account registration link for a
browser session without adding a passkey or registered device. Either use makes
the link unavailable for subsequent enrollment or login. Session lifetime and
revocation should follow the gateway's normal session policy. The success fixture
links to the existing fixed account overview; its device/session counts do not
simulate the new session. Production authentication is unchanged by these files.

The preview toolbar includes an **Expired / used link** fixture and a
[new-user invitation](register-invitation.html), also available in
[dark mode](dark/register-invitation.html). Invitations still require a username
and first passkey; the login alternative is scoped to existing accounts in this
proposal. No accounts, sessions, tokens or credentials are created or consumed.
Actions load authored local HTMX fragments with `hx-params="none"`; entered
form values are not transmitted. All assets remain local, with no custom script.

Screenshots: [light dropdown](register-dropdown-desktop.png),
[dark dropdown](dark/register-dropdown-desktop.png),
[mobile dropdown](register-dropdown-mobile.png),
[dark mobile dropdown](dark/register-dropdown-mobile.png),
[one-time login](login-once-desktop.png),
[dark one-time login](dark/login-once-desktop.png),
[mobile login](login-once-mobile.png),
[dark mobile login](dark/login-once-mobile.png).

Verification: headless Brave/Chromium rendered both full pages in both themes
at 320, 390, 768 and 1440 pixels (16 layout cases). Checks exercised the native
dropdown with Enter/Tab, required-field validation, switching both ways,
enrollment and login success fixtures, unavailable links and matching theme
navigation. Every tested state retained one primary heading, loaded assets and
no page-level horizontal overflow. No console/page/CSP errors, HTTP failures,
external requests or transmitted form values occurred. Twelve desktop/mobile
screenshots were saved and visually reviewed. Parent/component whitespace
checks passed. No Go checks or live WebAuthn/backend authentication ran because
only mockup files and documentation changed. Nothing was published or deployed.

The approved split-button flow is now implemented in the embedded gateway UI.
See [one-time link login](../reference.md#sign-in-once-with-a-registration-link)
for the endpoint, session policy and cross-store failure behavior, and the
[parent implementation notes](../../../docs/frontend-mockups.md#gateway-registration-link-one-time-login)
for verification. These mockup pages remain independent simulated examples.

## Account identity and alignment proposal

The updated overview shows Files' shield icon beside the signed-in username in
the upper-right header. The **Administrator** badge sits on the same line as the
username; omit the badge for regular users. The shield stays visible on mobile.
The former full-width account strip is removed. One **Sign out** button sits below the sidebar navigation,
with a note that connected applications are also signed out. On mobile, the
username and role stay visible and the sign-out action follows the wrapped
navigation. The sign-out link opens the sample sign-in page; it ends no session.

Devices and enrollment now start on the same row. Panel gaps and enrollment
headings use consistent spacing, the workspace fills its grid column, and the
header shares the centered application frame. `index.css` applies this proposal
only to the two overview fixtures. Production now implements the reviewed header,
sidebar sign-out and panel alignment. The username opens the configured public
gateway account page; these static fixtures link back to the sample overview.

Review [light desktop](index-desktop.png), [dark desktop](dark/index-desktop.png),
[light mobile](index-mobile.png), or [dark mobile](dark/index-mobile.png).
Chromium checked both themes at 320, 390, 768, 1440 and 1920 pixels (10 layout
cases), including identity visibility, desktop panel/frame alignment, headings,
assets, overflow, keyboard focus, navigation, theme round trips and sign-out
destinations. Refresh, rename, registration-link and user-creation fixtures passed;
overview HTMX requests omit form values. No console/page/CSP errors, failed
responses or external requests occurred. Desktop/mobile screenshots were visually
reviewed. Static mockups only: no Go build, backend authentication or deployment.
The shield/inline-badge revision repeated those checks, including the unbadged
regular-user header and a long username using temporary browser-only variants.
The saved fixtures show an administrator; regular-user content remains outside
this screen set.

Registration links now use Files' symmetric three-node Share icon in production
and both overview previews. The four overview screenshots were refreshed and
visually checked with Firefox at desktop and mobile widths in both themes.
Gateway build, vet and unit tests passed; PostgreSQL/Redis integration tests
skipped because their test backend variables were unset.

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
Production templates implement the reviewed account identity/alignment layout
and automatically follow the browser's light/dark preference. Files and Notes
use the same shield, linked username and inline administrator-only badge.
These mockup pages remain separate fixtures with
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
