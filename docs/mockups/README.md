# Access Gateway design concept

Serve the **Razzie Cloud parent directory** with
`go run scripts/serve.go`, then open
<http://127.0.0.1:8765/access-gateway/docs/mockups/index.html>.

| Screen | File | Review focus |
| --- | --- | --- |
| User filters (new proposal) | [activity.html](activity.html) | Admin-only per-list user dropdowns, current admin selected by default |
| Regular-user activity | [activity-member.html](activity-member.html) | Own devices/sessions with no user dropdowns or administration controls |
| Administrator overview | [index.html](index.html) | Devices and sessions beside enrollment/user creation |
| Grouped sessions | [sessions.html](sessions.html) | One row per gateway login, selectable app sessions and gateway trash action |
| Passkey sign-in | [login.html](login.html) | Two-column entry screen and clear primary action |
| Registration link | [register.html](register.html) | Enrollment by default, with one-time login in a Pico split-button dropdown |
| New-user invitation | [register-invitation.html](register-invitation.html) | Username and first passkey required to create an account |
| Administrator access denied | [admin-denied.html](admin-denied.html) | Centered branded 403 page on a protected app hostname |

[Account screenshot](index-desktop.png) · [Sign-in screenshot](login-desktop.png)

## Device and session user filters proposal

Open the [administrator preview](activity.html), its [dark counterpart](dark/activity.html),
or the [regular-user preview](activity-member.html) ([dark](dark/activity-member.html)).
The new activity concept uses the existing account shell and grouped sessions.
Both **Devices** and **Active sessions** have a compact user icon and chevron
beside their headings. The selected account remains visible when closed.

Each list defaults to **razzie (you)**, the signed-in sample administrator.
Choose one account or **All users** independently for each list. The selected
option has a checkmark; the heading count reflects that list's displayed rows.
**Refresh** keeps the selected account and restores that scope's sample records.
Switching one list preserves the other list's app selections and device drafts.
The sample account **taylor** has no devices or sessions, demonstrating empty
states without losing the filter. A full reload or theme switch resets the
sample selections to the signed-in account.

Regular users see only their own activity, without either user dropdown, the
administrator badge, the users table or user-creation form. This is a visual
fixture, not an authorization test. Production now implements the reviewed
filters on the server, including independent scope retention, role/owner checks,
long-name handling and the control/counter alignment. See
[managing devices and sessions](../reference.md#manage-devices-and-sessions) and the
[parent implementation verification](../../../docs/frontend-mockups.md#gateway-device-and-session-user-filters).
These pages remain separate sample-data fixtures.

Filtering uses authored HTML fragments under `fragments/activity/` with HTMX;
no hidden cross-user rows are downloaded in the initial own-account panels.
`activity.js` handles focus/Escape and the existing browser-local session
mutation simulation. Device actions display sample receipts. Requests omit
form values with `hx-params="none"`. No real API is contacted and no data persists;
changing scopes restores that scope's authored fixture. Serve the parent root,
as shared scope fragments use parent-relative absolute paths for both themes.

Screenshots: [default desktop](activity-desktop.png),
[default mobile](activity-mobile.png), [open dropdown](activity-dropdown-desktop.png),
[mobile dropdown](activity-dropdown-mobile.png),
[regular user](activity-member-desktop.png),
[regular user mobile](activity-member-mobile.png), and the matching
[dark desktop](dark/activity-desktop.png), [dark mobile](dark/activity-mobile.png),
[dark dropdown](dark/activity-dropdown-desktop.png),
[dark mobile dropdown](dark/activity-dropdown-mobile.png),
[dark regular user](dark/activity-member-desktop.png) and
[dark regular user mobile](dark/activity-member-mobile.png).

Verification: Brave/Chromium passed 16 admin/member layouts in light and dark
at 320, 390, 768 and 1440 pixels, plus 80 primary scope changes. Checks exercised
both independent filters, own-account defaults, all users, every individual
account, counts, empty states, scoped refresh, keyboard Enter/Tab/Escape and
focus restoration, theme round trips, member-only controls, preserved selections,
simulated app/gateway removal and draft-free device-action requests. Assets loaded,
one primary heading and no page overflow passed. There were no page/console/CSP
errors or HTTP failures; page HTTP traffic consisted of 526 local GETs with no
query/form values. Twelve screenshots were captured and visually reviewed.
Relative-reference and parent/component whitespace checks passed. Static mockups
only: no Go build/tests, live authentication, publication or deployment ran.

The alignment follow-up removes Pico's inherited Refresh bottom margin and
sets the dropdown and Refresh to the same 38px height, line height and 16px
icons. Heading counters for Devices, Active sessions and People with access
use centered flex rows with explicit spacing instead of inline baseline alignment.
Chromium checked counter/text centers, matching control top edges and icon centers in
all 16 admin/member theme/viewport cases above. Filtering, scoped refresh and
Escape/focus passed with no browser/CSP errors or failed responses. All twelve
screenshots were refreshed and visually reviewed; parent/component whitespace
checks passed. This remains a static-only mockup change with no Go checks.

## Grouped gateway sessions proposal

Open [the light preview](sessions.html) or [the dark preview](dark/sessions.html).
The overview's Sessions navigation opens this proposal. Each row represents one
gateway login, with its device/account, app sessions and gateway expiry. App
sessions appear as checkbox chips in the extra Apps column. Select one or more
and choose **Delete selected apps** to remove only those sample app sessions;
the gateway row remains. Two Files sessions under Studio laptop demonstrate
independent selection of sessions for the same app. Removing the final app
leaves **No app sessions**.

The row's trash button opens a native confirmation dialog. **Delete gateway
session** removes the complete sample row and its app sessions, updating the
gateway-session count. Cancel or Escape preserves it. This browser's gateway
and app sessions remain protected, with Sign out as its exit. The page explains
that deleting an app session allows automatic sign-in again while its parent
gateway session remains active. **Refresh** restores the original sample data.

These are browser-local sample changes using authored HTMX receipt fragments
and the mockup-only `sessions.js`; no session API is contacted or data persisted.
Requests use `hx-params="none"`. The historical overview retains its old table
for comparison. Production now implements this grouping in the existing activity
panel, using real app hostnames and server-validated deletion. See
[managing sessions](../reference.md#manage-devices-and-sessions) for its behavior.

Screenshots: [light desktop](sessions-desktop.png),
[dark desktop](dark/sessions-desktop.png), [light mobile](sessions-mobile.png),
[dark mobile](dark/sessions-mobile.png), [selected app](sessions-selected-desktop.png),
[dark selected app](dark/sessions-selected-desktop.png),
[gateway confirmation](sessions-delete-desktop.png),
[dark confirmation](dark/sessions-delete-desktop.png),
[mobile confirmation](sessions-delete-mobile.png),
[dark mobile confirmation](dark/sessions-delete-mobile.png).

Verification: Brave/Chromium checked both themes at 320, 390, 768 and 1440 pixels
(eight layout cases). All cases exercised keyboard checkbox selection, individual
and multiple app deletion, empty apps, gateway confirmation/cancellation/Escape,
focus return, current-browser protection, count updates, sample reset and theme
round trips. One primary heading, loaded images and no page overflow passed.
There were no page/console/CSP errors, failed HTTP responses or external HTTP
requests; all 184 HTTP requests were local GETs without query/form values.
Ten screenshots were captured and visually reviewed. Relative-reference and Git
whitespace checks passed. No Go build/tests or live authentication ran for these
static-only changes. Nothing was published or deployed.

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
