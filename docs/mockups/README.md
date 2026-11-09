# Access Gateway design concept

Serve the **Razzie Cloud parent directory** with
`python3 -m http.server 8765 --bind 127.0.0.1`, then open
<http://127.0.0.1:8765/access-gateway/docs/mockups/index.html>.

| Screen | File | Review focus |
| --- | --- | --- |
| Administrator overview | [index.html](index.html) | Devices and sessions beside enrollment/user creation |
| Passkey sign-in | [login.html](login.html) | Two-column entry screen and clear primary action |
| Device enrollment | [register.html](register.html) | Device naming and a separate return to sign-in |

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

See [the coordinated design notes](../../../docs/frontend-mockups.md) in the
parent checkout for scope and verification details.
