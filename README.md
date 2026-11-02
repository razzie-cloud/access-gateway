# Access Gateway

Passwordless accounts with passkeys, device onboarding links, and user management.
The web interface uses **HTMX and PicoCSS**, served locally by the gateway.

## Start

For local development, run `docker compose up --build` and open
<http://localhost:8080>. PostgreSQL and Redis are included. Ports 5432 and 8080
must be free. Redis uses a persistent volume and append-only storage.

Compose builds the checked-out source and tags the gateway image as
`ghcr.io/razzie-cloud/access-gateway:dev`. Set `ACCESS_GATEWAY_IMAGE_TAG`
to override the local build's tag.

To run the Go service directly:

```sh
export POSTGRES_URI='postgres://app:app@localhost:5432/app?sslmode=disable'
export REDIS_URI='redis://localhost:6379/0'
go run ./cmd/access-gateway
```

For a public installation, put the gateway behind HTTPS and set `ORIGIN` to its
full public origin (for example, `https://auth.example.com`) and `RP_ID` to its
hostname (`auth.example.com`). Use the same origin when opening registration links.
`SERVICE_PORT` defaults to `8080`; `RP_NAME` sets the passkey display name.

## Set up the administrator

On the first start with no users, find `BOOTSTRAP TOKEN` in the gateway logs.
Open the home page, enter a username, that token and a device name, and complete the passkey
prompt. Then sign in. The first account is the administrator; existing
installations promote their earliest account during migration.

Canceling the prompt leaves setup open for another attempt. The bootstrap token
is printed only when generated; restarting does not print it again.

## Add a device

Sign in on an existing device. Under **Device registration links**, choose an
expiration from **1 minute to 30 days** (default: 60 minutes), then select
**Generate link and QR code**. Open the link on the new device or scan the QR
code, name the device and create its passkey. The QR image can also be downloaded.

Each link registers one passkey for its designated account and expires at the
displayed time, even if registration is already in progress. A canceled prompt
can be retried while the link remains valid. After registration, enter your
username and choose **Sign in with a passkey**.
Multiple devices can have separate passkeys.

Login asks for a username and filters the browser's passkey choices to credentials
registered to that account. The ceremony binds the username, account UUID and
credential IDs; a different account's passkey cannot complete it. Named login
also accepts existing non-discoverable credentials and responses without a user
handle; a supplied handle must match the account.

Unknown usernames and accounts without credentials receive plausible dummy
options. Every account's list is padded to the same credential-count/ID-length
profile across the installation, without per-device transport metadata. Dummy
IDs are derived from a random secret persisted in PostgreSQL `app_states`, scoped
to `ORIGIN`, so they stay stable across restarts and replicas without extra
configuration. Do not delete or disclose that secret. This mitigates username
enumeration, but exposing real credential IDs still has privacy limits: known
IDs, authenticator-specific ID formats, changes over time and timing differences
can provide clues. See the [WebAuthn privacy considerations](https://www.w3.org/TR/webauthn-3/#sctn-username-enumeration).

Each valid username submission logs `login attempt` with the client IP and a
bounded, quoted `claimed_username`, even if the browser prompt is canceled or
the account does not exist. Failed verification logs the same claimed name and
a reason, while clients always receive the same 401 message. A claimed username
is unverified input. Cookies, assertions and enrollment secrets are never logged.

New registrations still request `residentKey=required`; pre-FIDO2 security keys
and authenticators without available discoverable storage cannot enroll.
Existing links remain valid until their original expiry; live gateway and app
sessions are preserved. In-progress ceremonies from older login flows must be
restarted. Legacy credentials with unknown discoverability are omitted from
enrollment exclusions so the same authenticator can be upgraded.

Treat links and QR codes like credentials: anyone holding one can register a
device for that account. Share them privately and use a separate link per device.
The complete link is shown only when generated; create another if you lose it.

## Add a user

As administrator, use **Create a user**, then choose that account under
**Device registration links**. Generate and privately send its link or QR code.
The recipient registers their first passkey and can then sign in and onboard
their own devices. New accounts are regular users, without admin permissions.

## Manage devices and sessions

Every signed-in user can view their own devices and active gateway/application
sessions. Administrators see all users, UUIDs, devices and sessions. Device names
identify registered passkeys; each new session records the passkey used to sign
in, and application sessions inherit that association.

Use **Rename** at any time, including for the current device. **Remove session**
ends another session; removing a gateway session also revokes its application
sessions. This browser's session and its application sessions are protected;
use **Sign out** to end them. A device can be removed once all its sessions have
ended, preventing future logins with that passkey. Login completion and device
removal lock the credential row so a concurrent login cannot bypass this check.

Existing passkeys start as **Unnamed device** and can be renamed. Older sessions
show **Unknown device** until the user signs in again. While those sessions are
live, their account's devices remain protected from removal. End the older
sessions from a new sign-in to identify and manage individual devices.

## Operational notes

Anonymous requests are limited to **60 per minute per IP**. Login begin and
finish requests share a separate **10 per minute per IP** budget, including
requests from signed-in users. Excess requests receive **429** and a
`Retry-After` header before allocating ceremonies or SSO flows. Live gateway
and origin-bound app sessions bypass the anonymous budget. Counters use bounded
process-local memory (at most 16,384 entries), expire automatically, and reset
on restart; replicas have independent budgets. A distributed attacker can still
consume the global SSO capacity, so these limits do not replace ingress controls.

By default the socket peer is the client IP; supplied IP headers are ignored.
Behind a reverse proxy, set `TRUSTED_PROXIES` (`--trusted-proxies`) to a
comma-separated list of its IP addresses or CIDRs. Only trusted socket peers
may supply `X-Forwarded-For`; the chain is read from right to left, stopping at
the first untrusted hop. For example, a loopback proxy can use
`TRUSTED_PROXIES=127.0.0.1,::1`. Restrict backend access and keep these ranges as
narrow as possible. Otherwise clients share the proxy's rate-limit budget.
The parent Compose/Swarm configurations trust private Docker network ranges
because the gateway backend has no published port. Do not use that broader
setting for a directly exposed gateway.

PostgreSQL stores users, passkeys, and registration links; migrations run at
startup. Redis stores gateway and app sessions, passkey ceremonies, pending SSO
flows, and one-time authorization grants. Gateway restarts preserve these records.
Replicas must use the same Redis backend/database and public `ORIGIN` to share
sessions. Keys are namespaced by a hash of `ORIGIN`, and bearer tokens are stored
only as SHA-256 hashes in Redis key names and references. There is currently no UI
for revoking unused registration links.

Configure Redis using `REDIS_URI` (`--redis-uri`), or discover its URI with
`REDIS_URI_FROM` (`--redis-uri-from`). `REDIS_PASSWORD_FILE`
(`--redis-password-file`) supplies a password without putting it in the URI
configuration; trailing line endings are removed. `redis://` and `rediss://`
connections are supported. Redis is required; startup checks connectivity and
does not fall back to process-local sessions. The local Compose Redis service
is internal; publish a loopback port separately when running the Go binary on
the host.

Each replica caches up to **4096 immutable session payloads** for **30 seconds**
(or until Redis expiry, whichever is earlier). Authorization still checks the
Redis key's remaining TTL on every lookup, including cache hits. Caching avoids
re-fetching and decoding payloads; it does not eliminate the Redis round trip.
Logout, eviction, and expiry invalidate authorization across replicas even with
warm caches. Redis failures return a storage error rather than accepting cached
sessions. Callback redemption and login completion use atomic Redis scripts so
only one replica can consume a code or login ceremony.

Redis TTLs are **30 minutes** for ceremonies, **7 days** for gateway sessions,
**10 minutes** for pending SSO flows, and **1 minute** for grants. App sessions
and grants cannot outlive their parent gateway session. Session survival across
Redis restarts depends on the backend's own persistence configuration; losing or
evicting Redis session keys signs users out.

Run the full integration suite with disposable local backends:

```sh
TEST_DATABASE_URL='postgres://user@127.0.0.1:5432/testdb?sslmode=disable' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' go test -race ./...
```

Redis tests clean up only their random key namespaces. PostgreSQL tests create
and drop random schemas. Without these variables the corresponding integration
tests skip; ordinary unit tests still run.

## Protect apps with Caddy

Set `ORIGIN` to the gateway's public URL and `FORWARD_AUTH_ORIGINS` (or
`--forward-auth-origins`) to a comma-separated list of exact app origins:

```sh
ORIGIN=https://auth.example.com
RP_ID=auth.example.com
FORWARD_AUTH_ORIGINS=https://app.example.com,https://other.example.net
```

Origins include a scheme and optional port, without a path, query, or wildcard.
HTTPS is required, except for loopback HTTP origins used in local development
(loopback IPs, `localhost`, and names ending in `.localhost`, such as
`http://files.localhost:8082`). These names still require exact allowlist entries.
An empty allowlist disables forward authentication (503). The gateway's own
origin must not be in this list.

Configure Caddy to expose the gateway and check requests before proxying each app:

```caddyfile
auth.example.com {
    reverse_proxy access-gateway:8080
}

(access_gateway) {
    forward_auth access-gateway:8080 {
        uri /forward_auth
        copy_headers X-Auth-Request-User X-Auth-Request-Name
    }
}

app.example.com {
    import access_gateway
    reverse_proxy app:8080
}

other.example.net {
    import access_gateway
    reverse_proxy other:8080
}
```

The same `forward_auth` options work as Caddy Docker Proxy labels. The infra
snippet includes the header copying; the stack still needs a gateway service
with its public route and the configuration above before it can be deployed.

`GET /forward_auth` reads `X-Forwarded-Proto`, `X-Forwarded-Host`,
`X-Forwarded-Uri`, and (on callbacks) `X-Forwarded-Method`. Caddy sets these from
the original request. Only trusted reverse proxies should reach this endpoint;
other proxies must overwrite client-supplied forwarded headers. Protect app
backends from direct access, and use `copy_headers` so Caddy replaces supplied
identity headers with the gateway's response values.

The sign-in flow works across unrelated app domains:

1. Missing, unknown, or expired app sessions receive a 303 redirect to
   `${ORIGIN}/auth/authorize?flow=...`, with a temporary state cookie set by the
   response on the app's hostname.
2. The gateway reuses its existing `auth` cookie. If absent or expired, it shows
   the normal passkey login page and resumes the flow after sign-in.
3. It redirects to the app's reserved `/_auth/callback` path with a one-time
   code. Caddy runs this request through `/forward_auth` too; no separate
   callback route or app changes are required. Do not exempt this path from
   forward auth. The callback checks the state cookie, app origin, code expiry,
   and gateway session before exchanging the code for a separate app session.
4. The callback sets an app cookie and redirects to the original path and query.
   Subsequent checks return **204** with `X-Auth-Request-User` (the user's UUID)
   and `X-Auth-Request-Name` (username), allowing Caddy to pass the request through.

App cookies are host-only, HttpOnly, SameSite=Lax, and Secure on HTTPS, with
`__Host-razcloud_app` as the HTTPS cookie name (`razcloud_app` on loopback HTTP).
The gateway's `auth` cookie is also Lax to permit top-level cross-site sign-in;
ceremony cookies remain Strict and all POSTs still require the configured Origin.
The central cookie is never copied to an app, and app tokens cannot sign in to
the gateway or another app origin. Signing out at the gateway invalidates all
app sessions derived from that gateway session. Deleting a user denies their
app requests (401); database failures deny access (503).

Pending flows expire after ten minutes; codes expire after one minute and are
consumed atomically once. Codes are bound to the initiating browser's state cookie
and original app origin. Keep callback query strings out of proxy access logs;
session tokens themselves never appear in URLs. All auth responses use no-store
and no-referrer. Simultaneous app sign-ins use separate state cookies.

Redirects resume with GET; an unauthenticated POST body is not replayed. API and
background requests should establish the app session through top-level browser
navigation first. App session lifetimes are bounded by the gateway's seven-day
session. Sessions, codes, and flows are shared through Redis, so a handoff may
start on one gateway replica and finish on another.

## Publish an image

The `Publish image` workflow builds the tagged commit's Dockerfile for
`linux/amd64` and pushes `ghcr.io/razzie-cloud/access-gateway:<git-tag>` when a
new tag is pushed to this service repository. Set `RELEASE_TAG` to your chosen
release tag, then run from this directory:

```sh
git tag "${RELEASE_TAG:?Set RELEASE_TAG}"
git push origin "$RELEASE_TAG"
```

The tagged commit must include `.github/workflows/publish-image.yml`. Creating
a new tag through GitHub's release UI also triggers the workflow. Tags in the
parent razcloud repository do not trigger service builds.

The image tag exactly matches the Git tag, including any `v` prefix; no `latest`
alias is added. Use Docker-compatible tags: 1–128 ASCII letters, digits,
underscores, dots, or hyphens, starting with a letter, digit, or underscore.
Incompatible tags fail before publication.

Authentication uses the built-in `GITHUB_TOKEN` with `packages: write`; no custom
registry secret is needed. Organization policy must allow package creation;
existing packages must grant this repository Actions write access. Set package
visibility to public for unauthenticated pulls, or authenticate deployment hosts.

## Health probes

Internal `GET /healthz` reports process liveness; `GET /readyz` reports readiness
of PostgreSQL and Redis.
Both support HEAD and return plain text: 200 on success, 503 when not ready,
and 405 for other methods. Responses use `Cache-Control: no-store` and never
include backend addresses, credentials, or error details.

Readiness checks run immediately in a background worker and repeat ten seconds
after each cycle, with a two-second deadline per dependency. Until the first
successful cycle, after a failed cycle, or once the last result is thirty seconds
old, readiness returns 503. Probes only read cached state; they never query a
backend, provision an instance, or generate request logs. Failed background
checks log the dependency name once per failed cycle without raw backend errors.

Use these endpoints directly on the private backend port. Keep public ingress
and authentication rules in place. Container health checks use `/readyz` on
`SERVICE_PORT` (default 8080).
