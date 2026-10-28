# Access Gateway development

## Scope and checks

This directory is the `github.com/razzie-cloud/access-gateway` Go 1.27 module and
a Git submodule of razcloud. Keep gateway code, migrations, tests, and its docs
here. Preserve unrelated parent and infra work. Do not push or deploy without
authorization. Check the parent AGENTS.md for repository workflow.

Run inside this directory:

```sh
gofmt -w <changed-go-files>
go build ./...
go vet ./...
go test ./...
# Explicitly use a disposable local PostgreSQL backend, never production:
TEST_DATABASE_URL='postgres://user@127.0.0.1:port/testdb?sslmode=disable' \
TEST_REDIS_URL='redis://127.0.0.1:redisport/0' go test -race ./...
```

PostgreSQL tests create and drop random schemas and need CREATE SCHEMA permission.
They skip unless both TEST_DATABASE_URL and TEST_REDIS_URL are set. Redis-only
tests need TEST_REDIS_URL and clean only random key namespaces, never FLUSHDB or
CONFIG. Use local disposable backends. Tests exercise authorization, QR PNG
output, expiration, account binding, transactional rollback, concurrent link
consumption, bootstrap retries/races, and upgrading an existing account to admin.
For full browser validation, use Chromium's CDP WebAuthn virtual authenticator
with CTAP2, internal transport, resident keys and user verification; exercise
bootstrap, login, HTMX user creation, device registration on a fresh browser
context, reuse rejection, and login with each device credential.

## Frontend requirements

**All frontend work must use HTMX and PicoCSS.** Use server-rendered HTML
fragments for account views and management forms. Do not introduce a SPA
framework or a frontend build pipeline. The only custom JavaScript bridge is
for browser WebAuthn APIs and status/HTMX integration.

- `internal/web/templates.html`: Go html/template page and fragment definitions.
- `internal/web/static/app.js`: WebAuthn bridge and HTMX error rendering.
- `internal/web/static/app.css`: small PicoCSS layout adjustments.
- Vendored HTMX 2.0.8 and PicoCSS 2.1.1 plus licenses live in `static/` and are
  embedded into the executable. Keep asset versions and licenses together.
- Keep HTMX evaluation, indicator style injection, and history snapshots disabled
  to work with CSP and avoid caching registration secrets. No inline JS/CSS.
- Use html/template escaping; only generated QR PNG data URLs are trusted URLs.

## Backend architecture

`cmd/access-gateway/main.go` loads `internal/config` into `app.Config`.
`internal/app/app.go` opens PostgreSQL, applies embedded Goose migrations,
initializes go-rel/WebAuthn, and generates bootstrap state. `Server.handler()`
applies security headers and Origin/content-type checks around the HTTP mux.
`http.go` serves WebAuthn JSON endpoints; `ui.go` serves HTML pages and fragments.
`registration.go` owns token hashing, lifetime bounds, and transactional enrollment.
`store.go` uses go-rel for user/credential reads and login credential updates.
New enrollment uses database/sql transactions through the same underlying DB.

Configuration: SERVICE_PORT (8080), POSTGRES_URI (required, or
POSTGRES_URI_FROM), POSTGRES_PASSWORD_FILE, ORIGIN (http://localhost:8080),
RP_ID (localhost), RP_NAME (Minimal WebAuthn). Matching CLI flags are in
`internal/config/config.go`. REDIS_URI (or REDIS_URI_FROM) is required for all
sessions; REDIS_PASSWORD_FILE supports password-only and ACL URIs. `main.go`
maps it into app.Config.RedisURL. Redis startup failures are fatal; no memory
fallback exists. MemorySessions is a test double compiled only in tests.
FORWARD_AUTH_ORIGINS (`--forward-auth-origins`) is a comma-separated allowlist of
exact public app origins, default empty (forward authentication disabled).
Public deployments need HTTPS, matching ORIGIN/RP_ID, and the configured ORIGIN
must be the externally reachable origin used to generate links. Do not build
absolute registration URLs from untrusted Host or forwarded headers.

## Data and enrollment invariants

- Add Goose migrations; never rewrite deployed migrations. `00002` adds
  users.is_admin and registration_links, and promotes the earliest existing
  user (created_at, then username for deterministic ties). Fresh bootstrap sets
  is_admin=true; admin-created users are always regular users.
- Bootstrap begin holds a pending User with a UUID in Redis. It must
  not persist a user before a valid passkey response. Finish locks the bootstrap
  app_states row, checks that no users exist, inserts admin and credential, and
  deletes bootstrap state in one transaction. Competing finishes must yield
  exactly one account. Failed/canceled ceremonies leave bootstrap retryable.
- Links use 32 cryptographically random bytes, hex encoded. PostgreSQL and
  registration sessions store SHA-256 hashes, never raw tokens. Links bind to
  a user ID and contain expires_at/used_at/created_at Unix timestamps.
- POST /ui/links accepts `minutes` (integer 1–43200) and optional `username`.
  Authenticated users may target themselves; only admins may target others.
  Generate the QR locally with go-qrcode; never send tokens to a QR service.
- Registration links are `${ORIGIN}/register#${token}`. The browser reads the
  fragment, removes it from history, and POSTs it as JSON `linkToken`. Never
  move the bearer secret to a query string, access log, referrer, or HTMX history.
- Link begin derives the account exclusively from the token and rejects username
  or bootstrap-token overrides. It supplies existing credential exclusions.
- Finish verifies WebAuthn first, then locks the link row FOR UPDATE. Recheck
  expiry, unused state, and user ID after acquiring the lock. Insert a new
  credential and mark the link used in the same transaction. Rollback must
  preserve the link if credential insertion fails. Enrollment must never upsert
  an existing credential or overwrite another account's credential.
- Consuming a link does not log the user in. Login is a separate WebAuthn ceremony.
- Migration `00003` adds device_name to passkeys. Registration accepts optional
  deviceName, trims it and stores it in the ceremony and enrollment transaction.
  Names contain 1–80 Unicode characters without controls. Old passkeys and
  ceremonies default to Unnamed device; names can be changed while in use.
- Device removal must lock the credential row, then check live Redis sessions.
  Login completion locks the same row and updates only an existing credential;
  never upsert a credential during login. Create its device-bound Redis session
  before releasing the row lock. Reject removal while any session uses the
  device; legacy sessions without a device ID protect all of that user's devices.
- No link deletion, role editing, or account recovery UI exists yet.

## HTTP and sessions

- GET / and /register: full pages. GET /ui/state: account fragment.
- GET /ui/activity: signed-in users see their own devices and sessions; admins
  also see all users/UUIDs, devices and sessions. GET /ui/admin is an admin-only
  alias. HTMX loads and refreshes the panel. Filter rows server-side, never in JS.
- POST /ui/devices/rename (device_id, device_name), /ui/devices/remove (device_id)
  and /ui/sessions/remove (kind, session_id): owner or admin only. Recheck access
  for each action; protect the caller's current gateway session and its app
  sessions. Device removal requires no live sessions (see locking rules above).
- Session references are token hashes; never render bearer tokens or ceremony
  data. Redis listing scans only the gateway namespace and excludes app sessions
  with expired/revoked parents. New auth payloads include DeviceID; app sessions
  inherit it through their parent. Legacy sessions remain usable with unknown
  devices. Removing an auth record revokes every app session derived from it.
- POST /ui/users: admin-only account creation (`username` form field); returns
  refreshed account HTML on success using HX-Retarget. Unique usernames return 409.
- POST /ui/links: returns a link, inline QR PNG, download link, and expiry.
- POST /ui/logout: clears auth and returns the signed-out fragment.
- GET /api/bootstrap, /api/me; POST /api/register/begin, /api/register/finish,
  /api/login/begin, /api/login/finish, /api/logout: JSON API.
- All POSTs require an Origin header matching configured ORIGIN. /api/ POSTs also
  require application/json. Maintain these checks when adding mutation routes.
- Responses use no-store, no-referrer, nosniff, and a self-only CSP (QR images
  allow data:). Cookies are HttpOnly and Secure for HTTPS origins. Ceremony
  cookies are SameSite=Strict; gateway auth and app cookies use SameSite=Lax
  for top-level navigation between unrelated sites. POST Origin checks remain.
- Redis stores ceremonies (30 minutes), auth sessions (7 days), app sessions
  (bounded by parent auth TTL), SSO flows (10 minutes), and grants (1 minute).
  WebAuthn challenge expiry and link expiry may be earlier. Replicas share a
  namespace derived from ORIGIN and require the same Redis database/config.
  Gateway restarts preserve sessions; Redis durability depends on its backend.
- A bounded LRU caches up to 4096 immutable payloads for at most 30 seconds.
  Always check Redis PTTL before using cached authorization data. Do not serve
  cached sessions on Redis errors, missing keys, or keys without a positive TTL.
  All writes use unique immutable keys; never replace an existing token identity.
- Redis keys and parent references contain token hashes, never raw bearer tokens.
  Login completion and SSO redemption must atomically validate, consume, and
  create session records in Redis. Never implement one-time consumption through
  a local cache or separate GET/DEL commands. Keep Redis command retries disabled
  for these non-idempotent scripts. Successful registration still relies on its
  PostgreSQL transaction to prevent replay if Redis ceremony cleanup fails.
- GET /forward_auth validates a separate app session using trusted proxy headers
  and returns 204 with X-Auth-Request-User (UUID) and X-Auth-Request-Name, or 303
  to the configured ORIGIN's /auth/authorize path. Empty allowlists return 503;
  malformed/unlisted forwarded origins return 400. Unknown paths return 404.
- The gateway session must never be accepted as an app session or copied to an
  app. App sessions bind to exact allowed origins and live gateway sessions.
  Logging out of the gateway revokes derived app sessions. User lookup failures
  must deny access; never echo client-supplied identity headers.
- /auth/authorize reuses the gateway session or renders the existing passkey UI.
  Successful login reloads the authorize URL. Caddy forwards the app callback
  (/_auth/callback) through /forward_auth; its non-2xx response sets host-only app
  cookies and redirects to the original URL. No separate callback route is needed.
- Callback state cookies bind the browser to a ten-minute flow and one-minute
  single-use code. Check state, exact app origin, expiry, and live parent session
  before consuming atomically. Codes are stored hashed. HTTPS app cookies use
  the __Host- prefix; all app/state cookies have Path=/ and no Domain attribute.
