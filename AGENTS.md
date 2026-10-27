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
TEST_DATABASE_URL='postgres://user@127.0.0.1:port/testdb?sslmode=disable' go test -race ./...
```

PostgreSQL tests create and drop random schemas and need CREATE SCHEMA permission.
They skip unless TEST_DATABASE_URL is set. They exercise authorization, QR PNG
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
`internal/config/config.go`. Redis options are parsed but storage is in memory.
Public deployments need HTTPS, matching ORIGIN/RP_ID, and the configured ORIGIN
must be the externally reachable origin used to generate links. Do not build
absolute registration URLs from untrusted Host or forwarded headers.

## Data and enrollment invariants

- Add Goose migrations; never rewrite deployed migrations. `00002` adds
  users.is_admin and registration_links, and promotes the earliest existing
  user (created_at, then username for deterministic ties). Fresh bootstrap sets
  is_admin=true; admin-created users are always regular users.
- Bootstrap begin holds a pending User with a UUID in MemorySessions. It must
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
- No passkey/link deletion, role editing, or account recovery UI exists yet.

## HTTP and sessions

- GET / and /register: full pages. GET /ui/state: account fragment.
- POST /ui/users: admin-only account creation (`username` form field); returns
  refreshed account HTML on success using HX-Retarget. Unique usernames return 409.
- POST /ui/links: returns a link, inline QR PNG, download link, and expiry.
- POST /ui/logout: clears auth and returns the signed-out fragment.
- GET /api/bootstrap, /api/me; POST /api/register/begin, /api/register/finish,
  /api/login/begin, /api/login/finish, /api/logout: JSON API.
- All POSTs require an Origin header matching configured ORIGIN. /api/ POSTs also
  require application/json. Maintain these checks when adding mutation routes.
- Responses use no-store, no-referrer, nosniff, and a self-only CSP (QR images
  allow data:). Cookies are HttpOnly, SameSite=Strict, and Secure for HTTPS origins.
- Registration/login ceremonies and auth sessions remain process-local. Ceremony
  map entries expire after 30 minutes; WebAuthn challenge expiry and link expiry
  may be earlier. Auth expires after 7 days. Restarting loses sessions but not
  stored links or passkeys. Multiple replicas require shared session storage.
- Unknown paths return 404; there is still no forward-auth handler. Do not infer
  forward-auth functionality from an HTML response or add deployment changes as
  part of ordinary gateway validation.
