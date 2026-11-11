# Access Gateway

Passkey sign-in and account management for self-hosted apps. Users enroll devices
with single-use links or QR codes; administrators create accounts. A reverse
proxy can use the gateway for shared sign-in and pass verified user identities
to protected apps, including apps restricted to administrators.

PostgreSQL stores accounts and passkeys. Redis stores sessions and sign-in flows.
Both are required; the service includes its web interface.

## Try it locally

You need Git and Docker with the Compose plugin. The included stack starts the
gateway, PostgreSQL, and Redis with local development credentials. Ports 5432
and 8080 must be free.

```sh
git clone https://github.com/razzie-cloud/access-gateway.git
cd access-gateway
docker compose up --build -d
docker compose logs app
```

Open <http://localhost:8080>. Find the `bootstrap.token_created` event in the
logs and enter its `bootstrap_token`, a username, and a device name. Complete the
passkey prompt to create the first administrator, then sign in. The token is
logged only once when generated; keep the initial logs until setup is complete.

## Enroll users and devices

As administrator, use **Create a user**, then select the account under
**Device registration links** and generate a link or QR code. Send it privately
to the user so they can register their first passkey and sign in.

Signed-in users can generate links for their own additional devices. Each link
registers one passkey and expires after the selected lifetime. Treat links and
QR codes as credentials. Devices and active sessions can be managed in the UI.

## Connect your apps

For a public installation, use HTTPS and set:

| Setting | Example / purpose |
| --- | --- |
| `ORIGIN` | `https://auth.example.com`, the public gateway URL |
| `RP_ID` | `auth.example.com`, the passkey relying-party hostname |
| `POSTGRES_URI` | PostgreSQL connection URI, or use `POSTGRES_URI_FROM` for broker discovery |
| `REDIS_URI` | Redis connection URI, or use `REDIS_URI_FROM` for broker discovery |
| `FORWARD_AUTH_ORIGINS` | Exact allowed app origins, e.g. `https://app.example.com` |

Configure Caddy to check every app path through `/forward_auth` (or
`/forward_auth/admin`) and pass the verified `X-Auth-Request-User` UUID and
`X-Auth-Request-Name` headers, plus `X-Auth-Request-Token` (PASETO v4.public). Keep app backends private and strip incoming
identity headers. See the [Caddy setup](docs/reference.md#protect-apps-with-caddy)
for a complete example.

For a working multi-app demo, use the
[Razzie Cloud local stack](https://github.com/razzie-cloud/.github#try-it-locally).
Configuration, enrollment details, operations, and image publishing are in the
[reference guide](docs/reference.md); development guidance is in
[AGENTS.md](AGENTS.md).

The header logo and Razzie Cloud name link to `LANDING_ORIGIN`
(`--landing-origin`, default `https://razzie.cloud`). Set this to the exact
HTTP(S) origin of your landing page, without a trailing slash. The adjacent
service name opens this app. Compose and Swarm set the landing origin for their
local/public domain.

Public verification keys are available at `/.well-known/paseto-keys`. Signing
keys rotate daily in shared Redis/Valkey. See the [signed identity contract](docs/reference.md#signed-proxy-identity).
