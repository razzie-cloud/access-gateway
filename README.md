# Access Gateway

Passwordless accounts with passkeys, device onboarding links, and user management.
The web interface uses **HTMX and PicoCSS**, served locally by the gateway.

## Start

For local development, run `docker compose up --build` and open
<http://localhost:8080>. PostgreSQL is included. Ports 5432 and 8080 must be free.

To run the Go service directly:

```sh
export POSTGRES_URI='postgres://app:app@localhost:5432/app?sslmode=disable'
go run ./cmd/access-gateway
```

For a public installation, put the gateway behind HTTPS and set `ORIGIN` to its
full public origin (for example, `https://auth.example.com`) and `RP_ID` to its
hostname (`auth.example.com`). Use the same origin when opening registration links.
`SERVICE_PORT` defaults to `8080`; `RP_NAME` sets the passkey display name.

## Set up the administrator

On the first start with no users, find `BOOTSTRAP TOKEN` in the gateway logs.
Open the home page, enter a username and that token, and complete the passkey
prompt. Then sign in. The first account is the administrator; existing
installations promote their earliest account during migration.

Canceling the prompt leaves setup open for another attempt. The bootstrap token
is printed only when generated; restarting does not print it again.

## Add a device

Sign in on an existing device. Under **Device registration links**, choose an
expiration from **1 minute to 30 days** (default: 60 minutes), then select
**Generate link and QR code**. Open the link on the new device or scan the QR
code and create its passkey. The QR image can also be downloaded.

Each link registers one passkey for its designated account and expires at the
displayed time, even if registration is already in progress. A canceled prompt
can be retried while the link remains valid. After registration, sign in with
the account's username. Multiple devices can have separate passkeys.

Treat links and QR codes like credentials: anyone holding one can register a
device for that account. Share them privately and use a separate link per device.
The complete link is shown only when generated; create another if you lose it.

## Add a user

As administrator, use **Create a user**, then choose that account under
**Device registration links**. Generate and privately send its link or QR code.
The recipient registers their first passkey and can then sign in and onboard
their own devices. New accounts are regular users, without admin permissions.

## Operational notes

PostgreSQL stores users, passkeys, and registration links; migrations run at
startup. Login and in-progress passkey sessions are held in memory, so restarts
sign users out and cancel active prompts. Unused links survive restarts. Use a
single gateway instance until shared session storage is implemented. There is
currently no UI for revoking passkeys or unused links.
