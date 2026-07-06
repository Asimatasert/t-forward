# t-forward web

A localhost-only control panel for t-forward: a live topology map with
per-tunnel throughput, a filterable network-event console, and up/down/code
actions — all driven from the same `t-forward` CLI and Docker state.

## Run

```sh
cd web
go build -o t-forward-web .
TF_WEB_TOKEN=$(openssl rand -hex 16) ./t-forward-web            # prints the URL
# or let it generate a token and print the full panel URL:
./t-forward-web
```

Flags: `--addr 127.0.0.1:8787`, `--token-file PATH`, `--tf t-forward`,
`--config-dir ~/.config/t-forward`. The token is required on every request
(header `X-Token` / `Authorization: Bearer`, or `?token=` on the initial
browser load — after which the daemon hands the token to a `SameSite=Strict`,
`HttpOnly` cookie, so no subsequent request carries the token in its URL).
The daemon binds 127.0.0.1 only and shells out to the CLI — it never talks to
a VPN itself. Stdlib only; no external Go modules.

Hardening flags:

- `--allow-totp-command` (or `TF_ALLOW_TOTP_COMMAND=1`) — required before a
  tunnel's `totp_command` will be auto-executed. It runs arbitrary shell as the
  daemon user, so it is **off by default**; without it a configured
  `totp_command` is ignored (a console note explains why).
- `--allowed-hosts a,b` — extra `Host` header values to accept. The daemon
  already accepts loopback, the bind host, and IP-literal Hosts; anything else
  (a rogue hostname, i.e. a DNS-rebinding attempt) is rejected `403`. Browser
  requests marked `Sec-Fetch-Site: cross-site` are rejected too, so a website
  the operator visits cannot drive the panel.
- `--no-auth` disables the token entirely. On a non-loopback bind it also needs
  `--expose` as an explicit acknowledgement that anyone who can reach the
  address gets full control.

## What it streams (SSE `/events`)

- `state`   — the full tunnel list (docker ps merged with conf.d)
- `stat`    — per-tunnel throughput (docker stats net I/O deltas, bytes/s)
- `event`   — classified log lines (conn / tunnel / auth / error)
- `waiting` — a tunnel is blocking on a TOTP code

## Actions

`POST /up {name}` · `POST /down {name|all}` · `POST /code {name,code}` ·
`POST /totp/<name> {code}` (the no-secret TOTP webhook).

## TOTP without a secret

For `TOTP=true` tunnels the code arrives out-of-band (SMS/mail/Telegram)
~10-30 s after the password. Supply it any of these ways:

- **Panel / CLI** — type it into the panel, or `t-forward code <name> <code>`.
- **Webhook** — `POST /totp/<name>` with the token; e.g. an iPhone Shortcut
  that reads the SMS and POSTs, or a Telegram bot.
- **TOTP_COMMAND** — set it in the tunnel's conf; the daemon runs it when the
  tunnel starts waiting and delivers the first 4-8 digit run from its stdout.
  Because it is arbitrary shell run as the daemon user, auto-execution is
  **off unless** the daemon was started with `--allow-totp-command`.

No secret is ever stored — codes are single-use and short-lived.
