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
(header `X-Token` / `Authorization: Bearer`, or `?token=` for the browser).
The daemon binds 127.0.0.1 only and shells out to the CLI — it never talks to
a VPN itself. Stdlib only; no external Go modules.

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

No secret is ever stored — codes are single-use and short-lived.
