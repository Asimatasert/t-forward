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
browser load — after which the panel uses a browser session, so no subsequent
request carries the token in its URL).

The browser session is deliberately split in two, because a cookie is scoped by
host and **not by port**: the browser sends this daemon's cookies to every
forwarded service you open on the same hostname. So the `tf_session` cookie
(`SameSite=Strict`, `HttpOnly`, no token material) is accepted only together
with a per-session key that the panel keeps in its own origin's storage and
sends in the `X-Session-Key` header; the admin session works the same way
(`tf_admin` cookie + `X-Admin-Key`, both issued by `POST /admin/unlock`). A
cookie replayed by another port cannot call the API or start a session; the
only thing it gets is the static panel page from `GET /` (no key, no data).
Consequences:

- Open a new browser profile (or a browser whose site data was cleared) through
  the `/?token=` link again; a bare `/` only works where the session exists.
- **Upgrading from v0.8.0 or earlier:** those versions kept the raw token in a
  `tf_token` cookie, so the browser sent the token itself to every forwarded
  HTTP service you opened on the same hostname. If you use a fixed token
  (`TF_WEB_TOKEN` or `--token-file`), treat it as disclosed to those services
  and rotate it. The daemon no longer accepts that cookie and tells the browser
  to drop it on the first request that carries it; every browser, and every
  panel tab left open across the upgrade, must open the `/?token=` link once.
- API clients are unaffected: send the token in `Authorization: Bearer` /
  `X-Token`, and the admin PIN in `X-Admin-Token`. The `tf_admin` cookie value
  is no longer accepted as `X-Admin-Token`. A value there that cannot be the PIN
  (shorter than 6 characters, or a live session token) is refused without
  counting towards the PIN lockout; any other wrong value still counts.
- Replacing an existing admin PIN needs `currentPin` in the `POST /settings`
  body (the panel asks for it); setting the first PIN does not. PIN lockouts
  are tracked per client address (peer address only, no forwarded-for
  headers) with a global ceiling; behind a reverse proxy all callers share one
  counter.
- Sessions survive a daemon restart only with a fixed token (`TF_WEB_TOKEN` or
  `--token-file`): they are bound to the token and to a random secret stored in
  `<config-dir>/web-session.key` (mode `600`). A token generated at startup is
  new on every start, so each restart signs every browser out. Changing the
  token, or deleting that file and restarting, signs every browser out too. Nothing else does: a
  browser session has no expiry of its own.
- What the split does not cover: the key has to be readable by the panel's
  script, so script injected into the panel origin could read it. A key
  together with its cookie (which a forwarded service on the same hostname
  receives) is a complete session that works from outside the browser until the
  token is rotated or `web-session.key` is deleted; for the admin session, until
  its 8 hours are over.

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
  the operator visits cannot drive the panel. The one exception is a top-level
  GET navigation (opening the panel link); a cross-site load into an
  `<iframe>` / `<frame>` / `<embed>` / `<object>` is rejected `403`.
- Every response carries `X-Frame-Options: DENY`,
  `Content-Security-Policy: frame-ancestors 'none'` and
  `X-Content-Type-Options: nosniff`: the panel cannot be embedded in another
  page (clickjacking), in either auth mode. Embedding it in a dashboard iframe
  is therefore not supported.
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

- **IMAP** — set `vpn.totp_imap` to poll an inbox automatically. Requires Python 3
  on the daemon host; no shell-execution flag is needed. See
  [configuration notes](../docs/CONFIG_NOTES.md#emailed-verification-codes) and
  [the example](../examples/vpn-imap.example.yaml). The IMAP password stays private;
  protect the YAML with mode `0600`.

Verification codes are single-use and short-lived.
