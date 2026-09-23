# Config format (YAML)

Each tunnel is one YAML file in `~/.config/t-forward/conf.d/<name>.yaml`. Both
consumers read it with **`yq`** — the CLI extracts fields with `yq`, the daemon
runs `yq -o=json` and unmarshals the JSON. The file is **never sourced as bash**,
so values need no shell quoting. `examples/` has fully-commented files.

## Why yq

The format used to be bash `KEY=VALUE` files with delimiter-packed arrays
(`HOSTS=("IP | note | 22:2207@ssh")`) plus side arrays cross-referenced by key
(`FWD_NOTES=("IP:22 = note")`). That grew three different micro-syntaxes and put a
forward's note in a different array from the forward. Moving to YAML + yq collapsed
all of it: every value lives where it belongs, and the daemon's ~300 lines of
hand-rolled parsing became a struct unmarshal. The cost is one dependency, the
`yq` binary (mikefarah v4), used by both the CLI and the daemon.

## Schema

```yaml
name:  string                 # display name (defaults to the file name)
type:  vpn | ssh | local
tags:  [string]               # optional, panel filters
socks: int | "any"            # optional SOCKS5 proxy port
restart: bool                 # optional, auto-reconnect policy
totp_command: string          # optional, TOTP automation (wraps `t-forward code`)

vpn:                          # when type: vpn
  server: string              # [https://]host[:port]  (openconnect);  host  (ipsec, IKE is UDP)
  protocol: fortinet | gp | anyconnect | nc | pulse | f5 | array | ipsec
  user: string               # SSL-VPN user, or the XAuth user when protocol: ipsec
  password: string            # omit -> prompted at connect (SSL-VPN); XAuth password (ipsec)
  servercert: string          # optional pin-sha256 (openconnect only)
  authgroup: string           # optional (openconnect only)
  totp: bool
  totp_secret: string         # optional base32 -> automatic code
  totp_imap:                  # optional; web daemon fetches emailed codes
    host: string
    port: int                # default 993 (TLS) or 143 (STARTTLS)
    user: string
    password: string         # SECRET; protect the YAML with chmod 600
    mailbox: string          # default INBOX
    from_filter: string      # optional IMAP FROM substring match
    tls: bool                # default true: implicit TLS; false: STARTTLS
  # --- protocol: ipsec (strongSwan) only ---
  psk: string                 # required: the IKE pre-shared key (shared secret, NOT the user password)
  ikev: 1 | 2                 # optional, default 1 (FortiGate dialup, aggressive mode); 2 = IKEv2
  ike_proposal: string        # optional Phase-1 proposals "enc-integ-dhgroup,..." (default matches common FortiGate)
  esp_proposal: string        # optional Phase-2 proposals (PFS via the modpXXXX group)
  ike_lifetime: string        # optional Phase-1 SA lifetime (default 28800s)
  lifetime: string            # optional Phase-2 SA lifetime (default 43200s)
  local_id: string            # optional Local ID / leftid (usually empty for dialup)
  remote_id: string           # optional expected gateway ID / rightid

ssh:                          # when type: ssh
  host: string                # the host you land on (forwards resolve from here)
  user: string
  port: int                   # default 22
  key: string                 # key path; required when `jump` is set
  jump: [string]              # ordered ProxyJump hops, "[user@]host[:port]"

hosts:                        # forward targets, grouped by host
  - ip: string
    name: string              # optional
    tags: [string]            # optional
    forwards:
      - remote: int           # the server's port
        local: int | "any" | "BIND:PORT"
        service: string       # optional; auto-detected from remote port
        user: string          # optional; feeds the panel copy string
        note: string          # optional

subnets:                      # optional labels for runtime-discovered VPN subnets
  - cidr: string
    label: string
    tags: [string]
```

## Web editing

The daemon's `/conf/<name>` endpoint edits a whitelist of fields (name, tags,
host name/tags, forward note, subnet label/tags) with `yq -i`. Values reach yq
only through environment variables read via `strenv()`/`fromjson`, so a crafted
value can never inject yq syntax, and the sensitive keys (password, servercert,
totp_secret, ssh key) are never on any editable path. `yq -i` preserves the rest
of the file, including comments.

## Emailed verification codes

Set `vpn.totp: true` and `vpn.totp_imap` on each VPN that receives emailed codes.
The web daemon must be running, and its host needs Python 3 (standard library
only; no pip packages). This uses the same wait hook and `t-forward code` delivery
as `totp_command`; CLI-only sessions retain manual entry. IMAP takes precedence
when both sources are configured, and does not require `--allow-totp-command`.
A configured `totp_secret` continues to use the existing generated-code flow.

The helper polls every 3 seconds for up to 90 seconds (the daemon enforces a
120-second total timeout). It searches unseen messages, optionally matching
`from_filter`, and inspects the newest 50 matches first using IMAP UIDs. Arrival
must be within 30 seconds before the current wait began and no more than 120
seconds before polling began. It extracts the first standalone 4–8 digit run
from decoded plain-text or HTML bodies, ignoring attachments and headers.
Use a dedicated mailbox or sender filter to avoid unrelated numeric messages.
Messages remain unread. A missing code or failed login leaves manual/webhook
entry available; a new wait starts a new attempt.

TLS certificates are verified. `tls: false` requires STARTTLS rather than sending
credentials in plaintext. The password travels to the helper through an anonymous
stdin pipe, never command arguments, logs, panel responses, or temporary auth
files. Keep the source YAML mode `0600`, like other password-bearing configs.
IMAP settings are excluded from the panel's editable whitelist.
See `examples/vpn-imap.example.yaml`.
