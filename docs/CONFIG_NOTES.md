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
  server: string              # [https://]host[:port]
  protocol: fortinet | gp | anyconnect | nc | pulse | f5 | array
  user: string
  password: string            # omit -> prompted at connect
  servercert: string          # optional pin-sha256
  authgroup: string           # optional
  totp: bool
  totp_secret: string         # optional base32 -> automatic code

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
