# Contributing to t-forward

Thanks for taking the time to contribute! t-forward is a small, focused tool —
a Docker-based tunnel & port-forward manager with an optional web panel. This
guide gets you from a clone to a green PR.

## Ways to help

- **File a bug** — use the *Bug report* issue template.
- **Propose a feature** — use the *Feature request* template. Small, composable
  additions fit the tool best.
- **Pick up an issue** — anything tagged
  [`good first issue`](https://github.com/Asimatasert/t-forward/labels/good%20first%20issue)
  or [`help wanted`](https://github.com/Asimatasert/t-forward/labels/help%20wanted)
  is a good entry point. Comment on it so we don't double up.
- **Improve the docs** — the README, `docs/CONFIG_NOTES.md`, and the
  `examples/` templates are all fair game.

## Project layout

| Path | What it is |
|---|---|
| `t-forward` | the CLI — a single Bash script (`#!/usr/bin/env bash`) |
| `entrypoint.sh` | runs inside the tunnel container (openconnect / ssh / socat) |
| `Dockerfile` | builds the Alpine tunnel image |
| `web/` | the optional web daemon — Go, standard library only (no deps) |
| `web/panel/index.html` | the panel UI (vanilla JS + canvas), embedded into the daemon |
| `examples/` | fully-commented config templates |
| `docs/` | config reference and the panel screenshot |

## Building & running locally

**CLI** — no build step; symlink it onto your `PATH`:

```sh
ln -s "$PWD/t-forward" /usr/local/bin/t-forward
```

**Web daemon** — Go ≥ 1.21 (the module targets the version in `web/go.mod`),
standard library only:

```sh
cd web
go build -o t-forward-web .
TF_WEB_TOKEN=dev ./t-forward-web --addr 127.0.0.1:8787
# open http://127.0.0.1:8787/?token=dev
```

The panel HTML is `//go:embed`-ed into the binary, so rebuild the daemon after
editing `web/panel/index.html`.

## Before you open a PR

CI runs on every push and PR (see `.github/workflows/ci.yml`). Run the same
checks locally so it comes back green:

```sh
cd web
gofmt -l .        # must print nothing
go vet ./...
go build ./...
go test ./...

# from the repo root — the Bash scripts must parse:
bash -n ../t-forward
bash -n ../entrypoint.sh
```

## Coding conventions

- **Go**: `gofmt`-clean, standard library only — please don't add module
  dependencies. Keep the daemon localhost-first and token/PIN-gated.
- **Bash**: target `bash` ≥ 3.2 (macOS ships 3.2). Quote expansions; never
  `source` a config file — configs are read with `yq`.
- **Panel**: vanilla JS, no framework, no external/CDN assets. Escape any
  value that could contain user/host-supplied text before inserting it into the
  DOM (see `esc()`), since hostnames and notes are attacker-influenceable.
- **Security**: this tool handles VPN/SSH credentials. Never log secrets, never
  return them to the panel, and never put real IPs, hostnames, or credentials in
  commits, issues, or PRs — use placeholders.

## Commit & PR style

- Keep commits focused; write imperative, present-tense subjects
  (`panel: add tree view`, not `added tree view`).
- Describe *what changed and why* in the body. Reference issues with `#NN`.
- If the change is user-visible, update the README / examples in the same PR.

## Releases

Maintainer-only: pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`,
which builds the multi-arch image, pushes it to Docker Hub, and attaches the
built binaries to the GitHub release.
