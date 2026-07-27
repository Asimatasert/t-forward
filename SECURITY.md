# Security Policy

t-forward manages VPN/SSH credentials and opens tunnels into private networks,
so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's
[**Report a vulnerability**](https://github.com/Asimatasert/t-forward/security/advisories/new)
(Security → Advisories). Include:

- what the issue is and how to reproduce it,
- the impact you foresee, and
- the affected version / commit.

Please **redact any real IPs, hostnames, or credentials** from your report.

You can expect an initial response within a few days. Once a fix is available it
will ship in a tagged release with credit to the reporter (unless you prefer to
stay anonymous).

## Supported versions

This is a small project; fixes land on the latest release. Please upgrade to the
newest tag before reporting.

## Handling model (for context)

- The web daemon is **localhost-first**: bind a trusted address (localhost or a
  private overlay), gated by a bearer token; it has **no TLS** and must not be
  exposed on a public interface.
- Configs hold **plaintext credentials** at mode `600` and are git-ignored.
- Panel config edits are whitelisted and never touch the password, server cert,
  TOTP secret, or SSH key.
