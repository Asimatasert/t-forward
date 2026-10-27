# Base image: a supported Alpine branch, pinned by the multi-arch index digest
# (bump the tag and the digest together; Dependabot does this).
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS build

# microsocks (tiny SOCKS5 server) is not packaged in Alpine; build from source.
# The release tarball is verified against a pinned SHA-256 (tag v1.0.5 is commit
# 98421a21c4adc4c77c0cf3a5d650cc28ad3e0107), so a moved tag or a tampered
# archive fails the build instead of landing in the image.
ARG MICROSOCKS_VERSION=1.0.5
ARG MICROSOCKS_SHA256=939d1851a18a4c03f3cc5c92ff7a50eaf045da7814764b4cb9e26921db15abc8
RUN apk add --no-cache build-base curl \
    && curl -fsSL -o /tmp/microsocks.tar.gz \
       "https://github.com/rofl0r/microsocks/archive/refs/tags/v${MICROSOCKS_VERSION}.tar.gz" \
    && echo "${MICROSOCKS_SHA256}  /tmp/microsocks.tar.gz" | sha256sum -c - \
    && tar xz -C /tmp -f /tmp/microsocks.tar.gz \
    && make -C "/tmp/microsocks-${MICROSOCKS_VERSION}" \
    && cp "/tmp/microsocks-${MICROSOCKS_VERSION}/microsocks" /usr/local/bin/microsocks

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

# openconnect -> SSL-VPN (fortinet/gp/anyconnect/...); strongswan -> IPsec/IKE
# (FortiGate dialup: PSK + XAuth), the two families most hospital gateways speak.
RUN apk add --no-cache bash openconnect socat iproute2 openssh-client sshpass \
    strongswan oath-toolkit-oathtool

# Unprivileged runtime user with a fixed UID/GID, so bind-mount ownership is
# predictable. The image defaults to it (USER below); only the vpn tunnel type
# needs root (route/tun setup) and the host CLI starts that one with `--user 0`.
RUN addgroup -g 10001 -S tforward \
    && adduser -S -D -u 10001 -G tforward -h /home/tforward -s /sbin/nologin tforward

COPY --from=build /usr/local/bin/microsocks /usr/local/bin/microsocks
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

USER tforward

ENTRYPOINT ["/entrypoint.sh"]
