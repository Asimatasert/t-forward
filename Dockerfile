FROM alpine:3.20 AS build

# microsocks (tiny SOCKS5 server) is not packaged in Alpine; build from source.
ARG MICROSOCKS_VERSION=1.0.5
RUN apk add --no-cache build-base curl \
    && curl -fsSL "https://github.com/rofl0r/microsocks/archive/refs/tags/v${MICROSOCKS_VERSION}.tar.gz" \
       | tar xz -C /tmp \
    && make -C "/tmp/microsocks-${MICROSOCKS_VERSION}" \
    && cp "/tmp/microsocks-${MICROSOCKS_VERSION}/microsocks" /usr/local/bin/microsocks

FROM alpine:3.20

RUN apk add --no-cache bash openconnect socat iproute2 openssh-client sshpass

COPY --from=build /usr/local/bin/microsocks /usr/local/bin/microsocks
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
