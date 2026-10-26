# Caddy + OWASP Coraza (CRS v4 nhung san trong module)
FROM caddy:2.11.7-builder AS builder
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2@v2.6.2

FROM caddy:2.11.7
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN mkdir -p /var/log/coraza
