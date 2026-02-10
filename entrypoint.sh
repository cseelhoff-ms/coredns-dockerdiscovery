#!/bin/sh
set -e

# Defaults
: "${DOCKER_ENDPOINT:=unix:///var/run/docker.sock}"
: "${DOCKER_DOMAIN:=docker.local}"
: "${TRAEFIK_IP:=}"
: "${TRAEFIK_HOST:=}"
: "${CF_TOKEN:=}"
: "${CF_TARGET:=}"
: "${CF_ZONE_DOMAIN:=}"
: "${CF_ZONE_ID:=}"
: "${FORWARD_DNS:=1.1.1.1 8.8.8.8}"
: "${CACHE_TTL:=30}"

# Build Corefile
cat > /tmp/Corefile <<COREFILE
.:53 {
COREFILE

# Hosts block (only if TRAEFIK_IP and TRAEFIK_HOST are set)
if [ -n "$TRAEFIK_IP" ] && [ -n "$TRAEFIK_HOST" ]; then
cat >> /tmp/Corefile <<COREFILE
    hosts {
        ${TRAEFIK_IP} ${TRAEFIK_HOST}
        fallthrough
    }
COREFILE
fi

# Docker plugin block
cat >> /tmp/Corefile <<COREFILE
    docker ${DOCKER_ENDPOINT} {
        domain ${DOCKER_DOMAIN}
COREFILE

if [ -n "$TRAEFIK_HOST" ]; then
cat >> /tmp/Corefile <<COREFILE
        traefik_cname ${TRAEFIK_HOST}
COREFILE
fi

if [ -n "$CF_TOKEN" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_token ${CF_TOKEN}
COREFILE
fi

if [ -n "$CF_TARGET" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_target ${CF_TARGET}
COREFILE
fi

if [ -n "$CF_ZONE_DOMAIN" ] && [ -n "$CF_ZONE_ID" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_zone ${CF_ZONE_DOMAIN} ${CF_ZONE_ID}
COREFILE
fi

cat >> /tmp/Corefile <<COREFILE
    }
COREFILE

# Forward - shell expansion splits on spaces naturally
cat >> /tmp/Corefile <<COREFILE
    forward . ${FORWARD_DNS}
    log
    errors
    cache ${CACHE_TTL}
}
COREFILE

echo "=== Generated Corefile ==="
cat /tmp/Corefile
echo "=========================="

exec /usr/local/bin/coredns -conf /tmp/Corefile "$@"
