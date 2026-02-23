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
: "${CF_TUNNEL_ID:=}"
: "${CF_ACCOUNT_ID:=}"
: "${FORWARD_DNS:=1.1.1.1 8.8.8.8}"
: "${CACHE_TTL:=30}"
: "${CNAME_TARGET:=}"
: "${CNAME_TARGET_IP:=}"

# Build Corefile
cat > /tmp/Corefile <<COREFILE
.:53 {
COREFILE

# Hosts block — resolve CNAME_TARGET and/or TRAEFIK_HOST to an IP.
# CNAME_TARGET_IP takes priority; falls back to TRAEFIK_IP.
HOSTS_IP="${CNAME_TARGET_IP:-$TRAEFIK_IP}"
HOSTS_ENTRIES=""

if [ -n "$HOSTS_IP" ] && [ -n "$CNAME_TARGET" ]; then
    HOSTS_ENTRIES="${HOSTS_ENTRIES}        ${HOSTS_IP} ${CNAME_TARGET}\n"
fi
if [ -n "$HOSTS_IP" ] && [ -n "$TRAEFIK_HOST" ] && [ "$TRAEFIK_HOST" != "$CNAME_TARGET" ]; then
    HOSTS_ENTRIES="${HOSTS_ENTRIES}        ${HOSTS_IP} ${TRAEFIK_HOST}\n"
fi

if [ -n "$HOSTS_ENTRIES" ]; then
printf "    hosts {\n${HOSTS_ENTRIES}        fallthrough\n    }\n" >> /tmp/Corefile
fi

# Docker plugin block
cat >> /tmp/Corefile <<COREFILE
    docker ${DOCKER_ENDPOINT} {
        domain ${DOCKER_DOMAIN}
COREFILE

# When CNAME_TARGET is set, use it for traefik_cname too (all CNAMEs point to the host).
# Otherwise fall back to TRAEFIK_HOST for backward compatibility.
if [ -n "$CNAME_TARGET" ]; then
cat >> /tmp/Corefile <<COREFILE
        traefik_cname ${CNAME_TARGET}
COREFILE
elif [ -n "$TRAEFIK_HOST" ]; then
cat >> /tmp/Corefile <<COREFILE
        traefik_cname ${TRAEFIK_HOST}
COREFILE
fi

if [ -n "$CNAME_TARGET" ]; then
cat >> /tmp/Corefile <<COREFILE
        cname_target ${CNAME_TARGET}
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

if [ -n "$CF_TUNNEL_ID" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_tunnel_id ${CF_TUNNEL_ID}
COREFILE
fi

if [ -n "$CF_ACCOUNT_ID" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_account_id ${CF_ACCOUNT_ID}
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
sed 's/\(cf_token\s\+\).*/\1***REDACTED***/' /tmp/Corefile
echo "=========================="

exec /usr/local/bin/coredns -conf /tmp/Corefile "$@"
