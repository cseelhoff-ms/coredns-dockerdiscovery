#!/bin/sh
set -e

# Defaults — see README.md for the full directive table.
: "${DOCKER_ENDPOINT:=unix:///var/run/docker.sock}"
: "${TRAEFIK_CNAME:=}"          # CNAME target served for every Traefik FQDN
: "${HOST_IP:=}"                # LAN-facing host IP for the `host` label
: "${CF_TOKEN:=}"
: "${CF_TUNNEL_ID:=}"
: "${CF_ACCOUNT_ID:=}"
: "${CF_TUNNEL_TARGET:=}"
: "${CF_ZONE_ID:=}"
: "${CF_EXCLUDE:=}"
: "${FORWARD_DNS:=1.1.1.1 8.8.8.8}"
: "${CACHE_TTL:=30}"
: "${INVENTORY_ADDR:=}"
: "${INVENTORY_PATH:=}"

# Fail fast on missing required combinations. Without these the plugin
# rejects the Corefile and the container loops on restart, hiding the
# real reason in a sea of "=== Generated Corefile ===" log entries.
if [ -n "$CF_TUNNEL_ID" ] && [ -z "$CF_TUNNEL_TARGET" ]; then
    echo "FATAL: CF_TUNNEL_ID is set but CF_TUNNEL_TARGET is empty." >&2
    echo "Set CF_TUNNEL_TARGET to the backend service URL cloudflared should forward to," >&2
    echo "e.g. https://localhost:443 for a co-located Traefik." >&2
    exit 64
fi
if [ -n "$CF_TUNNEL_ID" ] && [ -z "$CF_TOKEN" ]; then
    echo "FATAL: CF_TUNNEL_ID is set but CF_TOKEN is empty." >&2
    exit 64
fi

# Build Corefile
cat > /tmp/Corefile <<COREFILE
.:53 {
COREFILE

# Optional hosts block: when both HOST_IP and TRAEFIK_CNAME are set,
# resolve TRAEFIK_CNAME → HOST_IP locally so the chased CNAME from the
# docker plugin completes inside this CoreDNS instance.
if [ -n "$HOST_IP" ] && [ -n "$TRAEFIK_CNAME" ]; then
cat >> /tmp/Corefile <<COREFILE
    hosts {
        ${HOST_IP} ${TRAEFIK_CNAME}
        fallthrough
    }
COREFILE
fi

# Docker plugin block — opens
cat >> /tmp/Corefile <<COREFILE
    docker ${DOCKER_ENDPOINT} {
COREFILE

if [ -n "$TRAEFIK_CNAME" ]; then
cat >> /tmp/Corefile <<COREFILE
        traefik_cname ${TRAEFIK_CNAME}
COREFILE
fi

if [ -n "$HOST_IP" ]; then
cat >> /tmp/Corefile <<COREFILE
        host_ip ${HOST_IP}
COREFILE
fi

if [ -n "$CF_TOKEN" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_token ${CF_TOKEN}
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

if [ -n "$CF_TUNNEL_TARGET" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_tunnel_target ${CF_TUNNEL_TARGET}
COREFILE
fi

if [ -n "$CF_ZONE_ID" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_zone_id ${CF_ZONE_ID}
COREFILE
fi

if [ -n "$CF_EXCLUDE" ]; then
cat >> /tmp/Corefile <<COREFILE
        cf_exclude ${CF_EXCLUDE}
COREFILE
fi

if [ -n "$INVENTORY_ADDR" ]; then
cat >> /tmp/Corefile <<COREFILE
        inventory ${INVENTORY_ADDR} ${INVENTORY_PATH}
COREFILE
fi

# Docker plugin block — closes
cat >> /tmp/Corefile <<COREFILE
    }
COREFILE

# Forward upstreams + standard plugins
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
