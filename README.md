coredns-dockerdiscovery
===================================

A CoreDNS plugin that watches Docker/Podman containers and synthesises
DNS records from their labels — locally, and (optionally) as Cloudflare
Tunnel ingress rules.

This is a heavily reduced fork of
[kevinjqiu/coredns-dockerdiscovery](https://github.com/kevinjqiu/coredns-dockerdiscovery).
Container-IP A records, compose-domain auto-naming, network aliases,
and hostname-domain rewriting have all been removed. What remains is
two record-emission modes, an optional Cloudflare Tunnel ingress
syncer, an optional Cloudflare DNS syncer, and an inventory HTTP
endpoint:

| Mode | Trigger | Local record | Tunnel ingress | Public DNS |
|---|---|---|---|---|
| **Traefik CNAME** | `traefik.http.routers.*.rule=Host(...)` label | CNAME → `traefik_cname` | hostname → `cf_tunnel_target` | proxied CNAME → `<tunnel-id>.cfargotunnel.com` (when `cf_zone_id` is set) |
| **Host A** | `coredns.dockerdiscovery.host=fqdn` label | A → `host_ip` | (none unless the same FQDN also has a Traefik label) | (same as above when paired with a Traefik label) |

For containers without a `host` label, the local CNAME chases through
to the host A record so LAN clients reach the host directly.

For containers with a `host` label that ALSO carry a Traefik router
rule for the same FQDN (typical for Traefik itself), the A record wins
locally (LAN traffic skips Traefik) and the tunnel entry still emits
(public Cloudflare clients reach the same FQDN through the tunnel).

Quick start
-----------

```yaml
# docker-compose.yml
services:
  coredns:
    image: coredns-dockerdiscovery:latest
    restart: unless-stopped
    cap_add: ["NET_BIND_SERVICE"]
    security_opt: ["label=disable"]    # SELinux: required to read the docker socket
    volumes:
      - /run/podman/podman.sock:/var/run/docker.sock:ro
    environment:
      TRAEFIK_CNAME: traefik.177cpt.com    # CNAME target for every Traefik FQDN
      HOST_IP: 10.0.60.3                   # LAN-facing host IP for `host` label
      CF_TOKEN: ${CF_TOKEN}                # scoped Cloudflare API token
      CF_TUNNEL_ID: ${CF_TUNNEL_ID}
      CF_ACCOUNT_ID: ${CF_ACCOUNT_ID}
      CF_TUNNEL_TARGET: https://localhost:443
      CF_ZONE_ID: ${CF_ZONE_ID}            # optional; enables proxied-CNAME DNS sync
      INVENTORY_ADDR: ":8081"
      FORWARD_DNS: 1.1.1.1 8.8.8.8
      CACHE_TTL: "30"
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8081:8081/tcp"   # inventory HTTP endpoint (optional)
```

> **Podman socket:** rootful `/run/podman/podman.sock`, rootless
> `/run/user/$UID/podman/podman.sock`. Enable with
> `systemctl [--user] enable --now podman.socket`. SELinux hosts need
> `security_opt: ["label=disable"]`.

Worked examples (your homelab)
------------------------------

For each row, *Labels to add* is the **complete extra set** beyond
whatever Traefik labels you'd already have for routing.

| Service   | Labels to add | Local DNS | Cloudflare Tunnel |
|-----------|---------------|-----------|-------------------|
| portainer | (none beyond `traefik.http.routers.portainer.rule=Host(\`portainer.177cpt.com\`)`) | CNAME → `traefik.177cpt.com` | `portainer.177cpt.com` → `${CF_TUNNEL_TARGET}` |
| keycloak  | (none beyond `traefik.http.routers.keycloak.rule=Host(\`auth.177cpt.com\`)`) | CNAME → `traefik.177cpt.com` | `auth.177cpt.com` → `${CF_TUNNEL_TARGET}` |
| nexus     | (none beyond `traefik.http.routers.nexus.rule=Host(\`nexus.177cpt.com\`)`) | CNAME → `traefik.177cpt.com` | `nexus.177cpt.com` → `${CF_TUNNEL_TARGET}` |
| openldap  | `coredns.dockerdiscovery.host=ldap.177cpt.com` | A → `10.0.60.3` (= `${HOST_IP}`) | none (no Traefik label) |
| traefik   | `coredns.dockerdiscovery.host=traefik.177cpt.com` plus its dashboard's existing `traefik.http.routers.dashboard.rule=Host(\`traefik.177cpt.com\`)` | A → `10.0.60.3` | `traefik.177cpt.com` → `${CF_TUNNEL_TARGET}` |

LAN clients always end up on the host (`10.0.60.3`). For HTTP services
they go through Traefik on the host; for L4 services like LDAP they
hit the published port on the host directly.

Public clients (over Cloudflare) reach `${CF_TUNNEL_TARGET}` — typically
the local Traefik on `https://localhost:443` running alongside `cloudflared`.

Directives
----------

```
docker [DOCKER_ENDPOINT] {
    traefik_cname    HOSTNAME
    host_ip          IP
    ttl              SECONDS
    cf_token         TOKEN          # or cf_email + cf_key (legacy)
    cf_email         EMAIL
    cf_key           KEY
    cf_tunnel_id     UUID
    cf_account_id    ID
    cf_tunnel_target URL
    cf_zone_id       ZONE_ID        # optional; enables Cloudflare DNS sync
    cf_exclude       fqdn1,fqdn2
    inventory        ADDR [PATH]
}
```

| Directive | Effect |
|---|---|
| `DOCKER_ENDPOINT` | Path/URL to the Docker or Podman API socket. Default `unix:///var/run/docker.sock`. |
| `traefik_cname HOSTNAME` | CNAME target served for every FQDN extracted from `traefik.http.routers.*.rule` and `traefik.tcp.routers.*.rule` labels. |
| `host_ip IP` | LAN-facing host IP. Containers carrying `coredns.dockerdiscovery.host=<fqdn>` get an A record `<fqdn>` → `IP`. |
| `ttl SECONDS` | Record TTL. Default `3600`. |
| `cf_token` / `cf_email` + `cf_key` | Cloudflare credentials. Scoped API token preferred. Used by the Cloudflare Tunnel ingress syncer and (when `cf_zone_id` is set) the Cloudflare DNS syncer. |
| `cf_tunnel_id UUID` | Cloudflare Tunnel UUID. Required for tunnel sync. |
| `cf_account_id ID` | Cloudflare Account ID. Required for tunnel sync. |
| `cf_tunnel_target URL` | Backend service URL pushed as the ingress entry for every Traefik FQDN (e.g. `https://localhost:443` for a co-located Traefik). Required when `cf_tunnel_id` is set. |
| `cf_zone_id ZONE_ID` | Optional. When set, mirrors the tunnel ingress as proxied CNAMEs in this zone, pointing at `<tunnel-id>.cfargotunnel.com`. Replaces the manual CNAME step the Cloudflare dashboard does for you. See [Cloudflare DNS sync](#cloudflare-dns-sync) below. |
| `cf_exclude fqdn,...` | Comma-separated FQDNs to skip from tunnel sync **and** DNS sync. |
| `inventory ADDR [PATH]` | Start the inventory HTTP server on `ADDR` (e.g. `:8081`). JSON at `PATH` (default `/inventory`); HTML at `<PATH>.html`; `/healthz` always served. |

Container labels
----------------

| Label | Behavior |
|---|---|
| `traefik.http.routers.<name>.rule=Host(\`fqdn\`)` | FQDN gets a CNAME → `traefik_cname` locally and (when configured) a tunnel ingress entry → `cf_tunnel_target`. |
| `traefik.tcp.routers.<name>.rule=HostSNI(\`fqdn\`)` | Same as above. |
| `coredns.dockerdiscovery.host=<fqdn>` | FQDN gets an A record → `host_ip`. Requires the `host_ip` directive to be set. |
| `coredns.dockerdiscovery.cf_tunnel=false` | Opt this container out of tunnel sync. The local CNAME/A records are still emitted. Aliases: `off`, `no`, `0`, `disabled`. |

The plugin does **not** consume any other label and does **not** read
container IPs, network aliases, hostnames, or compose project/service
names. If a container has none of the labels above, the plugin
ignores it.

Environment variables (when using the bundled image)
----------------------------------------------------

The bundled `entrypoint.sh` generates a Corefile from these env vars.
Anything else can be expressed by mounting a custom Corefile.

| Variable | Default | Description |
|---|---|---|
| `DOCKER_ENDPOINT` | `unix:///var/run/docker.sock` | Docker/Podman socket. |
| `TRAEFIK_CNAME` | *(none)* | Sets `traefik_cname`. |
| `HOST_IP` | *(none)* | Sets `host_ip`. When set together with `TRAEFIK_CNAME`, the entrypoint also emits a CoreDNS `hosts` block resolving `TRAEFIK_CNAME` → `HOST_IP` so the chased CNAME completes locally. |
| `CF_TOKEN` | *(none)* | Sets `cf_token`. |
| `CF_TUNNEL_ID` | *(none)* | Sets `cf_tunnel_id`. |
| `CF_ACCOUNT_ID` | *(none)* | Sets `cf_account_id`. |
| `CF_TUNNEL_TARGET` | *(none)* | Sets `cf_tunnel_target`. |
| `CF_ZONE_ID` | *(none)* | Sets `cf_zone_id`. Enables Cloudflare DNS sync when non-empty. |
| `CF_EXCLUDE` | *(none)* | Sets `cf_exclude`. |
| `INVENTORY_ADDR` | *(none)* | Sets `inventory ADDR`. |
| `INVENTORY_PATH` | *(none)* | Optional second arg to `inventory`. |
| `FORWARD_DNS` | `1.1.1.1 8.8.8.8` | Upstream DNS servers for non-matching queries. |
| `CACHE_TTL` | `30` | DNS cache duration in seconds. |

Inventory HTTP endpoint
-----------------------

When `inventory` (or `INVENTORY_ADDR`) is set, the plugin starts a
small HTTP server exposing the live in-memory record table. Each row
carries source attribution (`docker:host_a`, `docker:cname`,
`docker:tunnel`, `docker:cf_dns`) so you can tell which directive
produced it.

| Path | Content-Type | Description |
|---|---|---|
| `/inventory` | `application/json` | Machine-readable record table. |
| `/inventory.html` | `text/html` | Human-readable table. |
| `/healthz` | `text/plain` | Liveness check (always `ok`). |

Custom path: `inventory :8081 /things` → JSON at `/things`, HTML at
`/things.html` (`/healthz` is unchanged).

JSON shape:

```json
{
  "generated_at": "2026-05-06T12:34:56Z",
  "plugin": "docker",
  "container_count": 5,
  "record_count": 8,
  "records": [
    { "domain": "ldap.177cpt.com", "kind": "A_HOST", "target": "10.0.60.3",
      "container_id": "1a2b3c4d5e6f", "container": "openldap",
      "source": "docker:host_a" },
    { "domain": "portainer.177cpt.com", "kind": "CNAME", "target": "traefik.177cpt.com",
      "container_id": "0a1b2c3d4e5f", "container": "portainer",
      "source": "docker:cname" },
    { "domain": "portainer.177cpt.com", "kind": "TUNNEL", "target": "https://localhost:443",
      "container_id": "0a1b2c3d4e5f", "container": "portainer",
      "source": "docker:tunnel" },
    { "domain": "portainer.177cpt.com", "kind": "CF_DNS", "target": "5c4fccc8-6376-479b-8131-7cd8cc033473.cfargotunnel.com",
      "container_id": "0a1b2c3d4e5f", "container": "portainer",
      "source": "docker:cf_dns" }
  ]
}
```

`kind` is one of `A_HOST`, `CNAME`, `TUNNEL`, or `CF_DNS`. `CF_DNS`
rows only appear when `cf_zone_id` is configured.

### Quick checks

```sh
curl -s http://localhost:8081/inventory | jq '.records[] | select(.kind=="CNAME")'
curl -s http://localhost:8081/inventory | jq '.record_count'
curl -s http://localhost:8081/healthz
```

### Debugging the endpoint

`ss`, `curl`, and `nc` are baked into the runtime image. If
`curl` against the inventory endpoint hangs, returns
`Connection refused`, or never loads:

**1. Did CoreDNS start the listener?**

```sh
docker logs coredns 2>&1 | grep -i inventory
# expect: [docker] inventory: serving on http://:8081/inventory
```

If absent, the directive (or `INVENTORY_ADDR`) was not parsed.

**2. Is the socket bound inside the container?**

```sh
docker exec coredns ss -ltn
docker exec coredns ss -ltnp | grep 8081
# expect a LISTEN row on :8081 owned by coredns
```

**3. Reachable from inside the container?**

```sh
docker exec coredns curl -sf http://127.0.0.1:8081/healthz
docker exec coredns nc -zv 127.0.0.1 8081
```

If this works but the host can't reach it, the issue is port mapping
or bind address, not the plugin.

**4. Is the port published to the host?**

```sh
ss -ltnp | grep 8081                            # on the host
nc -zv localhost 8081
curl -v http://localhost:8081/healthz
curl -v http://localhost:8081/inventory
```

**5. Bound to loopback inside the container?**
`INVENTORY_ADDR=127.0.0.1:8081` binds only to the container's loopback
and is **not** reachable through a published port. Use `:8081` (all
interfaces); restrict at the host level via `127.0.0.1:8081:8081`
mapping or your firewall.

**6. From another LAN host:**

```sh
curl -v http://<docker-host-ip>:8081/healthz
nc -zv <docker-host-ip> 8081
```

Security
--------

The inventory endpoint exposes container names, IPs, and tunnel
target URLs. Bind it to loopback (`INVENTORY_ADDR=127.0.0.1:8081`) on
multi-tenant hosts, and do not publish port 8081 to the internet.
There is no built-in authentication; put it behind a reverse proxy
with auth if you need remote access.

The Cloudflare API token needs different permissions depending on
which syncers you enable:

| Feature | Token permission | Required when |
|---|---|---|
| Tunnel ingress sync | **Account → Cloudflare Tunnel: Edit** for the configured account | `cf_tunnel_id` is set |
| DNS CNAME sync      | **Zone → DNS: Edit** for the configured zone           | `cf_zone_id` is set   |

If you only enable the tunnel syncer, do not grant DNS edit; if you
enable the DNS syncer, the token additionally needs Zone:DNS:Edit
scoped to that one zone.

Cloudflare DNS sync
-------------------

When the Cloudflare dashboard's tunnel "Public Hostnames" UI adds an
entry for `app.example.com`, it actually does **two** things behind
the scenes:

1. Append the ingress rule to the tunnel's configuration.
2. Create a proxied CNAME in your zone:
   `app.example.com → <tunnel-id>.cfargotunnel.com`.

The public Cloudflare API only does step (1). The CNAME has to be
created separately, and without it public DNS for the hostname will
not resolve to Cloudflare's edge — traffic never reaches the tunnel.

Setting `cf_zone_id` enables the DNS syncer, which performs step (2)
in lockstep with step (1):

- For each FQDN added to the tunnel ingress, create or update a
  proxied CNAME (`type=CNAME`, `content=<tunnel-id>.cfargotunnel.com`,
  `proxied=true`, `ttl=1`) in the configured zone.
- For each FQDN removed from the tunnel ingress, delete the
  corresponding CNAME.
- Records are tagged with the comment `managed by
  coredns-dockerdiscovery`. The syncer **only updates or deletes
  records carrying that comment**: any pre-existing record at the
  same name (manual entry, A record, different CNAME, etc.) is left
  alone and a warning is logged. This is the guardrail against
  clobbering hand-managed records.
- `cf_exclude` applies to both syncers — excluded FQDNs get neither
  a tunnel ingress entry nor a CNAME.

If you previously created the CNAMEs manually, either delete them
first (the syncer will recreate them on the next event) or edit them
and add the comment `managed by coredns-dockerdiscovery` so the
syncer adopts them.

Verifying a deployment
----------------------

Logs:

```
[docker] start
[docker] Connecting to Docker endpoint: unix:///var/run/docker.sock
[docker] Successfully connected to Docker/Podman API
[docker] Event listener registered successfully
[docker] Found N running containers at startup
...
[docker] Add CNAME entries for portainer (abc123…): [portainer.177cpt.com]
[docker] Add host-A entry for openldap (def456…): ldap.177cpt.com -> 10.0.60.3
[docker] Startup container scan complete. Listening for events...
```

DNS:

```sh
dig @localhost portainer.177cpt.com         # expect CNAME → traefik.177cpt.com → A 10.0.60.3
dig @localhost ldap.177cpt.com              # expect A 10.0.60.3
dig @localhost traefik.177cpt.com           # expect A 10.0.60.3
```

Cloudflare:
- Cloudflare dashboard → Networks → Tunnels → your tunnel → Public
  hostnames lists `portainer.177cpt.com`, `auth.177cpt.com`,
  `nexus.177cpt.com`, `traefik.177cpt.com`, all routed to
  `${CF_TUNNEL_TARGET}`.
- When `cf_zone_id` is set: Cloudflare dashboard → DNS → your zone
  shows proxied CNAME records for the same hostnames pointing at
  `<tunnel-id>.cfargotunnel.com`, each carrying the comment
  `managed by coredns-dockerdiscovery`.

Stop a container; the corresponding inventory rows disappear within
one event-loop tick, and any tunnel ingress entry it owned is
retracted.

Development
-----------

```sh
go build ./...
go test ./...
docker build -t coredns-dockerdiscovery:latest .
```

The plugin is registered as `docker` in CoreDNS's `plugin.cfg` (see
`Dockerfile` for the registration step). Tests rely on
`stretchr/testify` and `coredns/caddy`'s `NewTestController`.

License
-------

MIT (inherits from upstream).
