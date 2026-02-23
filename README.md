coredns-dockerdiscovery
===================================

Docker discovery plugin for coredns

Why This Fork?
--------------

This is a fork of [kevinjqiu/coredns-dockerdiscovery](https://github.com/kevinjqiu/coredns-dockerdiscovery)
that adds CNAME record support, Traefik label integration, and Cloudflare DNS
sync — capabilities that don't exist in the original project or in the common
alternative of pairing it with
[traefik-cloudflare-companion](https://github.com/tiredofit/docker-traefik-cloudflare-companion).

### The problem

The original dockerdiscovery plugin creates **A records pointing to container
IPs** (e.g. `172.17.0.5`). These IPs are internal to the Docker network and
**unreachable from other machines on your LAN**. This works for container-to-
container communication, but not for the common homelab scenario where a laptop,
phone, or other server needs to reach a containerized service by name.

There is no combination of labels, config directives, or network settings in the
original that can produce a DNS record pointing to the Docker host's LAN IP.
Even `--net=host` containers return `nil` and get no DNS record at all.

### What about traefik-cloudflare-companion?

Pairing the original plugin with
[traefik-cloudflare-companion](https://github.com/tiredofit/docker-traefik-cloudflare-companion)
solves the Cloudflare half — it reads Traefik labels and creates CNAME records in
Cloudflare. But it has two gaps:

1. **No local DNS.** The companion only writes to Cloudflare. It does not create
   any local DNS records. `dig @your-coredns traefik-app.example.com` returns
   nothing for Traefik-labeled containers — you must wait for Cloudflare
   propagation and query a public resolver.

2. **HTTP-only.** The companion only reads Traefik labels. Non-HTTP services
   (LDAP, PostgreSQL, MQTT, etc.) that use port mapping instead of a reverse
   proxy get no DNS at all — not locally, not in Cloudflare.

### What this fork adds

This fork follows the same architecture that Kubernetes uses with
[ExternalDNS](https://github.com/kubernetes-sigs/external-dns) + NodePort:
**DNS records point to the host, the host forwards to the container** (via
Traefik for HTTP, or kernel port mapping for everything else).

| Feature | Original | Original + companion | This fork |
|---|---|---|---|
| Local A records (container IPs) | Yes | Yes | Yes |
| Local CNAME → Docker host (Traefik labels) | No | No | Yes |
| Local CNAME → Docker host (non-HTTP labels) | No | No | Yes |
| Cloudflare sync (Traefik labels) | No | Yes | Yes |
| Cloudflare sync (non-HTTP labels) | No | No | Yes |
| Cloudflare Tunnel routes (per-container) | No | No | Yes |
| Containers required | 1 | 2 | 1 |

The `traefik-cloudflare-companion` remains a more mature choice if you need
Docker Swarm support, Traefik v1 labels, Traefik API polling, per-domain
Cloudflare target overrides, regex host filtering, or prebuilt multi-arch images.

### Is this an antipattern?

Exposing containerized non-HTTP services to the LAN via port mapping + DNS is
the Docker equivalent of Kubernetes NodePort + ExternalDNS. It's the standard
approach for single-host deployments where containers need to be reachable by
name from other machines. The alternatives (macvlan networking, host networking,
service mesh) each trade DNS simplicity for network complexity and are typically
reserved for multi-host or production-grade clusters.

Name
----

dockerdiscovery - add/remove DNS records for docker containers.

Syntax
------

    docker [DOCKER_ENDPOINT] {
        domain DOMAIN_NAME
        hostname_domain HOSTNAME_DOMAIN_NAME
        network_aliases DOCKER_NETWORK
        label LABEL
        cname_target CNAME_TARGET_HOSTNAME
        compose_domain COMPOSE_DOMAIN_NAME
        traefik_cname TRAEFIK_HOSTNAME
        traefik_a TRAEFIK_IP
        ttl TTL_SECONDS
        cf_token CLOUDFLARE_API_TOKEN
        cf_email CLOUDFLARE_EMAIL
        cf_key CLOUDFLARE_API_KEY
        cf_target CNAME_TARGET
        cf_zone DOMAIN ZONE_ID
        cf_proxied
        cf_exclude COMMA_SEPARATED_DOMAINS
        cf_tunnel_id CLOUDFLARE_TUNNEL_ID
        cf_account_id CLOUDFLARE_ACCOUNT_ID
    }

* `DOCKER_ENDPOINT`: the path to the docker socket. If unspecified, defaults to `unix:///var/run/docker.sock`. It can also be TCP socket, such as `tcp://127.0.0.1:999`.
* `DOMAIN_NAME`: the name of the domain for [container name](https://docs.docker.com/engine/reference/run/#name---name), e.g. when `DOMAIN_NAME` is `docker.loc`, your container with `my-nginx` (as subdomain) [name](https://docs.docker.com/engine/reference/run/#name---name) will be assigned the domain name: `my-nginx.docker.loc`
* `HOSTNAME_DOMAIN_NAME`: the name of the domain for [hostname](https://docs.docker.com/config/containers/container-networking/#ip-address-and-hostname). Work same as `DOMAIN_NAME` for hostname.
* `COMPOSE_DOMAIN_NAME`: the name of the domain when it is determined the
    container is managed by docker-compose.  e.g. for a compose project of
    "internal" and service of "nginx", if `COMPOSE_DOMAIN_NAME` is
    `compose.loc` the fqdn will be `nginx.internal.compose.loc`
* `DOCKER_NETWORK`: the name of the docker network. Resolve directly by [network aliases](https://docs.docker.com/v17.09/engine/userguide/networking/configure-dns) (like internal docker dns resolve host by aliases whole network)
* `LABEL`: container label of resolving host (by default enable and equals ```coredns.dockerdiscovery.host```)
* `CNAME_TARGET_HOSTNAME`: when set, containers with a `coredns.dockerdiscovery.hostname` label will have CNAME records created pointing to this hostname. For example, if `CNAME_TARGET_HOSTNAME` is `infra-1.homelab.local` and a container has the label `coredns.dockerdiscovery.hostname=ldap.homelab.local`, a DNS query for `ldap.homelab.local` will return a CNAME pointing to `infra-1.homelab.local`. Follows the Kubernetes ExternalDNS annotation convention.
* `TRAEFIK_HOSTNAME`: when set, scans container labels for Traefik router rules (e.g. `traefik.http.routers.*.rule=Host(...)`) and returns CNAME records pointing to this hostname. Mutually exclusive with `traefik_a`.
* `TRAEFIK_IP`: when set, scans container labels for Traefik router rules and returns A records with this IP address. Mutually exclusive with `traefik_cname`.
* `CLOUDFLARE_API_TOKEN`: Cloudflare API token (scoped, preferred). Use this OR `cf_email`/`cf_key`.
* `CLOUDFLARE_EMAIL`: Email address for Cloudflare global API key auth.
* `CLOUDFLARE_API_KEY`: Cloudflare global API key (legacy). Requires `cf_email`.
* `CNAME_TARGET`: The CNAME target domain for Cloudflare records (e.g. `traefik.homelab.net`).
* `cf_zone DOMAIN ZONE_ID`: Maps a domain to a Cloudflare zone ID. Can be specified multiple times.
* `cf_proxied`: Enable Cloudflare proxy (orange cloud) for created records.
* `TTL_SECONDS`: DNS record TTL in seconds. Default: `3600`.
* `cf_exclude COMMA_SEPARATED_DOMAINS`: Comma-separated list of domains to exclude from Cloudflare sync.
* `CLOUDFLARE_TUNNEL_ID`: UUID of the Cloudflare Tunnel. When set (with `cf_account_id`), containers with a `coredns.dockerdiscovery.cf_tunnel` label will get tunnel ingress routes instead of traditional DNS CNAME records.
* `CLOUDFLARE_ACCOUNT_ID`: Cloudflare Account ID. Required when `cf_tunnel_id` is set.

How To Build
------------

### Docker (recommended)

    docker build -t coredns-dockerdiscovery:latest .

### Export / Import Image

To transfer the image to another host (e.g. a Portainer-managed Docker host):

    # On the build machine:
    docker save coredns-dockerdiscovery:latest -o coredns-dockerdiscovery.tar

    # Copy to the target host:
    scp coredns-dockerdiscovery.tar user@your-docker-host:/tmp/

    # On the target host:
    docker load -i /tmp/coredns-dockerdiscovery.tar

### From source (without Docker)

    GO111MODULE=on go get -u github.com/coredns/coredns
    GO111MODULE=on go get github.com/kevinjqiu/coredns-dockerdiscovery
    cd ~/go/src/github.com/coredns/coredns
    echo "docker:github.com/kevinjqiu/coredns-dockerdiscovery" >> plugin.cfg
    cat plugin.cfg | uniq > plugin.cfg.tmp
    mv plugin.cfg.tmp plugin.cfg
    make all
    ~/go/src/github.com/coredns/coredns/coredns --version

Run tests

    go test -v

Deployment
----------

The Docker image generates a Corefile at runtime from environment variables via
its entrypoint script. No host-mounted config files are needed.

### docker-compose.yml

```yaml
version: "3.8"

services:
  coredns:
    image: coredns-dockerdiscovery:latest
    container_name: coredns
    restart: unless-stopped
    security_opt:
      - label=disable
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    volumes:
      # Docker: mount the Docker socket
      # - /var/run/docker.sock:/var/run/docker.sock:ro
      # Podman (rootful): mount the Podman-compatible socket
      # - /run/podman/podman.sock:/var/run/docker.sock:ro
      # Podman (rootless): mount the user-level Podman socket
      - /run/user/1000/podman/podman.sock:/var/run/docker.sock
    environment:
      - CNAME_TARGET=infravm.homelab.net
      - CNAME_TARGET_IP=10.10.10.2
      - DOCKER_DOMAIN=docker.local
      - CF_TOKEN=your-cloudflare-api-token
      - CF_TARGET=infravm.homelab.net
      - CF_ZONE_DOMAIN=homelab.net
      - CF_ZONE_ID=your-cloudflare-zone-id
      - FORWARD_DNS=1.1.1.1 8.8.8.8
      - CACHE_TTL=30
```

> **Note:** The container socket mount is required for container event discovery.
> For **Docker**, use `/var/run/docker.sock`. For **Podman (rootful)**, use
> `/run/podman/podman.sock`. For **Podman (rootless)**, use
> `/run/user/1000/podman/podman.sock` (adjust UID as needed).
> Ensure the socket is active — for Podman run `sudo systemctl enable --now podman.socket`
> (rootful) or `systemctl --user enable --now podman.socket` (rootless).
>
> **SELinux:** On SELinux-enabled hosts (Fedora CoreOS, RHEL, etc.), `security_opt: label=disable`
> is required to allow the container to access the Podman/Docker socket.
> Without it, socket access will be denied even with correct file permissions.
>
> In Portainer, create a new Stack and paste this compose content directly.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CNAME_TARGET` | *(none)* | FQDN of the Docker host. All CNAMEs (from `coredns.dockerdiscovery.hostname` labels and Traefik labels) point here. When set, `TRAEFIK_HOST` and `TRAEFIK_IP` are not needed. |
| `CNAME_TARGET_IP` | *(none)* | IP address of the Docker host. Creates an A record for `CNAME_TARGET` in the `hosts` block. Falls back to `TRAEFIK_IP` if not set. |
| `TRAEFIK_IP` | *(none)* | IP address of your Traefik host. Used for the `hosts` block when `CNAME_TARGET_IP` is not set. |
| `TRAEFIK_HOST` | *(none)* | FQDN of Traefik (used as CNAME target when `CNAME_TARGET` is not set; backward compatible) |
| `DOCKER_ENDPOINT` | `unix:///var/run/docker.sock` | Docker/Podman socket path |
| `DOCKER_DOMAIN` | `docker.local` | Domain suffix for container-name-based resolution. **Caution:** do not set this to your real domain (e.g. `homelab.net`) — it creates `{container_name}.{domain}` A records pointing to container IPs, which can shadow CNAME records. |
| `CF_TOKEN` | *(none)* | Cloudflare API token with `Zone:DNS:Edit` permission |
| `CF_TARGET` | *(none)* | CNAME target domain for Cloudflare records (e.g. `traefik.homelab.net`) |
| `CF_ZONE_DOMAIN` | *(none)* | Domain managed in Cloudflare |
| `CF_ZONE_ID` | *(none)* | Cloudflare zone ID (found on the zone Overview page) |
| `CF_TUNNEL_ID` | *(none)* | Cloudflare Tunnel UUID. Enables per-container tunnel route management via `coredns.dockerdiscovery.cf_tunnel` label. |
| `CF_ACCOUNT_ID` | *(none)* | Cloudflare Account ID. Required when `CF_TUNNEL_ID` is set. |
| `FORWARD_DNS` | `1.1.1.1 8.8.8.8` | Upstream DNS servers for non-matching queries |
| `CACHE_TTL` | `30` | DNS cache duration in seconds |

> **Note:** `traefik_a` mode (returning A records instead of CNAMEs for Traefik-labeled containers)
> is not available via environment variables. To use it, provide a custom Corefile mounted into the container.

### Verifying the deployment

Check the container started correctly:

    docker logs coredns

Expected output:

    [docker] start
    [docker] Connecting to Docker endpoint: unix:///var/run/docker.sock
    [docker] Successfully connected to Docker/Podman API
    [docker] Event listener registered successfully
    [docker] Found N running containers at startup
    ...
    [docker] Startup container scan complete. Listening for events...
    .:53
    CoreDNS-1.10.1
    linux/amd64, go1.21.x

### Testing: Traefik label auto-discovery

Start a test container with Traefik labels:

    docker run -d --name test-web \
      --label "traefik.enable=true" \
      --label "traefik.http.routers.test-web.rule=Host(\`test.homelab.net\`)" \
      nginx:alpine

Wait a moment, then query CoreDNS:

    dig @localhost test.homelab.net

Expected answer section:

    test.homelab.net.    3600    IN    CNAME    traefik.homelab.net.

The CNAME target (`traefik.homelab.net`) resolves to the `TRAEFIK_IP` via the `hosts` plugin.
Some recursive resolvers will chase the CNAME and include the A record automatically.

Check registration in the logs:

    docker logs coredns 2>&1 | grep test.homelab.net
    # [docker] Found traefik host for container xxxxxxxxxxxx: test.homelab.net
    # [docker] Add CNAME entries for container test-web (xxxxxxxxxxxx): [test.homelab.net]

### Testing: Container removal cleans up DNS

    docker stop test-web
    sleep 2
    dig @localhost test.homelab.net
    # Should return NXDOMAIN or fall through to the upstream forwarder

### Testing: Cloudflare sync

If `CF_TOKEN` and `CF_ZONE_ID` are configured, check the logs after starting a
container:

    docker logs coredns 2>&1 | grep cloudflare
    # [cloudflare] Creating CNAME record for test.homelab.net -> traefik.homelab.net

After stopping the container:

    # [cloudflare] Deleting CNAME record for test.homelab.net

Verify directly against Cloudflare DNS:

    dig @1.1.1.1 test.homelab.net

Cleanup:

    docker rm test-web

Example
-------

Container will be resolved by label as `nginx.loc`:

    docker run --label=coredns.dockerdiscovery.host=nginx.loc nginx

CNAME Target (non-HTTP services)
--------------------------------

For services that aren't behind a reverse proxy (LDAP, databases, MQTT, etc.),
the `cname_target` directive creates CNAME records from a simple Docker label.
This follows the same pattern as Kubernetes ExternalDNS annotations — containers
declare the DNS name they want via a label, and the plugin creates a CNAME
pointing to the Docker host.

### How It Works

1. You configure `cname_target` with the FQDN of the Docker host (set once per CoreDNS instance)
2. Containers declare `coredns.dockerdiscovery.hostname=<desired-fqdn>` as a label
3. The plugin creates a CNAME record: `<desired-fqdn>` → `<cname_target>`
4. When the container stops, the CNAME is removed

If the container moves to a different Docker host running its own CoreDNS with a
different `cname_target`, the DNS automatically points to the new host.

### Corefile

    .:53 {
        docker unix:///var/run/docker.sock {
            cname_target infra-1.homelab.local
        }
        forward . 1.1.1.1 8.8.8.8
    }

Or via environment variable: `CNAME_TARGET=infra-1.homelab.local`

### Example: Mixed HTTP and non-HTTP services

This example shows a typical deployment with HTTP services behind Traefik and
non-HTTP services exposed directly via port mapping. Both use `cname_target` to
point DNS at the Docker host.

`Corefile`:

    .:53 {
        docker unix:///var/run/docker.sock {
            cname_target infra-1.homelab.local
            traefik_cname infra-1.homelab.local
        }
        forward . 1.1.1.1 8.8.8.8
    }

`docker-compose.yml`:

```yaml
services:
  # ── Non-HTTP: OpenLDAP (ports 389/636) ──────────────────────
  # Uses coredns.dockerdiscovery.hostname label directly.
  # No Traefik involvement — LDAP is not an HTTP protocol.
  openldap:
    image: osixia/openldap:latest
    container_name: openldap
    hostname: ldap
    ports:
      - "389:389"
      - "636:636"
    labels:
      - "coredns.dockerdiscovery.hostname=ldap.homelab.local"

  # ── HTTP: phpLDAPadmin (web UI behind Traefik) ──────────────
  # Uses standard Traefik labels. The plugin reads the Host()
  # rule and creates a CNAME automatically.
  phpldapadmin:
    image: osixia/phpldapadmin:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ldapadmin.rule=Host(`ldapadmin.homelab.local`)"
      - "traefik.http.routers.ldapadmin.entrypoints=https"
      - "traefik.http.routers.ldapadmin.tls=true"
      - "traefik.http.services.ldapadmin.loadbalancer.server.port=80"

  # ── Non-HTTP: PostgreSQL (port 5432) ────────────────────────
  postgres:
    image: postgres:16
    ports:
      - "5432:5432"
    labels:
      - "coredns.dockerdiscovery.hostname=db.homelab.local"

  # ── HTTPS: Gitea (web UI behind Traefik) ────────────────────
  gitea:
    image: gitea/gitea:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.gitea.rule=Host(`git.homelab.local`)"
      - "traefik.http.routers.gitea.entrypoints=https"
      - "traefik.http.routers.gitea.tls=true"
      - "traefik.http.services.gitea.loadbalancer.server.port=3000"
```

**Resulting DNS records:**

| Query | Type | Answer | Source |
|---|---|---|---|
| `ldap.homelab.local` | CNAME | `infra-1.homelab.local` | `coredns.dockerdiscovery.hostname` label |
| `db.homelab.local` | CNAME | `infra-1.homelab.local` | `coredns.dockerdiscovery.hostname` label |
| `ldapadmin.homelab.local` | CNAME | `infra-1.homelab.local` | Traefik `Host()` rule |
| `git.homelab.local` | CNAME | `infra-1.homelab.local` | Traefik `Host()` rule |

All four CNAMEs point to `infra-1.homelab.local`, which is resolved by your
network's existing DNS (DHCP/DDNS, Pi-hole, static entry, etc.) to the Docker
host's IP address.

**Key points:**

- **HTTP/HTTPS services** (phpLDAPadmin, Gitea): use standard Traefik labels.
  The plugin reads `Host()` rules via `traefik_cname`. No extra labels needed.
- **Non-HTTP services** (OpenLDAP, PostgreSQL): use the
  `coredns.dockerdiscovery.hostname` label. No Traefik labels needed.
- **Both** produce CNAME records pointing to the same `cname_target` host.
- When any container stops, its DNS record is automatically removed.

Traefik Label Integration
-------------------------

This plugin can automatically create DNS entries from Traefik Docker labels, similar to [coredns-traefik](https://github.com/scottt732/coredns-traefik), but without requiring access to the Traefik API. Instead, it reads the Traefik labels directly from Docker containers via the Docker socket.

### Option 1: CNAME records

`Corefile`:

    homelab.net:53 {
        hosts {
            10.10.10.2 traefik.homelab.net
            fallthrough
        }
        docker unix:///var/run/docker.sock {
            traefik_cname traefik.homelab.net
        }
        forward . 10.10.10.1
    }

`docker-compose.yml`:

    services:
      gitea:
        image: gitea/gitea:latest
        labels:
          - "traefik.enable=true"
          - "traefik.http.routers.gitea.rule=Host(`gitea.homelab.net`)"

A DNS query for `gitea.homelab.net` will return `CNAME traefik.homelab.net`, which resolves to `10.10.10.2` via the hosts entry.

### Option 2: A records

`Corefile`:

    homelab.net:53 {
        docker unix:///var/run/docker.sock {
            traefik_a 10.10.10.2
        }
        forward . 10.10.10.1
    }

A DNS query for `gitea.homelab.net` will return `A 10.10.10.2` directly.

### How It Works

The plugin watches Docker container events and scans labels matching `traefik.http.routers.*.rule` for `Host()` and `HostSNI()` patterns. Hostnames are extracted and dynamically registered as DNS entries. When containers stop, the entries are removed automatically.

This works alongside all existing resolvers (domain, hostname_domain, compose_domain, label, network_aliases) — you can use traefik labels and other resolvers simultaneously.

Cloudflare DNS Sync
-------------------

Inspired by [traefik-cloudflare-updater](https://github.com/dchidell/traefik-cloudflare-updater), this plugin can automatically create, update, and delete CNAME records in Cloudflare DNS when containers with Traefik labels start or stop. This eliminates the need for a separate sidecar container to manage Cloudflare DNS entries.

### Configuration

Add `cf_*` options alongside your traefik configuration. All values support
environment variable substitution via the `{$VAR}` syntax:

    .:53 {
        docker unix:///var/run/docker.sock {
            traefik_cname traefik.homelab.net
            cf_token {$CF_TOKEN}
            cf_target traefik.homelab.net
            cf_zone homelab.net {$CF_ZONE_ID}
        }
        forward . 1.1.1.1 8.8.8.8
    }

When a container with `traefik.http.routers.*.rule=Host(...)` labels starts, the plugin will:
1. Register the hostname in CoreDNS (as CNAME or A record)
2. Create a CNAME record in Cloudflare pointing to `cf_target`

When the container stops, the CNAME record is deleted from Cloudflare.

### Authentication

**API Token (recommended):**

    cf_token your-scoped-api-token

Create a token at https://dash.cloudflare.com/profile/api-tokens with `Zone:DNS:Edit` permissions.

**Global API Key (legacy):**

    cf_email user@example.com
    cf_key your-global-api-key

### Multiple Zones

You can manage DNS records across multiple Cloudflare zones:

    docker unix:///var/run/docker.sock {
        traefik_cname traefik.homelab.net
        cf_token {$CF_TOKEN}
        cf_target traefik.homelab.net
        cf_zone homelab.net zone_id_1
        cf_zone example.com zone_id_2
    }

Domains are matched to zones by suffix — `app.homelab.net` goes to `zone_id_1`, `web.example.com` goes to `zone_id_2`.

### Excluding Domains

To prevent certain domains from being synced to Cloudflare:

    cf_exclude internal.homelab.net,private.homelab.net

### Cloudflare Proxy

To enable the Cloudflare proxy (orange cloud) on created records:

    cf_proxied

### Auto-enable Traefik

If you configure `cf_*` options without explicitly setting `traefik_cname` or `traefik_a`, the plugin will automatically enable the Traefik label resolver and set `traefik_cname` to the `cf_target` value.

Cloudflare Tunnel Support
-------------------------

In addition to traditional Cloudflare DNS CNAME records, this plugin can manage
**Cloudflare Tunnel published application routes** (ingress rules). This is
useful when your services are behind a Cloudflare Tunnel and don't need public
DNS records pointing to your server's IP.

### How it works

Traditional DNS sync and tunnel routes are **mutually exclusive per container**:

- **Default (no label):** Containers get traditional Cloudflare DNS CNAME records
  pointing to `cf_target` (existing behavior, backward compatible).
- **`coredns.dockerdiscovery.cf_tunnel` label:** Containers get a tunnel ingress
  rule instead. The plugin also creates a CNAME DNS record pointing to
  `<tunnel-id>.cfargotunnel.com` (required by Cloudflare for tunnel routing).

### Configuration

Add `cf_tunnel_id` and `cf_account_id` alongside your existing `cf_*` config:

    .:53 {
        docker unix:///var/run/docker.sock {
            traefik_cname traefik.homelab.net
            cf_token {$CF_TOKEN}
            cf_target traefik.homelab.net
            cf_zone homelab.net {$CF_ZONE_ID}
            cf_tunnel_id {$CF_TUNNEL_ID}
            cf_account_id {$CF_ACCOUNT_ID}
        }
        forward . 1.1.1.1 8.8.8.8
    }

Or via environment variables: `CF_TUNNEL_ID` and `CF_ACCOUNT_ID`.

> **Note:** `cf_target` is optional when using tunnel-only mode. If omitted,
> the Traefik resolver will auto-configure with the tunnel CNAME target
> (`<tunnel-id>.cfargotunnel.com`).

### Container Labels

Add the `coredns.dockerdiscovery.cf_tunnel` label to containers that should use
tunnel routes:

```yaml
services:
  # This container gets a tunnel route (not a traditional DNS CNAME)
  myapp:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`myapp.homelab.net`)"
      - "traefik.http.services.myapp.loadbalancer.server.port=8080"
      - "coredns.dockerdiscovery.cf_tunnel=http://localhost:8080"

  # This container gets a traditional DNS CNAME (default behavior)
  other-app:
    image: other-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.other.rule=Host(`other.homelab.net`)"
```

**Label values:**

| Value | Behavior |
|-------|----------|
| `http://localhost:8080` | Explicit service URL for the tunnel ingress rule |
| `https://localhost:8443` | HTTPS backend |
| `tcp://localhost:5432` | TCP service (PostgreSQL, etc.) |
| `true` | Auto-derive URL from Traefik service port label (`http://localhost:<port>`) |

When the value is `true`, the plugin looks for a
`traefik.http.services.*.loadbalancer.server.port` label and builds
`http://localhost:<port>` automatically.

### What happens on container start/stop

**Start** (with `cf_tunnel` label):
1. Hostname extracted from Traefik router rule (e.g. `myapp.homelab.net`)
2. Tunnel ingress rule added: `myapp.homelab.net → http://localhost:8080`
3. DNS CNAME created: `myapp.homelab.net → <tunnel-id>.cfargotunnel.com`
4. Local CoreDNS CNAME record registered

**Stop:**
1. Tunnel ingress rule removed
2. DNS CNAME record deleted
3. Local CoreDNS record removed

### Mixed tunnel and DNS example

```yaml
services:
  coredns:
    image: coredns-dockerdiscovery:latest
    environment:
      - CNAME_TARGET=infravm.homelab.net
      - CNAME_TARGET_IP=10.10.10.2
      - CF_TOKEN=your-token
      - CF_TARGET=infravm.homelab.net
      - CF_ZONE_DOMAIN=homelab.net
      - CF_ZONE_ID=your-zone-id
      - CF_TUNNEL_ID=your-tunnel-uuid
      - CF_ACCOUNT_ID=your-account-id

  # Tunnel route: accessible via Cloudflare Tunnel (no port forwarding needed)
  public-app:
    labels:
      - "traefik.http.routers.public.rule=Host(`public.homelab.net`)"
      - "traefik.http.services.public.loadbalancer.server.port=8080"
      - "coredns.dockerdiscovery.cf_tunnel=http://localhost:8080"

  # DNS CNAME: accessible via traditional DNS (requires port forwarding)
  internal-app:
    labels:
      - "traefik.http.routers.internal.rule=Host(`internal.homelab.net`)"
```

**Result:**
- `public.homelab.net` → Tunnel ingress route + CNAME to `<tunnel-id>.cfargotunnel.com`
- `internal.homelab.net` → Traditional CNAME to `infravm.homelab.net` in Cloudflare DNS

Development
-----------

See [setup.md](setup.md) for local development instructions.
