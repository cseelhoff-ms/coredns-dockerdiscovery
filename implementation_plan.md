# Implementation Plan: Cloudflare Tunnel Route Support

## Overview

Add per-container label-driven support for creating **Cloudflare Tunnel published
application routes** alongside the existing auto-sync DNS CNAME behavior. Two
Docker labels control which Cloudflare mechanism is used per container:

- `coredns.dockerdiscovery.cf_tunnel=<service_url>` — creates a tunnel ingress
  rule + CNAME to `<tunnel-id>.cfargotunnel.com`
- Default (no label) — existing behavior: CNAME to `cf_target` in Cloudflare DNS

These are **mutually exclusive** per container: if `cf_tunnel` is present, the
traditional DNS CNAME is suppressed.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Default behavior | Preserved (DNS auto-sync) | Backward compatible |
| Tunnel opt-in | Per-container label | User controls which containers use tunnels vs DNS |
| Mutual exclusivity | Tunnel suppresses DNS | Cloudflare Tunnel creates its own DNS CNAME to cfargotunnel.com; a second CNAME would conflict |
| Service URL source | Label value, with Traefik port fallback | Explicit is preferred; auto-derive covers the common HTTP case |
| Thread safety | Mutex on tunnel GET→modify→PUT | Prevents concurrent ingress array corruption |
| Library | cloudflare-go v0.116.0 (existing) | Already has `GetTunnelConfiguration`/`UpdateTunnelConfiguration` |

## New Corefile Directives

```
docker {
    # ... existing directives ...
    cf_tunnel_id   <tunnel-uuid>    # Cloudflare Tunnel ID
    cf_account_id  <account-id>     # Cloudflare Account ID (required for tunnel API)
}
```

## New Container Labels

| Label | Value | Effect |
|-------|-------|--------|
| `coredns.dockerdiscovery.cf_tunnel` | Service URL (e.g. `http://localhost:8080`) or `true` | Creates tunnel ingress rule; suppresses DNS CNAME |

When value is `true` or empty, the service URL is derived from Traefik labels:
`traefik.http.services.*.loadbalancer.server.port=<port>` → `http://localhost:<port>`

## New Environment Variables

| Variable | Corefile Directive | Description |
|----------|-------------------|-------------|
| `CF_TUNNEL_ID` | `cf_tunnel_id` | Cloudflare Tunnel UUID |
| `CF_ACCOUNT_ID` | `cf_account_id` | Cloudflare Account ID |

---

## Implementation Phases

### Phase 1: Core Tunnel Syncer

**Files:** `cloudflare.go` (extend interface + wrapper), new `tunnel.go`

1. **Extend `CloudflareAPI` interface** with tunnel methods:
   ```go
   GetTunnelConfiguration(ctx context.Context, accountID string, tunnelID string) (cloudflare.TunnelConfigurationResult, error)
   UpdateTunnelConfiguration(ctx context.Context, accountID string, tunnelID string, config cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error)
   ```

2. **Extend `cloudflareAPIWrapper`** to implement the new methods using the real
   cloudflare-go client's `GetTunnelConfiguration` / `UpdateTunnelConfiguration`
   with `cloudflare.AccountIdentifier(accountID)`.

3. **Create `TunnelConfig` struct** in `tunnel.go`:
   ```go
   type TunnelConfig struct {
       TunnelID  string
       AccountID string
   }
   ```

4. **Create `TunnelSyncer` struct** in `tunnel.go`:
   ```go
   type TunnelSyncer struct {
       api      CloudflareAPI
       tunnel   *TunnelConfig
       cf       *CloudflareConfig   // reuse for DNS + zone lookup
       mu       sync.Mutex          // protects GET→modify→PUT
   }
   ```

5. **Implement `TunnelSyncer.AddRoutes(hostnames []string, serviceURL string)`**:
   - Lock mutex
   - `GetTunnelConfiguration()` → current ingress rules
   - For each hostname: insert `UnvalidatedIngressRule{Hostname, Service}` before
     the catch-all (last rule). Skip if already exists with same service URL.
   - `UpdateTunnelConfiguration()` → PUT full config
   - Create CNAME DNS record: `hostname → <tunnel-id>.cfargotunnel.com`
   - Unlock

6. **Implement `TunnelSyncer.RemoveRoutes(hostnames []string)`**:
   - Lock mutex
   - `GetTunnelConfiguration()` → current ingress rules
   - Filter out rules matching the given hostnames
   - `UpdateTunnelConfiguration()` → PUT modified config
   - Delete CNAME DNS records for each hostname
   - Unlock

7. **Constructor functions**: `NewTunnelSyncer(tunnelCfg, cfCfg)` (real API) and
   `NewTunnelSyncerWithAPI(tunnelCfg, cfCfg, api)` (testing).

### Phase 2: Config Parsing

**Files:** `setup.go`, `entrypoint.sh`

8. **Add `cf_tunnel_id` directive** in `setup.go` switch block → store in new
   `dd.tunnelConfig.TunnelID` field.

9. **Add `cf_account_id` directive** in `setup.go` switch block → store in
   `dd.tunnelConfig.AccountID`.

10. **Validate tunnel config** in the Cloudflare init block of `setup.go`:
    - If `cf_tunnel_id` is set, require `cf_account_id` and auth credentials
    - Create `TunnelSyncer` and assign to `dd.tunnelSyncer`

11. **Add env vars** to `entrypoint.sh`: `CF_TUNNEL_ID` → `cf_tunnel_id`,
    `CF_ACCOUNT_ID` → `cf_account_id`.

### Phase 3: Label Parsing & Container Lifecycle Routing

**Files:** `dockerdiscovery.go`, `resolvers.go`

12. **Add `tunnelServiceURL` field** to `ContainerInfo` struct.

13. **Add `tunnelSyncer` and `tunnelConfig` fields** to `DockerDiscovery` struct.

14. **Add `getTraefikServicePort()` helper** in `resolvers.go`:
    - Scans container labels for `traefik.http.services.*.loadbalancer.server.port`
    - Returns the port string, or empty if not found

15. **Parse `cf_tunnel` label** in `updateContainerInfo()`:
    - Check `container.Config.Labels["coredns.dockerdiscovery.cf_tunnel"]`
    - If value is non-empty and not `"true"`: use as service URL directly
    - If value is `"true"` or empty: call `getTraefikServicePort()` and build
      `http://localhost:<port>`
    - Store in `ContainerInfo.tunnelServiceURL`

16. **Route to correct syncer** in `updateContainerInfo()`:
    ```go
    if dd.tunnelSyncer != nil && containerInfo.tunnelServiceURL != "" {
        go dd.tunnelSyncer.AddRoutes(cnameDomains, containerInfo.tunnelServiceURL)
    } else if dd.cloudflareSyncer != nil && len(cnameDomains) > 0 {
        go dd.cloudflareSyncer.SyncDomains(cnameDomains)  // existing behavior
    }
    ```

17. **Route removal** in `removeContainerInfo()`:
    ```go
    if dd.tunnelSyncer != nil && containerInfo.tunnelServiceURL != "" {
        go dd.tunnelSyncer.RemoveRoutes(containerInfo.cnameDomains)
    } else if dd.cloudflareSyncer != nil && len(containerInfo.cnameDomains) > 0 {
        go dd.cloudflareSyncer.RemoveDomains(containerInfo.cnameDomains)
    }
    ```

### Phase 4: Testing

**Files:** `cloudflare_test.go`, `setup_test.go`

18. **Extend `mockCloudflareAPI`** with tunnel state:
    - Add `tunnelIngress map[string][]cloudflare.UnvalidatedIngressRule` field  
      (key = tunnelID)
    - Implement `GetTunnelConfiguration` and `UpdateTunnelConfiguration` mock methods

19. **Tunnel syncer unit tests** (`cloudflare_test.go`):
    - `TestTunnelAddRoutes` — adds ingress + DNS CNAME to cfargotunnel.com
    - `TestTunnelAddRoutesIdempotent` — no duplicates on repeat
    - `TestTunnelRemoveRoutes` — removes ingress + DNS record
    - `TestTunnelPreservesCatchAll` — catch-all stays last
    - `TestTunnelDNSRecordContent` — CNAME target is `<tunnelID>.cfargotunnel.com`

20. **Config parsing tests** (`cloudflare_test.go`):
    - `TestTunnelConfigParsing` — `cf_tunnel_id` + `cf_account_id` parsed
    - `TestTunnelConfigMissingAccountID` — error
    - `TestTunnelConfigRequiresAuth` — error without credentials

21. **Label routing tests** (`setup_test.go`):
    - Verify `getTraefikServicePort()` extracts port correctly
    - Verify fallback when no Traefik service port label exists

### Phase 5: Documentation

**Files:** `README.md`

22. **Add "Cloudflare Tunnel Support" section** to README:
    - New directives and env vars
    - Container label usage
    - Example Corefile + compose
    - Mutual exclusivity explanation

23. **Update comparison table** in "Why This Fork?" to include tunnel support.

---

## Files Changed

| File | Changes |
|------|---------|
| `cloudflare.go` | Extend `CloudflareAPI` interface with tunnel methods; extend `cloudflareAPIWrapper` |
| `tunnel.go` | **New file.** `TunnelConfig`, `TunnelSyncer` with `AddRoutes`/`RemoveRoutes` |
| `setup.go` | Parse `cf_tunnel_id`, `cf_account_id`; validate; instantiate `TunnelSyncer` |
| `dockerdiscovery.go` | Add `tunnelSyncer`/`tunnelConfig` fields; route container events by label |
| `resolvers.go` | Add `getTraefikServicePort()` helper |
| `entrypoint.sh` | Add `CF_TUNNEL_ID`, `CF_ACCOUNT_ID` env vars |
| `cloudflare_test.go` | Extend mock; add tunnel syncer + config parsing tests |
| `setup_test.go` | Add `getTraefikServicePort()` tests |
| `README.md` | Document tunnel support |

## Verification Checklist

- [ ] `go build` succeeds
- [ ] All existing 33 tests pass unchanged
- [ ] New tunnel tests pass
- [ ] Container without `cf_tunnel` label → DNS sync (backward compat)
- [ ] Container with `cf_tunnel=http://localhost:8080` → tunnel route created
- [ ] Container with `cf_tunnel=true` + Traefik port label → tunnel route with derived URL
- [ ] Tunnel CNAME target is `<tunnelID>.cfargotunnel.com`
- [ ] Container stop → tunnel route + DNS record removed
- [ ] Tunnel catch-all rule preserved after add/remove operations

## Considerations

1. **Tunnel catch-all**: The tunnel's last ingress rule must always be a catch-all.
   `AddRoutes` inserts before it. If no catch-all exists, one is created
   (`http_status:404`).

2. **External race conditions**: The PUT API does full replacement. External tools
   (Dashboard, cloudflared CLI) modifying the tunnel config between our GET and PUT
   could lose changes. The mutex handles internal races only.

3. **Protocol derivation**: Traefik label fallback defaults to `http://`. Users
   needing HTTPS/TCP/other protocols should use the explicit label value.
