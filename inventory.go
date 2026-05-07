package dockerdiscovery

// Inventory exposes the dockerdiscovery plugin's live in-memory record
// table over a tiny HTTP endpoint. It is intentionally scoped to this
// plugin only — there is no AXFR, no polling, no cross-plugin reflection.
// Source attribution per record is free because we know exactly which
// resolver path produced each entry (A from container IP, CNAME from
// traefik/cname labels, or a Cloudflare Tunnel route).
//
// Configure with the `inventory` directive inside the `docker` block:
//
//   docker {
//       ...
//       inventory :8081           # JSON at /inventory, HTML at /inventory.html
//       inventory :8081 /things   # custom JSON path; HTML at <path>.html
//   }

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// RecordKind identifies which resolver path produced a record.
type RecordKind string

const (
	RecordKindCNAME  RecordKind = "CNAME"
	RecordKindHostA  RecordKind = "A_HOST"
	RecordKindTunnel RecordKind = "TUNNEL"
	RecordKindCFDNS  RecordKind = "CF_DNS"
)

// InventoryRecord is one logical DNS record served by this plugin.
type InventoryRecord struct {
	Domain      string     `json:"domain"`
	Kind        RecordKind `json:"kind"`
	Target      string     `json:"target"` // IP for A/AAAA, hostname/URL for CNAME/TUNNEL
	ContainerID string     `json:"container_id"`
	Container   string     `json:"container"`
	Source      string     `json:"source"` // e.g. "docker", "docker:traefik", "docker:cf_tunnel"
}

// InventorySnapshot is the JSON envelope returned by /inventory.
type InventorySnapshot struct {
	GeneratedAt    time.Time         `json:"generated_at"`
	Plugin         string            `json:"plugin"`
	ContainerCount int               `json:"container_count"`
	RecordCount    int               `json:"record_count"`
	Records        []InventoryRecord `json:"records"`
}

// Snapshot returns a stable, serializable view of the plugin's
// current in-memory record table.
func (dd *DockerDiscovery) Snapshot() InventorySnapshot {
	dd.mutex.RLock()
	defer dd.mutex.RUnlock()

	snap := InventorySnapshot{
		GeneratedAt:    time.Now().UTC(),
		Plugin:         "docker",
		ContainerCount: len(dd.containerInfoMap),
	}

	tunnelSet := make(map[string]bool)

	for id, ci := range dd.containerInfoMap {
		name := ""
		if ci.container != nil {
			name = normalizeContainerName(ci.container)
		}

		// Host-A record (single per container, when host_ip is set).
		if ci.hostADomain != "" && dd.hostIP != nil {
			snap.Records = append(snap.Records, InventoryRecord{
				Domain:      ci.hostADomain,
				Kind:        RecordKindHostA,
				Target:      dd.hostIP.String(),
				ContainerID: shortID(id),
				Container:   name,
				Source:      "docker:host_a",
			})
		}

		// Track which domains have a tunnel entry so we can join with
		// the CNAME emission below (same domain may carry both kinds).
		for _, d := range ci.tunnelDomains {
			tunnelSet[d] = true
			snap.Records = append(snap.Records, InventoryRecord{
				Domain:      d,
				Kind:        RecordKindTunnel,
				Target:      dd.cfTunnelTarget,
				ContainerID: shortID(id),
				Container:   name,
				Source:      "docker:tunnel",
			})
			if dd.dnsSyncer != nil {
				snap.Records = append(snap.Records, InventoryRecord{
					Domain:      d,
					Kind:        RecordKindCFDNS,
					Target:      dd.dnsSyncer.cnameTo,
					ContainerID: shortID(id),
					Container:   name,
					Source:      "docker:cf_dns",
				})
			}
		}

		// CNAME records for Traefik FQDNs. Suppressed when the same
		// domain is served as host-A locally — A wins for LAN clients.
		for _, d := range ci.cnameDomains {
			if strings.EqualFold(d, ci.hostADomain) {
				continue
			}
			snap.Records = append(snap.Records, InventoryRecord{
				Domain:      d,
				Kind:        RecordKindCNAME,
				Target:      dd.traefikCNAME,
				ContainerID: shortID(id),
				Container:   name,
				Source:      "docker:cname",
			})
		}
	}

	sort.Slice(snap.Records, func(i, j int) bool {
		if snap.Records[i].Domain != snap.Records[j].Domain {
			return snap.Records[i].Domain < snap.Records[j].Domain
		}
		return snap.Records[i].Kind < snap.Records[j].Kind
	})
	snap.RecordCount = len(snap.Records)
	return snap
}

// InventoryServer is a small HTTP server that exposes the plugin's
// in-memory record table. It runs on its own listener (so it doesn't
// depend on the prometheus/health plugins being loaded) and is
// started/stopped via caddy controller hooks.
type InventoryServer struct {
	addr string
	path string
	dd   *DockerDiscovery
	srv  *http.Server
	ln   net.Listener
}

// NewInventoryServer constructs a server bound to addr (e.g. ":8081" or
// "127.0.0.1:8081"). path is the JSON endpoint path (default /inventory).
func NewInventoryServer(addr, path string, dd *DockerDiscovery) *InventoryServer {
	if path == "" {
		path = "/inventory"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &InventoryServer{addr: addr, path: path, dd: dd}
}

// Start binds the listener (so bind errors surface synchronously) and
// then runs the server in a goroutine.
func (s *InventoryServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleJSON)
	mux.HandleFunc(s.path+".html", s.handleHTML)
	// Serve the HTML report at "/" so the inventory has a short URL
	// (e.g. https://dns.177cpt.com/). Anything that isn't an exact
	// match for "/" falls through to a 404 — we don't want this to
	// shadow other registered paths.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.handleHTML(w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("inventory: listen %s: %w", s.addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("[docker] inventory: serving on http://%s%s", ln.Addr().String(), s.path)
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[docker] inventory: server stopped: %s", err)
		}
	}()
	return nil
}

// Stop performs a graceful shutdown.
func (s *InventoryServer) Stop() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *InventoryServer) handleJSON(w http.ResponseWriter, r *http.Request) {
	snap := s.dd.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		log.Printf("[docker] inventory: encode error: %s", err)
	}
}

func (s *InventoryServer) handleHTML(w http.ResponseWriter, r *http.Request) {
	snap := s.dd.Snapshot()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><title>coredns docker inventory</title>`)
	b.WriteString(`<style>body{font-family:system-ui,sans-serif;margin:1.5rem;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:.35rem .6rem;text-align:left;font-size:.9rem;}th{background:#f3f3f3;}tr:nth-child(even){background:#fafafa;}code{font-size:.9em;}</style>`)
	fmt.Fprintf(&b, `<h1>coredns dockerdiscovery inventory</h1>`)
	fmt.Fprintf(&b, `<p>Generated %s — %d containers, %d records</p>`,
		html.EscapeString(snap.GeneratedAt.Format(time.RFC3339)),
		snap.ContainerCount, snap.RecordCount)
	b.WriteString(`<table><thead><tr><th>Domain</th><th>Kind</th><th>Target</th><th>Container</th><th>ID</th><th>Source</th></tr></thead><tbody>`)
	for _, rec := range snap.Records {
		fmt.Fprintf(&b,
			`<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`,
			html.EscapeString(rec.Domain),
			html.EscapeString(string(rec.Kind)),
			html.EscapeString(rec.Target),
			html.EscapeString(rec.Container),
			html.EscapeString(rec.ContainerID),
			html.EscapeString(rec.Source),
		)
	}
	b.WriteString(`</tbody></table>`)
	_, _ = w.Write([]byte(b.String()))
}
