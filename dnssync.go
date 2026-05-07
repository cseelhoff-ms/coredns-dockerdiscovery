package dockerdiscovery

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// dnsRecordOwnerComment is the marker we write into the Cloudflare DNS
// record's `comment` field. We will only ever update or delete a record
// whose comment matches this exact string. This is our safety net
// against clobbering hand-managed CNAMEs (e.g. someone's own
// `mail.example.com`) that happen to share the zone.
const dnsRecordOwnerComment = "managed by coredns-dockerdiscovery"

// DNSSyncer manages proxied CNAME records in a single Cloudflare zone.
// Each managed CNAME points at <tunnel-id>.cfargotunnel.com so that
// public clients can reach the tunnel target.
//
// Records are fingerprinted by `comment == dnsRecordOwnerComment`.
// The syncer never modifies records that don't carry this comment.
type DNSSyncer struct {
	api     CloudflareAPI
	cf      *CloudflareConfig
	zoneID  string
	cnameTo string // "<tunnel-id>.cfargotunnel.com" — every record points here
	mu      sync.Mutex
}

// NewDNSSyncer constructs a syncer wired to the same Cloudflare API
// that tunnel.go uses. Returns nil if zone management is not configured
// (caller checks for nil).
func NewDNSSyncer(api CloudflareAPI, cf *CloudflareConfig, tunnelID string) *DNSSyncer {
	if cf == nil || cf.ZoneID == "" || tunnelID == "" {
		return nil
	}
	return &DNSSyncer{
		api:     api,
		cf:      cf,
		zoneID:  cf.ZoneID,
		cnameTo: tunnelID + ".cfargotunnel.com",
	}
}

// AddRecords ensures a proxied CNAME exists for each hostname pointing
// at <tunnel-id>.cfargotunnel.com. Existing records owned by us are
// updated in place; records not owned by us are left alone (with a
// warning) — this is intentional, to avoid clobbering manually-managed
// records that happen to share the zone.
func (s *DNSSyncer) AddRecords(hostnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(hostnames) == 0 {
		return
	}
	log.Printf("[dns] AddRecords zone=%s target=%s hostnames=%v", s.zoneID, s.cnameTo, hostnames)
	ctx := context.Background()
	proxied := true

	for _, hostname := range hostnames {
		if s.cf.ExcludeDomains[hostname] {
			log.Printf("[dns] Skipping excluded domain: %s", hostname)
			continue
		}

		existing, err := s.findRecord(ctx, hostname)
		if err != nil {
			log.Printf("[dns] Error looking up %s: %s", hostname, err)
			continue
		}

		if existing == nil {
			log.Printf("[dns] %s: no existing record found, creating proxied CNAME", hostname)
			rec, err := s.api.CreateDNSRecord(ctx, s.zoneID, cloudflare.CreateDNSRecordParams{
				Type:    "CNAME",
				Name:    hostname,
				Content: s.cnameTo,
				TTL:     1, // 1 = "automatic" per Cloudflare's API
				Proxied: &proxied,
				Comment: dnsRecordOwnerComment,
			})
			if err != nil {
				log.Printf("[dns] Error creating CNAME for %s: %s", hostname, err)
				continue
			}
			log.Printf("[dns] Created CNAME %s -> %s (id=%s)", hostname, s.cnameTo, rec.ID)
			s.verifyRecord(ctx, hostname, rec.ID, "create")
			continue
		}

		log.Printf("[dns] %s: existing record id=%s type=%s content=%s comment=%q proxied=%v",
			hostname, existing.ID, existing.Type, existing.Content, existing.Comment, derefBool(existing.Proxied))

		// Found an existing record. Only touch it if we own it.
		if existing.Comment != dnsRecordOwnerComment {
			log.Printf("[dns] WARN: %s already exists and is not managed by us "+
				"(type=%s content=%s); leaving it alone", hostname, existing.Type, existing.Content)
			continue
		}

		needsUpdate := existing.Type != "CNAME" ||
			!strings.EqualFold(existing.Content, s.cnameTo) ||
			existing.Proxied == nil || !*existing.Proxied

		if !needsUpdate {
			log.Printf("[dns] %s: owned record already in canonical state, no update needed", hostname)
			continue
		}

		comment := dnsRecordOwnerComment
		err = s.api.UpdateDNSRecord(ctx, s.zoneID, cloudflare.UpdateDNSRecordParams{
			ID:      existing.ID,
			Type:    "CNAME",
			Name:    hostname,
			Content: s.cnameTo,
			TTL:     1,
			Proxied: &proxied,
			Comment: &comment,
		})
		if err != nil {
			log.Printf("[dns] Error updating CNAME for %s: %s", hostname, err)
			continue
		}
		log.Printf("[dns] Updated CNAME %s -> %s (id=%s)", hostname, s.cnameTo, existing.ID)
		s.verifyRecord(ctx, hostname, existing.ID, "update")
	}
}

// RemoveRecords deletes our managed CNAMEs for the given hostnames.
// Records we don't own are left alone.
func (s *DNSSyncer) RemoveRecords(hostnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(hostnames) == 0 {
		return
	}
	log.Printf("[dns] RemoveRecords zone=%s hostnames=%v", s.zoneID, hostnames)
	ctx := context.Background()

	for _, hostname := range hostnames {
		if s.cf.ExcludeDomains[hostname] {
			continue
		}

		existing, err := s.findRecord(ctx, hostname)
		if err != nil {
			log.Printf("[dns] Error looking up %s for removal: %s", hostname, err)
			continue
		}
		if existing == nil {
			continue
		}
		if existing.Comment != dnsRecordOwnerComment {
			log.Printf("[dns] Skipping deletion of %s: not managed by us", hostname)
			continue
		}
		if err := s.api.DeleteDNSRecord(ctx, s.zoneID, existing.ID); err != nil {
			log.Printf("[dns] Error deleting CNAME for %s: %s", hostname, err)
			continue
		}
		log.Printf("[dns] Deleted CNAME %s (id=%s)", hostname, existing.ID)
	}
}

// findRecord returns the (single) DNS record matching hostname (any
// type), or nil if no record exists. Cloudflare's ListDNSRecords with
// Name= matches the FQDN exactly.
func (s *DNSSyncer) findRecord(ctx context.Context, hostname string) (*cloudflare.DNSRecord, error) {
	records, err := s.api.ListDNSRecords(ctx, s.zoneID, cloudflare.ListDNSRecordsParams{
		Name: hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("ListDNSRecords: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	// Prefer a record we own if multiple exist (rare).
	for i := range records {
		if records[i].Comment == dnsRecordOwnerComment {
			return &records[i], nil
		}
	}
	return &records[0], nil
}

// verifyRecord re-reads the named record from Cloudflare immediately
// after a write so the server-side state shows up in the logs. This
// catches silent-success-but-wrong-zone or silent-success-but-bad-data
// cases that wouldn't otherwise surface until DNS resolution failed.
func (s *DNSSyncer) verifyRecord(ctx context.Context, hostname, expectedID, op string) {
	rec, err := s.findRecord(ctx, hostname)
	if err != nil {
		log.Printf("[dns] verify(%s) %s: lookup failed: %s", op, hostname, err)
		return
	}
	if rec == nil {
		log.Printf("[dns] verify(%s) %s: WARN no record found server-side after %s", op, hostname, op)
		return
	}
	if rec.ID != expectedID {
		log.Printf("[dns] verify(%s) %s: id mismatch (wrote=%s, server=%s) — possible duplicate",
			op, hostname, expectedID, rec.ID)
	}
	log.Printf("[dns] verify(%s) %s: id=%s type=%s content=%s proxied=%v comment=%q",
		op, hostname, rec.ID, rec.Type, rec.Content, derefBool(rec.Proxied), rec.Comment)
}

func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
