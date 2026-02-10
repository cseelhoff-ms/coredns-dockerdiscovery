package dockerdiscovery

import (
	"context"
	"fmt"
	"log"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// CloudflareConfig holds the configuration for Cloudflare DNS sync.
type CloudflareConfig struct {
	APIToken       string           // API token (preferred, scoped)
	APIKey         string           // Global API key (legacy)
	APIEmail       string           // Email for global API key auth
	TargetDomain   string           // CNAME target (e.g. "traefik.homelab.net")
	Proxied        bool             // Whether Cloudflare proxy is enabled
	ExcludeDomains map[string]bool  // Domains to exclude from sync
	Zones          []CloudflareZone // Explicit zone mappings
}

// CloudflareZone maps a domain suffix to a Cloudflare zone ID.
type CloudflareZone struct {
	Domain string // e.g. "example.com"
	ZoneID string // Cloudflare zone ID
}

// CloudflareAPI abstracts Cloudflare API calls for testability.
type CloudflareAPI interface {
	ListDNSRecords(ctx context.Context, zoneID string, record cloudflare.DNSRecord) ([]cloudflare.DNSRecord, error)
	CreateDNSRecord(ctx context.Context, zoneID string, record cloudflare.DNSRecord) (*cloudflare.DNSRecordResponse, error)
	UpdateDNSRecord(ctx context.Context, zoneID string, recordID string, record cloudflare.DNSRecord) error
	DeleteDNSRecord(ctx context.Context, zoneID string, recordID string) error
}

// cloudflareAPIWrapper wraps the real cloudflare-go API client.
type cloudflareAPIWrapper struct {
	api *cloudflare.API
}

func (w *cloudflareAPIWrapper) ListDNSRecords(ctx context.Context, zoneID string, record cloudflare.DNSRecord) ([]cloudflare.DNSRecord, error) {
	records, _, err := w.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Type: record.Type,
		Name: record.Name,
	})
	return records, err
}

func (w *cloudflareAPIWrapper) CreateDNSRecord(ctx context.Context, zoneID string, record cloudflare.DNSRecord) (*cloudflare.DNSRecordResponse, error) {
	resp, err := w.api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Content,
		Proxied: record.Proxied,
		TTL:     record.TTL,
	})
	if err != nil {
		return nil, err
	}
	return &cloudflare.DNSRecordResponse{Result: resp}, nil
}

func (w *cloudflareAPIWrapper) UpdateDNSRecord(ctx context.Context, zoneID string, recordID string, record cloudflare.DNSRecord) error {
	_, err := w.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      recordID,
		Type:    record.Type,
		Name:    record.Name,
		Content: record.Content,
		Proxied: record.Proxied,
		TTL:     record.TTL,
	})
	return err
}

func (w *cloudflareAPIWrapper) DeleteDNSRecord(ctx context.Context, zoneID string, recordID string) error {
	return w.api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), recordID)
}

// CloudflareSyncer manages syncing DNS records to Cloudflare.
type CloudflareSyncer struct {
	api    CloudflareAPI
	config *CloudflareConfig
}

// NewCloudflareSyncer creates a CloudflareSyncer with a real Cloudflare API client.
func NewCloudflareSyncer(config *CloudflareConfig) (*CloudflareSyncer, error) {
	var api *cloudflare.API
	var err error

	if config.APIToken != "" {
		api, err = cloudflare.NewWithAPIToken(config.APIToken)
	} else if config.APIKey != "" && config.APIEmail != "" {
		api, err = cloudflare.New(config.APIKey, config.APIEmail)
	} else {
		return nil, fmt.Errorf("cloudflare: either cf_token or both cf_email and cf_key must be provided")
	}

	if err != nil {
		return nil, fmt.Errorf("cloudflare: failed to create API client: %w", err)
	}

	return &CloudflareSyncer{
		api:    &cloudflareAPIWrapper{api: api},
		config: config,
	}, nil
}

// NewCloudflareSyncerWithAPI creates a CloudflareSyncer with a provided API (for testing).
func NewCloudflareSyncerWithAPI(config *CloudflareConfig, api CloudflareAPI) *CloudflareSyncer {
	return &CloudflareSyncer{
		api:    api,
		config: config,
	}
}

// SyncDomains creates or updates CNAME records in Cloudflare for the given domains.
func (s *CloudflareSyncer) SyncDomains(domains []string) {
	ctx := context.Background()
	for _, domain := range domains {
		if s.config.ExcludeDomains[domain] {
			log.Printf("[cloudflare] Skipping excluded domain: %s", domain)
			continue
		}

		zoneID := s.findZoneForDomain(domain)
		if zoneID == "" {
			log.Printf("[cloudflare] No zone found for domain: %s", domain)
			continue
		}

		if err := s.upsertRecord(ctx, zoneID, domain); err != nil {
			log.Printf("[cloudflare] Error syncing domain %s: %s", domain, err)
		}
	}
}

// RemoveDomains deletes CNAME records from Cloudflare for the given domains.
func (s *CloudflareSyncer) RemoveDomains(domains []string) {
	ctx := context.Background()
	for _, domain := range domains {
		if s.config.ExcludeDomains[domain] {
			continue
		}

		zoneID := s.findZoneForDomain(domain)
		if zoneID == "" {
			log.Printf("[cloudflare] No zone found for domain: %s", domain)
			continue
		}

		if err := s.deleteRecord(ctx, zoneID, domain); err != nil {
			log.Printf("[cloudflare] Error removing domain %s: %s", domain, err)
		}
	}
}

// findZoneForDomain returns the zone ID for the domain by matching configured zones.
func (s *CloudflareSyncer) findZoneForDomain(domain string) string {
	// Find the longest matching zone (most specific)
	var bestMatch string
	var bestZoneID string
	for _, zone := range s.config.Zones {
		if domain == zone.Domain || strings.HasSuffix(domain, "."+zone.Domain) {
			if len(zone.Domain) > len(bestMatch) {
				bestMatch = zone.Domain
				bestZoneID = zone.ZoneID
			}
		}
	}
	return bestZoneID
}

// upsertRecord creates or updates a CNAME record for the domain.
func (s *CloudflareSyncer) upsertRecord(ctx context.Context, zoneID string, domain string) error {
	// Search for existing CNAME record
	existing, err := s.api.ListDNSRecords(ctx, zoneID, cloudflare.DNSRecord{
		Type: "CNAME",
		Name: domain,
	})
	if err != nil {
		return fmt.Errorf("listing records for %s: %w", domain, err)
	}

	proxied := s.config.Proxied
	record := cloudflare.DNSRecord{
		Type:    "CNAME",
		Name:    domain,
		Content: s.config.TargetDomain,
		Proxied: &proxied,
		TTL:     1, // auto
	}

	if len(existing) > 0 {
		// Update if content changed
		rec := existing[0]
		if rec.Content == s.config.TargetDomain {
			log.Printf("[cloudflare] Record for %s already up to date", domain)
			return nil
		}
		log.Printf("[cloudflare] Updating CNAME record for %s -> %s", domain, s.config.TargetDomain)
		return s.api.UpdateDNSRecord(ctx, zoneID, rec.ID, record)
	}

	// Create new record
	log.Printf("[cloudflare] Creating CNAME record for %s -> %s", domain, s.config.TargetDomain)
	_, err = s.api.CreateDNSRecord(ctx, zoneID, record)
	return err
}

// deleteRecord removes a CNAME record for the domain.
func (s *CloudflareSyncer) deleteRecord(ctx context.Context, zoneID string, domain string) error {
	existing, err := s.api.ListDNSRecords(ctx, zoneID, cloudflare.DNSRecord{
		Type: "CNAME",
		Name: domain,
	})
	if err != nil {
		return fmt.Errorf("listing records for %s: %w", domain, err)
	}

	for _, rec := range existing {
		log.Printf("[cloudflare] Deleting CNAME record for %s (ID: %s)", domain, rec.ID)
		if err := s.api.DeleteDNSRecord(ctx, zoneID, rec.ID); err != nil {
			return fmt.Errorf("deleting record %s: %w", rec.ID, err)
		}
	}
	return nil
}
