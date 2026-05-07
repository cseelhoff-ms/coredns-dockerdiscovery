package dockerdiscovery

// Cloudflare API plumbing. Used by:
//   - tunnel.go: pushes ingress entries to a Cloudflare Tunnel
//   - dnssync.go: creates/updates/deletes proxied CNAME records in a
//     zone so public DNS resolution actually reaches the tunnel
//
// CloudflareAPI is the minimum surface those two consumers need.
// Keeping it as an interface lets tests inject a mock without
// touching the network.

import (
	"context"
	"fmt"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// CloudflareConfig holds credentials, the exclusion list shared with
// the tunnel syncer, and the zone ID used by the DNS syncer (optional).
type CloudflareConfig struct {
	APIToken       string          // API token (preferred, scoped)
	APIKey         string          // Global API key (legacy)
	APIEmail       string          // Email for global API key auth
	ExcludeDomains map[string]bool // Domains to exclude from tunnel & DNS sync
	ZoneID         string          // Zone to manage CNAME records in (optional)
}

// CloudflareAPI is the minimum surface tunnel.go and dnssync.go need.
type CloudflareAPI interface {
	GetTunnelConfiguration(ctx context.Context, accountID string, tunnelID string) (cloudflare.TunnelConfigurationResult, error)
	UpdateTunnelConfiguration(ctx context.Context, accountID string, tunnelID string, config cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error)

	ListDNSRecords(ctx context.Context, zoneID string, params cloudflare.ListDNSRecordsParams) ([]cloudflare.DNSRecord, error)
	CreateDNSRecord(ctx context.Context, zoneID string, params cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error)
	UpdateDNSRecord(ctx context.Context, zoneID string, params cloudflare.UpdateDNSRecordParams) error
	DeleteDNSRecord(ctx context.Context, zoneID string, recordID string) error
}

// cloudflareAPIWrapper adapts the cloudflare-go client to CloudflareAPI.
type cloudflareAPIWrapper struct {
	api *cloudflare.API
}

func (w *cloudflareAPIWrapper) GetTunnelConfiguration(ctx context.Context, accountID string, tunnelID string) (cloudflare.TunnelConfigurationResult, error) {
	return w.api.GetTunnelConfiguration(ctx, cloudflare.AccountIdentifier(accountID), tunnelID)
}

func (w *cloudflareAPIWrapper) UpdateTunnelConfiguration(ctx context.Context, accountID string, tunnelID string, config cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error) {
	return w.api.UpdateTunnelConfiguration(ctx, cloudflare.AccountIdentifier(accountID), config)
}

func (w *cloudflareAPIWrapper) ListDNSRecords(ctx context.Context, zoneID string, params cloudflare.ListDNSRecordsParams) ([]cloudflare.DNSRecord, error) {
	records, _, err := w.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), params)
	return records, err
}

func (w *cloudflareAPIWrapper) CreateDNSRecord(ctx context.Context, zoneID string, params cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error) {
	return w.api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), params)
}

func (w *cloudflareAPIWrapper) UpdateDNSRecord(ctx context.Context, zoneID string, params cloudflare.UpdateDNSRecordParams) error {
	_, err := w.api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), params)
	return err
}

func (w *cloudflareAPIWrapper) DeleteDNSRecord(ctx context.Context, zoneID string, recordID string) error {
	return w.api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), recordID)
}

// newCloudflareAPI builds a real Cloudflare API client from the config.
// Returns an error if no usable credentials are present.
func newCloudflareAPI(cfg *CloudflareConfig) (CloudflareAPI, error) {
	var api *cloudflare.API
	var err error
	switch {
	case cfg.APIToken != "":
		api, err = cloudflare.NewWithAPIToken(cfg.APIToken)
	case cfg.APIKey != "" && cfg.APIEmail != "":
		api, err = cloudflare.New(cfg.APIKey, cfg.APIEmail)
	default:
		return nil, fmt.Errorf("cloudflare: either cf_token or both cf_email and cf_key must be provided")
	}
	if err != nil {
		return nil, fmt.Errorf("cloudflare: failed to create API client: %w", err)
	}
	return &cloudflareAPIWrapper{api: api}, nil
}
