package dockerdiscovery

// Cloudflare API plumbing — used solely to support the Cloudflare Tunnel
// ingress-route syncer in tunnel.go. The DNS-record sync feature has
// been removed; we no longer create CNAME records in Cloudflare DNS.
// The wrapper still lives here so tunnel.go can construct a real client
// and tests can substitute a mock that satisfies CloudflareAPI.

import (
	"context"
	"fmt"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// CloudflareConfig holds the credentials and exclusion list shared with
// the tunnel syncer. There are no DNS-record fields here on purpose.
type CloudflareConfig struct {
	APIToken       string          // API token (preferred, scoped)
	APIKey         string          // Global API key (legacy)
	APIEmail       string          // Email for global API key auth
	ExcludeDomains map[string]bool // Domains to exclude from tunnel sync
}

// CloudflareAPI is the minimum surface tunnel.go needs. Keeping it as
// an interface lets tests inject a mock without touching the network.
type CloudflareAPI interface {
	GetTunnelConfiguration(ctx context.Context, accountID string, tunnelID string) (cloudflare.TunnelConfigurationResult, error)
	UpdateTunnelConfiguration(ctx context.Context, accountID string, tunnelID string, config cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error)
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
