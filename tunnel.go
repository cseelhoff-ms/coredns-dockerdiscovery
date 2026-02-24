package dockerdiscovery

import (
	"context"
	"fmt"
	"log"
	"sync"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// TunnelConfig holds configuration for Cloudflare Tunnel route management.
type TunnelConfig struct {
	TunnelID  string // Cloudflare Tunnel UUID
	AccountID string // Cloudflare Account ID
}

// TunnelSyncer manages adding/removing public hostname routes on a Cloudflare Tunnel.
type TunnelSyncer struct {
	api    CloudflareAPI
	tunnel *TunnelConfig
	cf     *CloudflareConfig // reused for DNS record management + zone lookup
	mu     sync.Mutex        // protects GET→modify→PUT on tunnel config
}

// NewTunnelSyncer creates a TunnelSyncer with a real Cloudflare API client.
func NewTunnelSyncer(tunnelCfg *TunnelConfig, cfCfg *CloudflareConfig) (*TunnelSyncer, error) {
	var api *cloudflare.API
	var err error

	if cfCfg.APIToken != "" {
		api, err = cloudflare.NewWithAPIToken(cfCfg.APIToken)
	} else if cfCfg.APIKey != "" && cfCfg.APIEmail != "" {
		api, err = cloudflare.New(cfCfg.APIKey, cfCfg.APIEmail)
	} else {
		return nil, fmt.Errorf("tunnel: either cf_token or both cf_email and cf_key must be provided")
	}

	if err != nil {
		return nil, fmt.Errorf("tunnel: failed to create API client: %w", err)
	}

	return &TunnelSyncer{
		api:    &cloudflareAPIWrapper{api: api},
		tunnel: tunnelCfg,
		cf:     cfCfg,
	}, nil
}

// NewTunnelSyncerWithAPI creates a TunnelSyncer with a provided API (for testing).
func NewTunnelSyncerWithAPI(tunnelCfg *TunnelConfig, cfCfg *CloudflareConfig, api CloudflareAPI) *TunnelSyncer {
	return &TunnelSyncer{
		api:    api,
		tunnel: tunnelCfg,
		cf:     cfCfg,
	}
}

// AddRoutes adds public hostname ingress rules to the tunnel.
func (s *TunnelSyncer) AddRoutes(hostnames []string, serviceURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()

	// Get current tunnel configuration
	result, err := s.api.GetTunnelConfiguration(ctx, s.tunnel.AccountID, s.tunnel.TunnelID)
	if err != nil {
		log.Printf("[tunnel] Error getting tunnel configuration: %s", err)
		return
	}

	ingress := result.Config.Ingress
	modified := false

	for _, hostname := range hostnames {
		if s.cf.ExcludeDomains[hostname] {
			log.Printf("[tunnel] Skipping excluded domain: %s", hostname)
			continue
		}

		// Check if rule already exists
		exists := false
		for i, rule := range ingress {
			if rule.Hostname == hostname {
				if rule.Service == serviceURL {
					log.Printf("[tunnel] Route for %s already up to date", hostname)
					exists = true
					break
				}
				// Update existing rule with new service URL
				log.Printf("[tunnel] Updating tunnel route for %s -> %s", hostname, serviceURL)
				ingress[i].Service = serviceURL
				exists = true
				modified = true
				break
			}
		}

		if !exists {
			// Insert before the catch-all (last rule)
			newRule := cloudflare.UnvalidatedIngressRule{
				Hostname: hostname,
				Service:  serviceURL,
			}

			if len(ingress) > 0 {
				// Insert before the last rule (catch-all)
				ingress = append(ingress[:len(ingress)-1], newRule, ingress[len(ingress)-1])
			} else {
				// No existing rules — add the rule and a catch-all
				ingress = append(ingress, newRule, cloudflare.UnvalidatedIngressRule{
					Service: "http_status:404",
				})
			}
			modified = true
			log.Printf("[tunnel] Adding tunnel route for %s -> %s", hostname, serviceURL)
		}
	}

	// Update tunnel configuration if modified
	if modified {
		params := cloudflare.TunnelConfigurationParams{
			TunnelID: s.tunnel.TunnelID,
			Config: cloudflare.TunnelConfiguration{
				Ingress:       ingress,
				WarpRouting:   result.Config.WarpRouting,
				OriginRequest: result.Config.OriginRequest,
			},
		}
		if _, err := s.api.UpdateTunnelConfiguration(ctx, s.tunnel.AccountID, s.tunnel.TunnelID, params); err != nil {
			log.Printf("[tunnel] Error updating tunnel configuration: %s", err)
			return
		}
	}

}

// RemoveRoutes removes public hostname ingress rules from the tunnel.
func (s *TunnelSyncer) RemoveRoutes(hostnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()

	// Get current tunnel configuration
	result, err := s.api.GetTunnelConfiguration(ctx, s.tunnel.AccountID, s.tunnel.TunnelID)
	if err != nil {
		log.Printf("[tunnel] Error getting tunnel configuration: %s", err)
		return
	}

	removeSet := make(map[string]bool)
	for _, h := range hostnames {
		if !s.cf.ExcludeDomains[h] {
			removeSet[h] = true
		}
	}

	// Filter out matching rules
	var filtered []cloudflare.UnvalidatedIngressRule
	modified := false
	for _, rule := range result.Config.Ingress {
		if removeSet[rule.Hostname] {
			log.Printf("[tunnel] Removing tunnel route for %s", rule.Hostname)
			modified = true
			continue
		}
		filtered = append(filtered, rule)
	}

	// Update tunnel configuration if modified
	if modified {
		params := cloudflare.TunnelConfigurationParams{
			TunnelID: s.tunnel.TunnelID,
			Config: cloudflare.TunnelConfiguration{
				Ingress:       filtered,
				WarpRouting:   result.Config.WarpRouting,
				OriginRequest: result.Config.OriginRequest,
			},
		}
		if _, err := s.api.UpdateTunnelConfiguration(ctx, s.tunnel.AccountID, s.tunnel.TunnelID, params); err != nil {
			log.Printf("[tunnel] Error updating tunnel configuration: %s", err)
			return
		}
	}

}
