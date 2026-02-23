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
// It also creates/deletes CNAME DNS records pointing to <tunnel-id>.cfargotunnel.com.
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

// AddRoutes adds public hostname ingress rules to the tunnel and creates
// corresponding CNAME DNS records pointing to <tunnel-id>.cfargotunnel.com.
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

	// Create CNAME DNS records pointing to <tunnel-id>.cfargotunnel.com
	cnameTarget := fmt.Sprintf("%s.cfargotunnel.com", s.tunnel.TunnelID)
	for _, hostname := range hostnames {
		if s.cf.ExcludeDomains[hostname] {
			continue
		}
		s.upsertTunnelDNS(ctx, hostname, cnameTarget)
	}
}

// RemoveRoutes removes public hostname ingress rules from the tunnel and
// deletes the corresponding CNAME DNS records.
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

	// Delete CNAME DNS records
	for _, hostname := range hostnames {
		if s.cf.ExcludeDomains[hostname] {
			continue
		}
		s.deleteTunnelDNS(ctx, hostname)
	}
}

// upsertTunnelDNS creates or updates a CNAME record pointing to the tunnel.
func (s *TunnelSyncer) upsertTunnelDNS(ctx context.Context, hostname string, cnameTarget string) {
	zoneID := s.findZoneForDomain(hostname)
	if zoneID == "" {
		log.Printf("[tunnel] No zone found for domain: %s", hostname)
		return
	}

	existing, err := s.api.ListDNSRecords(ctx, zoneID, cloudflare.DNSRecord{
		Type: "CNAME",
		Name: hostname,
	})
	if err != nil {
		log.Printf("[tunnel] Error listing DNS records for %s: %s", hostname, err)
		return
	}

	proxied := s.cf.Proxied
	record := cloudflare.DNSRecord{
		Type:    "CNAME",
		Name:    hostname,
		Content: cnameTarget,
		Proxied: &proxied,
		TTL:     1, // auto
	}

	if len(existing) > 0 {
		if existing[0].Content == cnameTarget {
			return
		}
		log.Printf("[tunnel] Updating DNS record for %s -> %s", hostname, cnameTarget)
		if err := s.api.UpdateDNSRecord(ctx, zoneID, existing[0].ID, record); err != nil {
			log.Printf("[tunnel] Error updating DNS record for %s: %s", hostname, err)
		}
		return
	}

	log.Printf("[tunnel] Creating DNS record for %s -> %s", hostname, cnameTarget)
	if _, err := s.api.CreateDNSRecord(ctx, zoneID, record); err != nil {
		log.Printf("[tunnel] Error creating DNS record for %s: %s", hostname, err)
	}
}

// deleteTunnelDNS removes CNAME DNS records for a hostname.
func (s *TunnelSyncer) deleteTunnelDNS(ctx context.Context, hostname string) {
	zoneID := s.findZoneForDomain(hostname)
	if zoneID == "" {
		return
	}

	existing, err := s.api.ListDNSRecords(ctx, zoneID, cloudflare.DNSRecord{
		Type: "CNAME",
		Name: hostname,
	})
	if err != nil {
		log.Printf("[tunnel] Error listing DNS records for %s: %s", hostname, err)
		return
	}

	for _, rec := range existing {
		log.Printf("[tunnel] Deleting DNS record for %s (ID: %s)", hostname, rec.ID)
		if err := s.api.DeleteDNSRecord(ctx, zoneID, rec.ID); err != nil {
			log.Printf("[tunnel] Error deleting DNS record for %s: %s", hostname, err)
		}
	}
}

// findZoneForDomain reuses the same zone-matching logic as CloudflareSyncer.
func (s *TunnelSyncer) findZoneForDomain(domain string) string {
	var bestMatch string
	var bestZoneID string
	for _, zone := range s.cf.Zones {
		if domain == zone.Domain || len(domain) > len(zone.Domain) && domain[len(domain)-len(zone.Domain)-1] == '.' && domain[len(domain)-len(zone.Domain):] == zone.Domain {
			if len(zone.Domain) > len(bestMatch) {
				bestMatch = zone.Domain
				bestZoneID = zone.ZoneID
			}
		}
	}
	return bestZoneID
}
