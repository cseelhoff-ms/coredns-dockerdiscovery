package dockerdiscovery

import (
	"context"
	"fmt"
	"sync"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
)

// mockCloudflareAPI implements CloudflareAPI for testing.
type mockCloudflareAPI struct {
	mutex         sync.Mutex
	records       map[string][]cloudflare.DNSRecord              // zoneID -> records
	tunnelIngress map[string][]cloudflare.UnvalidatedIngressRule // tunnelID -> ingress rules
	tunnelOrigin  map[string]cloudflare.OriginRequestConfig      // tunnelID -> origin config
	tunnelWarp    map[string]*cloudflare.WarpRoutingConfig       // tunnelID -> warp config
	nextID        int
}

func newMockCloudflareAPI() *mockCloudflareAPI {
	return &mockCloudflareAPI{
		records:       make(map[string][]cloudflare.DNSRecord),
		tunnelIngress: make(map[string][]cloudflare.UnvalidatedIngressRule),
		tunnelOrigin:  make(map[string]cloudflare.OriginRequestConfig),
		tunnelWarp:    make(map[string]*cloudflare.WarpRoutingConfig),
		nextID:        1,
	}
}

func (m *mockCloudflareAPI) ListDNSRecords(ctx context.Context, zoneID string, filter cloudflare.DNSRecord) ([]cloudflare.DNSRecord, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var result []cloudflare.DNSRecord
	for _, rec := range m.records[zoneID] {
		if (filter.Type == "" || rec.Type == filter.Type) &&
			(filter.Name == "" || rec.Name == filter.Name) {
			result = append(result, rec)
		}
	}
	return result, nil
}

func (m *mockCloudflareAPI) CreateDNSRecord(ctx context.Context, zoneID string, record cloudflare.DNSRecord) (*cloudflare.DNSRecordResponse, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	record.ID = fmt.Sprintf("rec_%d", m.nextID)
	m.nextID++
	m.records[zoneID] = append(m.records[zoneID], record)
	return &cloudflare.DNSRecordResponse{Result: record}, nil
}

func (m *mockCloudflareAPI) UpdateDNSRecord(ctx context.Context, zoneID string, recordID string, record cloudflare.DNSRecord) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	recs := m.records[zoneID]
	for i, r := range recs {
		if r.ID == recordID {
			record.ID = recordID
			recs[i] = record
			return nil
		}
	}
	return fmt.Errorf("record %s not found", recordID)
}

func (m *mockCloudflareAPI) DeleteDNSRecord(ctx context.Context, zoneID string, recordID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	recs := m.records[zoneID]
	for i, r := range recs {
		if r.ID == recordID {
			m.records[zoneID] = append(recs[:i], recs[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record %s not found", recordID)
}

// allRecords returns all records across all zones (for test assertions).
func (m *mockCloudflareAPI) allRecords() []cloudflare.DNSRecord {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var all []cloudflare.DNSRecord
	for _, recs := range m.records {
		all = append(all, recs...)
	}
	return all
}

func (m *mockCloudflareAPI) recordCount() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	count := 0
	for _, recs := range m.records {
		count += len(recs)
	}
	return count
}

func (m *mockCloudflareAPI) GetTunnelConfiguration(ctx context.Context, accountID string, tunnelID string) (cloudflare.TunnelConfigurationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return cloudflare.TunnelConfigurationResult{
		TunnelID: tunnelID,
		Config: cloudflare.TunnelConfiguration{
			Ingress:       m.tunnelIngress[tunnelID],
			WarpRouting:   m.tunnelWarp[tunnelID],
			OriginRequest: m.tunnelOrigin[tunnelID],
		},
	}, nil
}

func (m *mockCloudflareAPI) UpdateTunnelConfiguration(ctx context.Context, accountID string, tunnelID string, config cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.tunnelIngress[tunnelID] = config.Config.Ingress
	m.tunnelOrigin[tunnelID] = config.Config.OriginRequest
	m.tunnelWarp[tunnelID] = config.Config.WarpRouting

	return cloudflare.TunnelConfigurationResult{
		TunnelID: tunnelID,
		Config:   config.Config,
	}, nil
}

// tunnelIngressCount returns the number of ingress rules for a tunnel.
func (m *mockCloudflareAPI) tunnelIngressCount(tunnelID string) int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return len(m.tunnelIngress[tunnelID])
}

// tunnelIngressRules returns a copy of the ingress rules for a tunnel.
func (m *mockCloudflareAPI) tunnelIngressRules(tunnelID string) []cloudflare.UnvalidatedIngressRule {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	rules := make([]cloudflare.UnvalidatedIngressRule, len(m.tunnelIngress[tunnelID]))
	copy(rules, m.tunnelIngress[tunnelID])
	return rules
}

func TestCloudflareSyncDomains(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net", "git.homelab.net"})

	assert.Equal(t, 2, mock.recordCount())
	records := mock.allRecords()
	names := []string{records[0].Name, records[1].Name}
	assert.ElementsMatch(t, []string{"app.homelab.net", "git.homelab.net"}, names)
	assert.Equal(t, "traefik.homelab.net", records[0].Content)
	assert.Equal(t, "CNAME", records[0].Type)
}

func TestCloudflareIdempotentSync(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	// Sync twice - should not create duplicates
	syncer.SyncDomains([]string{"app.homelab.net"})
	syncer.SyncDomains([]string{"app.homelab.net"})

	assert.Equal(t, 1, mock.recordCount())
}

func TestCloudflareUpdateTarget(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik-old.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net"})
	assert.Equal(t, "traefik-old.homelab.net", mock.allRecords()[0].Content)

	// Change target and sync again
	config.TargetDomain = "traefik-new.homelab.net"
	syncer.SyncDomains([]string{"app.homelab.net"})

	assert.Equal(t, 1, mock.recordCount())
	assert.Equal(t, "traefik-new.homelab.net", mock.allRecords()[0].Content)
}

func TestCloudflareRemoveDomains(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net", "git.homelab.net"})
	assert.Equal(t, 2, mock.recordCount())

	syncer.RemoveDomains([]string{"app.homelab.net"})
	assert.Equal(t, 1, mock.recordCount())
	assert.Equal(t, "git.homelab.net", mock.allRecords()[0].Name)
}

func TestCloudflareExcludeDomains(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain: "traefik.homelab.net",
		Proxied:      false,
		ExcludeDomains: map[string]bool{
			"internal.homelab.net": true,
		},
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net", "internal.homelab.net"})
	assert.Equal(t, 1, mock.recordCount())
	assert.Equal(t, "app.homelab.net", mock.allRecords()[0].Name)
}

func TestCloudflareMultiZone(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
			{Domain: "example.com", ZoneID: "zone_2"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net", "web.example.com"})

	// Check records are in correct zones
	zone1Recs, _ := mock.ListDNSRecords(context.Background(), "zone_1", cloudflare.DNSRecord{})
	zone2Recs, _ := mock.ListDNSRecords(context.Background(), "zone_2", cloudflare.DNSRecord{})
	assert.Equal(t, 1, len(zone1Recs))
	assert.Equal(t, 1, len(zone2Recs))
	assert.Equal(t, "app.homelab.net", zone1Recs[0].Name)
	assert.Equal(t, "web.example.com", zone2Recs[0].Name)
}

func TestCloudflareNoZoneMatch(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	// Domain doesn't match any configured zone
	syncer.SyncDomains([]string{"app.unknown.org"})
	assert.Equal(t, 0, mock.recordCount())
}

func TestCloudflareFindZoneLongestMatch(t *testing.T) {
	config := &CloudflareConfig{
		Zones: []CloudflareZone{
			{Domain: "net", ZoneID: "zone_broad"},
			{Domain: "homelab.net", ZoneID: "zone_specific"},
		},
	}
	syncer := &CloudflareSyncer{config: config}

	assert.Equal(t, "zone_specific", syncer.findZoneForDomain("app.homelab.net"))
}

func TestCloudflareProxied(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        true,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net"})
	assert.Equal(t, 1, mock.recordCount())
	rec := mock.allRecords()[0]
	assert.NotNil(t, rec.Proxied)
	assert.True(t, *rec.Proxied)
}

func TestCloudflareRemoveUntracked(t *testing.T) {
	mock := newMockCloudflareAPI()
	config := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	syncer := NewCloudflareSyncerWithAPI(config, mock)

	syncer.SyncDomains([]string{"app.homelab.net"})
	assert.Equal(t, 1, mock.recordCount())

	// Remove the domain via container stop
	syncer.RemoveDomains([]string{"app.homelab.net"})
	assert.Equal(t, 0, mock.recordCount())
}

// Config parsing tests

func TestCloudflareConfigToken(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-api-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.NotNil(t, dd.cloudflareConfig)
	assert.Equal(t, "my-api-token", dd.cloudflareConfig.APIToken)
	assert.Equal(t, "traefik.homelab.net", dd.cloudflareConfig.TargetDomain)
	assert.Equal(t, 1, len(dd.cloudflareConfig.Zones))
	assert.Equal(t, "homelab.net", dd.cloudflareConfig.Zones[0].Domain)
	assert.Equal(t, "zone123", dd.cloudflareConfig.Zones[0].ZoneID)
}

func TestCloudflareConfigKeyEmail(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_email user@example.com
	cf_key global-api-key
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.NotNil(t, dd.cloudflareConfig)
	assert.Equal(t, "user@example.com", dd.cloudflareConfig.APIEmail)
	assert.Equal(t, "global-api-key", dd.cloudflareConfig.APIKey)
}

func TestCloudflareConfigMultiZone(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone_abc
	cf_zone example.com zone_def
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(dd.cloudflareConfig.Zones))
}

func TestCloudflareConfigProxied(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
	cf_proxied
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.True(t, dd.cloudflareConfig.Proxied)
}

func TestCloudflareConfigExclude(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
	cf_exclude internal.homelab.net,private.homelab.net
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.True(t, dd.cloudflareConfig.ExcludeDomains["internal.homelab.net"])
	assert.True(t, dd.cloudflareConfig.ExcludeDomains["private.homelab.net"])
}

func TestCloudflareConfigMissingZone(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_zone")
}

func TestCloudflareConfigMissingTarget(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_zone homelab.net zone123
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_target")
}

func TestCloudflareAutoEnablesTraefik(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	// Cloudflare config should auto-enable traefik resolver and set traefik_cname
	assert.NotNil(t, dd.traefikResolver)
	assert.Equal(t, "traefik.homelab.net", dd.traefikCNAME)
}

// --- Tunnel syncer tests ---

func newTunnelTestSetup() (*mockCloudflareAPI, *TunnelSyncer) {
	mock := newMockCloudflareAPI()
	tunnelCfg := &TunnelConfig{
		TunnelID:  "test-tunnel-uuid",
		AccountID: "test-account-id",
	}
	cfCfg := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		Proxied:        false,
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	// Seed the tunnel with a catch-all rule
	mock.tunnelIngress[tunnelCfg.TunnelID] = []cloudflare.UnvalidatedIngressRule{
		{Service: "http_status:404"},
	}
	syncer := NewTunnelSyncerWithAPI(tunnelCfg, cfCfg, mock)
	return mock, syncer
}

func TestTunnelAddRoutes(t *testing.T) {
	mock, syncer := newTunnelTestSetup()

	syncer.AddRoutes([]string{"app.homelab.net", "git.homelab.net"}, "http://localhost:8080")

	// Should have 2 ingress rules + catch-all
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 3, len(rules))
	assert.Equal(t, "app.homelab.net", rules[0].Hostname)
	assert.Equal(t, "http://localhost:8080", rules[0].Service)
	assert.Equal(t, "git.homelab.net", rules[1].Hostname)
	assert.Equal(t, "http://localhost:8080", rules[1].Service)
	// Catch-all is last
	assert.Equal(t, "", rules[2].Hostname)
	assert.Equal(t, "http_status:404", rules[2].Service)

	// Should NOT create DNS records (tunnel manages ingress only)
	assert.Equal(t, 0, mock.recordCount())
}

func TestTunnelAddRoutesIdempotent(t *testing.T) {
	mock, syncer := newTunnelTestSetup()

	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:8080")
	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:8080")

	// Should still have 1 ingress rule + catch-all, no duplicates
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "app.homelab.net", rules[0].Hostname)

	// No DNS records created
	assert.Equal(t, 0, mock.recordCount())
}

func TestTunnelAddRoutesUpdateService(t *testing.T) {
	mock, syncer := newTunnelTestSetup()

	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:8080")
	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:9090")

	// Should have updated service URL
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "http://localhost:9090", rules[0].Service)
}

func TestTunnelRemoveRoutes(t *testing.T) {
	mock, syncer := newTunnelTestSetup()

	syncer.AddRoutes([]string{"app.homelab.net", "git.homelab.net"}, "http://localhost:8080")
	assert.Equal(t, 3, mock.tunnelIngressCount("test-tunnel-uuid"))

	syncer.RemoveRoutes([]string{"app.homelab.net"})

	// Should have 1 rule + catch-all
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "git.homelab.net", rules[0].Hostname)
	assert.Equal(t, "http_status:404", rules[1].Service)

	// No DNS records managed by tunnel
	assert.Equal(t, 0, mock.recordCount())
}

func TestTunnelPreservesCatchAll(t *testing.T) {
	mock, syncer := newTunnelTestSetup()

	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:8080")
	syncer.RemoveRoutes([]string{"app.homelab.net"})

	// Should still have the catch-all
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 1, len(rules))
	assert.Equal(t, "", rules[0].Hostname)
	assert.Equal(t, "http_status:404", rules[0].Service)
}

func TestTunnelExcludeDomains(t *testing.T) {
	mock := newMockCloudflareAPI()
	tunnelCfg := &TunnelConfig{
		TunnelID:  "test-tunnel-uuid",
		AccountID: "test-account-id",
	}
	cfCfg := &CloudflareConfig{
		TargetDomain: "traefik.homelab.net",
		ExcludeDomains: map[string]bool{
			"internal.homelab.net": true,
		},
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	mock.tunnelIngress[tunnelCfg.TunnelID] = []cloudflare.UnvalidatedIngressRule{
		{Service: "http_status:404"},
	}
	syncer := NewTunnelSyncerWithAPI(tunnelCfg, cfCfg, mock)

	syncer.AddRoutes([]string{"app.homelab.net", "internal.homelab.net"}, "http://localhost:8080")

	// Only non-excluded domain should be added
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "app.homelab.net", rules[0].Hostname)

	// No DNS records created by tunnel
	assert.Equal(t, 0, mock.recordCount())
}

func TestTunnelEmptyTunnel(t *testing.T) {
	mock := newMockCloudflareAPI()
	tunnelCfg := &TunnelConfig{
		TunnelID:  "empty-tunnel",
		AccountID: "test-account-id",
	}
	cfCfg := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
		},
	}
	// No existing ingress rules at all
	syncer := NewTunnelSyncerWithAPI(tunnelCfg, cfCfg, mock)

	syncer.AddRoutes([]string{"app.homelab.net"}, "http://localhost:8080")

	// Should have created the rule + a catch-all
	rules := mock.tunnelIngressRules("empty-tunnel")
	assert.Equal(t, 2, len(rules))
	assert.Equal(t, "app.homelab.net", rules[0].Hostname)
	assert.Equal(t, "http_status:404", rules[1].Service)
}

func TestTunnelMultiZone(t *testing.T) {
	mock := newMockCloudflareAPI()
	tunnelCfg := &TunnelConfig{
		TunnelID:  "test-tunnel-uuid",
		AccountID: "test-account-id",
	}
	cfCfg := &CloudflareConfig{
		TargetDomain:   "traefik.homelab.net",
		ExcludeDomains: make(map[string]bool),
		Zones: []CloudflareZone{
			{Domain: "homelab.net", ZoneID: "zone_1"},
			{Domain: "example.com", ZoneID: "zone_2"},
		},
	}
	mock.tunnelIngress[tunnelCfg.TunnelID] = []cloudflare.UnvalidatedIngressRule{
		{Service: "http_status:404"},
	}
	syncer := NewTunnelSyncerWithAPI(tunnelCfg, cfCfg, mock)

	syncer.AddRoutes([]string{"app.homelab.net", "web.example.com"}, "http://localhost:8080")

	// Both ingress rules should be created
	rules := mock.tunnelIngressRules("test-tunnel-uuid")
	assert.Equal(t, 3, len(rules))
	assert.Equal(t, "app.homelab.net", rules[0].Hostname)
	assert.Equal(t, "web.example.com", rules[1].Hostname)

	// No DNS records created by tunnel
	assert.Equal(t, 0, mock.recordCount())
}

// --- Tunnel config parsing tests ---

func TestTunnelConfigParsing(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
	cf_tunnel_id my-tunnel-uuid
	cf_account_id my-account-id
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.NotNil(t, dd.tunnelConfig)
	assert.Equal(t, "my-tunnel-uuid", dd.tunnelConfig.TunnelID)
	assert.Equal(t, "my-account-id", dd.tunnelConfig.AccountID)
	assert.NotNil(t, dd.tunnelSyncer)
	// cloudflareSyncer should also be created when cf_target is set alongside tunnel
	assert.NotNil(t, dd.cloudflareSyncer)
}

func TestTunnelConfigMissingAccountID(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
	cf_tunnel_id my-tunnel-uuid
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_account_id")
}

func TestTunnelConfigMissingTunnelID(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_token my-token
	cf_target traefik.homelab.net
	cf_zone homelab.net zone123
	cf_account_id my-account-id
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_tunnel_id")
}

func TestTunnelConfigRequiresAuth(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	cf_zone homelab.net zone123
	cf_tunnel_id my-tunnel-uuid
	cf_account_id my-account-id
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_token")
}

func TestTunnelAutoEnablesTraefik(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	cf_token my-token
	cf_zone homelab.net zone123
	cf_tunnel_id my-tunnel-uuid
	cf_account_id my-account-id
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	// Should auto-enable traefik resolver with tunnel CNAME target
	assert.NotNil(t, dd.traefikResolver)
	assert.Equal(t, "my-tunnel-uuid.cfargotunnel.com", dd.traefikCNAME)
}
