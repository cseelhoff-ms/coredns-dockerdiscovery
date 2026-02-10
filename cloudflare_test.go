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
	mutex   sync.Mutex
	records map[string][]cloudflare.DNSRecord // zoneID -> records
	nextID  int
}

func newMockCloudflareAPI() *mockCloudflareAPI {
	return &mockCloudflareAPI{
		records: make(map[string][]cloudflare.DNSRecord),
		nextID:  1,
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
