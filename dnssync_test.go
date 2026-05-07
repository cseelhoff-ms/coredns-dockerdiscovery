package dockerdiscovery

import (
	"context"
	"errors"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/stretchr/testify/assert"
)

// fakeCFAPI implements CloudflareAPI for unit-testing the DNS syncer in
// isolation. Tunnel methods return zero values; DNS methods read/write
// an in-memory record store keyed by record ID.
type fakeCFAPI struct {
	records   map[string]cloudflare.DNSRecord // ID -> record
	nextID    int
	listErr   error
	createErr error
	updateErr error
	deleteErr error

	createCalls []cloudflare.CreateDNSRecordParams
	updateCalls []cloudflare.UpdateDNSRecordParams
	deleteCalls []string
}

func newFakeCFAPI() *fakeCFAPI {
	return &fakeCFAPI{records: map[string]cloudflare.DNSRecord{}}
}

func (f *fakeCFAPI) GetTunnelConfiguration(_ context.Context, _, _ string) (cloudflare.TunnelConfigurationResult, error) {
	return cloudflare.TunnelConfigurationResult{}, nil
}
func (f *fakeCFAPI) UpdateTunnelConfiguration(_ context.Context, _, _ string, _ cloudflare.TunnelConfigurationParams) (cloudflare.TunnelConfigurationResult, error) {
	return cloudflare.TunnelConfigurationResult{}, nil
}

func (f *fakeCFAPI) ListDNSRecords(_ context.Context, _ string, params cloudflare.ListDNSRecordsParams) ([]cloudflare.DNSRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []cloudflare.DNSRecord
	for _, r := range f.records {
		if params.Name != "" && r.Name != params.Name {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeCFAPI) CreateDNSRecord(_ context.Context, _ string, params cloudflare.CreateDNSRecordParams) (cloudflare.DNSRecord, error) {
	f.createCalls = append(f.createCalls, params)
	if f.createErr != nil {
		return cloudflare.DNSRecord{}, f.createErr
	}
	f.nextID++
	id := "rec-" + itoa(f.nextID)
	rec := cloudflare.DNSRecord{
		ID:      id,
		Type:    params.Type,
		Name:    params.Name,
		Content: params.Content,
		TTL:     params.TTL,
		Proxied: params.Proxied,
		Comment: params.Comment,
	}
	f.records[id] = rec
	return rec, nil
}

func (f *fakeCFAPI) UpdateDNSRecord(_ context.Context, _ string, params cloudflare.UpdateDNSRecordParams) error {
	f.updateCalls = append(f.updateCalls, params)
	if f.updateErr != nil {
		return f.updateErr
	}
	rec, ok := f.records[params.ID]
	if !ok {
		return errors.New("not found")
	}
	rec.Type = params.Type
	rec.Name = params.Name
	rec.Content = params.Content
	rec.TTL = params.TTL
	rec.Proxied = params.Proxied
	if params.Comment != nil {
		rec.Comment = *params.Comment
	}
	f.records[params.ID] = rec
	return nil
}

func (f *fakeCFAPI) DeleteDNSRecord(_ context.Context, _ string, recordID string) error {
	f.deleteCalls = append(f.deleteCalls, recordID)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.records, recordID)
	return nil
}

// tiny non-strconv int->string helper to keep imports lean.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func newSyncer(api CloudflareAPI) *DNSSyncer {
	return NewDNSSyncer(api,
		&CloudflareConfig{ZoneID: "zone123", ExcludeDomains: map[string]bool{}},
		"tunnelABC")
}

func TestDNSSyncer_AddCreatesRecord(t *testing.T) {
	api := newFakeCFAPI()
	s := newSyncer(api)
	s.AddRecords([]string{"app.example.com"})

	assert.Len(t, api.createCalls, 1)
	c := api.createCalls[0]
	assert.Equal(t, "CNAME", c.Type)
	assert.Equal(t, "app.example.com", c.Name)
	assert.Equal(t, "tunnelABC.cfargotunnel.com", c.Content)
	assert.Equal(t, dnsRecordOwnerComment, c.Comment)
	assert.NotNil(t, c.Proxied)
	assert.True(t, *c.Proxied)
	assert.Equal(t, 1, c.TTL)
}

func TestDNSSyncer_AddIsIdempotent(t *testing.T) {
	api := newFakeCFAPI()
	s := newSyncer(api)
	s.AddRecords([]string{"app.example.com"})
	s.AddRecords([]string{"app.example.com"})

	assert.Len(t, api.createCalls, 1, "second add should not create a duplicate")
	assert.Len(t, api.updateCalls, 0, "no update needed when content matches")
}

// If a record exists but isn't ours, leave it alone. This is the
// guardrail against clobbering hand-managed records.
func TestDNSSyncer_DoesNotClobberForeignRecord(t *testing.T) {
	api := newFakeCFAPI()
	api.records["foreign"] = cloudflare.DNSRecord{
		ID:      "foreign",
		Type:    "A",
		Name:    "app.example.com",
		Content: "192.0.2.1",
		// Comment intentionally NOT our marker.
	}
	s := newSyncer(api)
	s.AddRecords([]string{"app.example.com"})

	assert.Len(t, api.createCalls, 0)
	assert.Len(t, api.updateCalls, 0)
	assert.Equal(t, "192.0.2.1", api.records["foreign"].Content)
}

// If our managed record drifted (wrong content / wrong proxied flag),
// we should rewrite it back to the canonical state.
func TestDNSSyncer_UpdatesDriftedOwnedRecord(t *testing.T) {
	api := newFakeCFAPI()
	notProxied := false
	api.records["ours"] = cloudflare.DNSRecord{
		ID:      "ours",
		Type:    "CNAME",
		Name:    "app.example.com",
		Content: "old.cfargotunnel.com",
		Proxied: &notProxied,
		Comment: dnsRecordOwnerComment,
	}
	s := newSyncer(api)
	s.AddRecords([]string{"app.example.com"})

	assert.Len(t, api.createCalls, 0)
	assert.Len(t, api.updateCalls, 1)
	got := api.records["ours"]
	assert.Equal(t, "tunnelABC.cfargotunnel.com", got.Content)
	assert.NotNil(t, got.Proxied)
	assert.True(t, *got.Proxied)
}

func TestDNSSyncer_RemoveDeletesOwnedRecord(t *testing.T) {
	api := newFakeCFAPI()
	s := newSyncer(api)
	s.AddRecords([]string{"app.example.com"})
	assert.Len(t, api.records, 1)

	s.RemoveRecords([]string{"app.example.com"})
	assert.Len(t, api.records, 0)
	assert.Len(t, api.deleteCalls, 1)
}

func TestDNSSyncer_RemoveSkipsForeignRecord(t *testing.T) {
	api := newFakeCFAPI()
	api.records["foreign"] = cloudflare.DNSRecord{
		ID:      "foreign",
		Type:    "CNAME",
		Name:    "app.example.com",
		Content: "elsewhere.example.com",
	}
	s := newSyncer(api)
	s.RemoveRecords([]string{"app.example.com"})

	assert.Len(t, api.deleteCalls, 0)
	assert.Len(t, api.records, 1)
}

// Excluded domains must be skipped on both add and remove paths.
func TestDNSSyncer_RespectsExcludeList(t *testing.T) {
	api := newFakeCFAPI()
	cfg := &CloudflareConfig{
		ZoneID:         "zone123",
		ExcludeDomains: map[string]bool{"private.example.com": true},
	}
	s := NewDNSSyncer(api, cfg, "tunnelABC")
	s.AddRecords([]string{"private.example.com", "public.example.com"})

	assert.Len(t, api.createCalls, 1)
	assert.Equal(t, "public.example.com", api.createCalls[0].Name)
}

func TestNewDNSSyncerReturnsNilWhenZoneMissing(t *testing.T) {
	api := newFakeCFAPI()
	cfg := &CloudflareConfig{} // no ZoneID
	assert.Nil(t, NewDNSSyncer(api, cfg, "tunnelABC"))
}
