package dockerdiscovery

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/stretchr/testify/assert"
)

func TestInventoryDirectiveParsing(t *testing.T) {
	t.Run("addr only, default path", func(t *testing.T) {
		c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	inventory 127.0.0.1:18181
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.1:18181", dd.inventoryAddr)
		assert.Equal(t, "", dd.inventoryPath)
	})

	t.Run("addr + custom path", func(t *testing.T) {
		c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	inventory 127.0.0.1:18182 /things
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.1:18182", dd.inventoryAddr)
		assert.Equal(t, "/things", dd.inventoryPath)
	})

	t.Run("empty arg silently skipped", func(t *testing.T) {
		c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	inventory ""
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "", dd.inventoryAddr)
	})
}

func TestInventorySnapshot(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	// portainer-like: Traefik label only → CNAME row.
	portainer := genContainer("aa00", "portainer", map[string]string{
		"traefik.http.routers.portainer.rule": "Host(`portainer.example.com`)",
	})
	assert.Nil(t, dd.updateContainerInfo(portainer))

	// openldap-like: host label only → A_HOST row.
	openldap := genContainer("bb00", "openldap", map[string]string{
		"coredns.dockerdiscovery.host": "ldap.example.com",
	})
	assert.Nil(t, dd.updateContainerInfo(openldap))

	// traefik-like: both labels for the same FQDN → A_HOST only (CNAME suppressed).
	traefik := genContainer("cc00", "traefik", map[string]string{
		"coredns.dockerdiscovery.host":        "traefik.example.com",
		"traefik.http.routers.dashboard.rule": "Host(`traefik.example.com`)",
	})
	assert.Nil(t, dd.updateContainerInfo(traefik))

	snap := dd.Snapshot()
	assert.Equal(t, "docker", snap.Plugin)
	assert.Equal(t, 3, snap.ContainerCount)

	kinds := map[string][]InventoryRecord{}
	for _, rec := range snap.Records {
		kinds[string(rec.Kind)] = append(kinds[string(rec.Kind)], rec)
	}

	// Expect exactly: 1× CNAME (portainer), 2× A_HOST (openldap, traefik).
	assert.Len(t, kinds[string(RecordKindCNAME)], 1)
	assert.Equal(t, "portainer.example.com", kinds[string(RecordKindCNAME)][0].Domain)
	assert.Equal(t, "traefik.example.com", kinds[string(RecordKindCNAME)][0].Target)

	assert.Len(t, kinds[string(RecordKindHostA)], 2)
	hostADomains := []string{kinds[string(RecordKindHostA)][0].Domain, kinds[string(RecordKindHostA)][1].Domain}
	assert.ElementsMatch(t, []string{"ldap.example.com", "traefik.example.com"}, hostADomains)
	for _, rec := range kinds[string(RecordKindHostA)] {
		assert.Equal(t, "10.0.60.3", rec.Target)
		assert.Equal(t, "docker:host_a", rec.Source)
	}

	// No tunnel rows because cf_tunnel_target / tunnelSyncer aren't configured.
	assert.Len(t, kinds[string(RecordKindTunnel)], 0)
}

func TestInventorySnapshotEmpty(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { traefik_cname x.example.com }`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	snap := dd.Snapshot()
	assert.Equal(t, 0, snap.ContainerCount)
	assert.Equal(t, 0, snap.RecordCount)
	assert.Empty(t, snap.Records)
}

func TestInventoryServerJSONAndHTML(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	host_ip 10.0.0.7
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("ddee", "myhost", map[string]string{
		"coredns.dockerdiscovery.host": "myhost.example.com",
	})
	assert.Nil(t, dd.updateContainerInfo(cont))

	srv := NewInventoryServer("127.0.0.1:0", "", dd)
	assert.Nil(t, srv.Start())
	defer srv.Stop()

	base := "http://" + srv.ln.Addr().String()
	httpc := &http.Client{Timeout: 2 * time.Second}

	resp, err := httpc.Get(base + "/inventory")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var snap InventorySnapshot
	assert.Nil(t, json.NewDecoder(resp.Body).Decode(&snap))
	resp.Body.Close()
	assert.Equal(t, 1, snap.ContainerCount)
	assert.Greater(t, snap.RecordCount, 0)

	resp, err = httpc.Get(base + "/inventory.html")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.True(t, strings.Contains(string(body), "<table"))
	assert.True(t, strings.Contains(string(body), "10.0.0.7"))

	resp, err = httpc.Get(base + "/healthz")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestInventoryServerBindError(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { traefik_cname x.example.com }`)
	dd, _ := createPlugin(c)
	first := NewInventoryServer("127.0.0.1:0", "", dd)
	assert.Nil(t, first.Start())
	defer first.Stop()

	second := NewInventoryServer(first.ln.Addr().String(), "", dd)
	err := second.Start()
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "inventory: listen"))
}

// CNAME-only container (no host label, no host_ip) — still produces a CNAME row.
func TestInventoryCNAMEOnlyContainer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { traefik_cname tunnel.example.com }`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := &dockerapi.Container{
		ID:   "abcdef0123456789",
		Name: "lonely",
		Config: &dockerapi.Config{
			Labels: map[string]string{
				"traefik.http.routers.svc.rule": "Host(`svc.example.com`)",
			},
		},
		HostConfig:      &dockerapi.HostConfig{NetworkMode: "host"},
		NetworkSettings: &dockerapi.NetworkSettings{Networks: map[string]dockerapi.ContainerNetwork{}},
	}
	assert.Nil(t, dd.updateContainerInfo(cont))

	snap := dd.Snapshot()
	assert.Equal(t, 1, snap.RecordCount)
	assert.Equal(t, RecordKindCNAME, snap.Records[0].Kind)
	assert.Equal(t, "tunnel.example.com", snap.Records[0].Target)
}
