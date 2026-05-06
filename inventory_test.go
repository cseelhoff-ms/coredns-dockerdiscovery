package dockerdiscovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	domain docker.loc
	inventory 127.0.0.1:18181
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.1:18181", dd.inventoryAddr)
		assert.Equal(t, "", dd.inventoryPath)
	})

	t.Run("addr + custom path", func(t *testing.T) {
		c := caddy.NewTestController("dns", `docker {
	domain docker.loc
	inventory 127.0.0.1:18182 /things
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.1:18182", dd.inventoryAddr)
		assert.Equal(t, "/things", dd.inventoryPath)
	})

	t.Run("empty arg is silently skipped", func(t *testing.T) {
		c := caddy.NewTestController("dns", `docker {
	domain docker.loc
	inventory ""
}`)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, "", dd.inventoryAddr)
	})
}

func TestInventorySnapshot(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	domain docker.loc
	traefik_cname host.example.com
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	addr := net.ParseIP("10.0.0.42")
	container := genContainerDefn(addr.String(), "bridge", addr.String())
	// Add a traefik label so a CNAME entry appears.
	container.Config.Labels["traefik.http.routers.app.rule"] = "Host(`app.example.com`)"

	assert.Nil(t, dd.updateContainerInfo(container))

	snap := dd.Snapshot()
	assert.Equal(t, "docker", snap.Plugin)
	assert.Equal(t, 1, snap.ContainerCount)
	assert.Greater(t, snap.RecordCount, 0)

	var sawA, sawCNAME bool
	for _, rec := range snap.Records {
		switch rec.Kind {
		case RecordKindA:
			sawA = true
			assert.Equal(t, addr.String(), rec.Target)
			assert.Equal(t, "docker", rec.Source)
		case RecordKindCNAME:
			sawCNAME = true
			assert.Equal(t, "host.example.com", rec.Target)
			assert.Equal(t, "app.example.com", rec.Domain)
			assert.Equal(t, "docker:cname", rec.Source)
		}
	}
	assert.True(t, sawA, "expected an A record in snapshot")
	assert.True(t, sawCNAME, "expected a CNAME record in snapshot")
}

// Ensure the snapshot is safe to call when nothing has been registered.
func TestInventorySnapshotEmpty(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { domain docker.loc }`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	snap := dd.Snapshot()
	assert.Equal(t, 0, snap.ContainerCount)
	assert.Equal(t, 0, snap.RecordCount)
	assert.Empty(t, snap.Records)
}

func TestInventoryServerJSONAndHTML(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { domain docker.loc }`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	addr := net.ParseIP("10.0.0.7")
	container := genContainerDefn(addr.String(), "bridge", addr.String())
	assert.Nil(t, dd.updateContainerInfo(container))

	// Bind an ephemeral port to avoid conflicts.
	srv := NewInventoryServer("127.0.0.1:0", "", dd)
	assert.Nil(t, srv.Start())
	defer srv.Stop()

	base := "http://" + srv.ln.Addr().String()
	httpc := &http.Client{Timeout: 2 * time.Second}

	// JSON
	resp, err := httpc.Get(base + "/inventory")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var snap InventorySnapshot
	assert.Nil(t, json.NewDecoder(resp.Body).Decode(&snap))
	resp.Body.Close()
	assert.Equal(t, 1, snap.ContainerCount)
	assert.Greater(t, snap.RecordCount, 0)

	// HTML
	resp, err = httpc.Get(base + "/inventory.html")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.True(t, strings.Contains(string(body), "<table"))
	assert.True(t, strings.Contains(string(body), "10.0.0.7"))

	// Health
	resp, err = httpc.Get(base + "/healthz")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// Sanity: bind error surfaces synchronously so misconfigurations don't
// silently leave the endpoint missing.
func TestInventoryServerBindError(t *testing.T) {
	c := caddy.NewTestController("dns", `docker { domain docker.loc }`)
	dd, _ := createPlugin(c)
	first := NewInventoryServer("127.0.0.1:0", "", dd)
	assert.Nil(t, first.Start())
	defer first.Stop()

	// Reuse the exact bound address — second Start should fail.
	second := NewInventoryServer(first.ln.Addr().String(), "", dd)
	err := second.Start()
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "inventory: listen"))
}

// Ensure we cleanly serve no records (and don't panic) when a container
// has only CNAME labels but no resolvable IP.
func TestInventorySnapshotCNAMEOnly(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname tunnel.example.com
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	container := &dockerapi.Container{
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

	assert.Nil(t, dd.updateContainerInfo(container))

	snap := dd.Snapshot()
	if !assert.Equal(t, 1, snap.RecordCount) {
		for _, r := range snap.Records {
			fmt.Println(r)
		}
	}
	assert.Equal(t, RecordKindCNAME, snap.Records[0].Kind)
	assert.Equal(t, "tunnel.example.com", snap.Records[0].Target)
}
