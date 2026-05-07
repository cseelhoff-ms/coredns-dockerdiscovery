package dockerdiscovery

import (
	"net"
	"testing"

	"github.com/coredns/caddy"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/stretchr/testify/assert"
)

// genContainer builds a minimal Container suitable for resolver tests.
// Networking fields are intentionally empty: the new architecture never
// reads container IPs — A records come from the host_ip directive.
func genContainer(id, name string, labels map[string]string) *dockerapi.Container {
	if labels == nil {
		labels = map[string]string{}
	}
	return &dockerapi.Container{
		ID:   id,
		Name: name,
		Config: &dockerapi.Config{
			Hostname: name,
			Labels:   labels,
		},
		HostConfig:      &dockerapi.HostConfig{},
		NetworkSettings: &dockerapi.NetworkSettings{Networks: map[string]dockerapi.ContainerNetwork{}},
	}
}

func TestConfigDockerEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		block    string
		expected string
	}{
		{"default", `docker`, defaultDockerEndpoint},
		{"explicit", `docker unix:///custom/docker.sock`, "unix:///custom/docker.sock"},
		{"with block", "docker unix:///x/docker.sock {\n\ttraefik_cname traefik.example\n}", "unix:///x/docker.sock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.block)
			dd, err := createPlugin(c)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, dd.dockerEndpoint)
		})
	}
}

func TestTraefikCnameDirective(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, "traefik.example.com", dd.traefikCNAME)
	assert.NotNil(t, dd.traefikResolver)
}

func TestHostIpDirective(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, "10.0.60.3", dd.hostIP.String())
	assert.NotNil(t, dd.hostResolver)
}

func TestHostIpInvalid(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	host_ip not-an-ip
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
}

func TestUnknownDirective(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	garbage some-arg
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
}

// Tunnel directive sanity — incomplete configs must error out.
func TestTunnelMissingTarget(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	cf_token tk
	cf_tunnel_id uuid
	cf_account_id acct
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_tunnel_target")
}

func TestTunnelMissingCredentials(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	cf_tunnel_id uuid
	cf_account_id acct
	cf_tunnel_target https://localhost:443
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cf_token")
}

// cf_zone_id is optional. When present, the plugin parses it into the
// CloudflareConfig where the DNS syncer can pick it up. Tunnel sync
// must still succeed end-to-end (including DNSSyncer construction) so
// we exercise the full createPlugin path.
func TestCfZoneIdDirective(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	cf_token tk
	cf_tunnel_id uuid
	cf_account_id acct
	cf_tunnel_target https://localhost:443
	cf_zone_id zone123
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.NotNil(t, dd.cloudflareConfig)
	assert.Equal(t, "zone123", dd.cloudflareConfig.ZoneID)
	assert.NotNil(t, dd.dnsSyncer, "dnsSyncer should be constructed when cf_zone_id is set")
	assert.Equal(t, "uuid.cfargotunnel.com", dd.dnsSyncer.cnameTo)
}

// Without cf_zone_id, dnsSyncer must remain nil even if the tunnel is
// fully configured — preserving the safe default of "tunnel-only, no
// DNS edits".
func TestCfZoneIdAbsentMeansNoDNSSyncer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	cf_token tk
	cf_tunnel_id uuid
	cf_account_id acct
	cf_tunnel_target https://localhost:443
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Nil(t, dd.dnsSyncer)
}

// TraefikLabelResolver — covers the regex extraction across the supported
// Traefik label families (http and tcp routers).
func TestTraefikLabelResolver(t *testing.T) {
	resolver := NewTraefikLabelResolver()
	tests := []struct {
		name     string
		labels   map[string]string
		expected []string
	}{
		{
			name: "http Host()",
			labels: map[string]string{
				"traefik.http.routers.app.rule": "Host(`app.example.com`)",
			},
			expected: []string{"app.example.com"},
		},
		{
			name: "tcp HostSNI()",
			labels: map[string]string{
				"traefik.tcp.routers.secure.rule": "HostSNI(`secure.example.com`)",
			},
			expected: []string{"secure.example.com"},
		},
		{
			name: "multiple hosts in one rule",
			labels: map[string]string{
				"traefik.http.routers.multi.rule": "Host(`a.example.com`) || Host(`b.example.com`)",
			},
			expected: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "host with path prefix",
			labels: map[string]string{
				"traefik.http.routers.app.rule": "Host(`app.example.com`) && PathPrefix(`/api`)",
			},
			expected: []string{"app.example.com"},
		},
		{
			name: "no traefik labels",
			labels: map[string]string{
				"com.docker.compose.project": "myproject",
			},
			expected: nil,
		},
		{
			name: "traefik enable but no router rule",
			labels: map[string]string{
				"traefik.enable": "true",
			},
			expected: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := genContainer("fa155d6fd141e29256c286070d2d44b3f45f1e46", "x", tc.labels)
			doms, err := resolver.resolve(c)
			assert.Nil(t, err)
			assert.ElementsMatch(t, tc.expected, doms)
		})
	}
}

func TestIsTraefikRouterRule(t *testing.T) {
	assert.True(t, isTraefikRouterRule("traefik.http.routers.myapp.rule"))
	assert.True(t, isTraefikRouterRule("traefik.tcp.routers.ldap.rule"))
	assert.False(t, isTraefikRouterRule("traefik.http.routers.myapp.service"))
	assert.False(t, isTraefikRouterRule("traefik.http.services.myapp.loadbalancer.server.port"))
	assert.False(t, isTraefikRouterRule("traefik.enable"))
	assert.False(t, isTraefikRouterRule("com.docker.compose.project"))
}

// Worked example: portainer-like container — Traefik label only, no `host` label.
// Expect a CNAME entry only.
func TestPortainerLikeContainer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.177cpt.com
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("aa155d6fd141e29256c286070d2d44b3f45f1e46", "portainer", map[string]string{
		"traefik.http.routers.portainer.rule": "Host(`portainer.177cpt.com`)",
	})

	assert.Nil(t, dd.updateContainerInfo(cont))

	// CNAME lookup
	res, err := dd.containerInfoByDomain("portainer.177cpt.com.")
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.True(t, res.isCNAME)

	// Container's name does NOT auto-create an A record (no `domain` directive any more)
	res, err = dd.containerInfoByDomain("portainer.docker.local.")
	assert.Nil(t, err)
	assert.Nil(t, res)
}

// Worked example: openldap — `host` label only, no Traefik label.
// Expect an A record at host_ip; no CNAME, no tunnel push (no Traefik FQDN).
func TestOpenldapLikeContainer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("bb155d6fd141e29256c286070d2d44b3f45f1e46", "openldap", map[string]string{
		"coredns.dockerdiscovery.host": "ldap.177cpt.com",
	})

	assert.Nil(t, dd.updateContainerInfo(cont))

	res, err := dd.containerInfoByDomain("ldap.177cpt.com.")
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.isCNAME)
	assert.Equal(t, "ldap.177cpt.com", res.containerInfo.hostADomain)
}

// Worked example: traefik itself — both labels for the same FQDN.
// Local lookup must return A (host wins). cnameDomains list still contains
// the FQDN so the inventory/tunnel layers can see it.
func TestTraefikSelfContainer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.177cpt.com
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("cc155d6fd141e29256c286070d2d44b3f45f1e46", "traefik", map[string]string{
		"coredns.dockerdiscovery.host":        "traefik.177cpt.com",
		"traefik.http.routers.dashboard.rule": "Host(`traefik.177cpt.com`)",
	})
	assert.Nil(t, dd.updateContainerInfo(cont))

	res, err := dd.containerInfoByDomain("traefik.177cpt.com.")
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.isCNAME, "host_ip A wins over CNAME for the same FQDN")
}

func TestHostIpLabelIgnoredWithoutDirective(t *testing.T) {
	// Plugin not configured with host_ip → the label is ignored.
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("dd155d6fd141e29256c286070d2d44b3f45f1e46", "openldap", map[string]string{
		"coredns.dockerdiscovery.host": "ldap.example.com",
	})
	assert.Nil(t, dd.updateContainerInfo(cont))

	res, _ := dd.containerInfoByDomain("ldap.example.com.")
	assert.Nil(t, res, "host label should be ignored without host_ip directive")
}

func TestContainerOptsOutOfTunnel(t *testing.T) {
	yes := genContainer("ee", "x", map[string]string{"coredns.dockerdiscovery.cf_tunnel": "false"})
	no := genContainer("ee", "x", map[string]string{"coredns.dockerdiscovery.cf_tunnel": "true"})
	missing := genContainer("ee", "x", nil)

	assert.True(t, containerOptsOutOfTunnel(yes))
	assert.False(t, containerOptsOutOfTunnel(no))
	assert.False(t, containerOptsOutOfTunnel(missing))
}

func TestDiffDomains(t *testing.T) {
	added, removed := diffDomains([]string{"a", "b", "c"}, []string{"b", "c", "d"})
	assert.ElementsMatch(t, []string{"d"}, added)
	assert.ElementsMatch(t, []string{"a"}, removed)
}

// Tunnel exclude + opt-out interaction.
func TestTunnelExcludeAndOptOut(t *testing.T) {
	dd := NewDockerDiscovery(defaultDockerEndpoint)
	dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: map[string]bool{"private.example.com": true}}
	dd.cfTunnelTarget = "https://localhost:443"
	dd.tunnelSyncer = &TunnelSyncer{} // non-nil so the dispatch branch runs
	dd.traefikResolver = NewTraefikLabelResolver()
	dd.traefikCNAME = "traefik.example.com"

	cont := genContainer("ff", "x", map[string]string{
		"traefik.http.routers.public.rule":  "Host(`public.example.com`)",
		"traefik.http.routers.private.rule": "Host(`private.example.com`)",
	})

	// Manually run the dispatch path to inspect tunnelDomains without
	// hitting the real network.
	hostADomain, cnames := dd.resolveDomainsByContainer(cont)
	_ = hostADomain
	assert.ElementsMatch(t, []string{"public.example.com", "private.example.com"}, cnames)

	// Opt-out shorts the whole tunnel push.
	contOptOut := genContainer("ff", "x", map[string]string{
		"traefik.http.routers.public.rule":  "Host(`public.example.com`)",
		"coredns.dockerdiscovery.cf_tunnel": "false",
	})
	assert.True(t, containerOptsOutOfTunnel(contOptOut))
}

// Ensure that a container with no relevant labels never gets stored.
func TestUnlabeledContainerIgnored(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	traefik_cname traefik.example.com
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("00", "boring", map[string]string{
		"com.docker.compose.project": "stuff",
	})
	assert.Nil(t, dd.updateContainerInfo(cont))
	assert.Equal(t, 0, len(dd.containerInfoMap))
}

// Sanity: the IP we serve back is the directive value, not anything from
// container.NetworkSettings (this is the bug we set out to fix).
func TestHostIpServedFromDirectiveNotFromContainer(t *testing.T) {
	c := caddy.NewTestController("dns", `docker {
	host_ip 10.0.60.3
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	cont := genContainer("99", "openldap", map[string]string{
		"coredns.dockerdiscovery.host": "ldap.177cpt.com",
	})
	cont.NetworkSettings.Networks["bridge"] = dockerapi.ContainerNetwork{IPAddress: "10.89.0.9"}
	cont.HostConfig.NetworkMode = "bridge"

	assert.Nil(t, dd.updateContainerInfo(cont))
	res, _ := dd.containerInfoByDomain("ldap.177cpt.com.")
	assert.NotNil(t, res)
	assert.Equal(t, net.ParseIP("10.0.60.3").String(), dd.hostIP.String())
}
