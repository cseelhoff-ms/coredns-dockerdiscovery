package dockerdiscovery

import (
	"fmt"
	"net"
	"testing"

	"github.com/coredns/caddy"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/stretchr/testify/assert"
)

type setupDockerDiscoveryTestCase struct {
	configBlock            string
	expectedDockerEndpoint string
	expectedDockerDomain   string
}

func TestConfigDockerDiscovery(t *testing.T) {
	testCases := []setupDockerDiscoveryTestCase{
		setupDockerDiscoveryTestCase{
			"docker",
			defaultDockerEndpoint,
			defaultDockerDomain,
		},
		setupDockerDiscoveryTestCase{
			"docker unix:///var/run/docker.sock.backup",
			"unix:///var/run/docker.sock.backup",
			defaultDockerDomain,
		},
		setupDockerDiscoveryTestCase{
			`docker {
	hostname_domain example.org.
}`,
			defaultDockerEndpoint,
			"example.org.",
		},
		setupDockerDiscoveryTestCase{
			`docker unix:///home/user/docker.sock {
	hostname_domain home.example.org.
}`,
			"unix:///home/user/docker.sock",
			"home.example.org.",
		},
	}

	for _, tc := range testCases {
		c := caddy.NewTestController("dns", tc.configBlock)
		dd, err := createPlugin(c)
		assert.Nil(t, err)
		assert.Equal(t, dd.dockerEndpoint, tc.expectedDockerEndpoint)
	}
}

func TestSetupDockerDiscovery(t *testing.T) {
	networkName := "my_project_network_name"
	c := caddy.NewTestController("dns", fmt.Sprintf(`docker unix:///home/user/docker.sock {
	compose_domain compose.loc
	hostname_domain home.example.org
	domain docker.loc
	network_aliases %s
}`, networkName))
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	var address = net.ParseIP("192.11.0.1")
	var containers = []*dockerapi.Container{
		genContainerDefn(address.String(), networkName, ""),
		genContainerDefn("", networkName, address.String()),
		genContainerDefn(address.String(), networkName, address.String()),
	}

	for i := range containers {
		container := containers[i]
		e := dd.updateContainerInfo(container)
		assert.Nil(t, e)

		_ = ipOk(t, dd, "myproject.loc.", address)
		ipNotOk(t, dd, "wrong.loc.")
		_ = ipOk(t, dd, "nginx.home.example.org.", address)
		ipNotOk(t, dd, "wrong.home.example.org.")
		_ = ipOk(t, dd, "label-host.loc.", address)
		_ = ipOk(t, dd, "cservice.cproject.compose.loc.", address)

		containerInfo := ipOk(t, dd, fmt.Sprintf("%s.docker.loc.", container.Name), address)
		assert.Equal(t, container.Name, containerInfo.container.Name)
	}
}

func TestMultipleNetworksDockerDiscovery(t *testing.T) {
	networkName := "my_project_network_name"
	address := net.ParseIP("192.11.0.1")
	expectedAddress := net.ParseIP("9.14.1.30")
	expectedNet := "inquisition"

	c := caddy.NewTestController("dns", fmt.Sprintf(`docker unix:///home/user/docker.sock {
	compose_domain compose.loc
	hostname_domain home.example.org
	domain docker.loc
	network_aliases %s
}`, networkName))
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	// generate a configuration; tweak to add a second network
	container := genContainerDefn("", networkName, address.String())
	container.NetworkSettings.Networks[expectedNet] = dockerapi.ContainerNetwork{
		Aliases:   []string{"myproject.loc"},
		IPAddress: expectedAddress.String(),
	}

	err = dd.updateContainerInfo(container)
	assert.Nil(t, err)

	// without label, we expect the "NetworkMode" address to prevail
	_ = ipOk(t, dd, "label-host.loc.", address)

	// now, update for the label and try this again

	container.Config.Labels["coredns.dockerdiscovery.network"] = expectedNet
	err = dd.updateContainerInfo(container)
	assert.Nil(t, err)

	_ = ipOk(t, dd, "label-host.loc.", expectedAddress)

	return
}

// simple check
func ipOk(t *testing.T, dd *DockerDiscovery, domain string, address net.IP) *ContainerInfo {

	result, e := dd.containerInfoByDomain(domain)
	assert.Nil(t, e)
	assert.NotNil(t, result)

	// check as strings here, for us poor mortals
	assert.Equal(t, address.String(), result.containerInfo.address.String())

	return result.containerInfo
}

// simple check
func ipNotOk(t *testing.T, dd *DockerDiscovery, domain string) {

	result, e := dd.containerInfoByDomain(domain)
	assert.Nil(t, e)
	assert.Nil(t, result)

	return
}

// string, not net.IP, as 1) we're test, 2) the underling struct is a string,
// and 3) we may want something odd here
func genContainerDefn(nsAddress string, netMode string, netAddress string) *dockerapi.Container {
	container := &dockerapi.Container{
		ID:   "fa155d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "evil_ptolemy",
		Config: &dockerapi.Config{
			Hostname: "nginx",
			Labels: map[string]string{
				"coredns.dockerdiscovery.host": "label-host.loc",
				"com.docker.compose.project":   "cproject",
				"com.docker.compose.service":   "cservice",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: netMode,
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			IPAddress: nsAddress,
			Networks: map[string]dockerapi.ContainerNetwork{
				netMode: dockerapi.ContainerNetwork{
					Aliases:   []string{"myproject.loc"},
					IPAddress: netAddress,
				},
			},
		},
	}

	return container
}

func TestTraefikLabelResolver(t *testing.T) {
	resolver := NewTraefikLabelResolver()

	tests := []struct {
		name     string
		labels   map[string]string
		expected []string
	}{
		{
			name: "simple host rule",
			labels: map[string]string{
				"traefik.http.routers.app.rule": "Host(`app.example.com`)",
			},
			expected: []string{"app.example.com"},
		},
		{
			name: "HostSNI rule",
			labels: map[string]string{
				"traefik.http.routers.secure.rule": "HostSNI(`secure.example.com`)",
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
			name: "multiple routers",
			labels: map[string]string{
				"traefik.http.routers.web.rule":                      "Host(`web.example.com`)",
				"traefik.http.routers.api.rule":                      "Host(`api.example.com`)",
				"traefik.http.services.web.loadbalancer.server.port": "8080",
			},
			expected: []string{"web.example.com", "api.example.com"},
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
			container := &dockerapi.Container{
				ID: "fa155d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
				Config: &dockerapi.Config{
					Labels: tc.labels,
				},
			}
			domains, err := resolver.resolve(container)
			assert.Nil(t, err)
			assert.ElementsMatch(t, tc.expected, domains)
		})
	}
}

func TestTraefikCNAMEConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, "traefik.homelab.net", dd.traefikCNAME)
	assert.Nil(t, dd.traefikA)
	assert.NotNil(t, dd.traefikResolver)
}

func TestTraefikAConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_a 10.0.0.2
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, "", dd.traefikCNAME)
	assert.Equal(t, "10.0.0.2", dd.traefikA.String())
	assert.NotNil(t, dd.traefikResolver)
}

func TestTraefikMutuallyExclusive(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	traefik_cname traefik.homelab.net
	traefik_a 10.0.0.2
}`)
	_, err := createPlugin(c)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestTraefikCNAMEDomainResolution(t *testing.T) {
	networkName := "my_project_network_name"
	c := caddy.NewTestController("dns", fmt.Sprintf(`docker unix:///home/user/docker.sock {
	domain docker.loc
	network_aliases %s
	traefik_cname traefik.homelab.net
}`, networkName))
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	address := net.ParseIP("192.11.0.1")
	container := &dockerapi.Container{
		ID:   "ab155d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "my_app",
		Config: &dockerapi.Config{
			Hostname: "myapp",
			Labels: map[string]string{
				"traefik.enable":                "true",
				"traefik.http.routers.app.rule": "Host(`app.homelab.net`)",
				"coredns.dockerdiscovery.host":  "",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: networkName,
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			Networks: map[string]dockerapi.ContainerNetwork{
				networkName: {
					Aliases:   []string{"myapp.loc"},
					IPAddress: address.String(),
				},
			},
		},
	}

	e := dd.updateContainerInfo(container)
	assert.Nil(t, e)

	// Traefik-label domain should be found as a CNAME domain
	result, err := dd.containerInfoByDomain("app.homelab.net.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.isCNAME)

	// Regular domains should still resolve as A records
	result, err = dd.containerInfoByDomain("my_app.docker.loc.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.isCNAME)
	assert.Equal(t, address.String(), result.containerInfo.address.String())
}

func TestIsTraefikRouterRule(t *testing.T) {
	assert.True(t, isTraefikRouterRule("traefik.http.routers.myapp.rule"))
	assert.True(t, isTraefikRouterRule("traefik.http.routers.my-app-web.rule"))
	assert.False(t, isTraefikRouterRule("traefik.http.routers.myapp.service"))
	assert.False(t, isTraefikRouterRule("traefik.http.services.myapp.loadbalancer.server.port"))
	assert.False(t, isTraefikRouterRule("traefik.enable"))
	assert.False(t, isTraefikRouterRule("com.docker.compose.project"))
}

func TestCnameTargetConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	cname_target infra-1.homelab.local
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	assert.Equal(t, "infra-1.homelab.local", dd.traefikCNAME)
	assert.Equal(t, 1, len(dd.cnameResolvers))
}

func TestCnameTargetDomainResolution(t *testing.T) {
	networkName := "my_network"
	c := caddy.NewTestController("dns", fmt.Sprintf(`docker unix:///home/user/docker.sock {
	domain docker.loc
	network_aliases %s
	cname_target infra-1.homelab.local
}`, networkName))
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	address := net.ParseIP("192.11.0.1")
	container := &dockerapi.Container{
		ID:   "cd255d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "openldap",
		Config: &dockerapi.Config{
			Hostname: "ldap",
			Labels: map[string]string{
				"coredns.dockerdiscovery.hostname": "ldap.homelab.local",
				"coredns.dockerdiscovery.host":     "",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: networkName,
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			Networks: map[string]dockerapi.ContainerNetwork{
				networkName: {
					Aliases:   []string{"openldap.loc"},
					IPAddress: address.String(),
				},
			},
		},
	}

	e := dd.updateContainerInfo(container)
	assert.Nil(t, e)

	// coredns.dockerdiscovery.hostname label should resolve as CNAME
	result, err := dd.containerInfoByDomain("ldap.homelab.local.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.isCNAME)

	// Regular domain should still resolve as A record
	result, err = dd.containerInfoByDomain("openldap.docker.loc.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.isCNAME)
	assert.Equal(t, address.String(), result.containerInfo.address.String())
}

func TestCnameTargetWithTraefikCname(t *testing.T) {
	// Both cname_target and traefik_cname can coexist
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	cname_target infra-1.homelab.local
	traefik_cname infra-1.homelab.local
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)
	// traefik_cname overwrites — last writer wins, both set same value
	assert.Equal(t, "infra-1.homelab.local", dd.traefikCNAME)
	assert.NotNil(t, dd.traefikResolver)
	assert.Equal(t, 1, len(dd.cnameResolvers))
}

func TestCnameTargetWithoutLabel(t *testing.T) {
	// Container without the hostname label should not produce CNAME records
	c := caddy.NewTestController("dns", `docker unix:///home/user/docker.sock {
	cname_target infra-1.homelab.local
	domain docker.loc
}`)
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	container := &dockerapi.Container{
		ID:   "ef355d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "plain_container",
		Config: &dockerapi.Config{
			Hostname: "plain",
			Labels: map[string]string{
				"coredns.dockerdiscovery.host": "plain.docker.loc",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: "bridge",
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			IPAddress: "172.17.0.5",
			Networks:  map[string]dockerapi.ContainerNetwork{},
		},
	}

	e := dd.updateContainerInfo(container)
	assert.Nil(t, e)

	// Should resolve as A record via the label resolver, not CNAME
	result, err := dd.containerInfoByDomain("plain.docker.loc.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.isCNAME)

	// No CNAME domain should exist
	result, err = dd.containerInfoByDomain("ldap.homelab.local.")
	assert.Nil(t, err)
	assert.Nil(t, result)
}

func TestCnamePriorityOverARecord(t *testing.T) {
	// When DOCKER_DOMAIN matches the real domain, container names can
	// create A records that collide with CNAME domains from traefik labels.
	// Example: container_name "traefik" + domain "177cpt.com" creates
	// traefik.177cpt.com -> A -> container IP, which would shadow the
	// CNAME from traefik_cname. CNAMEs should always win.
	networkName := "proxy"
	c := caddy.NewTestController("dns", fmt.Sprintf(`docker unix:///home/user/docker.sock {
	domain 177cpt.com
	network_aliases %s
	traefik_cname infravm.177cpt.com
}`, networkName))
	dd, err := createPlugin(c)
	assert.Nil(t, err)

	traefikAddress := net.ParseIP("172.18.0.5")

	// Container named "traefik" — the domain resolver will create
	// traefik.177cpt.com -> A -> 172.18.0.5
	traefikContainer := &dockerapi.Container{
		ID:   "aa155d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "traefik",
		Config: &dockerapi.Config{
			Hostname: "traefik",
			Labels: map[string]string{
				"coredns.dockerdiscovery.host": "",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: networkName,
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			Networks: map[string]dockerapi.ContainerNetwork{
				networkName: {
					IPAddress: traefikAddress.String(),
				},
			},
		},
	}

	whoamiAddress := net.ParseIP("172.18.0.10")

	// Container with traefik label Host(`traefik.177cpt.com`) — creates
	// a CNAME domain for traefik.177cpt.com
	whoamiContainer := &dockerapi.Container{
		ID:   "bb255d6fd141e29256c286070d2d44b3f45f1e46822578f1e7d66c1e7981e6c7",
		Name: "whoami",
		Config: &dockerapi.Config{
			Hostname: "whoami",
			Labels: map[string]string{
				"traefik.enable":                 "true",
				"traefik.http.routers.dash.rule": "Host(`traefik.177cpt.com`)",
				"coredns.dockerdiscovery.host":   "",
			},
		},
		HostConfig: &dockerapi.HostConfig{
			NetworkMode: networkName,
		},
		NetworkSettings: &dockerapi.NetworkSettings{
			Networks: map[string]dockerapi.ContainerNetwork{
				networkName: {
					IPAddress: whoamiAddress.String(),
				},
			},
		},
	}

	e := dd.updateContainerInfo(traefikContainer)
	assert.Nil(t, e)
	e = dd.updateContainerInfo(whoamiContainer)
	assert.Nil(t, e)

	// traefik.177cpt.com should resolve as CNAME (from traefik label),
	// NOT as A record (from container name + domain)
	result, err := dd.containerInfoByDomain("traefik.177cpt.com.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.isCNAME, "traefik.177cpt.com should be CNAME, not A record")

	// whoami.177cpt.com should be an A record (from container name + domain)
	result, err = dd.containerInfoByDomain("whoami.177cpt.com.")
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.isCNAME)
}

func TestGetTraefikServicePort(t *testing.T) {
	// Standard Traefik service port label
	labels := map[string]string{
		"traefik.http.services.web.loadbalancer.server.port": "8080",
	}
	assert.Equal(t, "8080", getTraefikServicePort(labels))

	// No matching label
	labels = map[string]string{
		"traefik.http.routers.web.rule": "Host(`web.example.com`)",
	}
	assert.Equal(t, "", getTraefikServicePort(labels))

	// Empty labels
	assert.Equal(t, "", getTraefikServicePort(map[string]string{}))

	// Empty port value
	labels = map[string]string{
		"traefik.http.services.web.loadbalancer.server.port": "",
	}
	assert.Equal(t, "", getTraefikServicePort(labels))
}
