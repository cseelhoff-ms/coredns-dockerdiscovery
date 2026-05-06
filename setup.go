package dockerdiscovery

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	dockerapi "github.com/fsouza/go-dockerclient"

	"github.com/coredns/caddy"
)

const defaultDockerEndpoint = "unix:///var/run/docker.sock"

func init() {
	caddy.RegisterPlugin("docker", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

// createPlugin parses a single `docker` block.
//
// Supported directives (full set):
//
//	docker [DOCKER_ENDPOINT] {
//	    traefik_cname    HOSTNAME      # CNAME target for Traefik FQDNs
//	    host_ip          IP            # LAN-facing host IP for `host` label
//	    ttl              SECONDS
//	    cf_token         TOKEN
//	    cf_email         EMAIL
//	    cf_key           KEY
//	    cf_tunnel_id     UUID
//	    cf_account_id    ID
//	    cf_tunnel_target URL           # backend service URL pushed for every Traefik FQDN
//	    cf_exclude       a.com,b.com   # comma-separated FQDNs to skip from tunnel sync
//	    inventory        ADDR [PATH]
//	}
func createPlugin(c *caddy.Controller) (*DockerDiscovery, error) {
	dd := NewDockerDiscovery(defaultDockerEndpoint)

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 1 && args[0] != "" {
			dd.dockerEndpoint = args[0]
		}
		if len(args) > 1 {
			return dd, c.ArgErr()
		}

		for c.NextBlock() {
			value := c.Val()
			switch value {
			case "traefik_cname":
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.traefikCNAME = c.Val()
				dd.traefikResolver = NewTraefikLabelResolver()

			case "host_ip":
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				ip := net.ParseIP(c.Val())
				if ip == nil {
					return dd, c.Errf("invalid IP for host_ip: '%s'", c.Val())
				}
				dd.hostIP = ip
				dd.hostResolver = &LabelResolver{hostLabel: "coredns.dockerdiscovery.host"}

			case "ttl":
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				ttl, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return dd, err
				}
				if ttl > 0 {
					dd.ttl = uint32(ttl)
				}

			case "cf_token":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.cloudflareConfig.APIToken = c.Val()

			case "cf_email":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.cloudflareConfig.APIEmail = c.Val()

			case "cf_key":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.cloudflareConfig.APIKey = c.Val()

			case "cf_exclude":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				for _, d := range strings.Split(c.Val(), ",") {
					d = strings.TrimSpace(d)
					if d != "" {
						dd.cloudflareConfig.ExcludeDomains[d] = true
					}
				}

			case "cf_tunnel_id":
				if dd.tunnelConfig == nil {
					dd.tunnelConfig = &TunnelConfig{}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.tunnelConfig.TunnelID = c.Val()

			case "cf_account_id":
				if dd.tunnelConfig == nil {
					dd.tunnelConfig = &TunnelConfig{}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.tunnelConfig.AccountID = c.Val()

			case "cf_tunnel_target":
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.cfTunnelTarget = c.Val()

			case "inventory":
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.inventoryAddr = c.Val()
				if c.NextArg() && c.Val() != "" {
					dd.inventoryPath = c.Val()
				}

			default:
				return dd, c.Errf("unknown property: '%s'", c.Val())
			}
		}
	}

	// Cloudflare Tunnel initialization. Tunnel sync is the only Cloudflare-
	// side feature this plugin supports; no DNS records are created in
	// Cloudflare. Public DNS for tunnel hostnames is handled separately.
	if dd.tunnelConfig != nil {
		hasTunnelID := dd.tunnelConfig.TunnelID != ""
		hasAccountID := dd.tunnelConfig.AccountID != ""

		if hasTunnelID && hasAccountID {
			if dd.cloudflareConfig == nil {
				return dd, fmt.Errorf("tunnel: cf_tunnel_id requires cf_token (or cf_key + cf_email)")
			}
			hasCredentials := dd.cloudflareConfig.APIToken != "" || (dd.cloudflareConfig.APIKey != "" && dd.cloudflareConfig.APIEmail != "")
			if !hasCredentials {
				return dd, fmt.Errorf("tunnel: cf_tunnel_id requires cf_token (or cf_key + cf_email)")
			}
			if dd.cfTunnelTarget == "" {
				return dd, fmt.Errorf("tunnel: cf_tunnel_target is required when cf_tunnel_id is set")
			}

			// If the operator didn't pick a CNAME target, default to the
			// tunnel's own cfargotunnel.com hostname so LAN clients still
			// reach the tunnel.
			if dd.traefikCNAME == "" {
				dd.traefikCNAME = fmt.Sprintf("%s.cfargotunnel.com", dd.tunnelConfig.TunnelID)
				dd.traefikResolver = NewTraefikLabelResolver()
			}

			tunnelSyncer, err := NewTunnelSyncer(dd.tunnelConfig, dd.cloudflareConfig)
			if err != nil {
				return dd, err
			}
			dd.tunnelSyncer = tunnelSyncer
			log.Printf("[docker] Cloudflare Tunnel syncer enabled for tunnel %s (target=%s)", dd.tunnelConfig.TunnelID, dd.cfTunnelTarget)
		} else if hasTunnelID || hasAccountID {
			var missing []string
			if !hasTunnelID {
				missing = append(missing, "cf_tunnel_id")
			}
			if !hasAccountID {
				missing = append(missing, "cf_account_id")
			}
			return dd, fmt.Errorf("tunnel: incomplete configuration, missing: %s", strings.Join(missing, ", "))
		}
	}

	dockerClient, err := dockerapi.NewClient(dd.dockerEndpoint)
	if err != nil {
		return dd, err
	}
	dd.dockerClient = dockerClient
	go func() {
		if err := dd.start(); err != nil {
			log.Printf("[docker] FATAL: plugin start() failed: %s", err)
		}
	}()
	return dd, nil
}

func setup(c *caddy.Controller) error {
	dd, err := createPlugin(c)
	if err != nil {
		return err
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		dd.Next = next
		return dd
	})

	if dd.inventoryAddr != "" {
		dd.inventoryServer = NewInventoryServer(dd.inventoryAddr, dd.inventoryPath, dd)
		c.OnStartup(func() error {
			return dd.inventoryServer.Start()
		})
		c.OnShutdown(func() error {
			return dd.inventoryServer.Stop()
		})
	}

	return nil
}
