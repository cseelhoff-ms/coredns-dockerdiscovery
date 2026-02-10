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
const defaultDockerDomain = "docker.local"

func init() {
	caddy.RegisterPlugin("docker", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

// TODO(kevinjqiu): add docker endpoint verification
func createPlugin(c *caddy.Controller) (*DockerDiscovery, error) {
	dd := NewDockerDiscovery(defaultDockerEndpoint)
	labelResolver := &LabelResolver{hostLabel: "coredns.dockerdiscovery.host"}
	dd.resolvers = append(dd.resolvers, labelResolver)

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 1 && args[0] != "" {
			dd.dockerEndpoint = args[0]
		}

		if len(args) > 1 {
			return dd, c.ArgErr()
		}

		for c.NextBlock() {
			var value = c.Val()
			switch value {
			case "domain":
				var resolver = &SubDomainContainerNameResolver{
					domain: defaultDockerDomain,
				}
				dd.resolvers = append(dd.resolvers, resolver)
				if !c.NextArg() || c.Val() == "" {
					// Keep default domain
					continue
				}
				resolver.domain = c.Val()
			case "hostname_domain":
				var resolver = &SubDomainHostResolver{
					domain: defaultDockerDomain,
				}
				dd.resolvers = append(dd.resolvers, resolver)
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				resolver.domain = c.Val()
			case "compose_domain":
				var resolver = &ComposeResolver{
					domain: defaultDockerDomain,
				}
				dd.resolvers = append(dd.resolvers, resolver)
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				resolver.domain = c.Val()
			case "network_aliases":
				var resolver = &NetworkAliasesResolver{
					network: "",
				}
				dd.resolvers = append(dd.resolvers, resolver)
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				resolver.network = c.Val()
			case "label":
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				labelResolver.hostLabel = c.Val()
			case "traefik_cname":
				if !c.NextArg() || c.Val() == "" {
					// Skip — TRAEFIK_HOST env var not set
					continue
				}
				if dd.traefikA != nil {
					return dd, c.Err("traefik_cname and traefik_a are mutually exclusive")
				}
				dd.traefikCNAME = c.Val()
				dd.traefikResolver = NewTraefikLabelResolver()
			case "traefik_a":
				if !c.NextArg() {
					return dd, c.ArgErr()
				}
				if dd.traefikCNAME != "" {
					return dd, c.Err("traefik_cname and traefik_a are mutually exclusive")
				}
				ip := net.ParseIP(c.Val())
				if ip == nil {
					return dd, c.Errf("invalid IP address for traefik_a: '%s'", c.Val())
				}
				dd.traefikA = ip
				dd.traefikResolver = NewTraefikLabelResolver()
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
					// Skip — CF_TOKEN env var not set
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
			case "cf_target":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				if !c.NextArg() || c.Val() == "" {
					continue
				}
				dd.cloudflareConfig.TargetDomain = c.Val()
			case "cf_zone":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				args := c.RemainingArgs()
				if len(args) != 2 || args[0] == "" || args[1] == "" {
					// Skip — CF_ZONE_DOMAIN or CF_ZONE_ID not set
					continue
				}
				dd.cloudflareConfig.Zones = append(dd.cloudflareConfig.Zones, CloudflareZone{
					Domain: args[0],
					ZoneID: args[1],
				})
			case "cf_proxied":
				if dd.cloudflareConfig == nil {
					dd.cloudflareConfig = &CloudflareConfig{ExcludeDomains: make(map[string]bool)}
				}
				dd.cloudflareConfig.Proxied = true
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
			default:
				return dd, c.Errf("unknown property: '%s'", c.Val())
			}
		}
	}

	// Cloudflare DNS sync initialization — only if fully configured
	if dd.cloudflareConfig != nil {
		// Check if Cloudflare was actually configured (has credentials + target + zones)
		hasCredentials := dd.cloudflareConfig.APIToken != "" || (dd.cloudflareConfig.APIKey != "" && dd.cloudflareConfig.APIEmail != "")
		hasTarget := dd.cloudflareConfig.TargetDomain != ""
		hasZones := len(dd.cloudflareConfig.Zones) > 0

		if hasCredentials && hasTarget && hasZones {
			// Auto-enable traefik resolver if not already configured
			if dd.traefikResolver == nil {
				dd.traefikCNAME = dd.cloudflareConfig.TargetDomain
				dd.traefikResolver = NewTraefikLabelResolver()
			}

			syncer, err := NewCloudflareSyncer(dd.cloudflareConfig)
			if err != nil {
				return dd, err
			}
			dd.cloudflareSyncer = syncer
		} else if hasCredentials || hasTarget || hasZones {
			// Partially configured — warn about what's missing
			var missing []string
			if !hasCredentials {
				missing = append(missing, "cf_token (or cf_key + cf_email)")
			}
			if !hasTarget {
				missing = append(missing, "cf_target")
			}
			if !hasZones {
				missing = append(missing, "cf_zone")
			}
			return dd, fmt.Errorf("cloudflare: incomplete configuration, missing: %s", strings.Join(missing, ", "))
		}
		// If nothing meaningful was set (all empty from unset env vars), silently skip
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
	return nil
}
