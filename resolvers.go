package dockerdiscovery

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	dockerapi "github.com/fsouza/go-dockerclient"
)

func normalizeContainerName(container *dockerapi.Container) string {
	return strings.TrimLeft(container.Name, "/")
}

// resolvers implements ContainerDomainResolver

type SubDomainContainerNameResolver struct {
	domain string
}

func (resolver SubDomainContainerNameResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string
	domains = append(domains, fmt.Sprintf("%s.%s", normalizeContainerName(container), resolver.domain))
	return domains, nil
}

type SubDomainHostResolver struct {
	domain string
}

func (resolver SubDomainHostResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string
	domains = append(domains, fmt.Sprintf("%s.%s", container.Config.Hostname, resolver.domain))
	return domains, nil
}

type LabelResolver struct {
	hostLabel string
}

func (resolver LabelResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string

	for label, value := range container.Config.Labels {
		if label == resolver.hostLabel {
			domains = append(domains, value)
			break
		}
	}

	return domains, nil
}

// ComposeResolver sets names based on compose labels
type ComposeResolver struct {
	domain string
}

func (resolver ComposeResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string

	project, pok := container.Config.Labels["com.docker.compose.project"]
	service, sok := container.Config.Labels["com.docker.compose.service"]
	if !pok || !sok {
		return domains, nil
	}

	domain := fmt.Sprintf("%s.%s.%s", service, project, resolver.domain)
	domains = append(domains, domain)

	log.Printf("[docker] Found compose domain for container %s: %s", container.ID[:12], domain)
	return domains, nil
}

type NetworkAliasesResolver struct {
	network string
}

func (resolver NetworkAliasesResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string

	if resolver.network != "" {
		network, ok := container.NetworkSettings.Networks[resolver.network]
		if ok {
			domains = append(domains, network.Aliases...)
		}
	} else {
		for _, network := range container.NetworkSettings.Networks {
			domains = append(domains, network.Aliases...)
		}
	}

	return domains, nil
}

// TraefikLabelResolver extracts hostnames from Traefik Docker labels.
// It looks for labels matching traefik.http.routers.*.rule and extracts
// Host() and HostSNI() values, similar to how coredns-traefik parses
// Traefik's API response.
type TraefikLabelResolver struct {
	hostMatcher *regexp.Regexp
}

// traefikHostMatcher matches Host(`example.com`) and HostSNI(`example.com`) patterns
var traefikHostMatcher = regexp.MustCompile("Host(?:SNI)?\\(`([^`]+)`\\)")

func NewTraefikLabelResolver() *TraefikLabelResolver {
	return &TraefikLabelResolver{
		hostMatcher: traefikHostMatcher,
	}
}

func (resolver TraefikLabelResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string
	seen := make(map[string]bool)

	for label, value := range container.Config.Labels {
		if !isTraefikRouterRule(label) {
			continue
		}

		matches := resolver.hostMatcher.FindAllStringSubmatch(value, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				host := strings.ToLower(match[1])
				if !seen[host] {
					seen[host] = true
					domains = append(domains, host)
					log.Printf("[docker] Found traefik host for container %s: %s", container.ID[:12], host)
				}
			}
		}
	}

	return domains, nil
}

// isTraefikRouterRule checks if a Docker label is a Traefik HTTP router rule.
// Matches labels like: traefik.http.routers.<name>.rule
func isTraefikRouterRule(label string) bool {
	return strings.HasPrefix(label, "traefik.http.routers.") && strings.HasSuffix(label, ".rule")
}
