package dockerdiscovery

import (
	"log"
	"regexp"
	"strings"

	dockerapi "github.com/fsouza/go-dockerclient"
)

// normalizeContainerName trims the leading slash that the Docker API
// adds to container names.
func normalizeContainerName(container *dockerapi.Container) string {
	return strings.TrimLeft(container.Name, "/")
}

// LabelResolver returns the value of a single Docker label as a domain.
// Used by the host_ip flow to read `coredns.dockerdiscovery.host`.
type LabelResolver struct {
	hostLabel string
}

func (resolver LabelResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string
	if container.Config == nil {
		return domains, nil
	}
	if value, ok := container.Config.Labels[resolver.hostLabel]; ok && value != "" {
		domains = append(domains, value)
	}
	return domains, nil
}

// TraefikLabelResolver extracts hostnames from Traefik Docker labels.
// It looks for labels matching traefik.http.routers.*.rule and
// traefik.tcp.routers.*.rule, then pulls Host()/HostSNI() values.
type TraefikLabelResolver struct {
	hostMatcher *regexp.Regexp
}

// traefikHostMatcher matches Host(`example.com`) and HostSNI(`example.com`)
var traefikHostMatcher = regexp.MustCompile("Host(?:SNI)?\\(`([^`]+)`\\)")

func NewTraefikLabelResolver() *TraefikLabelResolver {
	return &TraefikLabelResolver{
		hostMatcher: traefikHostMatcher,
	}
}

func (resolver TraefikLabelResolver) resolve(container *dockerapi.Container) ([]string, error) {
	var domains []string
	if container.Config == nil {
		return domains, nil
	}
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
					log.Printf("[docker] Found traefik host for container %s: %s", shortID(container.ID), host)
				}
			}
		}
	}

	return domains, nil
}

// isTraefikRouterRule matches `traefik.http.routers.<name>.rule` and
// `traefik.tcp.routers.<name>.rule`.
func isTraefikRouterRule(label string) bool {
	if !strings.HasSuffix(label, ".rule") {
		return false
	}
	return strings.HasPrefix(label, "traefik.http.routers.") ||
		strings.HasPrefix(label, "traefik.tcp.routers.")
}
