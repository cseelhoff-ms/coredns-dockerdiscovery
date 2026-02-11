package dockerdiscovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/miekg/dns"
)

type ContainerInfo struct {
	container    *dockerapi.Container
	address      net.IP
	address6     net.IP
	domains      []string // resolved domains (A/AAAA records)
	cnameDomains []string // domains resolved via traefik labels (CNAME records)
}

type ContainerInfoMap map[string]*ContainerInfo

type ContainerDomainResolver interface {
	// return domains without trailing dot
	resolve(container *dockerapi.Container) ([]string, error)
}

// DockerDiscovery is a plugin that conforms to the coredns plugin interface
type DockerDiscovery struct {
	Next           plugin.Handler
	dockerEndpoint string
	resolvers      []ContainerDomainResolver
	dockerClient   *dockerapi.Client

	mutex            sync.RWMutex
	containerInfoMap ContainerInfoMap
	ttl              uint32

	// Traefik label support: when set, domains from TraefikLabelResolver
	// produce CNAME or A records pointing to the configured target.
	traefikResolver *TraefikLabelResolver
	traefikCNAME    string // CNAME target for traefik-discovered hosts
	traefikA        net.IP // A record target for traefik-discovered hosts

	// Cloudflare DNS sync: when configured, CNAME records are synced
	// to Cloudflare whenever containers start/stop.
	cloudflareSyncer *CloudflareSyncer
	cloudflareConfig *CloudflareConfig // set during config parsing, consumed at init
}

// NewDockerDiscovery constructs a new DockerDiscovery object
func NewDockerDiscovery(dockerEndpoint string) *DockerDiscovery {
	return &DockerDiscovery{
		dockerEndpoint:   dockerEndpoint,
		containerInfoMap: make(ContainerInfoMap),
		ttl:              3600,
	}
}

func (dd *DockerDiscovery) resolveDomainsByContainer(container *dockerapi.Container) ([]string, []string, error) {
	var domains []string
	var cnameDomains []string
	for _, resolver := range dd.resolvers {
		var d, err = resolver.resolve(container)
		if err != nil {
			log.Printf("[docker] Error resolving container domains %s", err)
		}
		domains = append(domains, d...)
	}

	// Resolve traefik label domains separately
	if dd.traefikResolver != nil {
		d, err := dd.traefikResolver.resolve(container)
		if err != nil {
			log.Printf("[docker] Error resolving traefik label domains %s", err)
		}
		cnameDomains = append(cnameDomains, d...)
	}

	return domains, cnameDomains, nil
}

// DomainLookupResult holds the result of a domain lookup with record type info
type DomainLookupResult struct {
	containerInfo *ContainerInfo
	isCNAME       bool // true if this domain should return CNAME/traefik-A records
}

func (dd *DockerDiscovery) containerInfoByDomain(requestName string) (*DomainLookupResult, error) {
	dd.mutex.RLock()
	defer dd.mutex.RUnlock()

	for _, containerInfo := range dd.containerInfoMap {
		for _, d := range containerInfo.domains {
			if fmt.Sprintf("%s.", d) == requestName {
				return &DomainLookupResult{containerInfo: containerInfo, isCNAME: false}, nil
			}
		}
		for _, d := range containerInfo.cnameDomains {
			if fmt.Sprintf("%s.", d) == requestName {
				return &DomainLookupResult{containerInfo: containerInfo, isCNAME: true}, nil
			}
		}
	}

	return nil, nil
}

// ServeDNS implements plugin.Handler
func (dd *DockerDiscovery) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	var answers []dns.RR
	switch state.QType() {
	case dns.TypeA:
		result, _ := dd.containerInfoByDomain(state.QName())
		if result != nil && result.isCNAME {
			if dd.traefikCNAME != "" {
				// Return CNAME record pointing to the traefik server
				answers = getCNAMEAnswer(state.Name(), dd.traefikCNAME, dd.ttl)
			} else if dd.traefikA != nil {
				// Return A record with the configured traefik IP
				answers = getAnswer(state.Name(), []net.IP{dd.traefikA}, dd.ttl, false)
			}
		} else if result != nil {
			answers = getAnswer(state.Name(), []net.IP{result.containerInfo.address}, dd.ttl, false)
		}
	case dns.TypeAAAA:
		result, _ := dd.containerInfoByDomain(state.QName())
		if result != nil && result.isCNAME {
			// For CNAME/traefik domains, return the CNAME for AAAA queries too
			if dd.traefikCNAME != "" {
				answers = getCNAMEAnswer(state.Name(), dd.traefikCNAME, dd.ttl)
			}
			// For traefik_a mode, we don't return AAAA records (IPv4 only)
		} else if result != nil && result.containerInfo.address6 != nil {
			answers = getAnswer(state.Name(), []net.IP{result.containerInfo.address6}, dd.ttl, true)
		} else if result != nil && result.containerInfo.address != nil {
			// Per RFC 6147 section 5.1.2: return a NODATA response (empty answer
			// section with NOERROR rcode) when no AAAA records are available but
			// an A record exists. We must NOT add a malformed AAAA record.
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.RecursionAvailable = false
			// Empty answer section = NODATA
			state.SizeAndDo(m)
			m = state.Scrub(m)
			w.WriteMsg(m)
			return dns.RcodeSuccess, nil
		}
	case dns.TypeCNAME:
		result, _ := dd.containerInfoByDomain(state.QName())
		if result != nil && result.isCNAME && dd.traefikCNAME != "" {
			answers = getCNAMEAnswer(state.Name(), dd.traefikCNAME, dd.ttl)
		}
	}

	if len(answers) == 0 {
		return plugin.NextOrFailure(dd.Name(), dd.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = answers

	state.SizeAndDo(m)
	m = state.Scrub(m)
	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("[docker] Error: %s", err.Error())
	}
	return dns.RcodeSuccess, nil
}

// Name implements plugin.Handler
func (dd *DockerDiscovery) Name() string {
	return "docker"
}

func (dd *DockerDiscovery) getContainerAddress(container *dockerapi.Container, v6 bool) (net.IP, error) {

	// save this away
	netName, hasNetName := container.Config.Labels["coredns.dockerdiscovery.network"]

	var networkMode string

	for {
		if container.NetworkSettings.IPAddress != "" && !hasNetName && !v6 {
			return net.ParseIP(container.NetworkSettings.IPAddress), nil
		}

		if container.NetworkSettings.GlobalIPv6Address != "" && !hasNetName && v6 {
			return net.ParseIP(container.NetworkSettings.GlobalIPv6Address), nil
		}

		networkMode = container.HostConfig.NetworkMode

		// TODO: Deal with containers run with host ip (--net=host)
		if networkMode == "host" {
			log.Println("[docker] Container uses host network")
			return nil, nil
		}

		if strings.HasPrefix(networkMode, "container:") {
			log.Printf("Container %s is in another container's network namspace", container.ID[:12])
			otherID := container.HostConfig.NetworkMode[len("container:"):]
			var err error
			container, err = dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: otherID})
			if err != nil {
				return nil, err
			}
		} else {
			break
		}
	}

	var (
		network dockerapi.ContainerNetwork
		ok      = false
	)

	if hasNetName {
		log.Printf("[docker] network name %s specified (%s)", netName, container.ID[:12])
		network, ok = container.NetworkSettings.Networks[netName]
	} else if len(container.NetworkSettings.Networks) == 1 {
		for netName, network = range container.NetworkSettings.Networks {
			ok = true
		}
	}

	if !ok { // sometime while "network:disconnect" event fire
		return nil, fmt.Errorf("unable to find network settings for the network %s", networkMode)
	}

	if !v6 {
		return net.ParseIP(network.IPAddress), nil // ParseIP return nil when IPAddress equals ""
	} else if v6 && len(network.GlobalIPv6Address) > 0 {
		return net.ParseIP(network.GlobalIPv6Address), nil
	}

	return nil, nil
}

func (dd *DockerDiscovery) updateContainerInfo(container *dockerapi.Container) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	_, isExist := dd.containerInfoMap[container.ID]
	if isExist { // remove previous resolved container info
		delete(dd.containerInfoMap, container.ID)
	}

	// Resolve domains FIRST — CNAME domains (traefik labels) don't need an IP
	domains, cnameDomains, _ := dd.resolveDomainsByContainer(container)

	// Try to get the container's IP address (needed for A/AAAA records only)
	containerAddress, err := dd.getContainerAddress(container, false)
	if err != nil {
		log.Printf("[docker] Could not resolve IP for container %s (%s): %s", normalizeContainerName(container), container.ID[:12], err)
	}

	var containerAddress6 net.IP
	if containerAddress != nil {
		containerAddress6, _ = dd.getContainerAddress(container, true)
	}

	// If we have no IP, we can't serve A/AAAA records for regular domains
	if containerAddress == nil && len(domains) > 0 {
		log.Printf("[docker] Dropping A/AAAA domains for container %s (%s): no IP address available", normalizeContainerName(container), container.ID[:12])
		domains = nil
	}

	if len(domains) > 0 || len(cnameDomains) > 0 {
		dd.containerInfoMap[container.ID] = &ContainerInfo{
			container:    container,
			address:      containerAddress,
			address6:     containerAddress6,
			domains:      domains,
			cnameDomains: cnameDomains,
		}

		if !isExist {
			if containerAddress != nil {
				log.Printf("[docker] Add entry of container %s (%s). IP: %v", normalizeContainerName(container), container.ID[:12], containerAddress)
			}
			if len(cnameDomains) > 0 {
				log.Printf("[docker] Add CNAME entries for container %s (%s): %v", normalizeContainerName(container), container.ID[:12], cnameDomains)
			}
		}

		// Sync CNAME domains to Cloudflare
		if dd.cloudflareSyncer != nil && len(cnameDomains) > 0 {
			go dd.cloudflareSyncer.SyncDomains(cnameDomains)
		}
	} else if isExist {
		log.Printf("[docker] Remove container entry %s (%s)", normalizeContainerName(container), container.ID[:12])
	}
	return nil
}

func (dd *DockerDiscovery) removeContainerInfo(containerID string) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	containerInfo, ok := dd.containerInfoMap[containerID]
	if !ok {
		log.Printf("[docker] No entry associated with the container %s", containerID[:12])
		return nil
	}
	// Remove CNAME domains from Cloudflare before deleting
	if dd.cloudflareSyncer != nil && len(containerInfo.cnameDomains) > 0 {
		domainsToRemove := make([]string, len(containerInfo.cnameDomains))
		copy(domainsToRemove, containerInfo.cnameDomains)
		go dd.cloudflareSyncer.RemoveDomains(domainsToRemove)
	}

	log.Printf("[docker] Deleting entry %s (%s)", normalizeContainerName(containerInfo.container), containerInfo.container.ID[:12])
	delete(dd.containerInfoMap, containerID)

	return nil
}

func (dd *DockerDiscovery) start() error {
	log.Println("[docker] start")
	log.Printf("[docker] Connecting to Docker endpoint: %s", dd.dockerEndpoint)

	// Test connectivity first
	if err := dd.dockerClient.Ping(); err != nil {
		log.Printf("[docker] ERROR: Cannot ping Docker API at %s: %s", dd.dockerEndpoint, err)
		log.Println("[docker] If using Podman, ensure the Podman socket is enabled:")
		log.Println("[docker]   rootful: sudo systemctl enable --now podman.socket")
		log.Println("[docker]   rootless: systemctl --user enable --now podman.socket")
		log.Println("[docker]   and mount the socket: -v /run/podman/podman.sock:/var/run/docker.sock")
		return err
	}
	log.Println("[docker] Successfully connected to Docker/Podman API")

	events := make(chan *dockerapi.APIEvents)

	if err := dd.dockerClient.AddEventListener(events); err != nil {
		log.Printf("[docker] ERROR: Failed to add event listener: %s", err)
		return err
	}
	log.Println("[docker] Event listener registered successfully")

	containers, err := dd.dockerClient.ListContainers(dockerapi.ListContainersOptions{})
	if err != nil {
		log.Printf("[docker] ERROR: Failed to list containers: %s", err)
		return err
	}
	log.Printf("[docker] Found %d running containers at startup", len(containers))

	for _, apiContainer := range containers {
		log.Printf("[docker] Inspecting container %s (names: %v)", apiContainer.ID[:12], apiContainer.Names)
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: apiContainer.ID})
		if err != nil {
			log.Printf("[docker] ERROR: Failed to inspect container %s: %s", apiContainer.ID[:12], err)
			continue
		}

		// Debug: show labels
		if container.Config != nil {
			for label, value := range container.Config.Labels {
				if strings.HasPrefix(label, "traefik.") || strings.HasPrefix(label, "coredns.") {
					log.Printf("[docker]   Label: %s = %s", label, value)
				}
			}
		}

		if err := dd.updateContainerInfo(container); err != nil {
			log.Printf("[docker] Error adding A/AAAA records for container %s: %s\n", container.ID[:12], err)
		}
	}

	log.Println("[docker] Startup container scan complete. Listening for events...")

	for msg := range events {
		go func(msg *dockerapi.APIEvents) {
			event := fmt.Sprintf("%s:%s", msg.Type, msg.Action)
			log.Printf("[docker] Received event: %s (actor: %s)", event, msg.Actor.ID[:12])
			switch event {
			case "container:start":
				log.Println("[docker] New container spawned. Attempt to add A/AAAA records for it")

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.ID})
				if err != nil {
					log.Printf("[docker] Event error %s #%s: %s", event, msg.Actor.ID[:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Printf("[docker] Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			case "container:die":
				log.Println("[docker] Container being stopped. Attempt to remove its A/AAAA records from the DNS", msg.Actor.ID[:12])
				if err := dd.removeContainerInfo(msg.Actor.ID); err != nil {
					log.Printf("[docker] Error deleting A/AAAA records for container: %s: %s", msg.Actor.ID[:12], err)
				}
			case "network:connect":
				// take a look https://gist.github.com/josefkarasek/be9bac36921f7bc9a61df23451594fbf for example of same event's types attributes
				log.Printf("[docker] Container %s being connected to network %s.", msg.Actor.Attributes["container"][:12], msg.Actor.Attributes["name"])

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
				if err != nil {
					log.Printf("[docker] Event error %s #%s: %s", event, msg.Actor.Attributes["container"][:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Printf("[docker] Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			case "network:disconnect":
				log.Printf("[docker] Container %s being disconnected from network %s", msg.Actor.Attributes["container"][:12], msg.Actor.Attributes["name"])

				container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
				if err != nil {
					log.Printf("[docker] Event error %s #%s: %s", event, msg.Actor.Attributes["container"][:12], err)
					return
				}
				if err := dd.updateContainerInfo(container); err != nil {
					log.Printf("[docker] Error adding A/AAAA records for container %s: %s", container.ID[:12], err)
				}
			}
		}(msg)
	}

	return errors.New("docker event loop closed")
}

// getCNAMEAnswer creates a CNAME DNS response record.
func getCNAMEAnswer(zone string, target string, ttl uint32) []dns.RR {
	// Ensure target has trailing dot for FQDN
	if !strings.HasSuffix(target, ".") {
		target = target + "."
	}
	record := new(dns.CNAME)
	record.Hdr = dns.RR_Header{
		Name:   zone,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	record.Target = target
	return []dns.RR{record}
}

// getAnswer function takes a slice of net.IPs and returns a slice of A/AAAA RRs.
func getAnswer(zone string, ips []net.IP, ttl uint32, v6 bool) []dns.RR {
	answers := []dns.RR{}
	for _, ip := range ips {
		if !v6 {
			record := new(dns.A)
			record.Hdr = dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			record.A = ip
			answers = append(answers, record)
		} else if v6 {
			record := new(dns.AAAA)
			record.Hdr = dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			}
			record.AAAA = ip
			answers = append(answers, record)
		}
	}
	return answers
}
