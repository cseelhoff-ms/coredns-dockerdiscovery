package dockerdiscovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/miekg/dns"
)

type ContainerInfo struct {
	container        *dockerapi.Container
	address          net.IP
	address6         net.IP
	domains          []string // resolved domains (A/AAAA records)
	cnameDomains     []string // domains resolved via traefik labels (CNAME records)
	tunnelServiceURL string   // if set, use tunnel routes instead of DNS CNAME
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

	// Resolvers whose results produce CNAME records (e.g. cname_target, traefik labels).
	cnameResolvers []ContainerDomainResolver

	// Traefik label support: when set, domains from TraefikLabelResolver
	// produce CNAME or A records pointing to the configured target.
	traefikResolver *TraefikLabelResolver
	traefikCNAME    string // CNAME target for traefik-discovered hosts
	traefikA        net.IP // A record target for traefik-discovered hosts

	// Cloudflare DNS sync: when configured, CNAME records are synced
	// to Cloudflare whenever containers start/stop.
	cloudflareSyncer *CloudflareSyncer
	cloudflareConfig *CloudflareConfig // set during config parsing, consumed at init

	// Cloudflare Tunnel: when configured, containers with the cf_tunnel
	// label get tunnel ingress routes instead of DNS CNAME records.
	tunnelSyncer *TunnelSyncer
	tunnelConfig *TunnelConfig // set during config parsing, consumed at init

	// Inventory HTTP endpoint. When inventoryAddr is non-empty, an HTTP
	// server is started on plugin startup that exposes the live record
	// table at inventoryPath (JSON) and inventoryPath+".html" (HTML).
	inventoryAddr   string
	inventoryPath   string
	inventoryServer *InventoryServer
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

	// Resolve CNAME label domains
	for _, resolver := range dd.cnameResolvers {
		d, err := resolver.resolve(container)
		if err != nil {
			log.Printf("[docker] Error resolving cname label domains %s", err)
		}
		cnameDomains = append(cnameDomains, d...)
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

	// Check CNAME domains first — they take priority over auto-generated
	// A record domains (e.g. from the domain directive). This prevents
	// container-name-based A records from shadowing explicit CNAME entries.
	// Example: container_name "traefik" + domain "177cpt.com" would create
	// an A record for traefik.177cpt.com pointing to the container IP,
	// shadowing the intended CNAME from traefik_cname.
	for _, containerInfo := range dd.containerInfoMap {
		for _, d := range containerInfo.cnameDomains {
			if fmt.Sprintf("%s.", d) == requestName {
				return &DomainLookupResult{containerInfo: containerInfo, isCNAME: true}, nil
			}
		}
	}

	for _, containerInfo := range dd.containerInfoMap {
		for _, d := range containerInfo.domains {
			if fmt.Sprintf("%s.", d) == requestName {
				return &DomainLookupResult{containerInfo: containerInfo, isCNAME: false}, nil
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
				// Chase the CNAME: resolve the target through the plugin chain
				// so the client gets both CNAME + A in one response
				if extra := dd.chaseCNAME(ctx, w, dd.traefikCNAME, dns.TypeA); extra != nil {
					answers = append(answers, extra...)
				}
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
				if extra := dd.chaseCNAME(ctx, w, dd.traefikCNAME, dns.TypeAAAA); extra != nil {
					answers = append(answers, extra...)
				}
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
			m.RecursionAvailable = true
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
		return plugin.NextOrFailure(dd.Name(), dd.Next, ctx, &raResponseWriter{ResponseWriter: w}, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, true, true
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

	// Allow explicit IP override via label
	if !v6 {
		if addrStr, ok := container.Config.Labels["coredns.dockerdiscovery.address"]; ok && addrStr != "" {
			if ip := net.ParseIP(addrStr); ip != nil && ip.To4() != nil {
				return ip, nil
			}
		}
	}

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
	} else if networkMode != "" {
		network, ok = container.NetworkSettings.Networks[networkMode]
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

		// Check for tunnel label — if present, use tunnel routes instead of DNS
		var tunnelServiceURL string
		if dd.tunnelSyncer != nil && container.Config != nil {
			if labelVal, ok := container.Config.Labels["coredns.dockerdiscovery.cf_tunnel"]; ok {
				if labelVal != "" && labelVal != "true" {
					tunnelServiceURL = labelVal
				} else {
					// Derive from Traefik service port label
					if port := getTraefikServicePort(container.Config.Labels); port != "" {
						tunnelServiceURL = "http://localhost:" + port
					} else {
						log.Printf("[docker] Container %s has cf_tunnel label but no service URL or Traefik port", container.ID[:12])
					}
				}
			}
		}
		dd.containerInfoMap[container.ID].tunnelServiceURL = tunnelServiceURL

		// Sync to Cloudflare: tunnel routes or DNS CNAME (mutually exclusive)
		if dd.tunnelSyncer != nil && tunnelServiceURL != "" && len(cnameDomains) > 0 {
			log.Printf("[docker] Dispatching tunnel sync for container %s: %d domain(s) -> %s", container.ID[:12], len(cnameDomains), tunnelServiceURL)
			doms := append([]string(nil), cnameDomains...)
			url := tunnelServiceURL
			cid := container.ID[:12]
			go func() {
				log.Printf("[docker] tunnel sync START container=%s domains=%v", cid, doms)
				dd.tunnelSyncer.AddRoutes(doms, url)
				log.Printf("[docker] tunnel sync END container=%s", cid)
			}()
		} else if dd.cloudflareSyncer != nil && len(cnameDomains) > 0 {
			log.Printf("[docker] Dispatching cloudflare sync for container %s: %v", container.ID[:12], cnameDomains)
			doms := append([]string(nil), cnameDomains...)
			cid := container.ID[:12]
			go func() {
				log.Printf("[docker] cloudflare sync START container=%s domains=%v", cid, doms)
				dd.cloudflareSyncer.SyncDomains(doms)
				log.Printf("[docker] cloudflare sync END container=%s", cid)
			}()
		} else if len(cnameDomains) > 0 {
			log.Printf("[docker] CNAME domains present but no syncer configured (tunnelSyncer=%v cloudflareSyncer=%v) container=%s domains=%v",
				dd.tunnelSyncer != nil, dd.cloudflareSyncer != nil, container.ID[:12], cnameDomains)
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
		log.Printf("[docker] No entry associated with the container %s", shortID(containerID))
		return nil
	}
	// Remove from Cloudflare: tunnel routes or DNS CNAME (mutually exclusive)
	if dd.tunnelSyncer != nil && containerInfo.tunnelServiceURL != "" && len(containerInfo.cnameDomains) > 0 {
		domainsToRemove := make([]string, len(containerInfo.cnameDomains))
		copy(domainsToRemove, containerInfo.cnameDomains)
		go dd.tunnelSyncer.RemoveRoutes(domainsToRemove)
	} else if dd.cloudflareSyncer != nil && len(containerInfo.cnameDomains) > 0 {
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

	// Initial container scan + periodic safety-net re-scan.
	// The re-scan catches any events the listener missed (e.g. during a
	// reconnect or if the daemon dropped events under load).
	dd.scanAllContainers("startup")
	go dd.periodicRescan()

	// Heartbeat: confirms the plugin's main goroutine is alive and the
	// listener loop is currently waiting for events. If you stop seeing
	// these in the logs, the goroutine has exited.
	go dd.heartbeat()

	// Reconnect loop. AddEventListener can fail and the events channel
	// can close at any time (daemon restart, socket replacement, network
	// blip). Without this loop a single disconnect would leave CoreDNS
	// running with no event processing until manually restarted.
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		err := dd.runEventListener()
		if err == nil {
			// Channel closed cleanly — treat as a disconnect and reconnect.
			err = errors.New("event channel closed")
		}
		log.Printf("[docker] Event listener exited: %s — reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		if pingErr := dd.dockerClient.Ping(); pingErr != nil {
			log.Printf("[docker] Ping failed during reconnect: %s — will keep retrying", pingErr)
			continue
		}
		// On a successful reconnect, do a full re-scan so we don't miss
		// any containers that started during the outage.
		dd.scanAllContainers("post-reconnect")
		backoff = time.Second
	}
}

// runEventListener registers an event listener and processes events
// until the channel closes or registration fails. It returns the error
// (or nil if the channel just closed).
func (dd *DockerDiscovery) runEventListener() error {
	events := make(chan *dockerapi.APIEvents)

	if err := dd.dockerClient.AddEventListener(events); err != nil {
		log.Printf("[docker] ERROR: Failed to add event listener: %s", err)
		return err
	}
	log.Println("[docker] Event listener registered successfully — listening for events...")

	// Best-effort cleanup on exit.
	defer func() {
		if err := dd.dockerClient.RemoveEventListener(events); err != nil {
			log.Printf("[docker] RemoveEventListener: %s", err)
		}
	}()

	for msg := range events {
		dd.handleDockerEvent(msg)
	}
	return nil
}

// handleDockerEvent dispatches a single Docker/Podman event.
func (dd *DockerDiscovery) handleDockerEvent(msg *dockerapi.APIEvents) {
	go func(msg *dockerapi.APIEvents) {
		event := fmt.Sprintf("%s:%s", msg.Type, msg.Action)
		if msg.Action == "health_status" || strings.HasPrefix(msg.Action, "health_status:") {
			return
		}
		log.Printf("[docker] Received event: %s (actor: %s)", event, shortID(msg.Actor.ID))
		switch event {
		case "container:start":
			log.Println("[docker] New container spawned. Attempt to add A/AAAA records for it")

			container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.ID})
			if err != nil {
				log.Printf("[docker] Event error %s #%s: %s", event, shortID(msg.Actor.ID), err)
				return
			}
			if err := dd.updateContainerInfo(container); err != nil {
				log.Printf("[docker] Error adding A/AAAA records for container %s: %s", shortID(container.ID), err)
			}
		case "container:die":
			log.Println("[docker] Container being stopped. Attempt to remove its A/AAAA records from the DNS", shortID(msg.Actor.ID))
			if err := dd.removeContainerInfo(msg.Actor.ID); err != nil {
				log.Printf("[docker] Error deleting A/AAAA records for container: %s: %s", shortID(msg.Actor.ID), err)
			}
		case "network:connect":
			// take a look https://gist.github.com/josefkarasek/be9bac36921f7bc9a61df23451594fbf for example of same event's types attributes
			log.Printf("[docker] Container %s being connected to network %s.", shortID(msg.Actor.Attributes["container"]), msg.Actor.Attributes["name"])

			container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
			if err != nil {
				log.Printf("[docker] Event error %s #%s: %s", event, shortID(msg.Actor.Attributes["container"]), err)
				return
			}
			if err := dd.updateContainerInfo(container); err != nil {
				log.Printf("[docker] Error adding A/AAAA records for container %s: %s", shortID(container.ID), err)
			}
		case "network:disconnect":
			log.Printf("[docker] Container %s being disconnected from network %s", shortID(msg.Actor.Attributes["container"]), msg.Actor.Attributes["name"])

			container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
			if err != nil {
				log.Printf("[docker] Event error %s #%s: %s", event, shortID(msg.Actor.Attributes["container"]), err)
				return
			}
			if err := dd.updateContainerInfo(container); err != nil {
				log.Printf("[docker] Error adding A/AAAA records for container %s: %s", shortID(container.ID), err)
			}
		}
	}(msg)
}

// scanAllContainers lists every running container and (re)processes it.
// Used at startup, after a reconnect, and on the periodic safety-net
// timer so that any events missed by the listener still land in the map.
func (dd *DockerDiscovery) scanAllContainers(reason string) {
	containers, err := dd.dockerClient.ListContainers(dockerapi.ListContainersOptions{})
	if err != nil {
		log.Printf("[docker] scan(%s): ERROR listing containers: %s", reason, err)
		return
	}
	log.Printf("[docker] scan(%s): found %d running containers", reason, len(containers))

	seen := make(map[string]bool, len(containers))
	for _, apiContainer := range containers {
		seen[apiContainer.ID] = true
		log.Printf("[docker] scan(%s): inspecting container %s (names: %v)", reason, apiContainer.ID[:12], apiContainer.Names)
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: apiContainer.ID})
		if err != nil {
			log.Printf("[docker] scan(%s): ERROR inspecting container %s: %s", reason, apiContainer.ID[:12], err)
			continue
		}

		// Debug: show labels
		if container.Config != nil {
			for label, value := range container.Config.Labels {
				if strings.HasPrefix(label, "traefik.") || strings.HasPrefix(label, "coredns.") {
					log.Printf("[docker] scan(%s):   Label: %s = %s", reason, label, value)
				}
			}
		}

		if err := dd.updateContainerInfo(container); err != nil {
			log.Printf("[docker] scan(%s): error updating container %s: %s", reason, container.ID[:12], err)
		}
	}

	// Drop entries for containers that disappeared while we weren't listening.
	dd.mutex.RLock()
	stale := make([]string, 0)
	for id := range dd.containerInfoMap {
		if !seen[id] {
			stale = append(stale, id)
		}
	}
	dd.mutex.RUnlock()
	for _, id := range stale {
		log.Printf("[docker] scan(%s): removing stale container entry %s", reason, shortID(id))
		if err := dd.removeContainerInfo(id); err != nil {
			log.Printf("[docker] scan(%s): error removing stale entry %s: %s", reason, shortID(id), err)
		}
	}
	log.Printf("[docker] scan(%s): complete", reason)
}

// periodicRescan re-scans all containers on a fixed interval as a
// safety net for any events the listener missed.
func (dd *DockerDiscovery) periodicRescan() {
	const interval = 60 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		dd.scanAllContainers("periodic")
	}
}

// heartbeat logs a line every minute summarising plugin state. If you
// stop seeing these, the goroutine is dead.
func (dd *DockerDiscovery) heartbeat() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		dd.mutex.RLock()
		n := len(dd.containerInfoMap)
		dd.mutex.RUnlock()
		log.Printf("[docker] heartbeat: %d containers tracked, cloudflareSyncer=%v tunnelSyncer=%v",
			n, dd.cloudflareSyncer != nil, dd.tunnelSyncer != nil)
	}
}

// shortID safely truncates an ID string to at most 12 characters.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
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

// chaseCNAME resolves a CNAME target by issuing a loopback DNS query to
// the server's own listener. This ensures the query traverses the full
// plugin chain from the top (e.g. hosts → docker → forward), unlike
// plugin.NextOrFailure which only reaches plugins after the current one.
func (dd *DockerDiscovery) chaseCNAME(ctx context.Context, w dns.ResponseWriter, target string, qtype uint16) []dns.RR {
	if !strings.HasSuffix(target, ".") {
		target += "."
	}
	m := new(dns.Msg)
	m.SetQuestion(target, qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	addr := w.LocalAddr().String()
	r, _, err := c.Exchange(m, addr)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}
	return r.Answer
}

// raResponseWriter wraps a dns.ResponseWriter and ensures the
// RecursionAvailable (RA) flag is set on all outgoing responses.
// This is needed because some downstream plugins (e.g. hosts) don't
// set RA, which causes resolvers like nslookup to skip the response
// and fall through to a secondary nameserver.
type raResponseWriter struct {
	dns.ResponseWriter
}

func (w *raResponseWriter) WriteMsg(m *dns.Msg) error {
	m.RecursionAvailable = true
	return w.ResponseWriter.WriteMsg(m)
}
