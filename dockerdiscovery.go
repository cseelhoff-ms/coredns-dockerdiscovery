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

// ContainerInfo is the per-container record set.
//
// hostADomain (singular) is set when the container carries the
// `coredns.dockerdiscovery.host` label AND `host_ip` is configured on the
// plugin. The A record always points at `dd.hostIP`, never the container's
// internal network IP — that's the whole point of the host_ip mode (the
// service is published on the LAN-facing host port).
//
// cnameDomains is the set of FQDNs extracted from Traefik router rules
// (Host()/HostSNI()). They produce CNAME records pointing at
// `dd.traefikCNAME` and, when the tunnel syncer is configured, also
// produce Cloudflare Tunnel ingress entries pointing at `dd.cfTunnelTarget`.
//
// When the same FQDN appears in BOTH sets, the A record wins locally
// (LAN clients hit the host directly) and the tunnel entry still emits
// (public clients reach the same hostname via Cloudflare).
type ContainerInfo struct {
	container     *dockerapi.Container
	hostADomain   string   // FQDN to serve as A → dd.hostIP (optional)
	cnameDomains  []string // FQDNs to serve as CNAME → dd.traefikCNAME (Traefik labels)
	tunnelDomains []string // FQDNs synced to the Cloudflare Tunnel (subset of cnameDomains, minus excludes)
}

// ContainerInfoMap is the keyed by Docker container ID.
type ContainerInfoMap map[string]*ContainerInfo

// DockerDiscovery is a CoreDNS plugin that synthesises records from
// running Docker/Podman containers and (optionally) syncs Cloudflare
// Tunnel ingress rules for those records.
type DockerDiscovery struct {
	Next           plugin.Handler
	dockerEndpoint string
	dockerClient   *dockerapi.Client

	mutex            sync.RWMutex
	containerInfoMap ContainerInfoMap
	ttl              uint32

	// host_ip mode
	hostIP       net.IP         // LAN-facing host IP, e.g. 10.0.60.3
	hostResolver *LabelResolver // reads coredns.dockerdiscovery.host

	// Traefik label mode
	traefikResolver *TraefikLabelResolver
	traefikCNAME    string // CNAME target served for Traefik FQDNs

	// Cloudflare credentials/exclude — used solely by the tunnel syncer.
	cloudflareConfig *CloudflareConfig

	// Cloudflare Tunnel ingress sync
	tunnelSyncer   *TunnelSyncer
	tunnelConfig   *TunnelConfig
	cfTunnelTarget string // backend service URL pushed for every Traefik FQDN

	// Inventory HTTP endpoint
	inventoryAddr   string
	inventoryPath   string
	inventoryServer *InventoryServer
}

// NewDockerDiscovery constructs a DockerDiscovery with sensible defaults.
func NewDockerDiscovery(dockerEndpoint string) *DockerDiscovery {
	return &DockerDiscovery{
		dockerEndpoint:   dockerEndpoint,
		containerInfoMap: make(ContainerInfoMap),
		ttl:              3600,
	}
}

// resolveDomainsByContainer extracts the per-container domain sets:
// one optional A-record FQDN and a slice of CNAME FQDNs.
func (dd *DockerDiscovery) resolveDomainsByContainer(container *dockerapi.Container) (string, []string) {
	var hostADomain string

	if dd.hostResolver != nil && dd.hostIP != nil {
		if doms, err := dd.hostResolver.resolve(container); err == nil && len(doms) > 0 {
			hostADomain = strings.ToLower(strings.TrimSpace(doms[0]))
		}
	}

	var cnameDomains []string
	if dd.traefikResolver != nil {
		if doms, err := dd.traefikResolver.resolve(container); err == nil {
			cnameDomains = doms
		}
	}

	return hostADomain, cnameDomains
}

// DomainLookupResult carries a matched container plus the kind of record
// the caller should emit.
type DomainLookupResult struct {
	containerInfo *ContainerInfo
	isCNAME       bool // true → emit CNAME → dd.traefikCNAME; false → emit A → dd.hostIP
}

// containerInfoByDomain finds the container responsible for the given
// query name. Host-A records win over CNAMEs for the same FQDN.
func (dd *DockerDiscovery) containerInfoByDomain(requestName string) (*DomainLookupResult, error) {
	dd.mutex.RLock()
	defer dd.mutex.RUnlock()

	target := strings.ToLower(strings.TrimSuffix(requestName, "."))

	// Host-A wins.
	for _, ci := range dd.containerInfoMap {
		if ci.hostADomain != "" && strings.EqualFold(ci.hostADomain, target) {
			return &DomainLookupResult{containerInfo: ci, isCNAME: false}, nil
		}
	}

	// Otherwise look for a CNAME match.
	for _, ci := range dd.containerInfoMap {
		for _, d := range ci.cnameDomains {
			if strings.EqualFold(d, target) {
				return &DomainLookupResult{containerInfo: ci, isCNAME: true}, nil
			}
		}
	}

	return nil, nil
}

// ServeDNS implements plugin.Handler.
func (dd *DockerDiscovery) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	var answers []dns.RR

	switch state.QType() {
	case dns.TypeA:
		result, _ := dd.containerInfoByDomain(state.QName())
		if result != nil && result.isCNAME && dd.traefikCNAME != "" {
			answers = getCNAMEAnswer(state.Name(), dd.traefikCNAME, dd.ttl)
			if extra := dd.chaseCNAME(ctx, w, dd.traefikCNAME, dns.TypeA); extra != nil {
				answers = append(answers, extra...)
			}
		} else if result != nil && !result.isCNAME && dd.hostIP != nil {
			answers = getAnswer(state.Name(), []net.IP{dd.hostIP}, dd.ttl, false)
		}
	case dns.TypeAAAA:
		result, _ := dd.containerInfoByDomain(state.QName())
		if result != nil && result.isCNAME && dd.traefikCNAME != "" {
			answers = getCNAMEAnswer(state.Name(), dd.traefikCNAME, dd.ttl)
			if extra := dd.chaseCNAME(ctx, w, dd.traefikCNAME, dns.TypeAAAA); extra != nil {
				answers = append(answers, extra...)
			}
		} else if result != nil && !result.isCNAME {
			// Host-A mode is IPv4-only. Per RFC 6147 §5.1.2 return NODATA
			// (NOERROR with empty answer) so the resolver doesn't fall
			// through and answer with something else.
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.RecursionAvailable = true
			state.SizeAndDo(m)
			m = state.Scrub(m)
			_ = w.WriteMsg(m)
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
	if err := w.WriteMsg(m); err != nil {
		log.Printf("[docker] Error: %s", err.Error())
	}
	return dns.RcodeSuccess, nil
}

// Name implements plugin.Handler.
func (dd *DockerDiscovery) Name() string { return "docker" }

// updateContainerInfo (re)builds the per-container record set and pushes
// any necessary tunnel-ingress changes.
func (dd *DockerDiscovery) updateContainerInfo(container *dockerapi.Container) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	// Clean any prior state for this container.
	prev, hadPrev := dd.containerInfoMap[container.ID]
	if hadPrev {
		delete(dd.containerInfoMap, container.ID)
	}

	hostADomain, cnameDomains := dd.resolveDomainsByContainer(container)

	if hostADomain == "" && len(cnameDomains) == 0 {
		if hadPrev {
			log.Printf("[docker] Remove container entry %s (%s)", normalizeContainerName(container), shortID(container.ID))
			// If we previously pushed tunnel routes, retract them now.
			if dd.tunnelSyncer != nil && len(prev.tunnelDomains) > 0 {
				doms := append([]string(nil), prev.tunnelDomains...)
				go dd.tunnelSyncer.RemoveRoutes(doms)
			}
		}
		return nil
	}

	// Decide which Traefik domains should also be pushed to the tunnel.
	tunnelOptOut := containerOptsOutOfTunnel(container)
	var tunnelDomains []string
	if dd.tunnelSyncer != nil && !tunnelOptOut && dd.cfTunnelTarget != "" {
		for _, d := range cnameDomains {
			if dd.cloudflareConfig != nil && dd.cloudflareConfig.ExcludeDomains[d] {
				continue
			}
			tunnelDomains = append(tunnelDomains, d)
		}
	}

	dd.containerInfoMap[container.ID] = &ContainerInfo{
		container:     container,
		hostADomain:   hostADomain,
		cnameDomains:  cnameDomains,
		tunnelDomains: tunnelDomains,
	}

	if !hadPrev {
		if hostADomain != "" {
			log.Printf("[docker] Add host-A entry for %s (%s): %s -> %s", normalizeContainerName(container), shortID(container.ID), hostADomain, dd.hostIP)
		}
		if len(cnameDomains) > 0 {
			log.Printf("[docker] Add CNAME entries for %s (%s): %v", normalizeContainerName(container), shortID(container.ID), cnameDomains)
		}
	}

	// Diff tunnel domains against the previous push and reconcile.
	if dd.tunnelSyncer != nil {
		var oldDoms []string
		if hadPrev {
			oldDoms = prev.tunnelDomains
		}
		toAdd, toRemove := diffDomains(oldDoms, tunnelDomains)
		if len(toRemove) > 0 {
			doms := append([]string(nil), toRemove...)
			go dd.tunnelSyncer.RemoveRoutes(doms)
		}
		if len(toAdd) > 0 {
			doms := append([]string(nil), toAdd...)
			target := dd.cfTunnelTarget
			cid := shortID(container.ID)
			go func() {
				log.Printf("[docker] tunnel sync container=%s domains=%v target=%s", cid, doms, target)
				dd.tunnelSyncer.AddRoutes(doms, target)
			}()
		}
	}

	return nil
}

// removeContainerInfo drops a container's record set and retracts any
// tunnel ingress entries it owned.
func (dd *DockerDiscovery) removeContainerInfo(containerID string) error {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	ci, ok := dd.containerInfoMap[containerID]
	if !ok {
		log.Printf("[docker] No entry associated with the container %s", shortID(containerID))
		return nil
	}

	if dd.tunnelSyncer != nil && len(ci.tunnelDomains) > 0 {
		doms := append([]string(nil), ci.tunnelDomains...)
		go dd.tunnelSyncer.RemoveRoutes(doms)
	}

	log.Printf("[docker] Deleting entry %s (%s)", normalizeContainerName(ci.container), shortID(ci.container.ID))
	delete(dd.containerInfoMap, containerID)
	return nil
}

// containerOptsOutOfTunnel returns true when the container carries
// `coredns.dockerdiscovery.cf_tunnel=false` (case-insensitive).
func containerOptsOutOfTunnel(container *dockerapi.Container) bool {
	if container.Config == nil {
		return false
	}
	v, ok := container.Config.Labels["coredns.dockerdiscovery.cf_tunnel"]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "off", "no", "0", "disabled":
		return true
	}
	return false
}

// diffDomains returns (added, removed) given the previous and current
// slices. Order is not preserved; small slices so the O(n*m) cost is fine.
func diffDomains(prev, curr []string) (added, removed []string) {
	prevSet := make(map[string]bool, len(prev))
	for _, d := range prev {
		prevSet[d] = true
	}
	currSet := make(map[string]bool, len(curr))
	for _, d := range curr {
		currSet[d] = true
		if !prevSet[d] {
			added = append(added, d)
		}
	}
	for _, d := range prev {
		if !currSet[d] {
			removed = append(removed, d)
		}
	}
	return added, removed
}

func (dd *DockerDiscovery) start() error {
	log.Println("[docker] start")
	log.Printf("[docker] Connecting to Docker endpoint: %s", dd.dockerEndpoint)

	if err := dd.dockerClient.Ping(); err != nil {
		log.Printf("[docker] ERROR: Cannot ping Docker API at %s: %s", dd.dockerEndpoint, err)
		log.Println("[docker] If using Podman, ensure the Podman socket is enabled:")
		log.Println("[docker]   rootful: sudo systemctl enable --now podman.socket")
		log.Println("[docker]   rootless: systemctl --user enable --now podman.socket")
		log.Println("[docker]   and mount the socket: -v /run/podman/podman.sock:/var/run/docker.sock")
		return err
	}
	log.Println("[docker] Successfully connected to Docker/Podman API")

	// Reconnect loop. The fsouza event listener is a long-poll HTTP stream;
	// Podman, idle timeouts, network blips, or socket restarts all silently
	// close it. Without this loop the plugin becomes blind to new containers
	// until CoreDNS itself is restarted.
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff
	for {
		err := dd.runEventLoop()
		log.Printf("[docker] event loop ended (%v); reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		if perr := dd.dockerClient.Ping(); perr != nil {
			log.Printf("[docker] reconnect ping failed: %s", perr)
			continue
		}
		log.Println("[docker] reconnect ping ok; restarting event listener")
		backoff = minBackoff
	}
}

// runEventLoop registers an event listener, performs a full container
// resync (covering anything we missed during the disconnect), then drains
// events until the channel closes or the heartbeat detects a dead
// connection. Returns when the listener is no longer usable.
func (dd *DockerDiscovery) runEventLoop() error {
	events := make(chan *dockerapi.APIEvents, 16)
	if err := dd.dockerClient.AddEventListener(events); err != nil {
		return fmt.Errorf("AddEventListener: %w", err)
	}
	log.Println("[docker] Event listener registered successfully")
	listenerRemoved := false
	removeListener := func() {
		if listenerRemoved {
			return
		}
		listenerRemoved = true
		if err := dd.dockerClient.RemoveEventListener(events); err != nil {
			log.Printf("[docker] RemoveEventListener: %s", err)
		}
	}
	defer removeListener()

	if err := dd.resyncAll(); err != nil {
		return fmt.Errorf("resync: %w", err)
	}

	// Heartbeat: ping the daemon periodically. If the ping fails we force
	// the events channel to close by removing the listener; the for-range
	// below then exits and start()'s outer loop reconnects.
	stopHeartbeat := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-t.C:
				if err := dd.dockerClient.Ping(); err != nil {
					log.Printf("[docker] heartbeat ping failed: %s; closing event listener", err)
					removeListener()
					return
				}
			}
		}
	}()
	defer func() {
		close(stopHeartbeat)
		<-heartbeatDone
	}()

	log.Println("[docker] Listening for events...")
	for msg := range events {
		go dd.handleEvent(msg)
	}
	return errors.New("events channel closed")
}

// resyncAll performs a full reconciliation against the live container
// list: ensures every running container is reflected in our state, and
// reaps entries for containers that have disappeared (in case we missed a
// die event during a disconnect).
func (dd *DockerDiscovery) resyncAll() error {
	containers, err := dd.dockerClient.ListContainers(dockerapi.ListContainersOptions{})
	if err != nil {
		return err
	}
	log.Printf("[docker] Found %d running containers", len(containers))

	seen := make(map[string]bool, len(containers))
	for _, apiContainer := range containers {
		seen[apiContainer.ID] = true
		log.Printf("[docker] Inspecting container %s (names: %v)", shortID(apiContainer.ID), apiContainer.Names)
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: apiContainer.ID})
		if err != nil {
			log.Printf("[docker] ERROR: Failed to inspect container %s: %s", shortID(apiContainer.ID), err)
			continue
		}

		if container.Config != nil {
			for label, value := range container.Config.Labels {
				if strings.HasPrefix(label, "traefik.") || strings.HasPrefix(label, "coredns.") {
					log.Printf("[docker]   Label: %s = %s", label, value)
				}
			}
		}

		if err := dd.updateContainerInfo(container); err != nil {
			log.Printf("[docker] Error adding records for container %s: %s", shortID(container.ID), err)
		}
	}

	// Reap stale entries (containers we know about but Docker no longer does).
	dd.mutex.RLock()
	stale := make([]string, 0)
	for id := range dd.containerInfoMap {
		if !seen[id] {
			stale = append(stale, id)
		}
	}
	dd.mutex.RUnlock()
	for _, id := range stale {
		log.Printf("[docker] Reaping stale entry for absent container %s", shortID(id))
		if err := dd.removeContainerInfo(id); err != nil {
			log.Printf("[docker] Error removing stale container %s: %s", shortID(id), err)
		}
	}
	log.Println("[docker] Resync complete")
	return nil
}

// handleEvent dispatches a single Docker/Podman event.
func (dd *DockerDiscovery) handleEvent(msg *dockerapi.APIEvents) {
	event := fmt.Sprintf("%s:%s", msg.Type, msg.Action)
	if msg.Action == "health_status" || strings.HasPrefix(msg.Action, "health_status:") {
		return
	}
	log.Printf("[docker] Received event: %s (actor: %s)", event, shortID(msg.Actor.ID))
	switch event {
	case "container:start":
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.ID})
		if err != nil {
			log.Printf("[docker] Event error %s #%s: %s", event, shortID(msg.Actor.ID), err)
			return
		}
		if err := dd.updateContainerInfo(container); err != nil {
			log.Printf("[docker] Error adding records for container %s: %s", shortID(container.ID), err)
		}
	case "container:die":
		if err := dd.removeContainerInfo(msg.Actor.ID); err != nil {
			log.Printf("[docker] Error deleting records for container %s: %s", shortID(msg.Actor.ID), err)
		}
	case "network:connect", "network:disconnect":
		container, err := dd.dockerClient.InspectContainerWithOptions(dockerapi.InspectContainerOptions{ID: msg.Actor.Attributes["container"]})
		if err != nil {
			log.Printf("[docker] Event error %s #%s: %s", event, shortID(msg.Actor.Attributes["container"]), err)
			return
		}
		if err := dd.updateContainerInfo(container); err != nil {
			log.Printf("[docker] Error adding records for container %s: %s", shortID(container.ID), err)
		}
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

// getAnswer takes a slice of net.IPs and returns A or AAAA records.
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
		} else {
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
// the server's own listener so the query traverses the full plugin chain.
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

// raResponseWriter wraps dns.ResponseWriter and forces RecursionAvailable.
type raResponseWriter struct {
	dns.ResponseWriter
}

func (w *raResponseWriter) WriteMsg(m *dns.Msg) error {
	m.RecursionAvailable = true
	return w.ResponseWriter.WriteMsg(m)
}
