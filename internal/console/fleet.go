package console

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/client"
	"github.com/jotra7/postern/internal/config"
)

// storeIndex mirrors the index.json `postern sign` writes and a hub reads.
//
// It is a third copy of that shape, and deliberately so: cmd/postern/cmd_sign.go
// writes it, internal/hub/store.go reads it, and hub/store.go's own comment
// already records why the two are not one type — cmd/postern is a main
// package neither of them may import. This package is in the same position.
// The JSON shape is the contract, and TestConsole_Deploy_SignsBundlesTheHubStoreCanRead
// is what holds the three copies together.
type storeIndex struct {
	Hosts map[string]storeIndexEntry `json:"hosts"`
}

type storeIndexEntry struct {
	Signing string `json:"signing"`
	Version uint64 `json:"version"`
}

func indexPath(dir string) string { return filepath.Join(dir, "index.json") }

// readIndex reads dir's index.json, treating an absent file as an empty
// index: a bundle directory that has never been signed into is not an error,
// it is the state every fleet starts in.
func readIndex(dir string) (*storeIndex, error) {
	if dir == "" {
		return &storeIndex{Hosts: map[string]storeIndexEntry{}}, nil
	}
	data, err := os.ReadFile(indexPath(dir)) //nolint:gosec // the operator named this directory
	if err != nil {
		if os.IsNotExist(err) {
			return &storeIndex{Hosts: map[string]storeIndexEntry{}}, nil
		}
		return nil, fmt.Errorf("console: read %s: %w", indexPath(dir), err)
	}
	var idx storeIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("console: parse %s: %w", indexPath(dir), err)
	}
	if idx.Hosts == nil {
		idx.Hosts = map[string]storeIndexEntry{}
	}
	return &idx, nil
}

func (idx *storeIndex) set(hostID [16]byte, signing [32]byte, version uint64) {
	idx.Hosts[hex.EncodeToString(hostID[:])] = storeIndexEntry{
		Signing: base64.StdEncoding.EncodeToString(signing[:]),
		Version: version,
	}
}

// maxVersion is the highest version recorded across every host in the index,
// which is the floor a re-sign has to clear. Same rule `postern sign`
// applies, and for the same reason: one inventory names one version for every
// bundle it produces, so a stale checkout has to be caught even when only one
// host is being re-signed.
func (idx *storeIndex) maxVersion() (version uint64, ok bool) {
	for _, e := range idx.Hosts {
		if !ok || e.Version > version {
			version, ok = e.Version, true
		}
	}
	return version, ok
}

func (idx *storeIndex) writeTo(dir string) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("console: encode index.json: %w", err)
	}
	data = append(data, '\n')
	// Same mode `postern sign` writes: index.json holds host_id, a public
	// signing key and a version, and whatever serves it to a hub may run as
	// another user.
	if err := os.WriteFile(indexPath(dir), data, 0o644); err != nil { //nolint:gosec // no secret in this file; meant to be served
		return fmt.Errorf("console: write %s: %w", indexPath(dir), err)
	}
	return nil
}

// LiveState is the last thing the console observed of a host directly, by
// running the same two assertions `postern status` runs.
//
// It exists because the hub cannot answer this question. internal/hub keeps
// the latest heartbeat per host in memory (hub.Beats) but serves it on no
// route: the public listener carries exactly `GET /bundle/{host_id}` and
// `POST /heartbeat`, and the private listener carries only aggregate
// Prometheus metrics — known_hosts is fleet size, not per-host freshness. So
// per-host liveness in this console is what this console measured, with the
// time it measured it, and it says so rather than implying a feed.
type LiveState struct {
	// Checked is when the console last ran status against this host.
	Checked time.Time
	// Pong reports whether the signed liveness pong came back and verified.
	Pong    bool
	PongErr string
	PongRTT time.Duration
	// ClockSkew is the host's clock minus this machine's.
	ClockSkew time.Duration
	// RecoveryService and Recovery are the second assertion: a TCP connect to
	// the service an operator would actually recover with.
	RecoveryService string
	Recovery        string
	Healthy         bool
}

// liveStore holds LiveState per host name for the life of the process.
type liveStore struct {
	mu sync.Mutex
	m  map[string]LiveState
}

func newLiveStore() *liveStore { return &liveStore{m: map[string]LiveState{}} }

func (l *liveStore) set(host string, st LiveState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[host] = st
}

func (l *liveStore) get(host string) (LiveState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.m[host]
	return st, ok
}

// GrantView is one operator's permission over this host, as the compiled
// policy resolves it. It is the answer to "who can knock this host, for
// what" — the question an inventory diff makes hard to read by hand, because
// a grant on hosts: ["*"] does not name the host it reaches.
type GrantView struct {
	Operator        string
	Services        []string
	MaxTTL          string
	AllowSourceCIDR bool
	MinIPv4Prefix   int
	MinIPv6Prefix   int
}

// ServiceView is one gated service or action on this host.
type ServiceView struct {
	Name string
	Kind string
	// Ports is rendered rather than carried as numbers, because a template
	// that joined them would be building markup out of data.
	Ports       string
	Proto       string
	DefaultTTL  string
	MaxTTL      string
	FailPosture string
}

// HostView is one row of the fleet view and the subject of the host page.
//
// Nothing here is key material. That is a property this type is required to
// keep: it is the only thing a template ever sees, so a rendering mistake can
// print a host name, an address or an error string and nothing worse.
type HostView struct {
	Name   string
	HostID string
	// KnockAddr is where a knock goes. It is an IP literal by construction
	// (config.ParseInventory refuses anything else).
	KnockAddr       string
	Groups          []string
	ProviderFronted bool
	// ConsoleURL is the provider console link from the inventory. It reaches
	// an href, so it is rendered through html/template's URL context, which
	// neutralises a javascript: scheme in a hand-edited file.
	ConsoleURL string
	// SSH is the command `postern open` would print on success.
	SSH string

	Services []ServiceView
	Grants   []GrantView

	// InventoryVersion is the version the inventory currently declares — what
	// the next signing run would stamp on every bundle.
	InventoryVersion uint64
	// SignedVersion is the version index.json records for this host, and
	// HasSigned distinguishes "never signed" from "signed at version 0",
	// which is a legal version.
	SignedVersion uint64
	HasSigned     bool

	Hub HubState

	// Stale means the bundle plane is behind: this host has never been
	// signed, or the version on file is older than the inventory's, or the
	// hub is not serving a bundle for it. Each of those means an agent
	// pulling right now would not get the policy in the inventory.
	Stale bool
	// StaleReason says which of those it is.
	StaleReason string

	// Knockable reports whether the operator's client config carries an entry
	// for this host. A host in the inventory but not in the client config can
	// be signed for and cannot be knocked from here, which is an ordinary
	// state — the inventory is the fleet, the client config is what this
	// laptop was enrolled against.
	Knockable bool
	// RecoveryService is the service `open` defaults to for this host.
	RecoveryService string
	// ServiceNames are the client-config service names an operator may open.
	ServiceNames []string

	// Live is the console's own last observation, and Checked reports whether
	// there has been one at all.
	Live     LiveState
	HasLive  bool
	LiveAge  string
	LiveCold bool
}

// FleetView is the whole page model.
type FleetView struct {
	FleetID string
	// Version is the inventory's declared version.
	Version uint64
	Hosts   []HostView
	// InventoryPath, OutDir and HubURL are shown so an operator can see which
	// files this console is actually reading.
	InventoryPath string
	OutDir        string
	HubURL        string
	// InventoryErr is set when the inventory could not be read or validated.
	// The console still renders: an unreadable inventory is exactly when an
	// operator wants to see the error rather than a blank page.
	InventoryErr string
	// StaleCount is how many hosts are behind.
	StaleCount int
	// UnhealthyCount, UncheckedCount and UnknockableCount are the other three
	// counts the fleet page leads with. They are computed here rather than in
	// a template so the page can be scanned before it is read: each one is a
	// different next action, and "checked and bad" is not "never checked".
	UnhealthyCount   int
	UncheckedCount   int
	UnknockableCount int
}

// sources is where a console reads its fleet from. Every path is supplied by
// the caller; nothing under internal/ knows where an operator keeps files.
type sources struct {
	inventoryPath string
	outDir        string
	clientCfg     *client.Config
	hub           HubClient
	// liveMaxAge is how old a console-run status observation may be before
	// the fleet view calls it cold.
	liveMaxAge time.Duration
	now        func() time.Time
}

// loadInventory parses and validates the inventory. Both steps, in the order
// `postern sign` uses them: ParseInventory returns structural problems and
// Validate returns the cross-referencing ones, and an operator looking at
// this console during a rollout needs the second kind most.
func (s *sources) loadInventory() (*config.Inventory, error) {
	if s.inventoryPath == "" {
		return nil, fmt.Errorf("console: no inventory is configured")
	}
	data, err := os.ReadFile(s.inventoryPath) //nolint:gosec // the operator named this path
	if err != nil {
		return nil, fmt.Errorf("console: read inventory: %w", err)
	}
	inv, err := config.ParseInventory(data)
	if err != nil {
		return nil, err
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	return inv, nil
}

// fleet assembles the whole view: the inventory, what has been signed, what
// the hub is serving, and what this console last observed directly.
func (s *sources) fleet(ctx context.Context, live *liveStore) FleetView {
	v := FleetView{
		InventoryPath: s.inventoryPath,
		OutDir:        s.outDir,
		HubURL:        s.hub.BaseURL,
	}
	inv, err := s.loadInventory()
	if err != nil {
		v.InventoryErr = err.Error()
		return v
	}
	v.FleetID = hex.EncodeToString(inv.FleetID[:])
	v.Version = inv.Version

	idx, err := readIndex(s.outDir)
	if err != nil {
		v.InventoryErr = err.Error()
		idx = &storeIndex{Hosts: map[string]storeIndexEntry{}}
	}

	for i := range inv.Hosts {
		hv := s.hostView(ctx, inv, &inv.Hosts[i], idx, live)
		if hv.Stale {
			v.StaleCount++
		}
		switch {
		case !hv.HasLive:
			v.UncheckedCount++
		case !hv.Live.Healthy:
			v.UnhealthyCount++
		}
		if !hv.Knockable {
			v.UnknockableCount++
		}
		v.Hosts = append(v.Hosts, hv)
	}
	sort.Slice(v.Hosts, func(i, j int) bool { return v.Hosts[i].Name < v.Hosts[j].Name })
	return v
}

func (s *sources) hostView(
	ctx context.Context,
	inv *config.Inventory,
	h *config.InventoryHost,
	idx *storeIndex,
	live *liveStore,
) HostView {
	hv := HostView{
		Name:             h.Name,
		HostID:           hex.EncodeToString(h.HostID[:]),
		KnockAddr:        h.KnockAddr.String(),
		Groups:           h.Groups,
		ProviderFronted:  h.ProviderFronted,
		ConsoleURL:       h.Console,
		InventoryVersion: inv.Version,
	}
	if h.SSH.Host != "" {
		hv.SSH = sshCommand(h.SSH)
	}

	// Services and grants come from the compiled policy rather than from the
	// raw inventory entry, because the compiled policy is what the host will
	// actually run: bundle.Compile is what resolves fleet defaults, adds the
	// fleet-wide action services, narrows every grant to this host, and drops
	// a grant left authorizing nothing. Reading the inventory by hand here
	// would produce a second answer to "what does this host permit", and the
	// second answer is the one that would be wrong.
	if policy, err := bundle.Compile(inv, h.Name); err == nil {
		hv.Services = serviceViews(policy)
		hv.Grants = grantViews(policy)
	}

	if e, ok := idx.Hosts[hv.HostID]; ok {
		hv.SignedVersion, hv.HasSigned = e.Version, true
	}
	hv.Hub = s.hub.Bundle(ctx, h.HostID)
	hv.Stale, hv.StaleReason = staleness(hv)

	if s.clientCfg != nil {
		if ch, err := s.clientCfg.Host(h.Name); err == nil {
			hv.Knockable = true
			hv.RecoveryService = ch.RecoveryService
			for name := range ch.Services {
				hv.ServiceNames = append(hv.ServiceNames, name)
			}
			sort.Strings(hv.ServiceNames)
			// Under rotation the knock port is time-derived, so the fleet view
			// shows the port a knock would land on right now — computed from the
			// same secret the client knocks with — rather than the inventory's
			// fixed spa_port. It advances each window, so the page's refresh
			// keeps it current. Fixed-port hosts keep the inventory address.
			if ch.PortRotation != nil {
				if port, ok := ch.CurrentKnockPort(s.clock().Unix()); ok {
					hv.KnockAddr = netip.AddrPortFrom(ch.KnockAddr, port).String()
				}
			}
		}
	}

	if st, ok := live.get(h.Name); ok {
		hv.Live, hv.HasLive = st, true
		age := s.clock().Sub(st.Checked)
		hv.LiveAge = age.Round(time.Second).String()
		hv.LiveCold = age >= s.liveAge()
	}
	return hv
}

func (s *sources) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *sources) liveAge() time.Duration {
	if s.liveMaxAge > 0 {
		return s.liveMaxAge
	}
	return DefaultLiveMaxAge
}

// DefaultLiveMaxAge is how long a console-run status observation stays
// interesting. Past it the fleet view marks the reading cold rather than
// dropping it: a five-minute-old "healthy" is still worth seeing, as long as
// nothing pretends it is current.
const DefaultLiveMaxAge = 2 * time.Minute

// staleness decides whether the bundle plane is behind for this host, and
// says which of the three ways it is.
//
// Order matters: "never signed" is checked before "hub is not serving",
// because a host that has never been signed has no bundle for a hub to serve
// and reporting the hub would name a symptom rather than the cause.
func staleness(hv HostView) (bool, string) {
	switch {
	case !hv.HasSigned:
		return true, "never signed: no bundle has been produced for this host"
	case hv.SignedVersion < hv.InventoryVersion:
		return true, fmt.Sprintf("signed at version %d, inventory is at %d",
			hv.SignedVersion, hv.InventoryVersion)
	case hv.Hub.Queried && hv.Hub.Err != "":
		return true, "the hub could not be asked: " + hv.Hub.Err
	case hv.Hub.Queried && !hv.Hub.Serving:
		return true, "signed, but the hub is not serving a bundle for this host"
	}
	return false, ""
}

func serviceViews(p *config.Policy) []ServiceView {
	out := make([]ServiceView, 0, len(p.Services))
	for name, svc := range p.Services {
		sv := ServiceView{
			Name:        name,
			Kind:        string(svc.Kind),
			Proto:       svc.Proto,
			FailPosture: string(svc.FailPosture),
		}
		for i, port := range svc.Ports {
			if i > 0 {
				sv.Ports += ", "
			}
			sv.Ports += fmt.Sprint(port)
		}
		if svc.DefaultTTL > 0 {
			sv.DefaultTTL = svc.DefaultTTL.String()
		}
		if svc.MaxTTL > 0 {
			sv.MaxTTL = svc.MaxTTL.String()
		}
		out = append(out, sv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func grantViews(p *config.Policy) []GrantView {
	var out []GrantView
	for _, op := range p.Operators {
		for _, g := range op.Grants {
			gv := GrantView{
				Operator:        op.Identity.Name,
				Services:        g.Services,
				AllowSourceCIDR: g.AllowSourceCIDR,
				MinIPv4Prefix:   g.MinIPv4Prefix,
				MinIPv6Prefix:   g.MinIPv6Prefix,
			}
			if g.MaxTTL > 0 {
				gv.MaxTTL = g.MaxTTL.String()
			}
			out = append(out, gv)
		}
	}
	return out
}

// sshCommand renders the command an operator runs once a gate is open, the
// same shape `postern open` prints.
func sshCommand(t config.InventorySSH) string {
	target := t.Host
	if t.User != "" {
		target = t.User + "@" + target
	}
	if t.Port != 0 && t.Port != 22 {
		return fmt.Sprintf("ssh -p %d %s", t.Port, target)
	}
	return "ssh " + target
}
