package console

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jotra7/postern/internal/bundle"
	"github.com/jotra7/postern/internal/config"
	"github.com/jotra7/postern/internal/identity"
)

// signedIssuedAt is the fixed instant stamped into every bundle's issued_at,
// matching cmd/postern/cmd_sign.go exactly. Wall-clock time there would make
// two signing runs of one unchanged inventory produce different bytes, and a
// console that signed differently from the CLI would produce bundles an
// operator could not tell apart from a real change.
var signedIssuedAt = time.Unix(0, 0).UTC()

// DeployChange is what would happen to one host on the next signing run.
type DeployChange struct {
	Host   string
	HostID string
	// Knock is the address:port an operator's knock is sent to for this host,
	// resolved from its own spa_port if set and defaults.spa_port otherwise. It
	// is surfaced so a per-host knock-port override is visible in the deploy
	// preview before the run is signed.
	Knock string
	// From is the version index.json currently records; HasFrom is false when
	// this host has never been signed.
	From    uint64
	HasFrom bool
	// To is the version the inventory declares.
	To uint64
	// Action is "new", "update", or "unchanged".
	Action string
	// HubServing is what the hub is doing about this host right now.
	HubServing bool
	HubQueried bool
	// PolicyErr is set when this host's policy does not compile, which stops
	// the whole run rather than producing a partial deploy.
	PolicyErr string
}

// DeployPlan is the diff between what the hub currently serves and what the
// inventory says it should.
//
// "The diff" is a version and membership diff, not a policy text diff, and
// the reason is structural rather than a shortcut: a bundle is sealed
// ciphertext (internal/bundle), the hub cannot read it and neither can this
// console, and the seal is anonymous and randomised so two seals of identical
// bytes do not even compare equal. index.json is the only record of what
// version is on file, which is exactly why `postern sign` keeps it. What the
// plan can therefore say is which hosts are new, which move version, which do
// not, and which the hub is not serving at all — and it says only that.
type DeployPlan struct {
	Version uint64
	Changes []DeployChange
	// Blocked is set when the run would be refused, with Reason saying why.
	// The version floor is the usual one: re-signing at a version that is not
	// newer produces bundles every agent rejects as not-newer.
	Blocked bool
	Reason  string
	// Signer is the operator name the inventory says must sign, resolved the
	// same way `postern sign --as` resolves it.
	Signer string
	// New, Update, Unchanged and Broken are Changes counted by what would
	// happen to each host, so the page can be scanned before the table is
	// read. Broken is how many hosts do not compile, which stops the run.
	New       int
	Update    int
	Unchanged int
	Broken    int
	// Err is a whole-plan failure: an unreadable inventory, a signer the
	// inventory does not declare.
	Err string
}

// planDeploy computes the plan without signing anything and without touching
// a key. It is what the GET side of the deploy page renders, which is the
// property that keeps signing a POST.
func (s *sources) planDeploy() DeployPlan {
	var p DeployPlan
	inv, err := s.loadInventory()
	if err != nil {
		p.Err = err.Error()
		return p
	}
	p.Version = inv.Version
	if name, err := resolveSigner(inv, ""); err == nil {
		p.Signer = name
	} else {
		p.Err = err.Error()
		return p
	}

	idx, err := readIndex(s.outDir)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	if floor, ok := idx.maxVersion(); ok && inv.Version <= floor {
		p.Blocked = true
		p.Reason = fmt.Sprintf("inventory version %d is not newer than %d, the highest version already in %s. "+
			"Re-signing at a version that is not newer produces bundles every agent rejects as not-newer; "+
			"bump the inventory's version field first.", inv.Version, floor, s.outDir)
	}

	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		c := DeployChange{
			Host:   h.Name,
			HostID: hex.EncodeToString(h.HostID[:]),
			Knock:  h.KnockAddr.String(),
			To:     inv.Version,
		}
		if e, ok := idx.Hosts[c.HostID]; ok {
			c.From, c.HasFrom = e.Version, true
		}
		switch {
		case !c.HasFrom:
			c.Action = "new"
			p.New++
		case c.From < c.To:
			c.Action = "update"
			p.Update++
		default:
			c.Action = "unchanged"
			p.Unchanged++
		}
		if _, err := bundle.Compile(inv, h.Name); err != nil {
			c.PolicyErr = err.Error()
			p.Broken++
		}
		p.Changes = append(p.Changes, c)
	}
	sort.Slice(p.Changes, func(i, j int) bool { return p.Changes[i].Host < p.Changes[j].Host })
	return p
}

// DeployResult is what a signing run did.
type DeployResult struct {
	Version uint64
	Signer  string
	Hosts   []string
	OutDir  string
	Err     string
}

// runDeploy compiles the inventory, seals one bundle per host, and writes
// them plus index.json into the output directory — the same sequence
// `postern sign` performs, with the same two identity checks in front of it
// and the same all-or-nothing write.
//
// The identity checks are not decoration. The signer's name must match the
// operator the inventory nominates, AND its actual public signing key must
// match what the inventory records for that operator: a name match alone
// would let a stale or mistyped local key produce bundles every agent rejects
// as coming from an untrusted signer, which is discovered at rollout rather
// than here.
func (s *sources) runDeploy(signer identity.Signer) DeployResult {
	var res DeployResult
	res.OutDir = s.outDir
	if s.outDir == "" {
		res.Err = "no output directory is configured, so there is nowhere to write bundles"
		return res
	}
	inv, err := s.loadInventory()
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Version = inv.Version

	asName, err := resolveSigner(inv, "")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Signer = asName
	op, err := findOperator(inv, asName)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if signer.Public().Name != asName {
		res.Err = fmt.Sprintf("the unlocked signing key is named %q, but the inventory's bundle signer is %q",
			signer.Public().Name, asName)
		return res
	}
	if signer.Public().Signing != op.Identity.Signing {
		res.Err = fmt.Sprintf("the unlocked signing key does not match the signing key the inventory records "+
			"for operator %q; bundles it signed would be rejected by every agent as coming from an untrusted signer",
			asName)
		return res
	}

	idx, err := readIndex(s.outDir)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if floor, ok := idx.maxVersion(); ok && inv.Version <= floor {
		res.Err = fmt.Sprintf("inventory version %d is not newer than %d, the highest version already in %s; "+
			"bump the inventory's version field before signing again", inv.Version, floor, s.outDir)
		return res
	}

	// Compile and seal everything before writing anything. A failure partway
	// through must not leave the directory holding some bundles at the new
	// version and some stale, which is the half-deployed state the version
	// floor above exists to stop an operator creating by hand.
	type sealedHost struct {
		host   config.InventoryHost
		sealed bundle.Sealed
	}
	sealed := make([]sealedHost, 0, len(inv.Hosts))
	for _, h := range inv.Hosts {
		policy, err := bundle.Compile(inv, h.Name)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		policyBytes, err := config.MarshalStandalone(policy)
		if err != nil {
			res.Err = fmt.Sprintf("host %q: marshal policy: %v", h.Name, err)
			return res
		}
		b, err := bundle.Seal(&bundle.Contents{
			FleetID:  inv.FleetID,
			HostID:   h.HostID,
			Version:  inv.Version,
			IssuedAt: signedIssuedAt,
			Policy:   policyBytes,
		}, signer, h.HostIdentity.Encryption)
		if err != nil {
			if errors.Is(err, bundle.ErrRecipientKey) {
				res.Err = fmt.Sprintf("host %q: host_identity.encryption is not a usable X25519 point: %v", h.Name, err)
				return res
			}
			res.Err = fmt.Sprintf("host %q: seal: %v", h.Name, err)
			return res
		}
		sealed = append(sealed, sealedHost{host: h, sealed: b})
	}

	if err := os.MkdirAll(s.outDir, 0o750); err != nil {
		res.Err = fmt.Sprintf("create %s: %v", s.outDir, err)
		return res
	}
	for _, sh := range sealed {
		path := filepath.Join(s.outDir, hex.EncodeToString(sh.host.HostID[:])+".bundle")
		// Sealed ciphertext, meant to be served, and readable by whatever
		// serves it — the same mode `postern sign` writes.
		if err := os.WriteFile(path, sh.sealed, 0o644); err != nil { //nolint:gosec // sealed ciphertext, meant to be served
			res.Err = fmt.Sprintf("write %s: %v", path, err)
			return res
		}
		idx.set(sh.host.HostID, sh.host.HostIdentity.Signing, inv.Version)
		res.Hosts = append(res.Hosts, sh.host.Name)
	}
	if err := idx.writeTo(s.outDir); err != nil {
		res.Err = err.Error()
		return res
	}
	return res
}

// resolveSigner applies the same rule `postern sign --as` applies: the
// inventory's one bundle_signers entry when there is exactly one, and a
// refusal naming the choice when there is more than one. The console offers
// no --as of its own, so a multi-signer fleet signs from the CLI.
func resolveSigner(inv *config.Inventory, as string) (string, error) {
	if as != "" {
		for _, name := range inv.BundleSigners {
			if name == as {
				return as, nil
			}
		}
		return "", fmt.Errorf("%q is not in the inventory's bundle_signers %v", as, inv.BundleSigners)
	}
	switch len(inv.BundleSigners) {
	case 1:
		return inv.BundleSigners[0], nil
	case 0:
		return "", errors.New("the inventory declares no bundle signers")
	default:
		return "", fmt.Errorf("the inventory names %d bundle signers %v; this console does not choose between "+
			"them — sign from the CLI with `postern sign --as NAME`", len(inv.BundleSigners), inv.BundleSigners)
	}
}

func findOperator(inv *config.Inventory, name string) (*config.InventoryOperator, error) {
	for i := range inv.Operators {
		if inv.Operators[i].Identity.Name == name {
			return &inv.Operators[i], nil
		}
	}
	return nil, fmt.Errorf("operator %q is not declared in the inventory", name)
}
