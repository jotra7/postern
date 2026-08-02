package agent

import (
	"fmt"
	"log/slog"

	"github.com/jotra7/postern/internal/config"
)

// LoadRunningPolicy chooses the policy a host runs at startup.
//
// On a fleet host a prior confirm persisted the fetched configuration (see
// persistRunningPolicy). Loading it here is what keeps a restart running that
// configuration rather than the enrollment-time bootstrap, which would
// re-admit operators a bundle removed and reopen services it closed, and which
// the hub could not then correct because its same-version bundle is refused as
// not-newer (#52).
//
// bootstrap is the operator-written /etc/postern/postern.yaml: the enrollment
// seed, and the trust anchor. The bundle signers and fleet identity that
// authenticate every pull come from it, and nothing a fetched policy carries
// moves them -- the caller keeps building the pull loop from bootstrap, not
// from whatever this returns. persistedPath is empty in standalone mode, where
// the bootstrap file already is the running config.
//
// The rules, in order:
//
//   - No persisted file: the bootstrap policy. First boot before any confirm,
//     and every standalone host.
//   - Present but unparseable or invalid: an error. A fleet host whose durable
//     config is corrupt or tampered must not silently fall back to bootstrap
//     and re-admit removed operators; it fails to start and an operator looks.
//   - Present and valid but naming a different fleet or host: the bootstrap
//     policy, with a warning. A re-enrolled host whose previous enrollment's
//     policy still lingers on disk, not this enrollment's config.
//   - Present, valid, and this host's: the persisted policy.
func LoadRunningPolicy(bootstrap *config.Policy, persistedPath string, log *slog.Logger) (*config.Policy, error) {
	if persistedPath == "" {
		return bootstrap, nil
	}
	b, err := readBlob(persistedPath)
	if err != nil {
		return nil, fmt.Errorf("agent: read the persisted running policy %s: %w", persistedPath, err)
	}
	if !b.present {
		return bootstrap, nil
	}

	persisted, err := config.ParseStandalone(b.data)
	if err != nil {
		return nil, fmt.Errorf("agent: the persisted running policy %s does not parse, and a fleet host "+
			"will not silently fall back to its enrollment config over a corrupt one; fix or remove the "+
			"file: %w", persistedPath, err)
	}
	if err := persisted.Validate(); err != nil {
		return nil, fmt.Errorf("agent: the persisted running policy %s failed validation; fix or remove "+
			"the file: %w", persistedPath, err)
	}
	if persisted.FleetID != bootstrap.FleetID || persisted.HostID != bootstrap.HostID {
		log.Warn("the persisted running policy names a different fleet or host than the enrollment "+
			"config, so it is from a prior enrollment; ignoring it and running the bootstrap policy",
			"path", persistedPath,
			"persisted_fleet", fmt.Sprintf("%x", persisted.FleetID),
			"bootstrap_fleet", fmt.Sprintf("%x", bootstrap.FleetID),
			"persisted_host", fmt.Sprintf("%x", persisted.HostID),
			"bootstrap_host", fmt.Sprintf("%x", bootstrap.HostID))
		return bootstrap, nil
	}

	log.Info("running the persisted policy a prior confirm installed rather than the enrollment bootstrap",
		"path", persistedPath, "revision", persisted.Revision)
	return persisted, nil
}
