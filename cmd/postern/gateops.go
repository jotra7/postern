package main

import "github.com/jotra7/postern/internal/gate"

// gateCommands selects what gate-teardown and gate-flush each run.
//
// It lives here, without a build tag, so the one property separating the two
// commands is testable on any platform rather than only inside the container:
// gate-flush must never delete a table. Its whole documented purpose is
// "empty every fail-closed gate set, leaving its drop rules standing", and a
// version that also removed postern_open would silently take down every
// fail-open service on the host.
//
// The list comes from gate.TeardownCommands — the same single source the
// rendered unit's ExecStopPost lines come from — so what an operator types
// and what systemd runs cannot drift. What this function must not do is
// depend on the *order* of that list. An earlier version sliced it with
// cmds[1:], which encoded "the postern_open delete is first" as an
// unexpressed cross-package invariant: reordering TeardownCommands, or
// adding a second command ahead of the delete, would have turned gate-flush
// into a command that deletes a table, with nothing failing. Filtering on
// the verb says what is meant.
func gateCommands(plan *gate.RulesetPlan, nftPath string, includeOpen bool) [][]string {
	all := gate.TeardownCommands(plan, nftPath)
	if includeOpen {
		return all
	}
	kept := make([][]string, 0, len(all))
	for _, argv := range all {
		if isDeleteCommand(argv) {
			continue
		}
		kept = append(kept, argv)
	}
	return kept
}

// isDeleteCommand reports whether an argv removes something rather than
// emptying it. nft's grammar puts the verb immediately after the binary.
func isDeleteCommand(argv []string) bool {
	return len(argv) > 1 && argv[1] == "delete"
}
