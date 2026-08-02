package agent

import (
	"errors"

	"github.com/jotra7/postern/internal/metrics"
	"github.com/jotra7/postern/internal/replay"
	"github.com/jotra7/postern/internal/spa"
)

// rejectReason maps a Validate error onto the closed label set
// internal/metrics accepts.
//
// The mapping is here rather than in internal/metrics because this package
// owns the sentinels, and it is a mapping onto a fixed enumeration rather
// than the error text because a label derived from error text would be
// attacker-influenced and unbounded — a rejected packet is unauthenticated
// input, and design section 8's whole point about rejections is that they are
// counted in aggregate rather than recorded one by one.
//
// Anything unrecognised becomes metrics.ReasonOther, which is a real
// operational signal in its own right: a rising "other" means a rejection
// path exists that this mapping does not know about.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, spa.ErrWrongSize):
		return "wrong_size"
	case errors.Is(err, spa.ErrNotCanonical):
		return "not_canonical"
	case errors.Is(err, spa.ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, spa.ErrUnknownKind):
		return "unknown_kind"
	case errors.Is(err, spa.ErrNoOperator):
		return "undecryptable"
	case errors.Is(err, spa.ErrKeyIDMismatch):
		return "key_id_mismatch"
	case errors.Is(err, spa.ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrWrongHost):
		return "wrong_host"
	case errors.Is(err, ErrTooOld):
		return "too_old"
	case errors.Is(err, ErrNotFresh):
		return "not_fresh"
	case errors.Is(err, ErrUnknownService):
		return "unknown_service"
	case errors.Is(err, ErrNotGranted):
		return "not_granted"
	case errors.Is(err, ErrKindMismatch):
		return "kind_mismatch"
	case errors.Is(err, ErrConfirmUnbound):
		return "confirm_unbound"
	case errors.Is(err, ErrSourceNotAllowed):
		return "source_not_allowed"
	case errors.Is(err, ErrUnsupportedAction):
		return "unsupported_action"
	case errors.Is(err, ErrLivenessOffPath):
		return "liveness_off_path"
	case errors.Is(err, replay.ErrDuplicate):
		return "replay"
	case errors.Is(err, replay.ErrCapacity):
		return "replay_capacity"
	case errors.Is(err, ErrStore):
		// Checked after the two specific replay outcomes above, because
		// Validate wraps both of them in ErrStore and a store-wide label
		// would hide the one rejection an operator actually acts on: a
		// duplicate request_id is a replay, not a disk problem.
		return "store"
	default:
		return metrics.ReasonOther
	}
}
