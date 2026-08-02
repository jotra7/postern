// Package config parses and validates postern configuration, resolving both
// standalone and fleet shapes into a single Policy the agent consumes.
package config

import (
	"fmt"
	"strings"
)

// ErrorList accumulates validation failures so an operator sees every problem
// in one pass rather than fixing them one run at a time.
type ErrorList []error

// Addf appends a formatted validation error.
func (e *ErrorList) Addf(format string, args ...any) {
	*e = append(*e, fmt.Errorf(format, args...))
}

// AddAll appends other to the receiver. If other was produced by another
// ErrorList's Err(), its individual problems are appended one by one rather
// than as a single wrapped item — the flattening callers need when they
// validate something that itself accumulates its own errors (Service.Validate
// wrapping ValidateServiceName; Policy.Validate wrapping each Service.Validate).
// Without this, the wrapped result nests one "N validation error(s):" block
// inside a single bullet of the outer list, and the outer count no longer
// equals the number of problems actually reported. Any other non-nil error is
// appended as a single item, same as Addf.
func (e *ErrorList) AddAll(other error) {
	if other == nil {
		return
	}
	if u, ok := other.(interface{ Unwrap() []error }); ok {
		*e = append(*e, u.Unwrap()...)
		return
	}
	*e = append(*e, other)
}

// Err returns nil when empty, otherwise a joined error whose Unwrap() []error
// exposes the individual items so a caller's ErrorList can flatten it via
// AddAll instead of nesting it as one opaque item.
func (e ErrorList) Err() error {
	if len(e) == 0 {
		return nil
	}
	return &joinedError{errs: append([]error(nil), e...)}
}

// joinedError is ErrorList.Err()'s concrete type. It keeps its constituent
// errors available through Unwrap() []error (the multi-error shape Go 1.20+
// tooling, including AddAll above, recognizes) while still rendering the
// same human-readable "N validation error(s): ..." text Error() always has.
type joinedError struct {
	errs []error
}

func (j *joinedError) Error() string {
	parts := make([]string, len(j.errs))
	for i, err := range j.errs {
		parts[i] = err.Error()
	}
	return fmt.Sprintf("%d validation error(s):\n  - %s", len(j.errs), strings.Join(parts, "\n  - "))
}

func (j *joinedError) Unwrap() []error {
	return j.errs
}
