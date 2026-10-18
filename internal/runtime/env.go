package runtime

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Env reads typed settings from environment variables that share a prefix.
//
// Every getter returns its default when the variable is unset or empty, and
// records a problem, rather than falling back to the default, when the value
// cannot be parsed: a typo in a production setting must stop the service, not
// silently select the default. Problems accumulate so that one failed start
// lists every mistake at once; [Env.Err] returns them.
//
// Problems name the variable but never repeat its value, because a value put in
// the wrong variable may be a secret.
//
// An Env is meant for startup and is not safe for concurrent use.
type Env struct {
	prefix string
	lookup func(string) (string, bool)
	report *report
}

type report struct {
	problems []string
}

// NewEnv returns an Env reading prefix+name through lookup, which is normally
// os.LookupEnv.
func NewEnv(prefix string, lookup func(string) (string, bool)) *Env {
	return &Env{prefix: prefix, lookup: lookup, report: &report{}}
}

// WithPrefix returns an Env for another prefix that records its problems in the
// same list as e, so a service's own settings and the shared RCS_ settings are
// reported together.
func (e *Env) WithPrefix(prefix string) *Env {
	return &Env{prefix: prefix, lookup: e.lookup, report: e.report}
}

// Err returns a *ConfigError listing every problem recorded so far, or nil.
func (e *Env) Err() error {
	if len(e.report.problems) == 0 {
		return nil
	}
	return &ConfigError{Problems: append([]string(nil), e.report.problems...)}
}

// Invalid records a problem with the variable name (without the prefix) that a
// getter cannot detect, such as a port out of range or two settings that
// contradict each other.
func (e *Env) Invalid(name, reason string) {
	e.report.problems = append(e.report.problems, e.prefix+name+": "+reason)
}

func (e *Env) get(name string) (string, bool) {
	v, ok := e.lookup(e.prefix + name)
	return v, ok && v != ""
}

// String returns the variable's value, or def when it is unset or empty.
func (e *Env) String(name, def string) string {
	if v, ok := e.get(name); ok {
		return v
	}
	return def
}

// RequiredString returns the variable's value and records a problem when it is
// unset or empty.
func (e *Env) RequiredString(name string) string {
	v, ok := e.get(name)
	if !ok {
		e.Invalid(name, "required")
	}
	return v
}

// Int returns the variable as a base-10 integer.
func (e *Env) Int(name string, def int) int {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.Invalid(name, "not a base-10 integer in range")
		return def
	}
	return n
}

// Bool returns the variable as a boolean in any form strconv.ParseBool accepts
// (true, false, 1, 0, …). Anything else, "yes" included, is a problem.
func (e *Env) Bool(name string, def bool) bool {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.Invalid(name, "not a boolean (want true or false)")
		return def
	}
	return b
}

// Duration returns the variable as a Go duration ("250ms", "20s", "1h30m").
// Negative durations are problems: no setting is meaningful below zero.
func (e *Env) Duration(name string, def time.Duration) time.Duration {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.Invalid(name, `not a duration (want a number with a unit, such as "20s")`)
		return def
	}
	if d < 0 {
		e.Invalid(name, "negative duration")
		return def
	}
	return d
}

// List returns the variable as a comma-separated list. Spaces around items are
// dropped; an empty item ("a,,b" or a trailing comma) is a problem, since it is
// almost always a typo.
func (e *Env) List(name string, def []string) []string {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	items, ok := splitList(v)
	if !ok {
		e.Invalid(name, "empty item in comma-separated list")
		return def
	}
	return items
}

// CIDRs returns the variable as a comma-separated list of IPv4 or IPv6 prefixes
// ("10.0.0.0/8, fd00::/8"). A prefix with host bits set ("10.0.0.1/8") is a
// problem rather than being silently widened: the operator meant either the
// host or the network, and guessing wrong opens or closes access.
func (e *Env) CIDRs(name string, def []netip.Prefix) []netip.Prefix {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	items, ok := splitList(v)
	if !ok {
		e.Invalid(name, "empty item in comma-separated list")
		return def
	}
	prefixes := make([]netip.Prefix, 0, len(items))
	for i, item := range items {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			e.Invalid(name, fmt.Sprintf("item %d is not a CIDR prefix", i+1))
			return def
		}
		if p != p.Masked() {
			e.Invalid(name, fmt.Sprintf("item %d has host bits set", i+1))
			return def
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

func splitList(v string) ([]string, bool) {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
		if parts[i] == "" {
			return nil, false
		}
	}
	return parts, true
}

// ConfigError lists every configuration problem found at startup.
type ConfigError struct {
	Problems []string
}

func (e *ConfigError) Error() string {
	return "invalid configuration: " + strings.Join(e.Problems, "; ")
}
