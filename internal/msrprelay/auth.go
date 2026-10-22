package msrprelay

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// Operations of the control API, the unit a caller's scope is made of
// (ADR 0007 §3; docs/api/msrp-relay.yaml has the scope table).
const (
	opCreate = "bindings.create"
	opUpdate = "bindings.update"
	opDelete = "bindings.delete"
)

// maxTokenLength bounds what is hashed for a presented token. Accepted
// tokens are far shorter; the bound only keeps a caller from making the
// relay hash a large header.
const maxTokenLength = 512

// caller is one service allowed to call the control API.
type caller struct {
	name string
	// digests are SHA-256 of the caller's accepted tokens, current and next.
	digests [][sha256.Size]byte
	scope   map[string]bool
}

// authorizer checks bearer tokens. Presented and accepted tokens are
// compared as SHA-256 digests in constant time, every accepted digest every
// time, so neither the length nor the content of a token, nor which caller
// it belongs to, shows in the time an answer takes (ADR 0007 §4).
type authorizer struct {
	callers []caller
}

// newAuthorizer accepts pcscf's tokens for every binding operation, which
// is all pcscf needs (ADR 0004). No token means no caller, and the API then
// answers 503 rather than being open.
func newAuthorizer(pcscfTokens []secret.Key) *authorizer {
	a := &authorizer{}
	if len(pcscfTokens) == 0 {
		return a
	}
	pcscf := caller{name: "pcscf", scope: map[string]bool{opCreate: true, opUpdate: true, opDelete: true}}
	for _, t := range pcscfTokens {
		pcscf.digests = append(pcscf.digests, sha256.Sum256(t.Reveal()))
	}
	a.callers = append(a.callers, pcscf)
	return a
}

// authenticate returns the caller presenting r's bearer token, or nil.
func (a *authorizer) authenticate(r *http.Request) *caller {
	token, ok := bearer(r.Header.Values("Authorization"))
	if !ok {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	var found *caller
	for i := range a.callers {
		for _, d := range a.callers[i].digests {
			if subtle.ConstantTimeCompare(sum[:], d[:]) == 1 {
				found = &a.callers[i]
			}
		}
	}
	return found
}

// bearer extracts the token of a single Authorization header with the
// Bearer scheme, whose name is case-insensitive (RFC 9110 §11.1; RFC 6750
// §2.1 for the token syntax).
func bearer(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	// The length check keeps EqualFold to ASCII: "K" (Kelvin) and the like
	// fold to letters of other schemes.
	if !ok || len(scheme) != len("Bearer") || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenLength {
		return "", false
	}
	// b64token: letters, digits and "-._~+/", then only "=" padding.
	body := strings.TrimRight(token, "=")
	if body == "" {
		return "", false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~+/", c) >= 0) {
			return "", false
		}
	}
	return token, true
}

// allows reports whether c may perform op.
func (c *caller) allows(op string) bool { return c.scope[op] }
