package cxclient

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// DefaultSchemes is the order in which an S-CSCF asks the HSS for credentials
// when the client has not named an algorithm: IMS AKA first, which RCS
// devices with a SIM use, then SIP Digest, which the others use. The HSS
// answers 5006 for a scheme the user has no credentials of; asking with
// SIP-Authentication-Scheme "Unknown" instead would get 5006 from a user with
// AKA keys only (TS 29.228 §6.3.1), so the S-CSCF asks for each in turn.
var DefaultSchemes = []string{cx.SchemeDigestAKAv1MD5, cx.SchemeSIPDigest}

// Schemes returns the SIP-Authentication-Scheme values to ask for, in order,
// for a REGISTER whose Authorization names algorithm (empty when it has none
// or names none). An algorithm the client named wins: AKAv1-MD5 and AKAv2-MD5
// (RFC 3310, RFC 4169; the HSS has one vector for both) ask for AKA only, and
// the plain Digest algorithms (RFC 2617, RFC 7616) for SIP Digest only.
// Otherwise preference applies, DefaultSchemes when nil. ok is false for an
// algorithm the HSS has no credentials for, which the S-CSCF refuses.
func Schemes(algorithm string, preference []string) (schemes []string, ok bool) {
	switch strings.ToLower(algorithm) {
	case "":
		if preference == nil {
			preference = DefaultSchemes
		}
		return slices.Clone(preference), true
	case "akav1-md5", "akav2-md5":
		return []string{cx.SchemeDigestAKAv1MD5}, true
	case "md5", "md5-sess", "sha-256", "sha-256-sess", "sha-512-256", "sha-512-256-sess":
		return []string{cx.SchemeSIPDigest}, true
	}
	return nil, false
}

// Authenticate sends the MAR with each scheme in turn, as Schemes ordered them,
// and returns the first answer that is not DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED
// (5006), or the last one. Each MAR is a request of its own, with its own
// Session-Id.
func (c *Client) Authenticate(ctx context.Context, r *cx.MAR, schemes []string) (*cx.MAA, error) {
	if len(schemes) == 0 {
		return nil, errors.New("cxclient: no authentication scheme to ask for")
	}
	var maa *cx.MAA
	for _, s := range schemes {
		req := *r
		req.AuthDataItem.Scheme = s
		req.Request.SessionID = ""
		var err error
		maa, err = c.MAR(ctx, &req)
		if err != nil {
			return nil, err
		}
		if Classify(maa.Result) != SchemeNotSupported {
			return maa, nil
		}
	}
	return maa, nil
}
