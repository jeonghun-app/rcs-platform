package registrar

import (
	"errors"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// register is what the registrar reads from a REGISTER.
type register struct {
	// impu is the To URI in canonical form, the identity registered.
	impu string
	// impi is the Authorization username, or derived from impu.
	impi string
	// creds are the credentials for the registrar's realm; nil without any.
	creds *digest.Credentials
	// algorithm is the algorithm parameter the client sent, "" without one,
	// which leaves the choice of scheme to the registrar.
	algorithm string
	// integrityProtected is the integrity-protected parameter of creds.
	integrityProtected string

	contacts []sip.Contact
	// star is a Contact of "*", which with Expires 0 removes every binding.
	star bool
	// expires is the Expires header field, hasExpires whether there is one.
	expires    uint32
	hasExpires bool
	callID     string
	cseq       uint32
	// path is the Path header field, topmost first (RFC 3327).
	path []string
}

// parseRegister reads req, or returns the response a malformed one gets.
func parseRegister(req *sip.Request, realm string) (*register, *failure) {
	if req.Method != "REGISTER" {
		return nil, refuse(405, "")
	}
	to, err := req.Header.To()
	if err != nil {
		return nil, refuse(400, "Bad To")
	}
	impu, ok := identity.CanonicalIMPU(to.URI.String())
	if !ok {
		return nil, refuse(403, "Not a public identity")
	}
	r := &register{impu: impu}
	if r.callID, err = req.Header.CallID(); err != nil {
		return nil, refuse(400, "Bad Call-ID")
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return nil, refuse(400, "Bad CSeq")
	}
	r.cseq = cseq.Seq
	if f := r.readCredentials(req, realm); f != nil {
		return nil, f
	}
	if r.impi == "" {
		// TS 24.229 §5.4.1.2.1: without credentials the private identity is
		// the public one without its scheme, which needs a SIP URI.
		if !strings.HasPrefix(impu, "sip:") {
			return nil, refuse(403, "No private identity")
		}
		r.impi = strings.TrimPrefix(impu, "sip:")
	}
	if identity.ValidIMPI(r.impi) != nil {
		return nil, refuse(403, "Not a private identity")
	}
	contacts, err := req.Header.Contact()
	if err != nil {
		return nil, refuse(400, "Bad Contact")
	}
	for _, c := range contacts {
		if c.Star {
			r.star = true
			continue
		}
		r.contacts = append(r.contacts, c)
	}
	if req.Header.Has("Expires") {
		if r.expires, err = req.Header.Expires(); err != nil && !errors.Is(err, sip.ErrOutOfRange) {
			return nil, refuse(400, "Bad Expires")
		}
		r.hasExpires = true
	}
	// RFC 3261 §10.3 step 6: "*" only alone, and only to remove.
	if r.star && (len(r.contacts) > 0 || !r.hasExpires || r.expires != 0) {
		return nil, refuse(400, "Contact * needs Expires 0")
	}
	path, err := req.Header.Path()
	if err != nil {
		return nil, refuse(400, "Bad Path")
	}
	for _, p := range path {
		r.path = append(r.path, p.String())
	}
	return r, nil
}

// readCredentials takes the Authorization field for realm. One for another
// realm is left alone (RFC 3261 §22.4); a malformed one for this realm is a
// 400, and one with an algorithm Digest has no use for a 403.
func (r *register) readCredentials(req *sip.Request, realm string) *failure {
	list, err := req.Header.Authorization()
	values := req.Header.Values("Authorization")
	if err != nil || len(list) != len(values) {
		return refuse(400, "Bad Authorization")
	}
	for i, c := range list {
		if !strings.EqualFold(c.Scheme, "Digest") {
			continue
		}
		if v, _ := c.Param("realm"); v != realm {
			continue
		}
		creds, err := digest.ParseCredentials(strings.TrimSpace(values[i]))
		if errors.Is(err, digest.ErrUnsupportedAlgorithm) {
			return refuse(403, "Unsupported algorithm")
		}
		if err != nil {
			return refuse(400, "Bad Authorization")
		}
		r.creds = &creds
		r.impi = creds.Username
		r.algorithm, _ = c.Param("algorithm")
		r.integrityProtected, _ = c.Param("integrity-protected")
		return nil
	}
	return nil
}
