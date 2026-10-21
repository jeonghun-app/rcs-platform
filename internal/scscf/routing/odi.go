package routing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// odiParam names the parameter of the Route back to the S-CSCF that carries
// a request's place in its served user's iFC chain: the original dialog
// identifier of TS 24.229 §5.4.3.2 and §5.4.3.3 (ADR 0005).
const odiParam = "odi"

// odiLabel separates these MACs from any other made with the same key.
const odiLabel = "rcs-platform scscf odi v1"

// odiMACBytes is how much of the HMAC-SHA256 the parameter keeps.
const odiMACBytes = 16

// position is where a request is in its served user's iFC chain: the
// user, the session case and its state, and the priority of the last
// criterion applied, -1 before the first.
type position struct {
	served     string
	scase      ifc.SessionCase
	registered bool
	priority   int
	// kept says the request came with a P-Served-User of its own, from an
	// application server that sent it for its user (#137), which the chain
	// keeps seeing: the one the S-CSCF puts in toward a server replaces it
	// (TS 24.229 §5.4.3.2), and hiding that would hide the request's own.
	kept bool
	// expires is when the position signed for the request opened stops
	// opening, zero for one not opened.
	expires time.Time
}

// Bits of the flags byte of a signed position.
const (
	flagRegistered = 1 << iota
	flagKept
)

// errBadODI is a Route parameter that is not one this S-CSCF signed for
// the request, or has expired.
var errBadODI = errors.New("routing: bad or expired iFC position")

// signODI writes pos as the value of the odi parameter for the request with
// callID, valid until expires: the current key's ID, the position, and an
// HMAC under that key over it and the Call-ID, so that it cannot be
// changed, replayed on another request, or used later (ADR 0005).
func (rt *Router) signODI(pos position, callID string, expires time.Time) string {
	payload := make([]byte, 0, 14+len(pos.served))
	payload = binary.BigEndian.AppendUint64(payload, uint64(expires.Unix()))
	payload = append(payload, byte(pos.scase))
	var flags byte
	if pos.registered {
		flags |= flagRegistered
	}
	if pos.kept {
		flags |= flagKept
	}
	payload = append(payload, flags)
	payload = binary.BigEndian.AppendUint32(payload, uint32(int32(pos.priority)))
	payload = append(payload, pos.served...)
	k := rt.cfg.DialogKeys[0]
	enc := base64.RawURLEncoding
	return k.ID + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString(odiMAC(k, payload, callID))
}

// odiMAC is the MAC under k of payload for the request with callID.
func odiMAC(k DialogKey, payload []byte, callID string) []byte {
	m := hmac.New(sha256.New, k.Key)
	m.Write([]byte(odiLabel))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(payload)))
	m.Write(n[:])
	m.Write(payload)
	m.Write([]byte(callID))
	return m.Sum(nil)[:odiMACBytes]
}

// openODI reads a position signODI wrote for the request with callID, at
// now: errBadODI unless it is intact and not expired.
func (rt *Router) openODI(v, callID string, now time.Time) (position, error) {
	enc := base64.RawURLEncoding.Strict()
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return position{}, errBadODI
	}
	i := slices.IndexFunc(rt.cfg.DialogKeys, func(k DialogKey) bool { return k.ID == parts[0] })
	payload, err1 := enc.DecodeString(parts[1])
	mac, err2 := enc.DecodeString(parts[2])
	if i < 0 || err1 != nil || err2 != nil || len(payload) < 14 || !hmac.Equal(mac, odiMAC(rt.cfg.DialogKeys[i], payload, callID)) {
		return position{}, errBadODI
	}
	expires := int64(binary.BigEndian.Uint64(payload))
	if now.Unix() > expires {
		return position{}, errBadODI
	}
	return position{
		scase:      ifc.SessionCase(payload[8]),
		registered: payload[9]&flagRegistered != 0,
		kept:       payload[9]&flagKept != 0,
		priority:   int(int32(binary.BigEndian.Uint32(payload[10:]))),
		served:     string(payload[14:]),
		expires:    time.Unix(expires, 0).UTC(),
	}, nil
}

// routedODI is the odi parameter of the S-CSCF's own Route entries the
// request consumed, if one has it: one without a value is still one, which
// openODI refuses, and no request with it is taken for a new one.
func routedODI(routed []sip.Address) (string, bool) {
	for _, a := range routed {
		if v, ok := a.URI.Param(odiParam); ok {
			return v, true
		}
	}
	return "", false
}
