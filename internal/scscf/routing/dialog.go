package routing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// dlgParam names the parameter of the S-CSCF's Record-Route value that
// binds a dialog's hops (#322): a key ID and a MAC per hop.
const dlgParam = "dlg"

// dlgLabel separates these MACs from any other made with the same key.
const dlgLabel = "rcs-platform scscf dialog hop v1"

// dlgMACBytes is how much of each HMAC-SHA256 the parameter keeps.
const dlgMACBytes = 16

// MinDialogKeyBytes is the shortest DialogKey.Key.
const MinDialogKeyBytes = 32

// DialogKey is a key the S-CSCF signs its Record-Route values with. ID names
// it in the values, so that the key can be rotated: the first of
// Config.DialogKeys signs, and each verifies.
type DialogKey struct {
	ID  string
	Key []byte
}

// redactedKey is what a DialogKey prints as: its ID, never its key.
func (k DialogKey) redacted() string { return "DialogKey{ID:" + k.ID + " Key:[redacted]}" }

// String, GoString, Format, LogValue and MarshalJSON print the key's ID
// alone, so that a Config logged or printed does not give the key away.
func (k DialogKey) String() string               { return k.redacted() }
func (k DialogKey) GoString() string             { return k.redacted() }
func (k DialogKey) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.redacted()) }
func (k DialogKey) LogValue() slog.Value         { return slog.StringValue(k.redacted()) }
func (k DialogKey) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// endpoint is a URI as a hop of a dialog: its scheme, user, host, port and
// transport, the default port and transport written out, so that the URI a
// route set holds compares equal to the one the S-CSCF signed, and to no URI
// that reaches another listener.
type endpoint struct {
	scheme, user, host string
	port               int
	transport          string
}

func endpointOf(u sip.URI) endpoint {
	e := endpoint{scheme: strings.ToLower(u.Scheme), user: u.User, host: proxy.HostKey(u.Host), port: u.Port, transport: "udp"}
	if e.scheme == "sips" {
		e.transport = "tls"
	}
	if t, ok := u.Param("transport"); ok {
		e.transport = strings.ToLower(t)
	}
	if e.port == 0 {
		e.port = 5060
		if e.transport == "tls" {
			e.port = 5061
		}
	}
	return e
}

// hopKey is u's endpoint as the S-CSCF signs it.
func hopKey(u sip.URI) string {
	e := endpointOf(u)
	return e.scheme + ":" + e.user + "@" + e.host + ":" + strconv.Itoa(e.port) + ";" + e.transport
}

// hopMAC is the MAC under k of hop as a hop of the dialog with callID, at
// this S-CSCF, named by its Record-Route host.
func (rt *Router) hopMAC(k DialogKey, callID, hop string) []byte {
	m := hmac.New(sha256.New, k.Key)
	for _, part := range []string{dlgLabel, rt.cfg.RecordRoute.URI.Host, callID, hop} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		m.Write(n[:])
		m.Write([]byte(part))
	}
	return m.Sum(nil)[:dlgMACBytes]
}

// signedRR is the S-CSCF's Record-Route value for the dialog with callID
// whose hops next to the S-CSCF are hops, as hopKey writes them: the
// configured value with the current key's ID and a MAC per hop.
func (rt *Router) signedRR(callID string, hops ...string) sip.Address {
	k := rt.cfg.DialogKeys[0]
	v := k.ID
	for _, h := range hops {
		v += "." + base64.RawURLEncoding.EncodeToString(rt.hopMAC(k, callID, h))
	}
	a := rt.cfg.RecordRoute
	a.URI.Params = append(sip.Params(nil), a.URI.Params...)
	a.URI.Params.Set(dlgParam, v)
	return a
}

// signedHop reports whether hop is one of the hops v, a dlg parameter the
// S-CSCF wrote for the dialog with callID, signs, under the key it names.
func (rt *Router) signedHop(v, callID, hop string) bool {
	id, macs, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	for _, k := range rt.cfg.DialogKeys {
		if k.ID != id {
			continue
		}
		want := rt.hopMAC(k, callID, hop)
		for m := range strings.SplitSeq(macs, ".") {
			got, err := base64.RawURLEncoding.Strict().DecodeString(m)
			if err == nil && hmac.Equal(got, want) {
				return true
			}
		}
	}
	return false
}

// recorder signs the S-CSCF's Record-Route value in the requests and the
// responses of one request that may set up a dialog. In each branch the
// value signs the hop toward the caller, which the callee's requests go to
// next: the Record-Route value below the S-CSCF's, or the caller's Contact.
// In a response it signs that hop and the one toward the callee, which the
// caller's requests go to: the value above the S-CSCF's, or the callee's
// Contact. A UA copies the values into its route set (RFC 3261 §12.1), so
// each in-dialog request carries the one its sender's route set holds.
// It is used only for a request that sets up a dialog (formsDialog), which
// pcscf records too; the Contact stands in only for a sender that records
// no route, as rcs-as, a core service, does for the requests it sends for
// its users.
type recorder struct {
	rt     *Router
	callID string
	// caller is the hop toward the caller, "" without one.
	caller string

	mu sync.Mutex
	// written are the values the branches carried, the S-CSCF's own to
	// find in responses, which may hold other values of it (a request
	// that passed it twice).
	written map[string]bool
}

func (rt *Router) recorder(req *sip.Request) *recorder {
	rec := &recorder{rt: rt, callID: req.Header.Get("Call-ID"), written: map[string]bool{}}
	if rr, err := req.Header.RecordRoute(); err == nil && len(rr) > 0 {
		rec.caller = hopKey(rr[0].URI)
	} else if cs, err := req.Header.Contact(); err == nil && len(cs) > 0 {
		rec.caller = hopKey(cs[0].Address.URI)
	}
	return rec
}

// hops are those of the value signed for hops in the given direction:
// none is no hop, which no next hop equals.
func (rec *recorder) hops(more ...string) []string {
	var out []string
	for _, h := range append([]string{rec.caller}, more...) {
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// prepare signs the S-CSCF's Record-Route value in a branch, the topmost.
func (rec *recorder) prepare(req *sip.Request) error {
	rr, err := req.Header.Elements("Record-Route")
	if err != nil || len(rr) == 0 || rr[0] != rec.rt.cfg.RecordRoute.String() {
		return err
	}
	v := rec.rt.signedRR(rec.callID, rec.hops()...)
	sv, _ := v.URI.Param(dlgParam)
	rec.mu.Lock()
	rec.written[sv] = true
	rec.mu.Unlock()
	return req.Header.ReplaceFirstElement("Record-Route", v.String())
}

// response signs the S-CSCF's value in res's Record-Route again, for the
// hop toward the callee as well.
func (rec *recorder) response(_ context.Context, res *sip.Response) {
	els, err := res.Header.Elements("Record-Route")
	if err != nil {
		return
	}
	for i, e := range els {
		a, err := sip.ParseAddress(e)
		if err != nil {
			continue
		}
		v, ok := a.URI.Param(dlgParam)
		rec.mu.Lock()
		ours := ok && rec.written[v]
		rec.mu.Unlock()
		if !ours {
			continue
		}
		callee := ""
		if i > 0 {
			if above, err := sip.ParseAddress(els[i-1]); err == nil {
				callee = hopKey(above.URI)
			}
		} else if cs, err := res.Header.Contact(); err == nil && len(cs) > 0 {
			callee = hopKey(cs[0].Address.URI)
		}
		els[i] = rec.rt.signedRR(rec.callID, rec.hops(callee)...).String()
		res.Header.Del("Record-Route")
		for _, e := range els {
			if err := res.Header.Add("Record-Route", e); err != nil {
				return
			}
		}
		return
	}
}
