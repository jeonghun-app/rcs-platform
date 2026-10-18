package sdp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Reasons NegotiateMSRP declines an offered media line. Each one is answered
// by rejecting the line (RejectMedia), or the whole offer with 488 when no line
// is left.
var (
	ErrNotMSRP           = errors.New("sdp: not an MSRP media line")
	ErrMediaDisabled     = errors.New("sdp: offered media line has port 0")
	ErrNoCommonType      = errors.New("sdp: no accept-types in common")
	ErrTransportMismatch = errors.New("sdp: local path scheme does not match the offered transport")
)

// MSRPEndpoint describes the local end of an MSRP media line being answered.
type MSRPEndpoint struct {
	Port int
	// Path is the local a=path. Its first URI's scheme must match the offered
	// transport: msrps: for TCP/TLS/MSRP, msrp: for TCP/MSRP.
	Path               []string
	AcceptTypes        []string // what the local end can receive; may contain wildcards
	AcceptWrappedTypes []string // likewise inside a wrapper; empty for none
	MaxSize            int64    // advertised as a=max-size when positive
	// PreferredSetup is the role taken when the offer is actpass: active or
	// passive. Empty means passive, because rcs-as, the answerer this package
	// is written for, is always connected to by msrp-relay (ADR 0004).
	PreferredSetup Setup
}

func (e *MSRPEndpoint) validate() error {
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("sdp: local endpoint: port must be from 1 to 65535")
	}
	if err := validatePath(e.Path); err != nil {
		return err
	}
	if len(e.AcceptTypes) == 0 {
		return errors.New("sdp: local endpoint: at least one accept type is required")
	}
	if err := validateMediaTypes("accept-types", e.AcceptTypes); err != nil {
		return err
	}
	if err := validateMediaTypes("accept-wrapped-types", e.AcceptWrappedTypes); err != nil {
		return err
	}
	if e.MaxSize < 0 {
		return errors.New("sdp: local endpoint: max size must not be negative")
	}
	switch e.PreferredSetup {
	case "", SetupActive, SetupPassive:
		return nil
	}
	return fmt.Errorf("sdp: local endpoint: preferred setup must be active or passive, not %.32q", e.PreferredSetup)
}

// NewAnswer starts the answer to offer. RFC 3264 §6 requires one answer media
// line per offered line, in the same order, so every line starts out rejected
// and the caller replaces those it accepts with the result of NegotiateMSRP.
// The t= lines are copied from the offer, as RFC 3264 §6 also requires.
func NewAnswer(offer *Session, origin Origin, conn Connection) *Session {
	ans := &Session{Origin: origin, Name: "-", Connection: &conn}
	for _, t := range offer.Times {
		ans.Times = append(ans.Times, Time{Start: t.Start, Stop: t.Stop, Repeats: slices.Clone(t.Repeats)})
	}
	ans.Media = make([]Media, len(offer.Media))
	for i := range offer.Media {
		ans.Media[i] = RejectMedia(&offer.Media[i])
	}
	return ans
}

// RejectMedia returns the answer line that declines an offered media line:
// the same media type and transport with port 0, and the offered formats,
// since at least one must be listed (RFC 3264 §6).
func RejectMedia(offer *Media) Media {
	return Media{Type: offer.Type, Proto: offer.Proto, Formats: slices.Clone(offer.Formats)}
}

// NegotiateMSRP answers media line i of offer for the local endpoint.
//
// The answer accepts the accept-types and accept-wrapped-types the two ends
// have in common (RFC 4975 §8.6), takes the connection role that complements
// the offered one (RFC 4145 §4, RFC 6135 §4.2), mirrors the direction
// (RFC 3264 §6.1) and, for a file transfer, echoes a=file-selector and
// a=file-transfer-id (RFC 5547 §8). A line offered with port 0 is never
// accepted (ErrMediaDisabled), nor is one with no type in common
// (ErrNoCommonType); either way the caller keeps the rejected line from
// NewAnswer. offer is not modified.
func NegotiateMSRP(offer *Session, i int, local MSRPEndpoint) (Media, error) {
	m, err := offer.media(i)
	if err != nil {
		return Media{}, err
	}
	if !m.IsMSRP() {
		return Media{}, ErrNotMSRP
	}
	if m.Port == 0 {
		return Media{}, ErrMediaDisabled
	}
	if err := local.validate(); err != nil {
		return Media{}, err
	}
	if secure, _ := msrpScheme(local.Path[0]); secure != strings.EqualFold(m.Proto, ProtoMSRPS) {
		return Media{}, ErrTransportMismatch
	}
	if _, err := m.Path(); err != nil {
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}

	offered, err := m.AcceptTypes()
	if err != nil {
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}
	types := intersectTypes(offered, local.AcceptTypes)
	if len(types) == 0 {
		return Media{}, ErrNoCommonType
	}
	var wrapped []string
	switch offeredWrapped, err := m.AcceptWrappedTypes(); {
	case err == nil:
		wrapped = intersectTypes(offeredWrapped, local.AcceptWrappedTypes)
	case !errors.Is(err, ErrNoAttribute):
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}

	setup, err := answerSetup(offer, i, local.PreferredSetup)
	if err != nil {
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}
	dir, err := offer.MediaDirection(i)
	if err != nil {
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}

	ans := Media{Type: m.Type, Port: local.Port, Proto: m.Proto, Formats: slices.Clone(m.Formats)}
	ans.Attributes.Add("accept-types", strings.Join(types, " "))
	if len(wrapped) > 0 {
		ans.Attributes.Add("accept-wrapped-types", strings.Join(wrapped, " "))
	}
	if local.MaxSize > 0 {
		ans.Attributes.Add("max-size", strconv.FormatInt(local.MaxSize, 10))
	}
	ans.Attributes.Add("path", strings.Join(local.Path, " "))
	ans.Attributes.Add("setup", string(setup))
	ans.Attributes.Add(string(answerDirection(dir)), "")
	if err := echoFileTransfer(m, &ans); err != nil {
		return Media{}, fmt.Errorf("sdp: offer: %w", err)
	}
	return ans, nil
}

// answerSetup picks the answerer's role. Without a=setup the offerer follows
// the original RFC 4975 model and connects itself, so it is treated as active
// (RFC 6135 §4). holdconn is answered in kind (RFC 4145 §4).
func answerSetup(offer *Session, i int, preferred Setup) (Setup, error) {
	offered, err := offer.MediaSetup(i)
	switch {
	case errors.Is(err, ErrNoAttribute):
		offered = SetupActive
	case err != nil:
		return "", err
	}
	switch offered {
	case SetupActive:
		return SetupPassive, nil
	case SetupPassive:
		return SetupActive, nil
	case SetupHoldConn:
		return SetupHoldConn, nil
	}
	if preferred == "" {
		return SetupPassive, nil
	}
	return preferred, nil
}

func answerDirection(offered Direction) Direction {
	switch offered {
	case SendOnly:
		return RecvOnly
	case RecvOnly:
		return SendOnly
	}
	return offered
}

// echoFileTransfer copies the attributes that identify the file being
// accepted, after checking they parse, so a malformed selector is refused
// rather than reflected.
func echoFileTransfer(offer, ans *Media) error {
	if _, err := offer.FileSelector(); err == nil {
		v, _ := offer.Attributes.Get("file-selector")
		ans.Attributes.Add("file-selector", v)
	} else if !errors.Is(err, ErrNoAttribute) {
		return err
	}
	if id, err := offer.FileTransferID(); err == nil {
		ans.Attributes.Add("file-transfer-id", id)
	} else if !errors.Is(err, ErrNoAttribute) {
		return err
	}
	return nil
}

// intersectTypes returns the media types both lists accept, in the order of
// offered. A wildcard on one side matches the other side's entry, and the
// narrower of the two is kept: offering * and accepting text/plain yields
// text/plain. Media types compare case-insensitively.
func intersectTypes(offered, local []string) []string {
	var out []string
	for _, o := range offered {
		for _, l := range local {
			t, ok := narrower(o, l)
			if ok && !slices.ContainsFunc(out, func(s string) bool { return strings.EqualFold(s, t) }) {
				out = append(out, t)
			}
		}
	}
	return out
}

func narrower(a, b string) (string, bool) {
	switch {
	case strings.EqualFold(a, b):
		return a, true
	case a == "*":
		return b, true
	case b == "*":
		return a, true
	}
	aType, aSub, _ := strings.Cut(a, "/")
	bType, bSub, _ := strings.Cut(b, "/")
	switch {
	case !strings.EqualFold(aType, bType):
		return "", false
	case aSub == "*":
		return b, true
	case bSub == "*":
		return a, true
	}
	return "", false
}
