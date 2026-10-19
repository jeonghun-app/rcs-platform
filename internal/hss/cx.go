package hss

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// CxServer answers the Cx requests of the I-CSCF and S-CSCF: UAR, MAR, SAR
// and LIR (TS 29.228 §6.1, §6.3; TS 29.229 §6.1).
type CxServer struct {
	h       *HSS
	node    *diameter.Node
	timeout time.Duration
}

// DefaultCxTimeout bounds the store work of one Cx request, well inside the
// S-CSCF's own Diameter request timeout.
const DefaultCxTimeout = 3 * time.Second

// ServeCx registers the Cx handlers on node, which must have the Cx
// dictionary and advertise cx.Application. timeout bounds each request's
// store work; DefaultCxTimeout when zero.
func (h *HSS) ServeCx(node *diameter.Node, timeout time.Duration) *CxServer {
	if timeout <= 0 {
		timeout = DefaultCxTimeout
	}
	c := &CxServer{h: h, node: node, timeout: timeout}
	node.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	node.HandleFunc(cx.ApplicationID, cx.CodeUserAuthorization, c.uar)
	node.HandleFunc(cx.ApplicationID, cx.CodeMultimediaAuth, c.mar)
	node.HandleFunc(cx.ApplicationID, cx.CodeServerAssignment, c.sar)
	node.HandleFunc(cx.ApplicationID, cx.CodeLocationInfo, c.lir)
	return c
}

// errResult is a Cx outcome reached before the procedure's own steps, such
// as an unknown user; handlers answer it in their command's format.
type errResult struct{ result cx.Result }

func (e *errResult) Error() string { return "cx: " + e.result.String() }

func experimental(code uint32) error { return &errResult{cx.ExperimentalResult(code)} }

var errUnableToComply = &errResult{cx.ResultCode(diameter.ResultUnableToComply)}

// resultOf turns an error from the procedure into the result to answer
// with. A store or keyring failure is DIAMETER_UNABLE_TO_COMPLY, as every
// procedure prescribes for an HSS that cannot fulfil a request, and is
// logged without the request.
func (c *CxServer) resultOf(cmd string, err error) cx.Result {
	var er *errResult
	if errors.As(err, &er) {
		return er.result
	}
	c.h.metrics.Count("cx."+cmd+".error", 1)
	c.h.log.Error("Cx request failed", slog.String("command", cmd), slog.String("error", pii.Redact(err.Error())))
	return cx.ResultCode(diameter.ResultUnableToComply)
}

// timed records the time a command takes, so a slow store shows in
// cx.<command> before requests start to time out.
func (c *CxServer) timed(cmd string) func() {
	start := time.Now()
	return func() { c.h.metrics.Timing("cx."+cmd, time.Since(start)) }
}

// busy is the answer to a request that waited too long for its
// subscription's lock in this task (errBusy): DIAMETER_TOO_BUSY, a protocol
// error (RFC 6733 §7.1.3), which the node sends in the generic answer
// format and which lets the client try another HSS task. A failing store
// is DIAMETER_UNABLE_TO_COMPLY instead (resultOf): every task shares it.
func busy(err error) error {
	if errors.Is(err, errBusy) {
		return &diameter.Error{ResultCode: diameter.ResultTooBusy, Message: "subscription busy"}
	}
	return nil
}

func (c *CxServer) count(cmd string, r cx.Result) {
	name := "cx." + cmd + "." + strconv.FormatUint(uint64(r.Code), 10)
	if r.Vendor != 0 {
		name = "cx." + cmd + ".e" + strconv.FormatUint(uint64(r.Code), 10)
	}
	c.h.metrics.Count(name, 1)
}

// pair finds the subscription of impi and checks that impu, in canonical
// form, is one of its identities (TS 29.228 §6.1.1.1, §6.3.1 steps 1 to 3).
func (c *CxServer) pair(ctx context.Context, impi, impu string) (*store.Subscription, string, error) {
	canonical, ok := identity.CanonicalIMPU(impu)
	if !ok {
		return nil, "", experimental(cx.ErrorUserUnknown)
	}
	s, err := c.h.store.Subscription(ctx, impi)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", experimental(cx.ErrorUserUnknown)
	}
	if err != nil {
		return nil, "", err
	}
	if s.Identity(canonical) != nil {
		return s, canonical, nil
	}
	// Both identities exist but do not belong together, or the IMPU is
	// unknown.
	_, err = c.h.store.SubscriptionByIMPU(ctx, canonical)
	switch {
	case err == nil:
		return nil, "", experimental(cx.ErrorIdentitiesDontMatch)
	case errors.Is(err, store.ErrNotFound):
		return nil, "", experimental(cx.ErrorUserUnknown)
	}
	return nil, "", err
}

// byIMPU finds the subscription of a public identity.
func (c *CxServer) byIMPU(ctx context.Context, impu string) (*store.Subscription, string, error) {
	canonical, ok := identity.CanonicalIMPU(impu)
	if !ok {
		return nil, "", experimental(cx.ErrorUserUnknown)
	}
	s, err := c.h.store.SubscriptionByIMPU(ctx, canonical)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", experimental(cx.ErrorUserUnknown)
	}
	return s, canonical, err
}

// profile reads a subscription's service profile. A missing one is a
// provisioning fault (docs/hss.md): the request cannot be served.
func (c *CxServer) profile(ctx context.Context, s *store.Subscription) (*store.ServiceProfile, error) {
	p, err := c.h.store.Profile(ctx, s.Profile)
	if errors.Is(err, store.ErrNotFound) {
		c.h.metrics.Count("profile.missing", 1)
		return nil, fmt.Errorf("hss: subscription refers to a missing service profile: %w", err)
	}
	return p, err
}

func (c *CxServer) context(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

func (c *CxServer) uar(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	defer c.timed("uar")()
	r, err := cx.ParseUAR(req)
	if err != nil {
		return nil, err
	}
	if r.AuthorizationType < cx.AuthorizeRegistration || r.AuthorizationType > cx.AuthorizeRegistrationAndCapabilities {
		return nil, &diameter.Error{ResultCode: diameter.ResultInvalidAVPValue,
			FailedAVP: req.Find(cx.AVPUserAuthorizationType, cx.Vendor3GPP), Message: "unknown User-Authorization-Type"}
	}
	ctx, cancel := c.context(ctx)
	defer cancel()
	var a cx.UAA
	out, err := c.decideUAR(ctx, r)
	if err != nil {
		a.Result = c.resultOf("uar", err)
	} else {
		a.Result, a.ServerName = out.result, out.serverName
		if out.capabilities {
			a.ServerCapabilities = out.caps
		}
	}
	c.count("uar", a.Result)
	return a.Message(c.node, req)
}

type uarAnswer struct {
	uarOutcome
	caps *cx.ServerCapabilities
}

func (c *CxServer) decideUAR(ctx context.Context, r *cx.UAR) (uarAnswer, error) {
	s, impu, err := c.pair(ctx, r.UserName, r.PublicIdentity)
	if err != nil {
		return uarAnswer{}, err
	}
	out := uarAnswer{uarOutcome: decideUAR(s, impu, r.AuthorizationType)}
	if out.capabilities {
		p, err := c.profile(ctx, s)
		if err != nil {
			return uarAnswer{}, err
		}
		out.caps = c.h.capabilities(p)
	}
	return out, nil
}

func (c *CxServer) lir(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	defer c.timed("lir")()
	r, err := cx.ParseLIR(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.context(ctx)
	defer cancel()
	var a cx.LIA
	out, err := c.decideLIR(ctx, r)
	if err != nil {
		a.Result = c.resultOf("lir", err)
	} else {
		a.Result, a.ServerName, a.ServerCapabilities = out.result, out.serverName, out.caps
	}
	c.count("lir", a.Result)
	return a.Message(c.node, req)
}

type lirAnswer struct {
	lirOutcome
	caps *cx.ServerCapabilities
}

func (c *CxServer) decideLIR(ctx context.Context, r *cx.LIR) (lirAnswer, error) {
	s, impu, err := c.byIMPU(ctx, r.PublicIdentity)
	if err != nil {
		return lirAnswer{}, err
	}
	var p *store.ServiceProfile
	unregistered := false
	if !s.Identity(impu).State.Served() {
		if p, err = c.profile(ctx, s); err != nil {
			return lirAnswer{}, err
		}
		unregistered = hasUnregisteredServices(p)
	}
	out := lirAnswer{lirOutcome: decideLIR(s, impu, r.OriginatingRequest, unregistered)}
	if out.capabilities {
		out.caps = c.h.capabilities(p)
	}
	return out, nil
}

func (c *CxServer) sar(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	defer c.timed("sar")()
	r, err := cx.ParseSAR(req)
	if err != nil {
		return nil, err
	}
	// TS 29.228 Table 6.1.2.1 and §6.1.2.1 step 3: some assignment types
	// need exactly one Public-Identity, the others an identity or the IMPI.
	ids := req.FindAll(cx.AVPPublicIdentity, cx.Vendor3GPP)
	switch {
	case singleIdentityAssignment(r.AssignmentType) && len(ids) > 1:
		return nil, &diameter.Error{ResultCode: diameter.ResultAVPOccursTooManyTimes, FailedAVP: ids[1],
			Message: "Server-Assignment-Type allows one Public-Identity"}
	case singleIdentityAssignment(r.AssignmentType) && len(ids) == 0,
		len(ids) == 0 && r.UserName == "":
		return nil, &diameter.Error{ResultCode: diameter.ResultMissingAVP,
			FailedAVP: diameter.NewAVP(cx.AVPPublicIdentity, diameter.FlagMandatory, cx.Vendor3GPP, nil),
			Message:   "Public-Identity is missing"}
	}
	ctx, cancel := c.context(ctx)
	defer cancel()
	a := cx.SAA{}
	if err := c.applySAR(ctx, r, &a); err != nil {
		if b := busy(err); b != nil {
			return nil, b
		}
		a = cx.SAA{UserName: a.UserName}
		a.Result = c.resultOf("sar", err)
	}
	c.count("sar", a.Result)
	return a.Message(c.node, req)
}

func (c *CxServer) applySAR(ctx context.Context, r *cx.SAR, a *cx.SAA) error {
	var s *store.Subscription
	var err error
	impus := make([]string, 0, len(r.PublicIdentities))
	for _, id := range r.PublicIdentities {
		canonical, ok := identity.CanonicalIMPU(id)
		if !ok {
			return experimental(cx.ErrorUserUnknown)
		}
		impus = append(impus, canonical)
	}
	if r.UserName != "" {
		if len(impus) > 0 {
			s, _, err = c.pair(ctx, r.UserName, r.PublicIdentities[0])
		} else if s, err = c.h.store.Subscription(ctx, r.UserName); errors.Is(err, store.ErrNotFound) {
			err = experimental(cx.ErrorUserUnknown)
		}
	} else {
		s, _, err = c.byIMPU(ctx, r.PublicIdentities[0])
	}
	if err != nil {
		return err
	}
	a.UserName = s.IMPI
	for _, impu := range impus {
		if s.Identity(impu) == nil {
			return experimental(cx.ErrorIdentitiesDontMatch)
		}
	}
	// The profile is needed for User-Data and for the decision to keep
	// the server name; read it before the write so that a missing profile
	// changes nothing.
	p, err := c.profile(ctx, s)
	if err != nil {
		return err
	}
	keep := hasUnregisteredServices(p)
	var out sarOutcome
	var data []byte
	saved, err := c.h.updateFrom(ctx, s.IMPI, s, func(cur *store.Subscription) error {
		for _, impu := range impus {
			if cur.Identity(impu) == nil {
				return experimental(cx.ErrorUserUnknown) // removed meanwhile
			}
		}
		out = applySAR(cur, impus, r, keep)
		data = nil
		if out.userData {
			// Built before the write, so that User-Data the HSS cannot send
			// leaves the state as it was.
			var err error
			data, err = userData(cur, cur.Identity(impus[0]).ImplicitSet, p)
			if errors.Is(err, ifc.ErrTooLarge) {
				c.h.metrics.Count("userdata.too_large", 1)
				return experimental(cx.ErrorTooMuchData)
			}
			if err != nil {
				return err
			}
		}
		if !out.changed {
			return errUnchanged
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.Result, a.ServerName = out.result, out.serverName
	if out.userData {
		a.UserData, a.ChargingInformation = data, charging(saved.Charging)
	}
	return nil
}

func (c *CxServer) mar(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	defer c.timed("mar")()
	r, err := cx.ParseMAR(req)
	if err != nil {
		return nil, err
	}
	resync := r.AuthDataItem.Authorization
	if len(resync) > 0 && (r.AuthDataItem.Scheme != cx.SchemeDigestAKAv1MD5 || len(resync) != milenage.RANDSize+milenage.AUTSSize) {
		// TS 29.228 Table 6.3.2: SIP-Authorization only for an AKA
		// resynchronisation, carrying RAND ‖ AUTS.
		return nil, &diameter.Error{ResultCode: diameter.ResultInvalidAVPValue,
			FailedAVP: req.Find(cx.AVPSIPAuthDataItem, cx.Vendor3GPP), Message: "SIP-Authorization is not RAND and AUTS of an AKA scheme"}
	}
	ctx, cancel := c.context(ctx)
	defer cancel()
	a := cx.MAA{}
	items, err := c.authenticate(ctx, r)
	if b := busy(err); b != nil {
		return nil, b
	}
	if err != nil {
		a.Result = c.resultOf("mar", err)
	} else {
		a.Result = success()
		a.UserName, a.PublicIdentity = r.UserName, r.PublicIdentity
		a.NumberAuthItems, a.AuthDataItems = uint32(len(items)), items
	}
	c.count("mar", a.Result)
	return a.Message(c.node, req)
}

// authenticate applies TS 29.228 §6.3.1: it checks the scheme, records the
// S-CSCF and the pending authentication, reserves the sequence numbers of
// the vectors in the same conditional write, so that no two MARs on any
// tasks issue the same SQN, and then builds the vectors.
func (c *CxServer) authenticate(ctx context.Context, r *cx.MAR) ([]cx.AuthDataItem, error) {
	s, impu, err := c.pair(ctx, r.UserName, r.PublicIdentity)
	if err != nil {
		return nil, err
	}
	scheme := r.AuthDataItem.Scheme
	if scheme == cx.SchemeUnknown && s.DigestFor(c.h.imsRealm) != nil {
		scheme = cx.SchemeSIPDigest // §6.3.1 step 4: the stored scheme
	}
	switch {
	case scheme == cx.SchemeDigestAKAv1MD5 && s.AKA != nil:
	case scheme == cx.SchemeSIPDigest && s.DigestFor(c.h.imsRealm) != nil:
	default:
		return nil, experimental(cx.ErrorAuthSchemeNotSupported)
	}
	n := 1
	if scheme == cx.SchemeDigestAKAv1MD5 {
		n = int(min(r.NumberAuthItems, uint32(c.h.maxItems)))
	}
	resync := r.AuthDataItem.Authorization
	var first milenage.SQN
	var m milenage.Milenage
	var amf [milenage.AMFSize]byte
	saved, err := c.h.updateFrom(ctx, s.IMPI, s, func(cur *store.Subscription) error {
		if cur.Identity(impu) == nil {
			return experimental(cx.ErrorUserUnknown) // removed meanwhile
		}
		if len(resync) > 0 && cur.ServerName != r.ServerName {
			// §6.3.1 step 4 processes AUTS only from the S-CSCF that holds
			// the challenge; anything else is an error situation.
			return errUnableToComply
		}
		changed := applyMAR(cur, impu, r.ServerName)
		if scheme != cx.SchemeDigestAKAv1MD5 {
			if !changed {
				return errUnchanged
			}
			return nil
		}
		if cur.AKA == nil {
			return experimental(cx.ErrorAuthSchemeNotSupported) // removed meanwhile
		}
		var err error
		if m, err = c.h.milenage(cur); err != nil {
			return err
		}
		he := milenage.SQN(cur.AKA.SQN)
		if len(resync) > 0 {
			he = c.resynchronise(m, he, resync)
		}
		next := he
		for i := range n {
			if next, err = next.Next(); err != nil {
				c.h.metrics.Count("aka.sqn_exhausted", 1)
				return err
			}
			if i == 0 {
				first = next
			}
		}
		cur.AKA.SQN = uint64(next)
		amf = cur.AKA.AMF
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scheme == cx.SchemeSIPDigest {
		item, err := c.h.digestItem(saved)
		if err != nil {
			return nil, err
		}
		return []cx.AuthDataItem{item}, nil
	}
	return c.h.vectors(m, first, n, amf)
}

// resynchronise applies TS 33.102 §6.3.5: SQN_HE is reset to SQN_MS only
// when AUTS verifies and the next vector from SQN_HE would be refused; with
// an AUTS that does not verify, vectors continue from SQN_HE.
func (c *CxServer) resynchronise(m milenage.Milenage, he milenage.SQN, randAUTS []byte) milenage.SQN {
	ms, err := m.VerifyAUTS([milenage.RANDSize]byte(randAUTS[:milenage.RANDSize]), [milenage.AUTSSize]byte(randAUTS[milenage.RANDSize:]))
	if err != nil {
		c.h.metrics.Count("aka.auts_invalid", 1)
		return he
	}
	c.h.metrics.Count("aka.resync", 1)
	return milenage.Resynchronise(he, ms)
}

// vectors builds n AKA vectors with sequence numbers from first.
func (h *HSS) vectors(m milenage.Milenage, first milenage.SQN, n int, amf [milenage.AMFSize]byte) ([]cx.AuthDataItem, error) {
	items := make([]cx.AuthDataItem, 0, n)
	sqn := first
	for i := range n {
		if i > 0 {
			var err error
			if sqn, err = sqn.Next(); err != nil {
				return nil, err
			}
		}
		var rnd [milenage.RANDSize]byte
		if _, err := io.ReadFull(h.rand, rnd[:]); err != nil {
			return nil, fmt.Errorf("hss: reading RAND: %w", err)
		}
		v := m.Vector(rnd, sqn, amf)
		r, autn, xres, ck, ik := v.RAND(), v.AUTN(), v.XRES(), v.CK(), v.IK()
		items = append(items, cx.AuthDataItem{
			ItemNumber:         uint32(i + 1),
			Scheme:             cx.SchemeDigestAKAv1MD5,
			Authenticate:       append(r[:], autn[:]...),
			Authorization:      xres[:],
			ConfidentialityKey: ck[:],
			IntegrityKey:       ik[:],
		})
	}
	return items, nil
}

// digestItem is the SIP Digest item of TS 29.228 Table 6.3.7: the MD5 HA1
// for the IMS realm, with the SHA-256 HA1 as the alternate (RFC 7616), qop
// auth.
func (h *HSS) digestItem(s *store.Subscription) (cx.AuthDataItem, error) {
	d := s.DigestFor(h.imsRealm)
	if d == nil {
		return cx.AuthDataItem{}, experimental(cx.ErrorAuthSchemeNotSupported)
	}
	md5, err := h.openHA1(s.IMPI, d, digest.MD5)
	if err != nil {
		return cx.AuthDataItem{}, err
	}
	sha, err := h.openHA1(s.IMPI, d, digest.SHA256)
	if err != nil {
		return cx.AuthDataItem{}, err
	}
	return cx.AuthDataItem{
		Scheme: cx.SchemeSIPDigest,
		Digest: &cx.DigestAuthenticate{
			Realm: d.Realm, Algorithm: string(digest.MD5), QoP: digest.QOPAuth, HA1: md5,
			AlternateAlgorithm: string(digest.SHA256), AlternateHA1: sha,
		},
	}, nil
}
