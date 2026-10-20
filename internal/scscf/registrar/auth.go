package registrar

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// akaVectorSize is the Authenticate of an AKA item: RAND ‖ AUTN (TS 29.229
// §6.3.14).
const akaVectorSize = 32

// authenticate returns nil once r's credentials answer a challenge an
// instance issued, and otherwise the 401 or 403 to send (TS 24.229
// §5.4.1.2.1, §5.4.1.2.2). known is whether r.impu is registered by r.impi
// already, which only matters to TrustIntegrityProtected.
func (g *Registrar) authenticate(ctx context.Context, r *register, known bool) *failure {
	if g.cfg.TrustIntegrityProtected && known && r.integrityProtected == "tls-yes" {
		return nil
	}
	c := r.creds
	if c == nil || c.Nonce == "" {
		return g.challenge(ctx, r, false)
	}
	if c.Algorithm == digest.AKAv1MD5 && c.Response == "" && len(c.AUTS) == 0 {
		return g.networkNotAuthenticated(ctx, r, c)
	}
	// Check needs no secret, so a nonce no instance issued costs no read.
	if g.digest.Check(*c) != nil {
		return g.challenge(ctx, r, false)
	}
	ch, err := g.cfg.Store.TakeChallenge(ctx, r.impi, c.Nonce, g.cfg.Now())
	switch {
	case errors.Is(err, state.ErrNotFound), errors.Is(err, state.ErrInvalid):
		// Expired, already answered, or one this instance cannot open: the
		// client answers a fresh challenge without asking its user.
		return g.challenge(ctx, r, true)
	case err != nil:
		return g.internal("taking a challenge", err)
	}
	if ch.IMPU != r.impu {
		g.count("registrar.auth_failed")
		return refuse(403, "Challenge for another identity")
	}
	if ch.AKA != nil {
		err = g.digest.VerifyAKA(ctx, "REGISTER", *c, ch.AKA.XRES, ch.Expires)
		var sync *digest.SyncFailure
		if errors.As(err, &sync) {
			if ch.Resynchronised {
				// The HSS resynchronised for this window already; another
				// failure is not worth another round trip.
				g.count("registrar.auth_failed")
				return refuse(403, "Authentication failed")
			}
			return g.resynchronise(ctx, r, sync)
		}
	} else {
		err = g.verifyDigest(ctx, c, ch.Digest)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, digest.ErrStaleNonce):
		return g.challenge(ctx, r, true)
	}
	g.count("registrar.auth_failed")
	return refuse(403, "Authentication failed")
}

// networkNotAuthenticated answers the REGISTER of a UE whose card did not
// verify the challenge's AUTN: the challenge's nonce, an empty response and
// no auts (TS 33.203 §6.1.2.2, TS 24.229 §5.4.1.2.3A). The vector is deleted,
// the HSS is told (SAR AUTHENTICATION_FAILURE, TS 29.228 §6.1.2) so it ends
// the pending authentication, and the UE gets 403.
func (g *Registrar) networkNotAuthenticated(ctx context.Context, r *register, c *digest.Credentials) *failure {
	// The answer carries no qop, nc or cnonce, which Check requires; with
	// them filled in, Check still proves the nonce and opaque are an
	// instance's own before anything is read.
	probe := *c
	probe.QOP, probe.NC, probe.CNonce = digest.QOPAuth, 1, "-"
	if g.digest.Check(probe) != nil {
		return g.challenge(ctx, r, false)
	}
	g.count("registrar.network_not_authenticated")
	ch, err := g.cfg.Store.TakeChallenge(ctx, r.impi, c.Nonce, g.cfg.Now())
	switch {
	case errors.Is(err, state.ErrNotFound), errors.Is(err, state.ErrInvalid):
		// Expired or answered already: nothing is pending at the HSS.
		return refuse(403, "Network authentication failed")
	case err != nil:
		return g.internal("taking a challenge", err)
	}
	if ch.AKA == nil || ch.IMPU != r.impu {
		return refuse(403, "Network authentication failed")
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.AuthenticationFailure})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	// The 403 stands whatever the HSS answers; one that missed the SAR ends
	// the pending authentication when it times out (TS 29.228 §6.1.2).
	if cxclient.Classify(res) != cxclient.Success || err != nil {
		g.count("registrar.hss_failed")
	}
	return refuse(403, "Network authentication failed")
}

func (g *Registrar) verifyDigest(ctx context.Context, c *digest.Credentials, d *state.DigestChallenge) error {
	// The secret carries the challenge's algorithm, so credentials for
	// another one fail to verify.
	secret, err := digest.HA1(digest.Algorithm(d.Algorithm), d.HA1)
	if err != nil {
		return err
	}
	return g.digest.Verify(ctx, "REGISTER", *c, secret)
}

// challenge asks the HSS for authentication data and returns the 401 that
// carries it, after storing what checking the answer needs. stale tells the
// client that its credentials were good but the challenge is gone, so it
// answers the new one without asking its user (RFC 7616 §3.3).
func (g *Registrar) challenge(ctx context.Context, r *register, stale bool) *failure {
	schemes, ok := cxclient.Schemes(r.algorithm, g.cfg.Schemes)
	if !ok {
		return refuse(403, "Unsupported algorithm")
	}
	if f := g.limitChallenges(ctx, r, g.cfg.Now()); f != nil {
		return f
	}
	maa, err := g.cfg.HSS.Authenticate(ctx, &cx.MAR{UserName: r.impi, PublicIdentity: r.impu, NumberAuthItems: 1}, schemes)
	return g.challengeFrom(ctx, r, maa, err, stale, false)
}

// resynchronise sends the client's AUTS to the HSS (TS 33.102 §6.3.5) and
// challenges with the vector it returns, marked so that a further AUTS for it
// is refused: one resynchronisation per challenge (Challenge.Resynchronised).
// An AUTS is unauthenticated (digest.SyncFailure), so the IMPI also has a
// budget of them (limitResyncs), used only by one that reaches the HSS and
// gets a vector back.
func (g *Registrar) resynchronise(ctx context.Context, r *register, sync *digest.SyncFailure) *failure {
	now := g.cfg.Now()
	if f := g.limitChallenges(ctx, r, now); f != nil {
		return f
	}
	slot, f := g.limitResyncs(ctx, r, now)
	if f != nil {
		return f
	}
	g.count("registrar.resync")
	auth := make([]byte, 0, len(sync.RAND)+len(sync.AUTS))
	auth = append(append(auth, sync.RAND[:]...), sync.AUTS[:]...)
	maa, err := g.cfg.HSS.MAR(ctx, &cx.MAR{
		UserName: r.impi, PublicIdentity: r.impu, NumberAuthItems: 1,
		AuthDataItem: cx.AuthDataItem{Scheme: cx.SchemeDigestAKAv1MD5, Authorization: auth},
	})
	f = g.challengeFrom(ctx, r, maa, err, false, true)
	if f == nil || f.code != 401 {
		// Nothing came of it: the slot is the UE's again.
		g.giveBack(ctx, slot)
	}
	return f
}

func (g *Registrar) challengeFrom(ctx context.Context, r *register, maa *cx.MAA, err error, stale, resynced bool) *failure {
	var res cx.Result
	if maa != nil {
		res = maa.Result
	}
	if f := g.cxFailure("MAR", res, err); f != nil {
		return f
	}
	if len(maa.AuthDataItems) == 0 {
		return g.internal("MAA without authentication data", nil)
	}
	item := maa.AuthDataItems[0]
	var f *failure
	switch item.Scheme {
	case cx.SchemeDigestAKAv1MD5:
		f, err = g.akaChallenge(ctx, r, item, stale, resynced)
	case cx.SchemeSIPDigest:
		f, err = g.digestChallenges(ctx, r, item.Digest, stale)
	default:
		return g.internal("MAA with an unexpected scheme", nil)
	}
	if err != nil {
		return g.internal("issuing a challenge", err)
	}
	g.count("registrar.challenged")
	return f
}

func (g *Registrar) akaChallenge(ctx context.Context, r *register, item cx.AuthDataItem, stale, resynced bool) (*failure, error) {
	if len(item.Authenticate) != akaVectorSize || len(item.Authorization) == 0 {
		return nil, errors.New("AKA item without a vector")
	}
	rand, autn := item.Authenticate[:16], item.Authenticate[16:]
	ch, err := g.digest.AKAChallenge(rand, autn, stale)
	if err != nil {
		return nil, err
	}
	// CK and IK are kept for a security association with the P-CSCF, which
	// this platform does not set up (it uses TLS), so they are not sent in
	// the 401 (TS 24.229 §5.4.1.2.1 adds them for IPsec only).
	err = g.store(ctx, r, ch.Nonce, &state.Challenge{Resynchronised: resynced, AKA: &state.AKAVector{
		RAND: rand, AUTN: autn, XRES: item.Authorization, CK: item.ConfidentialityKey, IK: item.IntegrityKey,
	}})
	if err != nil {
		return nil, err
	}
	return &failure{code: 401, fields: [][2]string{{"WWW-Authenticate", ch.Header()}}}, nil
}

// digestChallenges challenges with every algorithm the HSS has an HA1 for,
// strongest first (RFC 8760 §2.4), or only with the one the client named.
func (g *Registrar) digestChallenges(ctx context.Context, r *register, d *cx.DigestAuthenticate, stale bool) (*failure, error) {
	if d == nil || d.Realm != g.cfg.Realm {
		return nil, errors.New("SIP Digest item without HA1 for the realm")
	}
	type option struct {
		alg digest.Algorithm
		ha1 string
	}
	var options []option
	if d.AlternateAlgorithm == string(digest.SHA256) && d.AlternateHA1 != "" {
		options = append(options, option{digest.SHA256, d.AlternateHA1})
	}
	if d.Algorithm == string(digest.MD5) && d.HA1 != "" {
		options = append(options, option{digest.MD5, d.HA1})
	}
	f := &failure{code: 401}
	for _, o := range options {
		if r.algorithm != "" && !strings.EqualFold(r.algorithm, string(o.alg)) {
			continue
		}
		ch, err := g.digest.Challenge(o.alg, stale)
		if err != nil {
			return nil, err
		}
		err = g.store(ctx, r, ch.Nonce, &state.Challenge{Digest: &state.DigestChallenge{
			Realm: ch.Realm, Algorithm: string(o.alg), QoP: digest.QOPAuth, Opaque: ch.Opaque, HA1: o.ha1,
		}})
		if err != nil {
			return nil, err
		}
		f.fields = append(f.fields, [2]string{"WWW-Authenticate", ch.Header()})
	}
	if len(f.fields) == 0 {
		return refuse(403, "Unsupported algorithm"), nil
	}
	return f, nil
}

func (g *Registrar) store(ctx context.Context, r *register, nonce string, c *state.Challenge) error {
	now := g.cfg.Now()
	c.IMPI, c.Nonce, c.IMPU = r.impi, nonce, r.impu
	c.Issued, c.Expires = now, now.Add(g.cfg.ChallengeLifetime)
	return g.cfg.Store.AddChallenge(ctx, c)
}

// cxFailure maps a Cx answer or error to the response the client gets, nil
// for success (TS 24.229 §5.4.1.2.1: an identity the HSS refuses is 403).
func (g *Registrar) cxFailure(cmd string, res cx.Result, err error) *failure {
	o := cxclient.Classify(res)
	if err != nil {
		o = cxclient.ErrorOutcome(err)
	}
	switch o {
	case cxclient.Success:
		return nil
	case cxclient.UserUnknown, cxclient.IdentitiesDontMatch, cxclient.RoamingNotAllowed,
		cxclient.ServedElsewhere, cxclient.SchemeNotSupported, cxclient.Rejected, cxclient.NotRegistered:
		g.count("registrar.hss_refused")
		return refuse(403, "Forbidden")
	case cxclient.Unavailable:
		g.count("registrar.hss_unavailable")
		return refuse(480, "HSS unavailable")
	}
	g.log.Warn("registrar: Cx failure", slog.String("command", cmd), slog.String("outcome", o.String()))
	g.count("registrar.hss_failed")
	return refuse(500, "")
}

// internal is a 500 for a failure of this instance or its store. The store's
// and the digest package's errors name no identity or credential.
func (g *Registrar) internal(what string, err error) *failure {
	attrs := []any{slog.String("step", what)}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	g.log.Error("registrar: internal failure", attrs...)
	g.count("registrar.internal_errors")
	return refuse(500, "")
}
