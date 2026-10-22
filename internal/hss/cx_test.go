package hss

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

func wantResult(t *testing.T, what string, got, want cx.Result) {
	t.Helper()
	if got != want {
		t.Fatalf("%s result = %v, want %v", what, got, want)
	}
}

var (
	resSuccess = cx.ResultCode(diameter.ResultSuccess)
	resUnable  = cx.ResultCode(diameter.ResultUnableToComply)
)

func exp(code uint32) cx.Result { return cx.ExperimentalResult(code) }

// The registration of TS 24.229 §5.1.1 seen from the HSS, end to end over a
// Diameter connection: the I-CSCF's UAR, the S-CSCF's MAR and SAR, a
// re-registration, a terminating LIR and the deregistration.
func TestAKARegistrationRunsEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, tel1)
	node := serveHSS(t, e.h, "hss-a.rcs.local")
	icscf := connectCSCF(t, node, "icscf-1.rcs.local")
	scscf := connectCSCF(t, node, "scscf-1.rcs.local")

	uaa := icscf.uar(impi1, impu1, cx.AuthorizeRegistration)
	wantResult(t, "first UAR", uaa.Result, exp(cx.FirstRegistration))
	if uaa.ServerName != "" || uaa.ServerCapabilities == nil || !slices.Equal(uaa.ServerCapabilities.ServerNames, []string{scscfName}) {
		t.Fatalf("first UAA = %+v", uaa)
	}

	maa := scscf.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 2, scscfName, nil)
	wantResult(t, "MAR", maa.Result, resSuccess)
	if maa.NumberAuthItems != 2 || len(maa.AuthDataItems) != 2 || maa.UserName != impi1 {
		t.Fatalf("MAA = %+v", maa)
	}
	for i, item := range maa.AuthDataItems {
		if item.ItemNumber != uint32(i+1) || item.Scheme != cx.SchemeDigestAKAv1MD5 || item.Authorization.Len() != milenage.RESSize ||
			item.ConfidentialityKey.Len() != milenage.CKSize || item.IntegrityKey.Len() != milenage.IKSize {
			t.Fatalf("item %d = %v", i, item)
		}
		// The vector is what the card computes: XRES equals f2(RAND).
		m := milenage.New(testK, testOPc)
		if xres := m.F2([16]byte(item.Authenticate[:16])); !bytes.Equal(xres[:], item.Authorization.Reveal()) {
			t.Fatalf("item %d XRES is not f2(RAND)", i)
		}
	}
	if a, b := sqnOf(t, maa.AuthDataItems[0]), sqnOf(t, maa.AuthDataItems[1]); a.SEQ() != 1 || b.SEQ() != 2 {
		t.Fatalf("SQNs = %d, %d, want SEQ 1 and 2", a.SEQ(), b.SEQ())
	}
	if s := e.sub(impi1); s.ServerName != scscfName || !s.AuthPending || s.AKA.SQN != 2<<milenage.INDBits {
		t.Fatalf("after MAR: %+v", s)
	}

	// The second REGISTER's UAR finds the S-CSCF chosen during authentication.
	uaa = icscf.uar(impi1, impu1, cx.AuthorizeRegistration)
	wantResult(t, "UAR during authentication", uaa.Result, exp(cx.SubsequentRegistration))

	saa := scscf.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	wantResult(t, "SAR", saa.Result, resSuccess)
	doc, err := ifc.ParseSubscription(saa.UserData)
	if err != nil {
		t.Fatalf("User-Data: %v", err)
	}
	ids := doc.ServiceProfiles[0].PublicIdentities
	if doc.PrivateID != impi1 || len(ids) != 2 || ids[0].Identity != impu1 || ids[1].Identity != tel1 {
		t.Fatalf("User-Data = %+v", doc)
	}
	if set, err := ifc.Compile(doc.ServiceProfiles[0].InitialFilterCriteria); err != nil || set.Len() != 5 {
		t.Fatalf("criteria: %v", err)
	}
	s := e.sub(impi1)
	if s.AuthPending || s.Identity(impu1).State != store.Registered || s.Identity(tel1).State != store.Registered {
		t.Fatalf("after SAR: %+v", s)
	}

	// Re-registration: the I-CSCF learns the serving S-CSCF.
	uaa = icscf.uar(impi1, tel1, cx.AuthorizeRegistration)
	wantResult(t, "re-registration UAR", uaa.Result, exp(cx.SubsequentRegistration))
	if uaa.ServerName != scscfName || uaa.ServerCapabilities != nil {
		t.Fatalf("re-registration UAA = %+v", uaa)
	}
	// A MAR for a registered user by its S-CSCF changes no state.
	before := e.sub(impi1).Version
	scscf.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	if after := e.sub(impi1); after.AuthPending || after.Version != before+1 {
		t.Fatalf("re-authentication changed state: %+v", after)
	}
	saa = scscf.sar(impi1, []string{impu1}, cx.ReRegistration, scscfName)
	wantResult(t, "re-registration SAR", saa.Result, resSuccess)

	lia := icscf.lir(tel1, false)
	wantResult(t, "LIR", lia.Result, resSuccess)
	if lia.ServerName != scscfName {
		t.Fatalf("LIA = %+v", lia)
	}

	uaa = icscf.uar(impi1, impu1, cx.AuthorizeDeregistration)
	wantResult(t, "deregistration UAR", uaa.Result, resSuccess)
	saa = scscf.sar(impi1, nil, cx.UserDeregistration, scscfName)
	wantResult(t, "deregistration SAR", saa.Result, resSuccess)
	if s := e.sub(impi1); s.ServerName != "" || s.Identity(impu1).State != store.NotRegistered {
		t.Fatalf("after deregistration: %+v", s)
	}
	uaa = icscf.uar(impi1, impu1, cx.AuthorizeDeregistration)
	wantResult(t, "UAR after deregistration", uaa.Result, exp(cx.ErrorIdentityNotRegistered))
}

func TestSIPDigestMARReturnsBothHA1sForTheIMSRealm(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	scscf := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	for _, scheme := range []string{cx.SchemeSIPDigest, cx.SchemeUnknown} {
		maa := scscf.mar(impi1, impu1, scheme, 3, scscfName, nil)
		wantResult(t, scheme, maa.Result, resSuccess)
		if maa.NumberAuthItems != 1 || len(maa.AuthDataItems) != 1 {
			t.Fatalf("%s: %d items; SIP Digest has one", scheme, len(maa.AuthDataItems))
		}
		item := maa.AuthDataItems[0]
		d := item.Digest
		if item.Scheme != cx.SchemeSIPDigest || item.ItemNumber != 0 || d == nil || d.Realm != domain || d.QoP != "auth" ||
			d.Algorithm != "MD5" || d.HA1 != ha1(t, digest.MD5, impi1, domain) ||
			d.AlternateAlgorithm != "SHA-256" || d.AlternateHA1 != ha1(t, digest.SHA256, impi1, domain) {
			t.Fatalf("%s: item %+v, digest %#v", scheme, item, d)
		}
	}
	if s := e.sub(impi1); s.AKA.SQN != 0 {
		t.Error("a Digest MAR advanced SQN")
	}
}

func TestMARRefusesSchemesTheSubscriberHasNoCredentialFor(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) { s.Digest = nil })
	e.provision(impi2, impu2)
	e.modify(impi2, func(s *store.Subscription) { s.AKA = nil })
	scscf := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	for name, c := range map[string]struct{ impi, impu, scheme string }{
		"Digest without HA1":   {impi1, impu1, cx.SchemeSIPDigest},
		"Unknown without HA1":  {impi1, impu1, cx.SchemeUnknown},
		"AKA without keys":     {impi2, impu2, cx.SchemeDigestAKAv1MD5},
		"unsupported scheme":   {impi1, impu1, cx.SchemeNASSBundled},
		"early IMS security":   {impi1, impu1, cx.SchemeEarlyIMSSecurity},
		"unknown scheme value": {impi1, impu1, "Digest-AKAv9-XYZ"},
	} {
		maa := scscf.mar(c.impi, c.impu, c.scheme, 1, scscfName, nil)
		wantResult(t, name, maa.Result, exp(cx.ErrorAuthSchemeNotSupported))
		if len(maa.AuthDataItems) != 0 {
			t.Errorf("%s: items in a failure answer", name)
		}
	}
	if s := e.sub(impi1); s.ServerName != "" {
		t.Error("a refused MAR stored the S-CSCF name")
	}
}

func TestUnknownAndMismatchedIdentitiesAreRefused(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.provision(impi2, impu2)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	unknown, mismatch := exp(cx.ErrorUserUnknown), exp(cx.ErrorIdentitiesDontMatch)
	wantResult(t, "UAR unknown IMPI", c.uar(impi3, impu1, 0).Result, unknown)
	wantResult(t, "UAR unknown IMPU", c.uar(impi1, impu3, 0).Result, unknown)
	wantResult(t, "UAR not an IMPU", c.uar(impi1, "mailto:someone", 0).Result, unknown)
	wantResult(t, "UAR other's IMPU", c.uar(impi1, impu2, 0).Result, mismatch)
	wantResult(t, "MAR unknown", c.mar(impi3, impu3, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil).Result, unknown)
	wantResult(t, "MAR other's IMPU", c.mar(impi1, impu2, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil).Result, mismatch)
	wantResult(t, "SAR unknown IMPI", c.sar(impi3, nil, cx.UserDeregistration, scscfName).Result, unknown)
	wantResult(t, "SAR unknown IMPU", c.sar("", []string{impu3}, cx.UnregisteredUser, scscfName).Result, unknown)
	wantResult(t, "SAR other's IMPU", c.sar(impi1, []string{impu2}, cx.Registration, scscfName).Result, mismatch)
	wantResult(t, "LIR unknown", c.lir(impu3, false).Result, unknown)
	wantResult(t, "LIR not an IMPU", c.lir("sip:@", false).Result, unknown)
}

func TestIMPUsMatchInCanonicalForm(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, tel1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	for _, impu := range []string{
		"sip:%2B15550100001@" + strings.ToUpper(domain),
		impu1 + ";user=phone",
		"tel:+1-555-0100-001",
	} {
		wantResult(t, impu, c.uar(impi1, impu, 0).Result, exp(cx.FirstRegistration))
	}
}

func TestBarredIdentityRegistersOnlyWithAnUnbarredOne(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, tel1)
	e.modify(impi1, func(s *store.Subscription) {
		s.PublicIdentities[1].Barred = true // tel1 barred, impu1 not
	})
	e.provision(impi2, impu2)
	e.modify(impi2, func(s *store.Subscription) { s.PublicIdentities[0].Barred = true })
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "icscf-1.rcs.local")
	wantResult(t, "barred with a free identity", c.uar(impi1, tel1, 0).Result, exp(cx.FirstRegistration))
	wantResult(t, "barred alone", c.uar(impi2, impu2, 0).Result, cx.ResultCode(diameter.ResultAuthorizationRejected))
	uaa := c.uar(impi1, impu1, cx.AuthorizeRegistrationAndCapabilities)
	wantResult(t, "capabilities", uaa.Result, resSuccess)
	if uaa.ServerCapabilities == nil || uaa.ServerName != "" {
		t.Errorf("UAA = %+v", uaa)
	}
}

func TestAUTSResynchronisesTheSequenceNumber(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	wantResult(t, "MAR", maa.Result, resSuccess)
	rnd := [16]byte(maa.AuthDataItems[0].Authenticate[:16])

	// The card has seen SEQ 1000 (another network element, or a reset
	// HSS), so it refuses SEQ 1 and reports SQN_MS in AUTS.
	ms, _ := milenage.NewSQN(1000, 0)
	m := milenage.New(testK, testOPc)
	auts := m.AUTS(rnd, ms)
	maa = c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, append(rnd[:], auts[:]...))
	wantResult(t, "resync MAR", maa.Result, resSuccess)
	if got := sqnOf(t, maa.AuthDataItems[0]); got.SEQ() != 1001 || !milenage.Fresh(got, ms) {
		t.Fatalf("SQN after resync = SEQ %d, want 1001", got.SEQ())
	}

	// An AUTS that does not verify changes nothing; vectors continue.
	bad := auts
	bad[13] ^= 1
	maa = c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, append(rnd[:], bad[:]...))
	wantResult(t, "bad AUTS", maa.Result, resSuccess)
	if got := sqnOf(t, maa.AuthDataItems[0]); got.SEQ() != 1002 {
		t.Fatalf("SQN after a bad AUTS = SEQ %d, want 1002", got.SEQ())
	}
	if e.metrics.get("aka.auts_invalid") != 1 || e.metrics.get("aka.resync") != 1 {
		t.Errorf("metrics: %v", e.metrics.counts)
	}

	// AUTS from an S-CSCF that does not hold the challenge is refused.
	wantResult(t, "AUTS from another S-CSCF", c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, otherName, append(rnd[:], auts[:]...)).Result, resUnable)
}

func TestMalformedResynchronisationIsAnInvalidAVP(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	for name, tc := range map[string]struct {
		scheme string
		auth   []byte
	}{
		"short AUTS":       {cx.SchemeDigestAKAv1MD5, make([]byte, 20)},
		"AUTS with Digest": {cx.SchemeSIPDigest, make([]byte, 30)},
	} {
		wantResult(t, name, c.mar(impi1, impu1, tc.scheme, 1, scscfName, tc.auth).Result, cx.ResultCode(diameter.ResultInvalidAVPValue))
	}
}

func TestMARCapsTheVectorsAndStopsWhenSQNIsExhausted(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	if maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 100, scscfName, nil); len(maa.AuthDataItems) != DefaultMaxAuthItems {
		t.Fatalf("%d vectors, want the cap %d", len(maa.AuthDataItems), DefaultMaxAuthItems)
	}
	last, _ := milenage.NewSQN(milenage.MaxSEQ, 0)
	e.modify(impi1, func(s *store.Subscription) { s.AKA.SQN = uint64(last) })
	wantResult(t, "exhausted", c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil).Result, resUnable)
	if e.metrics.get("aka.sqn_exhausted") != 1 {
		t.Error("exhaustion not counted")
	}
}

func TestMARFromANewSCSCFTakesOverTheAssignment(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	c.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	// TS 29.228 §8.1: a MAR from another S-CSCF overwrites the name...
	wantResult(t, "MAR", c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, otherName, nil).Result, resSuccess)
	if s := e.sub(impi1); s.ServerName != otherName || !s.AuthPending {
		t.Fatalf("after MAR from another S-CSCF: %+v", s)
	}
	// ...but a SAR from the old one is refused and told the new name.
	saa := c.sar(impi1, []string{impu1}, cx.ReRegistration, scscfName)
	wantResult(t, "SAR from the old S-CSCF", saa.Result, exp(cx.ErrorIdentityAlreadyRegistered))
	if saa.ServerName != otherName || saa.UserData != nil {
		t.Fatalf("SAA = %+v", saa)
	}
}

func TestSARChecksTheNumberOfPublicIdentities(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1, tel1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	saa := c.sar(impi1, []string{impu1, tel1}, cx.Registration, scscfName)
	wantResult(t, "two identities", saa.Result, cx.ResultCode(diameter.ResultAVPOccursTooManyTimes))
	wantResult(t, "no identity", c.sar(impi1, nil, cx.Registration, scscfName).Result, cx.ResultCode(diameter.ResultMissingAVP))
	wantResult(t, "nothing", c.sar("", nil, cx.UserDeregistration, scscfName).Result, cx.ResultCode(diameter.ResultMissingAVP))
	// Deregistrations accept several identities.
	c.sar(impi1, []string{impu1}, cx.UnregisteredUser, scscfName)
	wantResult(t, "deregister both", c.sar(impi1, []string{impu1, tel1}, cx.AdministrativeDeregistration, scscfName).Result, resSuccess)
}

func TestTerminatingRequestForAnUnregisteredUserReachesAnSCSCF(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	// The default profile has services for unregistered users (rcs-as
	// stores messages), so the I-CSCF is told to pick an S-CSCF.
	lia := c.lir(impu1, false)
	wantResult(t, "LIR", lia.Result, exp(cx.UnregisteredService))
	if lia.ServerName != "" || lia.ServerCapabilities == nil {
		t.Fatalf("LIA = %+v", lia)
	}
	saa := c.sar("", []string{impu1}, cx.UnregisteredUser, scscfName)
	wantResult(t, "SAR", saa.Result, resSuccess)
	if saa.UserName != impi1 || saa.UserData == nil {
		t.Fatalf("SAA = %+v", saa)
	}
	if s := e.sub(impi1); s.Identity(impu1).State != store.Unregistered || s.ServerName != scscfName {
		t.Fatalf("after SAR: %+v", s)
	}
	if lia := c.lir(impu1, false); lia.Result != resSuccess || lia.ServerName != scscfName {
		t.Fatalf("LIA for the unregistered user = %+v", lia)
	}
	// The user registers from there.
	wantResult(t, "UAR", c.uar(impi1, impu1, 0).Result, exp(cx.SubsequentRegistration))
}

func TestUserWithoutUnregisteredServicesIsNotRegisteredForLIR(t *testing.T) {
	e := newEnv(t)
	registeredOnly := DefaultRCSProfile("registered-only", asURI)
	for i := range registeredOnly.Criteria {
		registeredOnly.Criteria[i].ProfilePart = ifc.ProfilePartRegistered
	}
	if _, err := e.store.CreateProfile(context.Background(), registeredOnly); err != nil {
		t.Fatal(err)
	}
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) { s.Profile = "registered-only" })
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "icscf-1.rcs.local")
	wantResult(t, "terminating", c.lir(impu1, false).Result, exp(cx.ErrorIdentityNotRegistered))
	wantResult(t, "originating", c.lir(impu1, true).Result, exp(cx.UnregisteredService))
	// Deregistration offering to keep the name: not kept.
	c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	c.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	saa := c.sar(impi1, nil, cx.TimeoutDeregistrationStoreServerName, scscfName)
	wantResult(t, "store server name", saa.Result, exp(cx.SuccessServerNameNotStored))
	if s := e.sub(impi1); s.ServerName != "" || s.Identity(impu1).State != store.NotRegistered {
		t.Fatalf("after deregistration: %+v", s)
	}
}

func TestDeregistrationKeepsTheNameWhenUnregisteredServicesNeedIt(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	c.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	saa := c.sar(impi1, []string{impu1}, cx.UserDeregistrationStoreServerName, scscfName)
	wantResult(t, "store server name", saa.Result, resSuccess)
	if s := e.sub(impi1); s.ServerName != scscfName || s.Identity(impu1).State != store.Unregistered {
		t.Fatalf("after deregistration: %+v", s)
	}
	if lia := c.lir(impu1, false); lia.Result != resSuccess || lia.ServerName != scscfName {
		t.Fatalf("LIA = %+v", lia)
	}
}

func TestUserDataAlreadyAvailableLeavesItOut(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) {
		s.Charging = &store.ChargingInformation{PrimaryEventChargingFunctionName: "aaa://ecf." + domain}
	})
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	saa := c.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	if saa.UserData == nil || saa.ChargingInformation == nil || saa.ChargingInformation.PrimaryEventChargingFunctionName != "aaa://ecf."+domain {
		t.Fatalf("SAA = %+v", saa)
	}
	r := &cx.SAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentities: []string{impu1},
		ServerName: scscfName, AssignmentType: cx.ReRegistration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable}
	saa, err := cx.ParseSAA(c.send(r.Message(c.node)))
	if err != nil {
		t.Fatal(err)
	}
	if saa.Result != resSuccess || saa.UserData != nil || saa.ChargingInformation != nil {
		t.Fatalf("SAA with data already available = %+v", saa)
	}
}

func TestTooLargeUserDataIsTooMuchData(t *testing.T) {
	e := newEnv(t)
	big := DefaultRCSProfile("big", asURI)
	big.Criteria = nil
	for i := range 64 {
		big.Criteria = append(big.Criteria, ifc.FilterCriteria{
			Priority:          i,
			ApplicationServer: ifc.ApplicationServer{ServerName: asURI, ServiceInfo: strings.Repeat("x", 2100)},
		})
	}
	if _, err := e.store.CreateProfile(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	e.provision(impi1, impu1)
	e.modify(impi1, func(s *store.Subscription) { s.Profile = "big" })
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	wantResult(t, "SAR", c.sar(impi1, []string{impu1}, cx.Registration, scscfName).Result, exp(cx.ErrorTooMuchData))
	if s := e.sub(impi1); s.Identity(impu1).State != store.NotRegistered || s.ServerName != "" {
		t.Errorf("a SAR answered with too much data registered the user: %+v", s)
	}
}

func TestStoreFailuresAreUnableToComply(t *testing.T) {
	e := newEnvWith(t, &failingStore{Store: store.NewMemory()})
	e.provision(impi1, impu1)
	e.store.(*failingStore).fail.Store(true)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	wantResult(t, "UAR", c.uar(impi1, impu1, 0).Result, resUnable)
	wantResult(t, "MAR", c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil).Result, resUnable)
	wantResult(t, "SAR", c.sar(impi1, []string{impu1}, cx.Registration, scscfName).Result, resUnable)
	wantResult(t, "LIR", c.lir(impu1, false).Result, resUnable)
	if e.metrics.get("cx.mar.error") != 1 || !strings.Contains(e.logs.String(), "Cx request failed") {
		t.Error("store failure not logged and counted")
	}
	assertNoSecrets(t, "logs", e.logs.String())
}

func TestMissingProfileIsUnableToComply(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	// The memory store refuses to delete a profile in use; DynamoDB's
	// eventually consistent check may not, which is the case simulated.
	h := e.newHSS(func(o *Options) { o.Store = &profileless{Store: e.store} })
	c := connectCSCF(t, serveHSS(t, h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	wantResult(t, "SAR", c.sar(impi1, []string{impu1}, cx.Registration, scscfName).Result, resUnable)
	wantResult(t, "LIR", c.lir(impu1, false).Result, resUnable)
	wantResult(t, "UAR", c.uar(impi1, impu1, 0).Result, resUnable)
	if e.metrics.get("profile.missing") != 3 {
		t.Errorf("missing profile counted %d times", e.metrics.get("profile.missing"))
	}
	if s := e.sub(impi1); s.Identity(impu1).State != store.NotRegistered {
		t.Error("a SAR that could not be served changed the state")
	}
}

// profileless reports every profile as missing.
type profileless struct{ store.Store }

func (p *profileless) Profile(context.Context, string) (*store.ServiceProfile, error) {
	return nil, store.ErrNotFound
}

func TestUnknownUserAuthorizationTypeIsAnInvalidAVP(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "icscf-1.rcs.local")
	wantResult(t, "UAR", c.uar(impi1, impu1, 7).Result, cx.ResultCode(diameter.ResultInvalidAVPValue))
}

func TestCxAnswersCarryNoSecretInLogs(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	c := connectCSCF(t, serveHSS(t, e.h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	dmaa := c.mar(impi1, impu1, cx.SchemeSIPDigest, 1, scscfName, nil)
	c.sar(impi1, []string{impu1}, cx.Registration, scscfName)
	logs := e.logs.String()
	item := maa.AuthDataItems[0]
	assertNoSecrets(t, "logs", logs, string(hexOf(item.Authorization.Reveal())), string(hexOf(item.ConfidentialityKey.Reveal())),
		dmaa.AuthDataItems[0].Digest.HA1, "15550100001", imsi1)
}

func hexOf(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return out
}

func TestVersionConflictsAreRetriedWithAFreshRead(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	// The first write loses a race: another task writes in between.
	racy := &racingStore{Store: e.store, before: func() {
		e.modify(impi1, func(s *store.Subscription) { s.AKA.SQN += 10 << milenage.INDBits })
	}}
	h := e.newHSS(func(o *Options) { o.Store = racy })
	c := connectCSCF(t, serveHSS(t, h, "hss-a.rcs.local"), "scscf-1.rcs.local")
	maa := c.mar(impi1, impu1, cx.SchemeDigestAKAv1MD5, 1, scscfName, nil)
	if got := sqnOf(t, maa.AuthDataItems[0]); got.SEQ() != 11 {
		t.Fatalf("SEQ = %d, want 11: the retry must start from the other task's SQN", got.SEQ())
	}
	if e.metrics.get("store.conflict") != 1 {
		t.Errorf("conflicts = %d", e.metrics.get("store.conflict"))
	}
}

// racingStore runs before once, just before the first update.
type racingStore struct {
	store.Store
	before func()
	done   bool
}

func (r *racingStore) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if !r.done {
		r.done = true
		r.before()
	}
	return r.Store.UpdateSubscription(ctx, old, s)
}

func TestUpdateGivesUpUnderEndlessContention(t *testing.T) {
	e := newEnv(t)
	e.provision(impi1, impu1)
	h := e.newHSS(func(o *Options) { o.Store = &conflictingStore{Store: e.store} })
	// Every caller has a deadline, which is what stops the retries.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := h.update(ctx, impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil })
	if !errors.Is(err, errContention) {
		t.Fatalf("update = %v, want errContention", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := h.update(ctx, impi1, func(s *store.Subscription) error { s.AuthPending = true; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("update with a cancelled context = %v", err)
	}
}

type conflictingStore struct{ store.Store }

func (conflictingStore) UpdateSubscription(context.Context, *store.Subscription, *store.Subscription) (*store.Subscription, error) {
	return nil, store.ErrConflict
}
