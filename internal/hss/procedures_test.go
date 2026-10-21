package hss

import (
	"reflect"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// subWith builds a subscription for the procedure tables: impu1 and tel1 in
// set 0, impu2 in set 1, each set in the state given.
func subWith(set0, set1 store.RegistrationState, server string, pending bool) *store.Subscription {
	return &store.Subscription{
		IMPI: impi1, Profile: DefaultProfileID, ServerName: server, AuthPending: pending,
		PublicIdentities: []store.PublicIdentity{
			{IMPU: impu1, State: set0}, {IMPU: tel1, State: set0}, {IMPU: impu2, ImplicitSet: 1, State: set1},
		},
	}
}

const (
	nr  = store.NotRegistered
	reg = store.Registered
	unr = store.Unregistered
)

func TestUARFollowsTheRegistrationState(t *testing.T) {
	for name, c := range map[string]struct {
		sub        *store.Subscription
		typ        cx.UserAuthorizationType
		result     cx.Result
		serverName string
		caps       bool
	}{
		"first registration":                {subWith(nr, nr, "", false), cx.AuthorizeRegistration, exp(cx.FirstRegistration), "", true},
		"registered":                        {subWith(reg, nr, scscfName, false), cx.AuthorizeRegistration, exp(cx.SubsequentRegistration), scscfName, false},
		"unregistered":                      {subWith(unr, nr, scscfName, false), cx.AuthorizeRegistration, exp(cx.SubsequentRegistration), scscfName, false},
		"other set registered":              {subWith(nr, reg, scscfName, false), cx.AuthorizeRegistration, exp(cx.SubsequentRegistration), scscfName, false},
		"authentication pending":            {subWith(nr, nr, scscfName, true), cx.AuthorizeRegistration, exp(cx.SubsequentRegistration), scscfName, false},
		"deregistration of registered":      {subWith(reg, nr, scscfName, false), cx.AuthorizeDeregistration, resSuccess, scscfName, false},
		"deregistration of unregistered":    {subWith(unr, nr, scscfName, false), cx.AuthorizeDeregistration, resSuccess, scscfName, false},
		"deregistration during auth":        {subWith(nr, nr, scscfName, true), cx.AuthorizeDeregistration, resSuccess, scscfName, false},
		"deregistration of not registered":  {subWith(nr, reg, scscfName, false), cx.AuthorizeDeregistration, exp(cx.ErrorIdentityNotRegistered), "", false},
		"registration and capabilities":     {subWith(reg, nr, scscfName, false), cx.AuthorizeRegistrationAndCapabilities, resSuccess, "", true},
		"capabilities for a first register": {subWith(nr, nr, "", false), cx.AuthorizeRegistrationAndCapabilities, resSuccess, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			got := decideUAR(c.sub, impu1, c.typ)
			want := uarOutcome{result: c.result, serverName: c.serverName, capabilities: c.caps}
			if got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestMARStoresTheServerAndSetsAuthenticationPending(t *testing.T) {
	for name, c := range map[string]struct {
		sub     *store.Subscription
		server  string
		changed bool
		pending bool
	}{
		"not registered":            {subWith(nr, nr, "", false), scscfName, true, true},
		"registered, same S-CSCF":   {subWith(reg, nr, scscfName, false), scscfName, false, false},
		"registered, other S-CSCF":  {subWith(reg, nr, scscfName, false), otherName, true, true},
		"unregistered, same S-CSCF": {subWith(unr, nr, scscfName, false), scscfName, true, true},
		"already pending":           {subWith(nr, nr, scscfName, true), scscfName, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			s := c.sub
			if changed := applyMAR(s, impu1, c.server); changed != c.changed || s.AuthPending != c.pending || s.ServerName != c.server {
				t.Errorf("changed %t, pending %t, server %q", changed, s.AuthPending, s.ServerName)
			}
		})
	}
}

func TestSARAppliesEachAssignmentType(t *testing.T) {
	type want struct {
		result     cx.Result
		userData   bool
		set0, set1 store.RegistrationState
		server     string
		pending    bool
	}
	for name, c := range map[string]struct {
		sub   *store.Subscription
		impus []string
		typ   cx.ServerAssignmentType
		from  string
		keep  bool
		want  want
	}{
		"registration":                     {subWith(nr, nr, scscfName, true), []string{impu1}, cx.Registration, scscfName, true, want{resSuccess, true, reg, nr, scscfName, false}},
		"registration without a MAR":       {subWith(nr, nr, "", false), []string{tel1}, cx.Registration, scscfName, true, want{resSuccess, true, reg, nr, scscfName, false}},
		"re-registration":                  {subWith(reg, nr, scscfName, false), []string{impu1}, cx.ReRegistration, scscfName, true, want{resSuccess, true, reg, nr, scscfName, false}},
		"registration by another S-CSCF":   {subWith(reg, nr, scscfName, false), []string{impu1}, cx.Registration, otherName, true, want{exp(cx.ErrorIdentityAlreadyRegistered), false, reg, nr, scscfName, false}},
		"unregistered user":                {subWith(nr, nr, "", false), []string{impu1}, cx.UnregisteredUser, scscfName, true, want{resSuccess, true, unr, nr, scscfName, false}},
		"unregistered user while reg":      {subWith(reg, nr, scscfName, false), []string{impu1}, cx.UnregisteredUser, scscfName, true, want{resSuccess, true, unr, nr, scscfName, false}},
		"unregistered user, other S-CSCF":  {subWith(unr, nr, scscfName, false), []string{impu1}, cx.UnregisteredUser, otherName, true, want{exp(cx.ErrorIdentityAlreadyRegistered), false, unr, nr, scscfName, false}},
		"no assignment":                    {subWith(reg, nr, scscfName, false), []string{impu1}, cx.NoAssignment, scscfName, true, want{resSuccess, true, reg, nr, scscfName, false}},
		"no assignment, other S-CSCF":      {subWith(reg, nr, scscfName, false), []string{impu1}, cx.NoAssignment, otherName, true, want{resUnable, false, reg, nr, scscfName, false}},
		"no assignment, nothing stored":    {subWith(nr, nr, "", false), []string{impu1}, cx.NoAssignment, scscfName, true, want{resUnable, false, nr, nr, "", false}},
		"user deregistration of one set":   {subWith(reg, reg, scscfName, false), []string{tel1}, cx.UserDeregistration, scscfName, true, want{resSuccess, false, nr, reg, scscfName, false}},
		"timeout deregistration of all":    {subWith(reg, unr, scscfName, false), nil, cx.TimeoutDeregistration, scscfName, true, want{resSuccess, false, nr, nr, "", false}},
		"administrative deregistration":    {subWith(reg, nr, scscfName, true), nil, cx.AdministrativeDeregistration, scscfName, true, want{resSuccess, false, nr, nr, "", false}},
		"too much data":                    {subWith(reg, nr, scscfName, false), []string{impu1}, cx.DeregistrationTooMuchData, scscfName, true, want{resSuccess, false, nr, nr, "", false}},
		"deregistration, other S-CSCF":     {subWith(reg, nr, scscfName, false), nil, cx.UserDeregistration, otherName, true, want{exp(cx.ErrorIdentityAlreadyRegistered), false, reg, nr, scscfName, false}},
		"store server name, kept":          {subWith(reg, nr, scscfName, false), []string{impu1}, cx.UserDeregistrationStoreServerName, scscfName, true, want{resSuccess, false, unr, nr, scscfName, false}},
		"store server name, not kept":      {subWith(reg, nr, scscfName, false), nil, cx.TimeoutDeregistrationStoreServerName, scscfName, false, want{exp(cx.SuccessServerNameNotStored), false, nr, nr, "", false}},
		"store server name, other set reg": {subWith(reg, reg, scscfName, false), []string{impu1}, cx.UserDeregistrationStoreServerName, scscfName, false, want{exp(cx.SuccessServerNameNotStored), false, nr, reg, scscfName, false}},
		"authentication failure":           {subWith(nr, nr, scscfName, true), []string{impu1}, cx.AuthenticationFailure, scscfName, true, want{resSuccess, false, nr, nr, "", false}},
		"authentication timeout while reg": {subWith(reg, nr, scscfName, true), []string{impu1}, cx.AuthenticationTimeout, scscfName, true, want{resSuccess, false, reg, nr, scscfName, false}},
		"unknown assignment type":          {subWith(reg, nr, scscfName, false), []string{impu1}, 12, scscfName, true, want{exp(cx.ErrorInAssignmentType), false, reg, nr, scscfName, false}},
	} {
		t.Run(name, func(t *testing.T) {
			s := c.sub
			out := applySAR(s, c.impus, &cx.SAR{ServerName: c.from, AssignmentType: c.typ}, c.keep)
			got := want{out.result, out.userData, s.Identity(impu1).State, s.Identity(impu2).State, s.ServerName, s.AuthPending}
			if got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
			if s.Identity(impu1).State != s.Identity(tel1).State {
				t.Error("an implicit set was split")
			}
			if (out.result == exp(cx.ErrorIdentityAlreadyRegistered)) != (out.serverName != "") {
				t.Errorf("server name in the answer = %q for %v", out.serverName, out.result)
			}
		})
	}
}

func TestLIRFollowsTheRegistrationState(t *testing.T) {
	for name, c := range map[string]struct {
		sub          *store.Subscription
		originating  bool
		unregistered bool
		want         lirOutcome
	}{
		"registered":                       {subWith(reg, nr, scscfName, false), false, false, lirOutcome{resSuccess, scscfName, false}},
		"unregistered":                     {subWith(unr, nr, scscfName, false), false, false, lirOutcome{resSuccess, scscfName, false}},
		"not registered with services":     {subWith(nr, nr, "", false), false, true, lirOutcome{exp(cx.UnregisteredService), "", true}},
		"not registered, other set served": {subWith(nr, reg, scscfName, false), false, true, lirOutcome{resSuccess, scscfName, false}},
		"not registered, originating":      {subWith(nr, nr, "", false), true, false, lirOutcome{exp(cx.UnregisteredService), "", true}},
		"not registered without services":  {subWith(nr, nr, "", false), false, false, lirOutcome{exp(cx.ErrorIdentityNotRegistered), "", false}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := decideLIR(c.sub, impu1, c.originating, c.unregistered); got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestProvisioningChangesTellTheSCSCFWhatItMustKnow(t *testing.T) {
	ids := func(set0 store.RegistrationState, list ...store.PublicIdentity) *store.Subscription {
		s := &store.Subscription{IMPI: impi1, Profile: DefaultProfileID, ServerName: scscfName, PublicIdentities: list}
		if set0 == nr {
			s.ServerName = ""
		}
		for i := range s.PublicIdentities {
			if s.PublicIdentities[i].ImplicitSet == 0 {
				s.PublicIdentities[i].State = set0
			}
		}
		return s
	}
	id := func(impu string, set int, barred bool) store.PublicIdentity {
		return store.PublicIdentity{IMPU: impu, ImplicitSet: set, Barred: barred}
	}
	charged := func(s *store.Subscription) *store.Subscription {
		s.Charging = &store.ChargingInformation{PrimaryEventChargingFunctionName: "aaa://ecf." + domain}
		return s
	}
	for name, c := range map[string]struct {
		old, next      *store.Subscription
		profileChanged bool
		want           []push
		state          store.RegistrationState // of next's set 0
		server         string
	}{
		"nothing served": {
			ids(nr, id(impu1, 0, false)), ids(nr, id(impu1, 0, false), id(tel1, 0, false)), false, nil, nr, "",
		},
		"identity added to a registered set": {
			ids(reg, id(impu1, 0, false)), ids(nr, id(impu1, 0, false), id(tel1, 0, false)), false,
			[]push{{set: 0}}, reg, scscfName,
		},
		"identity barred": {
			ids(reg, id(impu1, 0, false), id(tel1, 0, false)), ids(nr, id(impu1, 0, false), id(tel1, 0, true)), false,
			[]push{{set: 0}}, reg, scscfName,
		},
		"profile changed": {
			ids(reg, id(impu1, 0, false)), ids(nr, id(impu1, 0, false)), true, []push{{set: 0}}, reg, scscfName,
		},
		"default identity changed": {
			ids(reg, id(impu1, 0, false), id(tel1, 0, false)), ids(nr, id(tel1, 0, false), id(impu1, 0, false)), false,
			[]push{{deregister: true, reason: cx.ServerChange, impus: []string{impu1, tel1}, set: -1}}, nr, "",
		},
		"set emptied": {
			ids(reg, id(impu1, 0, false), id(tel1, 0, false)), ids(nr, id(impu2, 1, false)), false,
			[]push{{deregister: true, reason: cx.PermanentTermination, impus: []string{impu1, tel1}, set: -1}}, nr, "",
		},
		"charging changed alone": {
			ids(reg, id(impu1, 0, false)), charged(ids(nr, id(impu1, 0, false))), false,
			[]push{{set: -1, charging: true}}, reg, scscfName,
		},
		"charging changed with identities": {
			ids(reg, id(impu1, 0, false)), charged(ids(nr, id(impu1, 0, false), id(tel1, 0, false))), false,
			[]push{{set: 0, charging: true}}, reg, scscfName,
		},
		"no change": {
			ids(reg, id(impu1, 0, false)), ids(nr, id(impu1, 0, false)), false, nil, reg, scscfName,
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := c.next
			if c.old.ServerName != "" {
				next.ServerName = c.old.ServerName
			}
			got := reconcile(c.old, next, c.profileChanged)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("pushes\n got %+v\nwant %+v", got, c.want)
			}
			for _, p := range next.PublicIdentities {
				if p.ImplicitSet == 0 && p.State != c.state {
					t.Errorf("%s state = %v, want %v", p.IMPU, p.State, c.state)
				}
			}
			if next.ServerName != c.server {
				t.Errorf("server name = %q, want %q", next.ServerName, c.server)
			}
		})
	}
}

// #213: an identity that moves between two served implicit registration
// sets updates the set losing it first, then the one gaining it (TS 29.228
// §6.5.2.1), whichever comes first in the subscription.
func TestAnIdentityMovingBetweenSetsUpdatesTheOldSetFirst(t *testing.T) {
	registered := func(list ...store.PublicIdentity) *store.Subscription {
		s := &store.Subscription{IMPI: impi1, Profile: DefaultProfileID, ServerName: scscfName, PublicIdentities: list}
		for i := range s.PublicIdentities {
			s.PublicIdentities[i].State = reg
		}
		return s
	}
	id := func(impu string, set int) store.PublicIdentity {
		return store.PublicIdentity{IMPU: impu, ImplicitSet: set}
	}
	for name, c := range map[string]struct {
		old, next []store.PublicIdentity
		want      []push
	}{
		// set 1 comes first in the subscription, and gains tel1.
		"from set 0 to set 1": {
			[]store.PublicIdentity{id(impu2, 1), id(impu1, 0), id(tel1, 0)},
			[]store.PublicIdentity{id(impu2, 1), id(tel1, 1), id(impu1, 0)},
			[]push{{set: 0}, {set: 1}},
		},
		// set 0 comes first, and gains impu3.
		"from set 1 to set 0": {
			[]store.PublicIdentity{id(impu1, 0), id(impu2, 1), id(impu3, 1)},
			[]store.PublicIdentity{id(impu1, 0), id(impu3, 0), id(impu2, 1)},
			[]push{{set: 1}, {set: 0}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := registered(c.next...)
			if got := reconcile(registered(c.old...), next, false); !reflect.DeepEqual(got, c.want) {
				t.Errorf("pushes\n got %+v\nwant %+v", got, c.want)
			}
			for _, p := range next.PublicIdentities {
				if p.State != reg {
					t.Errorf("%s state = %v, want registered", p.IMPU, p.State)
				}
			}
		})
	}
}

func TestDigestAndDeletionPushes(t *testing.T) {
	if p := digestPushes(subWith(reg, nr, scscfName, false)); len(p) != 1 || !p[0].digest {
		t.Errorf("registered: %+v", p)
	}
	if p := digestPushes(subWith(nr, nr, scscfName, true)); len(p) != 1 {
		t.Errorf("pending: %+v", p)
	}
	if p := digestPushes(subWith(unr, nr, scscfName, false)); p != nil {
		t.Errorf("unregistered only: %+v", p)
	}
	if p := deletePushes(subWith(nr, unr, scscfName, false)); len(p) != 1 || !p[0].deregister || p[0].reason != cx.PermanentTermination || p[0].impus != nil {
		t.Errorf("delete served: %+v", p)
	}
	if p := deletePushes(subWith(nr, nr, "", false)); p != nil {
		t.Errorf("delete idle: %+v", p)
	}
	if p := profilePushes(subWith(reg, unr, scscfName, false)); len(p) != 2 || p[0].set != 0 || p[1].set != 1 {
		t.Errorf("profile: %+v", p)
	}
}
