package conference

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func mustMerge(t *testing.T, local *Info, doc string) *Info {
	t.Helper()
	out, err := Merge(local, mustParse(t, doc))
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return out
}

func TestTheFirstFullDocumentBecomesTheState(t *testing.T) {
	got := mustMerge(t, nil, fullDoc)
	if !reflect.DeepEqual(got, fullInfo()) {
		t.Errorf("Merge(nil, full) = %+v", got)
	}
}

func TestTheFirstDocumentCannotBePartial(t *testing.T) {
	if _, err := Merge(nil, mustParse(t, partial(""))); !errors.Is(err, ErrNoFullState) {
		t.Errorf("Merge(nil, partial) error = %v, want ErrNoFullState", err)
	}
}

func TestAPartialDocumentChangesOnlyWhatItCarries(t *testing.T) {
	local := fullInfo()
	got := mustMerge(t, local, partial(`
<conference-description><subject>Dinner only</subject></conference-description>
<users state="partial">
  <user entity="`+alice+`" state="partial">
    <display-text>Alice K.</display-text>
    <endpoint entity="alice-phone" state="partial">
      <status>disconnected</status>
      <disconnection-method>departed</disconnection-method>
    </endpoint>
    <endpoint entity="alice-tablet" state="partial"><status>dialing-in</status></endpoint>
    <endpoint entity="alice-watch" state="deleted"/>
  </user>
  <user entity="`+bob+`" state="deleted"/>
  <user entity="`+carol+`" state="full"><display-text>Carol</display-text></user>
  <user entity="`+dave+`" state="partial">
    <roles><entry>participant</entry></roles>
    <endpoint entity="dave-phone" state="partial"><status>alerting</status></endpoint>
    <endpoint entity="dave-old" state="deleted"/>
  </user>
  <user entity="sip:nobody@ims.mnc001.mcc001.3gppnetwork.org" state="deleted"/>
</users>`))

	want := &Info{
		Entity:  chat,
		State:   Full,
		Version: 2,
		// The description is atomic: the new one replaces the old whole.
		Description: &Description{Subject: "Dinner only"},
		Users: &Users{State: Full, List: []User{
			{Entity: alice, State: Full, DisplayText: "Alice K.", Roles: []string{"chairman", "participant"}, Endpoints: []Endpoint{
				{Entity: "alice-phone", State: Full, DisplayText: "Alice's phone", Status: Disconnected, JoiningMethod: DialedIn, DisconnectionMethod: Departed},
				{Entity: "alice-tablet", State: Full, Status: DialingIn},
			}},
			{Entity: carol, State: Full, DisplayText: "Carol"},
			{Entity: dave, State: Full, Roles: []string{"participant"}, Endpoints: []Endpoint{
				{Entity: "dave-phone", State: Full, Status: Alerting},
			}},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Merge() =\n%+v\nwant\n%+v", got, want)
	}
	if !reflect.DeepEqual(local, fullInfo()) {
		t.Errorf("Merge modified the local state: %+v", local)
	}
}

func TestAFullEndpointInAPartialUserReplacesTheOldOne(t *testing.T) {
	got := mustMerge(t, fullInfo(), partial(`<users state="partial"><user entity="`+alice+`" state="partial">
<roles><entry>participant</entry></roles>
<endpoint entity="alice-phone" state="full"><status>on-hold</status></endpoint></user></users>`))
	alice := got.Users.List[0]
	if !reflect.DeepEqual(alice.Roles, []string{"participant"}) {
		t.Errorf("roles = %v; a present <roles> replaces the old whole", alice.Roles)
	}
	if want := []Endpoint{{Entity: "alice-phone", State: Full, Status: OnHold}}; !reflect.DeepEqual(alice.Endpoints, want) {
		t.Errorf("endpoints = %+v", alice.Endpoints)
	}
}

func TestUsersWithoutAStateInAPartialDocumentAreReadAsPartial(t *testing.T) {
	// The RFC 4575 §7.2 example writes a delta this way; reading it with the
	// schema default would replace the roster with the one user it names.
	got := mustMerge(t, fullInfo(), partial(`<users><user entity="`+dave+`"/></users>`))
	if n := len(got.Users.List); n != 4 || got.Users.List[3].Entity != dave {
		t.Errorf("users = %+v; the roster must keep its members and gain dave", got.Users.List)
	}
	if got.Description == nil || got.Description.Subject != "Hiking & dinner" {
		t.Errorf("an absent description is kept: %+v", got.Description)
	}
}

func TestFullUsersInAPartialDocumentReplaceTheRoster(t *testing.T) {
	got := mustMerge(t, fullInfo(), partial(`<users state="full"><user entity="`+dave+`"/></users>`))
	if want := []User{{Entity: dave, State: Full}}; !reflect.DeepEqual(got.Users.List, want) {
		t.Errorf("users = %+v", got.Users.List)
	}
}

func TestForeignNamespacedAttributesAreNotStateOrEntity(t *testing.T) {
	const head = `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" xmlns:x="urn:example:ext" entity="sip:conf@example.com" x:entity="sip:other@example.com" state="%s" x:state="deleted" version="%d" x:version="9">`
	base, err := Parse([]byte(fmt.Sprintf(head, "full", 1) + `<conference-description/><users x:state="deleted"><user entity="sip:a@example.com"/><user entity="sip:b@example.com" x:entity="sip:evil@example.com"><endpoint entity="b1" x:entity="e" x:state="deleted"/></user></users></conference-info>`))
	if err != nil {
		t.Fatal(err)
	}
	if base.Entity != "sip:conf@example.com" || base.Version != 1 || base.State != Full {
		t.Errorf("root attributes = %+v", base)
	}
	if base.Users.List[1].Entity != "sip:b@example.com" || base.Users.List[1].Endpoints[0] != (Endpoint{Entity: "b1", State: Full}) {
		t.Errorf("x:entity or x:state overrode an attribute: %+v", base.Users.List[1])
	}
	doc, err := Parse([]byte(fmt.Sprintf(head, "partial", 2) + `<users state="partial"><user entity="sip:a@example.com" state="partial" x:state="deleted"><display-text>A</display-text></user></users></conference-info>`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Merge(base, doc)
	if err != nil || len(got.Users.List) != 2 || got.Users.List[0].DisplayText != "A" {
		t.Errorf("x:state=\"deleted\" removed a user: %+v, %v", got, err)
	}
}

func TestDeletedUsersEmptyTheRoster(t *testing.T) {
	got := mustMerge(t, fullInfo(), partial(`<users state="deleted"/>`))
	if got.Users == nil || len(got.Users.List) != 0 {
		t.Errorf("users = %+v", got.Users)
	}
	if _, err := got.Marshal(); err != nil {
		t.Errorf("the merged state still marshals as a full document: %v", err)
	}
}

func TestOldAndRepeatedDocumentsAreDiscarded(t *testing.T) {
	local := mustMerge(t, nil, root(`version="5"`, `<conference-description/><users/>`))
	for _, version := range []string{"5", "4", "0"} {
		for _, state := range []string{"full", "partial", "deleted"} {
			doc := root(`state="`+state+`" version="`+version+`"`, "")
			if state == "full" {
				doc = root(`version="`+version+`"`, `<conference-description/><users/>`)
			}
			if _, err := Merge(local, mustParse(t, doc)); !errors.Is(err, ErrStaleVersion) {
				t.Errorf("version %s %s: error = %v, want ErrStaleVersion", version, state, err)
			}
		}
	}
	top := mustMerge(t, nil, root(`version="4294967295"`, `<conference-description/><users/>`))
	if _, err := Merge(top, mustParse(t, root(`state="partial" version="4294967295"`, ""))); !errors.Is(err, ErrStaleVersion) {
		t.Errorf("at the top version: %v", err)
	}
	if top.Version != math.MaxUint32 {
		t.Errorf("Version = %d", top.Version)
	}
}

func TestAPartialDocumentThatSkipsAVersionNeedsARefresh(t *testing.T) {
	_, err := Merge(fullInfo(), mustParse(t, root(`state="partial" version="3"`, "")))
	if !errors.Is(err, ErrVersionGap) {
		t.Errorf("Merge() error = %v, want ErrVersionGap", err)
	}
}

func TestAFullDocumentMayJumpVersions(t *testing.T) {
	got := mustMerge(t, fullInfo(), root(`version="40"`, `<conference-description/><users/>`))
	if got.Version != 40 || len(got.Users.List) != 0 {
		t.Errorf("Merge() = %+v", got)
	}
}

func TestADeletedConferenceReplacesTheState(t *testing.T) {
	got := mustMerge(t, fullInfo(), root(`state="deleted" version="9"`, ""))
	if want := (&Info{Entity: chat, State: Deleted, Version: 9}); !reflect.DeepEqual(got, want) {
		t.Errorf("Merge() = %+v", got)
	}
	if _, err := Merge(got, mustParse(t, root(`state="partial" version="10"`, ""))); !errors.Is(err, ErrNoFullState) {
		t.Errorf("partial after deleted: %v, want ErrNoFullState", err)
	}
	if again := mustMerge(t, got, root(`version="11"`, `<conference-description/><users/>`)); again.State != Full {
		t.Errorf("a new full document restarts the state: %+v", again)
	}
	if first := mustMerge(t, nil, root(`state="deleted" version="1"`, "")); first.State != Deleted {
		t.Errorf("a deleted first document: %+v", first)
	}
}

func TestADocumentAboutAnotherConferenceIsRejected(t *testing.T) {
	other := `<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:chat-2@ims.mnc001.mcc001.3gppnetwork.org" state="partial" version="2"/>`
	if _, err := Merge(fullInfo(), mustParse(t, other)); !errors.Is(err, ErrEntityMismatch) {
		t.Errorf("Merge() error = %v, want ErrEntityMismatch", err)
	}
}

func TestMergeRejectsInvalidInputs(t *testing.T) {
	if _, err := Merge(fullInfo(), nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("nil document: %v", err)
	}
	bad := fullInfo()
	bad.Users = nil
	if _, err := Merge(nil, bad); !errors.Is(err, ErrMalformed) {
		t.Errorf("invalid document: %v", err)
	}
	if _, err := Merge(bad, mustParse(t, partial(""))); !errors.Is(err, ErrMalformed) {
		t.Errorf("invalid local state: %v", err)
	}
}

func TestMergeNeverSharesMemoryWithItsInputs(t *testing.T) {
	doc := mustParse(t, fullDoc)
	got, err := Merge(nil, doc)
	if err != nil {
		t.Fatal(err)
	}
	got.Description.Subject = "changed"
	got.Users.List[0].Roles[0] = "changed"
	got.Users.List[0].Endpoints[0].Status = Disconnected
	if !reflect.DeepEqual(doc, fullInfo()) {
		t.Errorf("changing the result changed the document: %+v", doc)
	}

	upd := mustParse(t, partial(`<conference-description><subject>s</subject></conference-description>
<users state="partial"><user entity="`+dave+`" state="partial"><roles><entry>participant</entry></roles></user></users>`))
	next, err := Merge(fullInfo(), upd)
	if err != nil {
		t.Fatal(err)
	}
	next.Description.Subject = "changed"
	next.Users.List[3].Roles[0] = "changed"
	if upd.Description.Subject != "s" || upd.Users.List[0].Roles[0] != "participant" {
		t.Errorf("changing the result changed the update: %+v", upd)
	}
}

func TestTheMergedStateMarshalsAsAFullDocument(t *testing.T) {
	got := mustMerge(t, fullInfo(), partial(`<users state="partial"><user entity="`+dave+`" state="partial"><endpoint entity="d" state="partial"><status>pending</status></endpoint></user></users>`))
	out, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back := mustParse(t, string(out))
	if !reflect.DeepEqual(back, got) {
		t.Errorf("merged state does not round-trip:\n%+v\n%+v", got, back)
	}
}

func TestAPartialEndpointKeepsWhatItOmits(t *testing.T) {
	got := mustMerge(t, fullInfo(), partial(`<users state="partial"><user entity="`+alice+`" state="partial">
<endpoint entity="alice-phone" state="partial"><display-text>Work phone</display-text><joining-method>dialed-out</joining-method></endpoint>
</user></users>`))
	want := Endpoint{Entity: "alice-phone", State: Full, DisplayText: "Work phone", Status: Connected, JoiningMethod: DialedOut}
	if e := got.Users.List[0].Endpoints[0]; e != want {
		t.Errorf("endpoint = %+v, want %+v", e, want)
	}
}
