package state_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

func TestMemoryStoreMeetsTheContract(t *testing.T) {
	statetest.Run(t, func(*testing.T) state.Store { return state.NewMemory() }, statetest.Options{
		// Two instances sharing DynamoDB are two handles on one store here.
		Second: func(_ *testing.T, first state.Store) state.Store { return first },
	})
}

func TestPruneRemovesOnlyExpiredContacts(t *testing.T) {
	r := statetest.Registration(statetest.IMPI1, statetest.IMPU1, -time.Minute, time.Hour, 0)
	expired := r.Prune(statetest.T0)
	if len(expired) != 2 || len(r.Contacts) != 1 || r.Contacts[0].Expires != statetest.T0.Add(time.Hour) {
		t.Fatalf("expired %d, left %+v", len(expired), r.Contacts)
	}
	if got := r.NextExpiry(); got != statetest.T0.Add(time.Hour) {
		t.Errorf("NextExpiry = %v", got)
	}
	if got := (&state.Registration{}).NextExpiry(); !got.IsZero() {
		t.Errorf("NextExpiry without contacts = %v, want zero", got)
	}
}

func TestCredentialsAreNotPrinted(t *testing.T) {
	c := statetest.Challenge(statetest.IMPI1, "n", time.Minute)
	c.AKA.XRES = []byte("SECRET-XRES")
	d := state.DigestChallenge{Realm: "r", Algorithm: "MD5", HA1: "SECRET-HA1"}
	for _, s := range []string{fmt.Sprint(c.AKA), fmt.Sprintf("%v %+v %#v", *c.AKA, *c.AKA, *c.AKA), fmt.Sprintf("%v %+v %#v", d, d, d)} {
		if strings.Contains(s, "SECRET") {
			t.Errorf("printed a credential: %s", s)
		}
	}
}
