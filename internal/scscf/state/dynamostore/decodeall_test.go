package dynamostore

import (
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

// A listing with undecodable items returns the readable ones and one
// ErrInvalid for each other item, joined once, so that the RTR counts
// them (#478 QA).
func TestAListingJoinsOneErrorPerUnreadableItem(t *testing.T) {
	impus := []string{statetest.IMPU1, statetest.IMPU2, statetest.IMPU3, "sip:+15550100004@" + statetest.Domain, "sip:+15550100005@" + statetest.Domain}
	for bad := 1; bad <= 4; bad++ {
		f := newFake(t)
		d := newTestStore(t, f)
		for _, impu := range impus {
			if _, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, impu, time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		for _, impu := range impus[1 : 1+bad] {
			f.tables[DefaultRegistrationsTable][itemKey(key(setPK(statetest.Key1(impu))))][attrDoc] = bin([]byte("{"))
		}
		regs, err := d.RegistrationsOf(bg(), statetest.IMPI1)
		j, ok := err.(interface{ Unwrap() []error })
		if !ok || len(j.Unwrap()) != bad || !errors.Is(err, state.ErrInvalid) || len(regs) != len(impus)-bad {
			t.Errorf("%d unreadable: %d readable, error %v", bad, len(regs), err)
		}
	}
}
