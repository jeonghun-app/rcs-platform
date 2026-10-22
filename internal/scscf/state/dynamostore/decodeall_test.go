package dynamostore

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

// A listing with unreadable items returns the readable ones and one
// ErrInvalid for each other item, joined once, so that the RTR counts
// them: an item that does not decode, or one whose IMPI is invalid, whose
// error wraps two (#478 QA).
func TestAListingJoinsOneErrorPerUnreadableItem(t *testing.T) {
	impus := []string{statetest.IMPU1, statetest.IMPU2, statetest.IMPU3, "sip:+15550100004@" + statetest.Domain, "sip:+15550100005@" + statetest.Domain}
	for _, invalidIMPI := range []bool{false, true} {
		for bad := 1; bad <= 4; bad++ {
			f := newFake(t)
			d := newTestStore(t, f)
			for _, impu := range impus {
				if _, err := d.SaveRegistration(bg(), statetest.Registration(statetest.IMPI1, impu, time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			for _, impu := range impus[1 : 1+bad] {
				item := f.tables[DefaultRegistrationsTable][itemKey(key(setPK(statetest.Key1(impu))))]
				doc := []byte("{")
				if invalidIMPI {
					old := item[attrDoc].(*types.AttributeValueMemberB).Value
					if doc = bytes.Replace(old, []byte(`"impi":"`+statetest.IMPI1+`"`), []byte(`"impi":"not-an-impi"`), 1); bytes.Equal(doc, old) {
						t.Fatal("no IMPI in the stored document")
					}
				}
				item[attrDoc] = bin(doc)
			}
			regs, err := d.RegistrationsOf(bg(), statetest.IMPI1)
			j, ok := err.(interface{ Unwrap() []error })
			if !ok || len(j.Unwrap()) != bad || !errors.Is(err, state.ErrInvalid) || len(regs) != len(impus)-bad {
				t.Errorf("invalid IMPI %v, %d unreadable: %d readable, error %v", invalidIMPI, bad, len(regs), err)
			}
		}
	}
}
