package registrar

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// TestAnUnregisteredUserIsServedThoughANewerProfileWasSavedMeanwhile (QA on
// #359): a newer profile a REGISTER saved meanwhile stays, and the unregistered
// user is still served (unregistered.go keeps going on ErrConflict).
func TestAnUnregisteredUserIsServedThoughANewerProfileWasSavedMeanwhile(t *testing.T) {
	e := newEnv(t)
	e.akaUser(impi1, impu1, tel1)
	g := e.instance(1)
	key := state.SetKey{IMPI: impi1, IMPU: impu1}
	if err := e.store.SaveProfile(bg, &state.Profile{Key: key, UserData: []byte("<IMSSubscription/>"), Received: t0.Add(time.Hour), KeepUntil: t0.Add(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Unregistered(bg, impu1); err != nil {
		t.Errorf("refused: %v", err)
	}
}
