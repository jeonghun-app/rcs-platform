package routing

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// TestAPositionLastsTheConfiguredLifetime (QA on #359): Config.ODILifetime
// is the one the position is signed with.
func TestAPositionLastsTheConfiguredLifetime(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
	short := func(c *Config) { c.ODILifetime = 10 * time.Second }
	r := fromUser(t, "MESSAGE", impu2)
	d := e.router(nil, short).Initial(bg, r)
	e.clock.advance(11 * time.Second)
	if got := e.router(nil, short).Initial(bg, backFrom(t, r, d, 0)); got.Status != 403 {
		t.Errorf("a position past its 10 s lifetime: status %d, targets %d", got.Status, len(got.Targets))
	}
}

// TestAKeyRotationKeepsTheChainGoingAcrossInstances (QA on #359): a key
// rotation: the new key goes first on one instance while another
// still signs with the old one; the chain goes on across both.
func TestAKeyRotationKeepsTheChainGoingAcrossInstances(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated), criterion(30, operatorAS, method("MESSAGE"), ifc.SessionTerminated))
	oldK := DialogKey{ID: "k1", Key: bytes.Repeat([]byte{1}, MinDialogKeyBytes)}
	newK := DialogKey{ID: "k3", Key: bytes.Repeat([]byte{3}, MinDialogKeyBytes)}
	notYet := e.router(nil, func(c *Config) { c.DialogKeys = []DialogKey{oldK} })
	rotated := e.router(nil, func(c *Config) { c.DialogKeys = []DialogKey{newK, oldK} })
	r := fromUser(t, "MESSAGE", impu2)
	d := notYet.Initial(bg, r)
	back := backFrom(t, r, d, 0)
	second := rotated.Initial(bg, back)
	if serverOf(t, second) != "third-as.rcs.local" {
		t.Fatalf("the rotated instance did not resume the old key's position: %d", second.Status)
	}
	if v, _ := second.Targets[0].Routes[1].URI.Param(odiParam); !strings.HasPrefix(v, "k3.") {
		t.Errorf("the rotated instance signs with %q, not its first key", strings.SplitN(v, ".", 2)[0])
	}
}
