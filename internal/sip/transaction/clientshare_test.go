package transaction

import (
	"math"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ClientShareOf rounds up, so that a bound of 1 still lets a client in, and
// never passes the bound, so that a share of 1 or one that rounds to it
// keeps even the largest bound (#511 code review).
func TestClientShareOfRoundsUpWithinTheBound(t *testing.T) {
	for _, tt := range []struct {
		bound int64
		share float64
		want  int64
	}{
		{1843, 0.8, 1475},
		{1, 0.8, 1},
		{10, 0.8, 8},
		{0, 0.8, 0},
		{math.MaxInt64, 1, math.MaxInt64},
		// Just under 1: 2^63 less 2^10, exactly, still within the bound.
		{math.MaxInt64, math.Nextafter(1, 0), math.MaxInt64 - 1<<10 + 1},
		{1843, 1, 1843},
	} {
		if got := ClientShareOf(tt.bound, tt.share); got != tt.want {
			t.Errorf("ClientShareOf(%d, %v) = %d, want %d", tt.bound, tt.share, got, tt.want)
		}
	}
}

// A share of 1 with the largest byte bound admits a client request: the
// client bound is not taken past the int64 range (#511 code review).
func TestAWholeClientShareOfTheLargestBoundAdmitsClients(t *testing.T) {
	h := newHarness(t, transport.UDP, Config{MaxServerTransactionBytes: math.MaxInt64, ClientShare: 1})
	h.layer.Receive(transport.Inbound{Message: request(t, "MESSAGE", "z9hG4bKone"), Source: transport.Source{Flow: "f", Network: transport.UDP, ClientFacing: true}})
	check(t, "TU calls", h.tu.take(), []string{"request MESSAGE"})
}

// A NaN share is outside 0..1 too (#511 code review).
func TestValidateRefusesANaNClientShare(t *testing.T) {
	if err := (Config{ClientShare: math.NaN()}).Validate(); err == nil {
		t.Fatal("a NaN ClientShare is valid")
	}
}
