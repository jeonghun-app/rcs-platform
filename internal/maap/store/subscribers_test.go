package store_test

import (
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

func TestMemorySubscribersMeetTheContract(t *testing.T) {
	storetest.RunSubscribers(t, func(*testing.T) store.Subscribers { return store.NewMemorySubscribers() })
}

func TestOnlyTheOneFormOfAnAliasIDOrSubscriberIsValid(t *testing.T) {
	id := "ab" + storetest.AliasID()[2:] // so that its first character has a case
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{id, true},
		{strings.ToUpper(id), false},
		{strings.ToUpper(id[:1]) + id[1:], false},
		{id[1:], false},
		{id + "a", false},
		{id[1:] + "1", false},
		{id[1:] + "=", false},
		{"", false},
	} {
		if got := store.ValidAliasID(tc.id); got != tc.want {
			t.Errorf("ValidAliasID(%q) = %v", tc.id, got)
		}
	}
	for s, want := range map[string]bool{
		storetest.Subscriber: true, "tel:+1": true, "tel:+" + strings.Repeat("1", 15): true,
		"tel:+" + strings.Repeat("1", 16): false, "tel:+": false, "tel:15550100001": false, "TEL:+15550100001": false,
		"tel:+1-555-0100": false, "tel:+15550100001;ext=1": false, "sip:+15550100001@example.com": false,
	} {
		if got := store.ValidSubscriber(s); got != want {
			t.Errorf("ValidSubscriber(%q) = %v", s, got)
		}
	}
}
