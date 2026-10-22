package store_test

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/content/contenttest"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// No fmt verb, valid or not, slog record or JSON encoding shows a queued
// message's CPIM (#547): a message is what the store and the queue's
// workers handle, so a debug line of one must not carry the chat.
func TestACPIMIsPrintedNowhere(t *testing.T) {
	const chat = "meet me at the usual place"
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	m := store.Message{Recipient: "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org", ID: "0001",
		CPIM: content.BodyOf([]byte(chat)), Enqueued: at, Expires: at.Add(time.Hour)}
	clone := m.Clone()
	contenttest.Hidden(t, chat, m, &m, clone, []store.Message{m}, map[string]store.Message{"m": m})
}

// A clone shares no memory with its message: the memory store keeps one,
// and a caller that changes the bytes it handed in or got back must not
// change what is stored.
func TestACloneSharesNoCPIM(t *testing.T) {
	cpim := []byte("From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>\r\n\r\nhi")
	m := store.Message{Recipient: "r", ID: "1", CPIM: content.BodyOf(cpim)}
	clone := m.Clone()
	cpim[0] = 'X'
	if got := clone.CPIM.Bytes(); got[0] != 'F' || len(got) != len(cpim) {
		t.Fatalf("the clone changed with its message: %q", got[:4])
	}
}
