package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store/storetest"
)

func TestMemoryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return store.NewMemory() })
}

func TestModesHaveNames(t *testing.T) {
	for m, want := range map[store.Mode]string{store.Chat: "chat", store.Standalone: "standalone", 0: "unknown"} {
		if m.String() != want {
			t.Errorf("%d = %q", m, m.String())
		}
	}
}

// #121 D2: a fenced copy is queued only while the groups store still names
// its owner; none at all without a groups store beside the queue.
func TestAFencedEnqueueNeedsTheGroupsOwner(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	copyOf := func(id string, f *store.Fence) store.Message {
		return store.Message{Recipient: "tel:+15550100002", ID: id, Sender: "sip:chat-1@conf.example.net", Mode: store.Group,
			CPIM: content.BodyOf([]byte("x")), Enqueued: at, Expires: at.Add(time.Hour), Fence: f}
	}
	s := store.NewMemory()
	fence := &store.Fence{Group: "sip:chat-1@conf.example.net", Task: "task-a", Epoch: 1}
	if err := s.Enqueue(ctx, copyOf("1", fence), store.Limit{}); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("a fenced enqueue with no groups store = %v", err)
	}
	s.SetFence(func(f store.Fence) bool { return f.Task == "task-a" && f.Epoch == 1 })
	if err := s.Enqueue(ctx, copyOf("2", fence), store.Limit{}); err != nil {
		t.Fatalf("the owner's enqueue = %v", err)
	}
	stale := *fence
	stale.Epoch = 2
	if err := s.Enqueue(ctx, copyOf("3", &stale), store.Limit{}); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("a stale owner's enqueue = %v", err)
	}
	got, err := s.Pending(ctx, "tel:+15550100002", "", at, 10)
	if err != nil || len(got) != 1 || got[0].ID != "2" || got[0].Fence != nil {
		t.Fatalf("queue %+v, %v", got, err)
	}
}
