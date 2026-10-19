package awsstore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store/storetest"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func TestTheStoreMeetsTheContractOverTheFake(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return NewWithClient("messages", newFakeDynamo(t)) })
}

func TestKeysCannotCollideAcrossIdentities(t *testing.T) {
	// Without the length prefix "q#ab" + "c" and "q#a" + "bc" would meet.
	if identityKey(queuePrefix, "ab") == identityKey(queuePrefix, "a") || identityKey(queuePrefix, "x") == identityKey(sentPrefix, "x") {
		t.Fatal("keys collide")
	}
}

func TestReadyReportsTheTableState(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	if err := s.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.status = dtypes.TableStatusCreating
	if err := s.Ready(context.Background()); err == nil {
		t.Fatal("a table being created is ready")
	}
	f.fail = &smithy.GenericAPIError{Code: "ResourceNotFoundException"}
	if err := s.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "ResourceNotFoundException") {
		t.Fatalf("Ready = %v", err)
	}
}

func TestEveryOperationReportsAFailedRequest(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	f.fail = &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException"}
	for name, op := range map[string]func() error{
		"Enqueue":        func() error { return s.Enqueue(ctx, store.Message{Recipient: "r", ID: "1"}, store.Limit{}) },
		"Pending":        func() error { _, err := s.Pending(ctx, "r", "", t0, 1); return err },
		"Claim":          func() error { _, err := s.Claim(ctx, "r", "1", "o", t0, t0); return err },
		"Release":        func() error { return s.Release(ctx, "r", "1", "o") },
		"Remove":         func() error { return s.Remove(ctx, store.Message{Recipient: "r", ID: "1"}, "o") },
		"Expired":        func() error { _, _, err := s.Expired(ctx, t0, "", 1); return err },
		"RecordSent":     func() error { return s.RecordSent(ctx, store.Sent{Sender: "s", MessageID: "m"}, t0) },
		"Sent":           func() error { _, err := s.Sent(ctx, "s", "m", t0); return err },
		"MarkNotified":   func() error { return s.MarkNotified(ctx, "s", "m", "k", "displayed", "t", t0) },
		"UnmarkNotified": func() error { return s.UnmarkNotified(ctx, "s", "m", "k", "t") },
	} {
		if err := op(); err == nil || !strings.Contains(err.Error(), "ProvisionedThroughputExceededException") {
			t.Errorf("%s = %v", name, err)
		}
	}
}

func TestErrorsNeverCarryRequestDetails(t *testing.T) {
	cases := map[error]string{
		context.DeadlineExceeded: "context deadline exceeded",
		&url.Error{Op: "Post", URL: "https://dynamodb.example/tel:+15550100001", Err: errors.New("connection refused")}: "connection refused",
		errors.New("tel:+15550100001 something"): "request failed",
	}
	for in, want := range cases {
		got := sanitize("op", in).Error()
		if !strings.Contains(got, want) || strings.Contains(got, "+1555") {
			t.Errorf("sanitize(%v) = %q", in, got)
		}
	}
}

func TestDamagedItemsAreReportedNotGuessed(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	f.rows["q#1#r\x00x"] = map[string]dtypes.AttributeValue{
		attrPK: str("q#1#r"), attrSK: str("x"), attrSender: num(3), attrExpires: stamp(t0.Add(time.Hour)),
		attrEnqueued: &dtypes.AttributeValueMemberN{Value: "soon"},
	}
	if _, err := s.Pending(ctx, "r", "", t0, 5); err == nil {
		t.Fatal("a damaged queue item decoded")
	}
	f.rows["s#1#s\x00m"] = map[string]dtypes.AttributeValue{
		attrPK: str("s#1#s"), attrSK: str("m"), attrExpires: stamp(t0.Add(time.Hour)), attrDispositions: num(1),
		attrRecipients: &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{num(1)}},
	}
	if _, err := s.Sent(ctx, "s", "m", t0); err == nil {
		t.Fatal("a damaged sent record decoded")
	}
	delete(f.rows["s#1#s\x00m"], attrRecipients)
	if _, err := s.Sent(ctx, "s", "m", t0); err == nil {
		t.Fatal("a sent record without recipients decoded")
	}
	if _, err := decodeMessage(map[string]dtypes.AttributeValue{attrPK: str("s#1#r"), attrSK: str("x"), attrSender: str("a"),
		attrMode: num(1), attrEnqueued: num(1), attrExpires: num(1), attrCPIM: &dtypes.AttributeValueMemberB{}}); err == nil {
		t.Fatal("a sent key decoded as a queued message")
	}
}

func TestOptionalAttributesAreLeftOutRatherThanStoredEmpty(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	m := store.Message{Recipient: "r", ID: "1", Sender: "s", Mode: store.Standalone, CPIM: []byte("x"), Enqueued: t0, Expires: t0.Add(time.Hour)}
	if err := s.Enqueue(context.Background(), m, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{attrConversation, attrContribution, attrInReplyTo, attrMessageID, attrOwner} {
		if _, ok := f.rows["q#1#r\x001"][name]; ok {
			t.Errorf("%s stored though empty", name)
		}
	}
}

func TestLimitZeroAsksForNothing(t *testing.T) {
	s := NewWithClient("messages", newFakeDynamo(t))
	if got, err := s.Pending(context.Background(), "r", "", t0, 0); err != nil || got != nil {
		t.Fatalf("Pending = %v, %v", got, err)
	}
	if got, _, err := s.Expired(context.Background(), t0, "", 0); err != nil || got != nil {
		t.Fatalf("Expired = %v, %v", got, err)
	}
}

func TestNewNeedsNoRequest(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	if _, err := New(context.Background(), Config{Table: "messages", Endpoint: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
}

func TestAMessageLargerThanAnItemIsRefusedBeforeAnyRequest(t *testing.T) {
	f := newFakeDynamo(t)
	f.fail = errors.New("no request expected")
	s := NewWithClient("messages", f)
	err := s.Enqueue(context.Background(), store.Message{Recipient: "r", ID: "1", CPIM: make([]byte, MaxCPIMSize+1)}, store.Limit{})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Enqueue = %v", err)
	}
}

// lostAnswers performs every conditional update twice and returns the
// second answer, as when the SDK retries a request whose first answer was
// lost after it took effect.
type lostAnswers struct{ *fakeDynamo }

func (l lostAnswers) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if _, err := l.fakeDynamo.UpdateItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return l.fakeDynamo.UpdateItem(ctx, in, o...)
}

func (l lostAnswers) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	// DynamoDB answers a repeat with the same ClientRequestToken as it
	// answered the first; only a removal is repeated without one here,
	// as a caller retrying after a timeout would.
	out, err := l.fakeDynamo.TransactWriteItems(ctx, in, o...)
	if err != nil || in.TransactItems[0].Delete == nil {
		return out, err
	}
	return l.fakeDynamo.TransactWriteItems(ctx, in, o...)
}

func TestARepeatedWriteThatTookEffectIsNotAConflict(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", lostAnswers{f})
	ctx := context.Background()
	m := store.Message{Recipient: "r", ID: "1", Sender: "s", Mode: store.Chat, CPIM: []byte("x"), Enqueued: t0, Expires: t0.Add(time.Hour)}
	if err := s.Enqueue(ctx, m, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	held, err := s.Claim(ctx, "r", "1", "task-a", t0, t0.Add(time.Minute))
	if err != nil || held.Owner != "task-a" {
		t.Fatalf("Claim = %+v, %v", held, err)
	}
	if err := s.Release(ctx, "r", "1", "task-a"); err != nil {
		t.Fatalf("Release = %v", err)
	}
	if held, err = s.Claim(ctx, "r", "1", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-a"); err != nil {
		t.Fatalf("Remove = %v", err)
	}
	// The repeated removal failed its condition, so the queue's size was
	// taken down once.
	if got := nOf(f.rows["c#1#r\x00n"][attrCount]); got != 0 {
		t.Fatalf("queue size after a repeated removal = %d", got)
	}
	r := store.Sent{Sender: "s", MessageID: "m", Recipients: []string{"r"}, Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotified(ctx, "s", "m", "k", "displayed", "t1", t0); err != nil {
		t.Fatalf("MarkNotified = %v", err)
	}
}

func TestExpiredReadsTheIndexAndResumes(t *testing.T) {
	f := newFakeDynamo(t)
	f.pageSize = 1
	s := NewWithClient("messages", f)
	ctx := context.Background()
	// Recipients spread over the buckets, expiring in turn.
	var want []string
	for i := range 40 {
		r := fmt.Sprintf("sip:user%d@example.net", i)
		m := store.Message{Recipient: r, ID: fmt.Sprint(i), Sender: "s", Mode: store.Chat, CPIM: []byte("x"),
			Enqueued: t0, Expires: t0.Add(time.Duration(i) * time.Second)}
		if err := s.Enqueue(ctx, m, store.Limit{}); err != nil {
			t.Fatal(err)
		}
		want = append(want, m.ID)
	}
	var got []string
	cursor := ""
	for range 100 {
		page, next, err := s.Expired(ctx, t0.Add(time.Hour), cursor, 7)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range page {
			got = append(got, m.ID)
			if m.Recipient == "" || m.Expires.IsZero() {
				t.Fatalf("Expired = %+v", m)
			}
		}
		if cursor = next; cursor == "" {
			break
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Expired found %v, want %v", got, want)
	}
	// A failure part-way keeps what was found and where to go on.
	f.pageSize = 100
	first, cursor, err := s.Expired(ctx, t0.Add(time.Hour), "", 3)
	if err != nil || len(first) != 3 || cursor == "" {
		t.Fatalf("Expired = %v, %q, %v", first, cursor, err)
	}
	f.fail = &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException"}
	if part, again, err := s.Expired(ctx, t0.Add(time.Hour), cursor, 3); err == nil || len(part) != 0 || again != cursor {
		t.Fatalf("Expired while failing = %v, %q, %v", part, again, err)
	}
	f.fail = nil
	if _, _, err := s.Expired(ctx, t0.Add(time.Hour), "not a cursor", 1); err != nil {
		t.Fatalf("a cursor from elsewhere = %v", err)
	}
}

// A queue item deleted behind the store's back (DynamoDB's TTL, by hand)
// would count for ever: a refusal counts the queue and corrects the size.
func TestASizeThatDriftedIsCorrectedWhenItRefuses(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	l := store.Limit{Count: 2, SenderCount: 2}
	msg := func(id string) store.Message {
		return store.Message{Recipient: "r", ID: id, Sender: "s", Mode: store.Chat, CPIM: []byte("x"), Enqueued: t0, Expires: t0.Add(time.Hour)}
	}
	for _, id := range []string{"1", "2"} {
		if err := s.Enqueue(ctx, msg(id), l); err != nil {
			t.Fatal(err)
		}
	}
	delete(f.rows, "q#1#r\x001") // the TTL took it
	if err := s.Enqueue(ctx, msg("3"), l); err != nil {
		t.Fatalf("Enqueue after drift = %v", err)
	}
	if got := nOf(f.rows["c#1#r\x00n"][attrCount]); got != 2 {
		t.Fatalf("queue size %d", got)
	}
	if got := nOf(f.rows["c#1#r\x00s#1#s"][attrCount]); got != 2 {
		t.Fatalf("sender size %d", got)
	}
	// A queue that is really full stays refused.
	if err := s.Enqueue(ctx, msg("4"), l); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("Enqueue to a full queue = %v", err)
	}
}

// The total of group notifications drifts like any size, and a refusal
// for it corrects it the same way.
func TestADriftedGroupNotificationTotalIsCorrected(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	l := store.Limit{Count: 10, SenderCount: 10, GroupCount: 2}
	notice := func(id, group string) store.Message {
		return store.Message{Recipient: "r", ID: id, Sender: group, Author: "sip:p@example.net", Mode: store.Group, Notification: true,
			CPIM: []byte("x"), Enqueued: t0, Expires: t0.Add(time.Hour)}
	}
	for _, id := range []string{"1", "2"} {
		if err := s.Enqueue(ctx, notice(id, "sip:g"+id), l); err != nil {
			t.Fatal(err)
		}
	}
	delete(f.rows, "q#1#r\x001") // the TTL took it
	if err := s.Enqueue(ctx, notice("3", "sip:g3"), l); err != nil {
		t.Fatalf("Enqueue after drift = %v", err)
	}
	key := "c#1#r\x00s#" + fmt.Sprint(len(store.GroupNotifications)) + "#" + store.GroupNotifications
	if got := nOf(f.rows[key][attrCount]); got != 2 {
		t.Fatalf("total %d", got)
	}
	// Really full, it stays refused.
	if err := s.Enqueue(ctx, notice("4", "sip:g4"), l); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("beyond the total = %v", err)
	}
}

// A count reads the whole partition: a queue refused again and again is
// counted at most once per RecountInterval, by whichever task wins.
func TestAFullQueueIsRecountedAtMostOncePerInterval(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	l := store.Limit{Count: 1}
	at := func(id string, when time.Time) store.Message {
		return store.Message{Recipient: "r", ID: id, Sender: "s", Mode: store.Chat, CPIM: []byte("x"), Enqueued: when, Expires: when.Add(time.Hour)}
	}
	if err := s.Enqueue(ctx, at("0", t0), l); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		when := t0.Add(time.Duration(i) * time.Second)
		if err := s.Enqueue(ctx, at(fmt.Sprint("a", i), when), l); !errors.Is(err, store.ErrQueueFull) {
			t.Fatalf("Enqueue %d = %v", i, err)
		}
	}
	if f.recounts != 1 {
		t.Fatalf("%d recounts for 50 refusals within an interval", f.recounts)
	}
	if err := s.Enqueue(ctx, at("b", t0.Add(RecountInterval)), l); !errors.Is(err, store.ErrQueueFull) {
		t.Fatal(err)
	}
	if f.recounts != 2 {
		t.Fatalf("%d recounts once the interval passed", f.recounts)
	}
}

// Removing an old message must not bring the size item's TTL forward: it
// still counts messages that live longer, and losing it would restart the
// counts from zero under a queue that is still there.
func TestARemovalLeavesTheQueueSizeTTLAlone(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewWithClient("messages", f)
	ctx := context.Background()
	old := store.Message{Recipient: "r", ID: "1", Sender: "s", Mode: store.Chat, CPIM: []byte("x"), Enqueued: t0, Expires: t0.Add(time.Hour)}
	young := old
	young.ID, young.Expires = "2", t0.Add(7*24*time.Hour)
	for _, m := range []store.Message{old, young} {
		if err := s.Enqueue(ctx, m, store.Limit{}); err != nil {
			t.Fatal(err)
		}
	}
	held, err := s.Claim(ctx, "r", "1", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-a"); err != nil {
		t.Fatal(err)
	}
	want := nOf(ttlOf(young.Expires.Add(retention)))
	for _, k := range []string{"c#1#r\x00n", "c#1#r\x00s#1#s"} {
		if got := nOf(f.rows[k][attrTTL]); got != want {
			t.Errorf("%q ttl %d, want %d", k, got, want)
		}
	}
}

// conflicting refuses its first updates conditional writes and its first
// transactions transactions as DynamoDB does one that meets a transaction
// in progress on the same item: an UpdateItem with
// TransactionConflictException, a transaction cancelled for a
// TransactionConflict. The SDK retries neither.
type conflicting struct {
	*fakeDynamo
	updates, transactions int
}

func (c *conflicting) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if c.updates > 0 {
		c.updates--
		return nil, &dtypes.TransactionConflictException{Message: aws.String("Transaction is ongoing for the item")}
	}
	return c.fakeDynamo.UpdateItem(ctx, in, o...)
}

func (c *conflicting) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if c.transactions > 0 {
		c.transactions--
		reasons := make([]dtypes.CancellationReason, len(in.TransactItems))
		for i := range reasons {
			reasons[i] = dtypes.CancellationReason{Code: aws.String("None")}
		}
		reasons[len(reasons)-1].Code = aws.String("TransactionConflict")
		return nil, &dtypes.TransactionCanceledException{Message: aws.String("Transaction cancelled"), CancellationReasons: reasons}
	}
	return c.fakeDynamo.TransactWriteItems(ctx, in, o...)
}

// A group's sent record is in a summary's removal, a transaction, and in
// every notifier's mark, a single update: one that meets the other is
// tried again, and past conflictAttempts reported as busy, with nothing
// written.
func TestAWriteThatMeetsATransactionIsTriedAgain(t *testing.T) {
	c := &conflicting{fakeDynamo: newFakeDynamo(t)}
	s := NewWithClient("messages", c)
	ctx := context.Background()
	const group = "sip:chat-1@conf.example.net"
	r := store.Sent{Sender: group, MessageID: "g-1", Author: "sip:a@example.net", Recipients: []string{"sip:b@example.net", "sip:c@example.net"},
		Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	marks := func() int64 {
		t.Helper()
		got, err := s.Sent(ctx, group, "g-1", t0)
		if err != nil {
			t.Fatal(err)
		}
		return got.MarkCount
	}
	c.updates = conflictAttempts - 1
	if err := s.MarkNotified(ctx, group, "g-1", "display-notification sip:b@example.net", "displayed", "t1", t0); err != nil || c.updates != 0 {
		t.Fatalf("MarkNotified after %d conflicts = %v", conflictAttempts-1, err)
	}
	c.updates = conflictAttempts
	if err := s.MarkNotified(ctx, group, "g-1", "display-notification sip:c@example.net", "displayed", "t2", t0); !errors.Is(err, store.ErrBusy) || c.updates != 0 {
		t.Fatalf("MarkNotified after %d conflicts = %v, %d left", conflictAttempts, err, c.updates)
	}
	if got := marks(); got != 1 {
		t.Fatalf("%d marks", got)
	}
	sum := store.Message{Recipient: r.Author, ID: "r-g-1", Sender: group, Mode: store.Group, Notification: true, Summary: true,
		MessageID: "g-1", Enqueued: t0, Expires: t0.Add(time.Hour)}
	if err := s.Enqueue(ctx, sum, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	held, err := s.Claim(ctx, r.Author, sum.ID, "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	c.transactions = conflictAttempts
	if err := s.RemoveSummary(ctx, held, "task-a", 1); !errors.Is(err, store.ErrBusy) || c.transactions != 0 {
		t.Fatalf("RemoveSummary after %d conflicts = %v, %d left", conflictAttempts, err, c.transactions)
	}
	queued := func() bool { _, ok := c.rows[rowKey(key(identityKey(queuePrefix, r.Author), sum.ID))]; return ok }
	if !queued() {
		t.Fatal("a busy removal removed the summary")
	}
	c.transactions = conflictAttempts - 1
	if err := s.RemoveSummary(ctx, held, "task-a", 1); err != nil || c.transactions != 0 {
		t.Fatalf("RemoveSummary after %d conflicts = %v", conflictAttempts-1, err)
	}
	if queued() {
		t.Fatal("the summary is still queued")
	}
	if got := nOf(c.rows[rowKey(senderSizeKey(r.Author, store.GroupSummaries))][attrCount]); got != 0 {
		t.Fatalf("summaries' total after the removal = %d", got)
	}
}
