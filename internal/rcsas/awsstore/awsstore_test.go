package awsstore

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

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
		"Enqueue":    func() error { return s.Enqueue(ctx, store.Message{Recipient: "r", ID: "1"}) },
		"Pending":    func() error { _, err := s.Pending(ctx, "r", "", t0, 1); return err },
		"Claim":      func() error { _, err := s.Claim(ctx, "r", "1", "o", t0, t0); return err },
		"Release":    func() error { return s.Release(ctx, "r", "1", "o") },
		"Remove":     func() error { return s.Remove(ctx, "r", "1", "o") },
		"Expired":    func() error { _, err := s.Expired(ctx, t0, 1); return err },
		"RecordSent": func() error { return s.RecordSent(ctx, store.Sent{Sender: "s", MessageID: "m"}, t0) },
		"Sent":       func() error { _, err := s.Sent(ctx, "s", "m", t0); return err },
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
	if err := s.Enqueue(context.Background(), m); err != nil {
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
	if got, err := s.Expired(context.Background(), t0, 0); err != nil || got != nil {
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
	err := s.Enqueue(context.Background(), store.Message{Recipient: "r", ID: "1", CPIM: make([]byte, MaxCPIMSize+1)})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Enqueue = %v", err)
	}
}
