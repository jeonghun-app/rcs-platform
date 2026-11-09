package awsstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// tableStub answers the calls of TableAPI with what its functions return,
// or err.
type tableStub struct {
	err     error
	put     func(*dynamodb.PutItemInput) error
	update  func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
	query   func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
	batch   func(*dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error)
	batches int
}

func (s *tableStub) DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return nil, s.err
}

func (s *tableStub) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if s.put != nil {
		return &dynamodb.PutItemOutput{}, s.put(in)
	}
	return nil, s.err
}

func (s *tableStub) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if s.update != nil {
		return s.update(in)
	}
	return nil, s.err
}

func (s *tableStub) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if s.query != nil {
		return s.query(in)
	}
	return nil, s.err
}

func (s *tableStub) BatchWriteItem(_ context.Context, in *dynamodb.BatchWriteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	s.batches++
	if s.batch != nil {
		return s.batch(in)
	}
	return nil, s.err
}

func (s *tableStub) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: "ACTIVE"}}, s.err
}

// testKey is the RCS_PII_HMAC_KEY of the tests.
var testKey = secret.NewString("pii-hmac-key-of-the-tests-0123456789")

// The digest a table keeps is an HMAC, so that its reader cannot test
// guesses of a request; tables under other keys keep other values.
func TestTheStoredDigestIsKeyed(t *testing.T) {
	rec := storetest.Idempotency("cb-1")
	var digests [][]byte
	for _, k := range []secret.Key{testKey, secret.NewString("another-key-0123456789abcdef0123456789"), {}} {
		r := NewRequests(&tableStub{put: func(in *dynamodb.PutItemInput) error {
			digests = append(digests, in.Item[attrDigest].(*types.AttributeValueMemberB).Value)
			return nil
		}}, "maap-requests", k)
		if _, _, err := r.Remember(context.Background(), rec, storetest.Now); err != nil {
			t.Fatal(err)
		}
	}
	for i, d := range digests {
		if len(d) != 32 || bytes.Equal(d, rec.Digest[:]) || i > 0 && bytes.Equal(d, digests[i-1]) {
			t.Fatalf("stored digests %x for %x", digests, rec.Digest)
		}
	}
	// It is HMAC(HMAC(key, "maap-requests digest"), digest): a subkey of
	// its own, so that no other use of the key gives the same value.
	sub := hmac.New(sha256.New, testKey.Reveal())
	sub.Write([]byte("maap-requests digest"))
	mac := hmac.New(sha256.New, sub.Sum(nil))
	mac.Write(rec.Digest[:])
	if !bytes.Equal(digests[0], mac.Sum(nil)) {
		t.Fatalf("stored digest %x is not the subkey's HMAC", digests[0])
	}
}

// captureLog sends the default logger to the returned buffer until the
// test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// A store failure is neither a refusal nor a damaged record, and neither
// the error a caller logs nor the log carries the idempotency key, even
// when DynamoDB's message names it (ADR 0009 §10).
func TestARequestsFailureIsNoRefusalAndNamesNoKey(t *testing.T) {
	log := captureLog(t)
	rec := storetest.Idempotency(storetest.Chatbot().ID)
	r := NewRequests(&tableStub{err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "key i#" + rec.Key}}, "maap-requests", testKey)
	ctx := context.Background()
	_, _, rememberErr := r.Remember(ctx, rec, storetest.Now)
	for _, err := range []error{
		rememberErr, r.Settle(ctx, rec.Chatbot, rec.Key, "w", nil, storetest.Now), r.Forget(ctx, rec.Chatbot, rec.Key, "w"),
		r.DeleteChatbot(ctx, rec.Chatbot),
	} {
		if err == nil || errors.Is(err, store.ErrKeyReused) || errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrConflict) ||
			!strings.Contains(err.Error(), "ProvisionedThroughputExceededException") || strings.Contains(err.Error(), rec.Key) {
			t.Errorf("error = %v", err)
		}
	}
	// Nor does a refusal, or a damaged record.
	damaged := requestKey(rec.Chatbot, rec.Key)
	r = NewRequests(&tableStub{put: func(*dynamodb.PutItemInput) error {
		return &types.ConditionalCheckFailedException{Item: damaged}
	}}, "maap-requests", testKey)
	if _, _, err := r.Remember(context.Background(), rec, storetest.Now); !errors.Is(err, store.ErrInvalid) || strings.Contains(err.Error(), rec.Key) {
		t.Errorf("damaged record = %v", err)
	}
	bad := rec
	bad.Key += "\r\n"
	if _, _, err := r.Remember(context.Background(), bad, storetest.Now); !errors.Is(err, store.ErrInvalid) || strings.Contains(err.Error(), rec.Key) {
		t.Errorf("malformed key = %v", err)
	}
	if strings.Contains(log.String(), rec.Key) {
		t.Fatalf("log = %s", log)
	}
}

// What DynamoDB answers the SDK's second send of a put that took effect
// is this call's own record, not a repeat of another request.
func TestARememberSentAgainFindsItsOwnRecord(t *testing.T) {
	rec := storetest.Idempotency(storetest.Chatbot().ID)
	var sent map[string]types.AttributeValue
	r := NewRequests(&tableStub{put: func(in *dynamodb.PutItemInput) error {
		sent = in.Item
		return &types.ConditionalCheckFailedException{Item: in.Item}
	}}, "maap-requests", testKey)
	got, fresh, err := r.Remember(context.Background(), rec, storetest.Now)
	if err != nil || !fresh || got.MessageID != rec.MessageID || !got.Created.Equal(storetest.Now) {
		t.Fatalf("Remember = %+v, %v, %v", got, fresh, err)
	}
	// Another writer's record with the same digest is a repeat.
	sent[attrWriter] = str("another")
	r.api.(*tableStub).put = func(*dynamodb.PutItemInput) error { return &types.ConditionalCheckFailedException{Item: sent} }
	rec.MessageID = storetest.MessageID()
	if got, fresh, err = r.Remember(context.Background(), rec, storetest.Now); err != nil || fresh || got.MessageID == rec.MessageID {
		t.Fatalf("Remember = %+v, %v, %v", got, fresh, err)
	}
}

// Every item carries its TTL attribute in Unix seconds, at the end of
// the time its kind is kept, so that TTL never deletes a live one.
func TestItemsCarryTheirTTL(t *testing.T) {
	var ttls []string
	s := &tableStub{put: func(in *dynamodb.PutItemInput) error {
		ttls = append(ttls, sv(in.Item[attrTTL]))
		return nil
	}}
	r := NewRequests(s, "maap-requests", testKey)
	at := storetest.Now.Add(800 * time.Millisecond)
	if _, _, err := r.Remember(context.Background(), storetest.Idempotency("cb-1"), at); err != nil {
		t.Fatal(err)
	}
	if want := []string{strconv.FormatInt(storetest.Now.Add(store.IdempotencyTTL).Unix(), 10)}; !slices.Equal(ttls, want) {
		t.Fatalf("ttl = %v, want %v", ttls, want)
	}
}

// A deletion sends again what DynamoDB left unprocessed, with a pause,
// and fails, to be called again, when it keeps leaving some.
func TestADeletionSendsUnprocessedItemsAgain(t *testing.T) {
	prevWait, prevPace := batchWait, batchPace
	batchWait, batchPace = 0, 0
	t.Cleanup(func() { batchWait, batchPace = prevWait, prevPace })
	items := make([]map[string]types.AttributeValue, 30)
	for i := range items {
		items[i] = key("c#cb-1", "i#k"+string(rune('a'+i)))
	}
	query := func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
		return &dynamodb.QueryOutput{Items: items}, nil
	}
	left := 2
	s := &tableStub{query: query, batch: func(in *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
		reqs := in.RequestItems["maap-requests"]
		if len(reqs) > 25 {
			return nil, errors.New("over 25")
		}
		if left > 0 {
			left--
			return &dynamodb.BatchWriteItemOutput{UnprocessedItems: map[string][]types.WriteRequest{"maap-requests": reqs[1:]}}, nil
		}
		return &dynamodb.BatchWriteItemOutput{}, nil
	}}
	if err := NewRequests(s, "maap-requests", testKey).DeleteChatbot(context.Background(), "cb-1"); err != nil || s.batches != 4 {
		t.Fatalf("DeleteChatbot = %v after %d batches", err, s.batches)
	}
	s = &tableStub{query: query, batch: func(in *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
		return &dynamodb.BatchWriteItemOutput{UnprocessedItems: in.RequestItems}, nil
	}}
	if err := NewRequests(s, "maap-requests", testKey).DeleteChatbot(context.Background(), "cb-1"); err == nil || s.batches != batchAttempts {
		t.Fatalf("DeleteChatbot = %v after %d batches", err, s.batches)
	}
}

// A stored record is read strictly: one that is not whole is damaged,
// never a record with a short digest, a Message-ID of another form, or
// pending with an answer.
func FuzzDecodeIdempotency(f *testing.F) {
	f.Add(make([]byte, 32), "0123456789abcdef0123456789abcdef", "1", "2", []byte("{}"), true, false)
	f.Add([]byte{}, "", "", "", []byte{}, false, true)
	f.Add(make([]byte, 33), "0123456789ABCDEF0123456789abcdef", "-1", "x", make([]byte, 9000), true, true)
	f.Fuzz(func(t *testing.T, digest []byte, messageID, created, ttl string, answer []byte, hasAnswer, pending bool) {
		item := requestKey("cb-1", "k-1")
		item[attrDigest], item[attrMessageID] = &types.AttributeValueMemberB{Value: digest}, str(messageID)
		item[attrCreated], item[attrTTL] = &types.AttributeValueMemberN{Value: created}, &types.AttributeValueMemberN{Value: ttl}
		if hasAnswer {
			item[attrAnswer] = &types.AttributeValueMemberB{Value: answer}
		}
		if pending {
			item[attrPending] = &types.AttributeValueMemberBOOL{Value: true}
		}
		rec, stored, err := decodeIdempotency("cb-1", "k-1", item)
		if err != nil {
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("error %v", err)
			}
			return
		}
		if len(digest) != 32 || !bytes.Equal(stored, digest) || rec.MessageID != messageID || !store.ValidMessageID(rec.MessageID) ||
			len(rec.Answer) > store.MaxAnswerBytes || hasAnswer && !bytes.Equal(rec.Answer, answer) || rec.Created.Location() != time.UTC ||
			rec.Pending != pending || pending && hasAnswer || rec.Writer != "" {
			t.Fatalf("decoded %+v", rec)
		}
	})
}

// A deletion stops before its context's deadline with ErrUnfinished, at
// most at its pace, and logs its progress as counts only.
func TestADeletionStopsBeforeItsDeadlineAndLogsCounts(t *testing.T) {
	log := captureLog(t)
	prev := batchPace
	batchPace = time.Hour // so that the second batch would end after the deadline
	t.Cleanup(func() { batchPace = prev })
	items := make([]map[string]types.AttributeValue, 30)
	for i := range items {
		items[i] = key("c#cb-1", "i#secret-key-"+strconv.Itoa(i))
	}
	s := &tableStub{
		query: func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: items}, nil
		},
		batch: func(*dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
			return &dynamodb.BatchWriteItemOutput{}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	err := NewRequests(s, "maap-requests", testKey).DeleteChatbot(ctx, "cb-1")
	if !errors.Is(err, store.ErrUnfinished) || s.batches != 1 || time.Since(start) > 5*time.Second {
		t.Fatalf("DeleteChatbot = %v after %d batches, %v", err, s.batches, time.Since(start))
	}
	// A deadline that cuts a request short is unfinished too.
	gone, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	cut := &tableStub{query: func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error) { return nil, gone.Err() }}
	if err := NewRequests(cut, "maap-requests", testKey).DeleteChatbot(gone, "cb-1"); !errors.Is(err, store.ErrUnfinished) {
		t.Fatalf("DeleteChatbot past its deadline = %v", err)
	}
	// Without a deadline, batches keep their pace.
	batchPace = 20 * time.Millisecond
	start = time.Now()
	if err := NewRequests(s, "maap-requests", testKey).DeleteChatbot(context.Background(), "cb-1"); err != nil || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("DeleteChatbot = %v in %v, under its pace", err, time.Since(start))
	}
	out := log.String()
	if !strings.Contains(out, `"msg":"awsstore: chatbot deletion progress"`) || !strings.Contains(out, `"deleted":25`) ||
		!strings.Contains(out, `"finished":false`) || !strings.Contains(out, `"chatbot":"cb-1"`) || strings.Contains(out, "secret-key") {
		t.Fatalf("log = %s", out)
	}
}
