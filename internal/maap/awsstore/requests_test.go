package awsstore

import (
	"bytes"
	"context"
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

func (s *tableStub) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
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
	r := NewRequests(&tableStub{err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "key i#" + rec.Key}}, "maap-requests", storetest.StatusTTL)
	ctx := context.Background()
	_, _, rememberErr := r.Remember(ctx, rec, storetest.Now)
	_, statusErr := r.Status(ctx, rec.Chatbot, rec.MessageID, storetest.Now)
	_, advanceErr := r.Advance(ctx, rec.Chatbot, rec.MessageID, store.Delivered, storetest.Now)
	for _, err := range []error{
		rememberErr, statusErr, advanceErr, r.Accept(ctx, rec.Chatbot, rec.MessageID, storetest.Now), r.DeleteChatbot(ctx, rec.Chatbot),
	} {
		if err == nil || errors.Is(err, store.ErrKeyReused) || errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrNotFound) ||
			!strings.Contains(err.Error(), "ProvisionedThroughputExceededException") || strings.Contains(err.Error(), rec.Key) {
			t.Errorf("error = %v", err)
		}
	}
	// Nor does a refusal, or a damaged record.
	damaged := requestKey(rec.Chatbot, rec.Key)
	r = NewRequests(&tableStub{put: func(*dynamodb.PutItemInput) error {
		return &types.ConditionalCheckFailedException{Item: damaged}
	}}, "maap-requests", storetest.StatusTTL)
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
	}}, "maap-requests", storetest.StatusTTL)
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
	r := NewRequests(s, "maap-requests", storetest.StatusTTL)
	at := storetest.Now.Add(800 * time.Millisecond)
	if _, _, err := r.Remember(context.Background(), storetest.Idempotency("cb-1"), at); err != nil {
		t.Fatal(err)
	}
	if err := r.Accept(context.Background(), "cb-1", storetest.MessageID(), at); err != nil {
		t.Fatal(err)
	}
	want := []string{
		strconv.FormatInt(storetest.Now.Add(store.IdempotencyTTL).Unix(), 10), strconv.FormatInt(storetest.Now.Add(storetest.StatusTTL).Unix(), 10),
	}
	if !slices.Equal(ttls, want) {
		t.Fatalf("ttl = %v, want %v", ttls, want)
	}
}

// An advance the SDK sent again after it took effect changed the status;
// one that met a status already as far is no change.
func TestAnAdvanceSentAgainFindsItsOwnUpdate(t *testing.T) {
	item := statusKey("cb-1", storetest.MessageID())
	item[attrTTL] = num(storetest.Now.Add(time.Hour).Unix())
	s := &tableStub{}
	r := NewRequests(s, "maap-requests", storetest.StatusTTL)
	for _, tc := range []struct {
		writer  func(in *dynamodb.UpdateItemInput) string
		changed bool
	}{
		{func(in *dynamodb.UpdateItemInput) string { return sv(in.ExpressionAttributeValues[":w"]) }, true},
		{func(*dynamodb.UpdateItemInput) string { return "another" }, false},
	} {
		s.update = func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			item[attrWriter] = str(tc.writer(in))
			return nil, &types.ConditionalCheckFailedException{Item: item}
		}
		if changed, err := r.Advance(context.Background(), "cb-1", sv(item[attrSK])[2:], store.Displayed, storetest.Now); err != nil || changed != tc.changed {
			t.Errorf("Advance = %v, %v; want %v", changed, err, tc.changed)
		}
	}
}

// A deletion sends again what DynamoDB left unprocessed, with a pause,
// and fails, to be called again, when it keeps leaving some.
func TestADeletionSendsUnprocessedItemsAgain(t *testing.T) {
	prev := batchWait
	batchWait = 0
	t.Cleanup(func() { batchWait = prev })
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
	if err := NewRequests(s, "maap-requests", storetest.StatusTTL).DeleteChatbot(context.Background(), "cb-1"); err != nil || s.batches != 4 {
		t.Fatalf("DeleteChatbot = %v after %d batches", err, s.batches)
	}
	s = &tableStub{query: query, batch: func(in *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
		return &dynamodb.BatchWriteItemOutput{UnprocessedItems: in.RequestItems}, nil
	}}
	if err := NewRequests(s, "maap-requests", storetest.StatusTTL).DeleteChatbot(context.Background(), "cb-1"); err == nil || s.batches != batchAttempts {
		t.Fatalf("DeleteChatbot = %v after %d batches", err, s.batches)
	}
}

// A stored record is read strictly: one that is not whole is damaged,
// never a record with a short digest or a Message-ID of another form.
func FuzzDecodeIdempotency(f *testing.F) {
	f.Add(make([]byte, 32), "0123456789abcdef0123456789abcdef", "1", "2", []byte("{}"), true)
	f.Add([]byte{}, "", "", "", []byte{}, false)
	f.Add(make([]byte, 33), "0123456789ABCDEF0123456789abcdef", "-1", "x", make([]byte, 9000), true)
	f.Fuzz(func(t *testing.T, digest []byte, messageID, created, ttl string, answer []byte, hasAnswer bool) {
		item := requestKey("cb-1", "k-1")
		item[attrDigest], item[attrMessageID] = &types.AttributeValueMemberB{Value: digest}, str(messageID)
		item[attrCreated], item[attrTTL] = &types.AttributeValueMemberN{Value: created}, &types.AttributeValueMemberN{Value: ttl}
		if hasAnswer {
			item[attrAnswer] = &types.AttributeValueMemberB{Value: answer}
		}
		rec, err := decodeIdempotency("cb-1", "k-1", item)
		if err != nil {
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("error %v", err)
			}
			return
		}
		if len(digest) != 32 || string(rec.Digest[:]) != string(digest) || rec.MessageID != messageID || !store.ValidMessageID(rec.MessageID) ||
			len(rec.Answer) > store.MaxAnswerBytes || hasAnswer && !bytes.Equal(rec.Answer, answer) || rec.Created.Location() != time.UTC {
			t.Fatalf("decoded %+v", rec)
		}
	})
}

// A stored status is read strictly: an unknown state or a time that is no
// number is damaged.
func FuzzDecodeStatus(f *testing.F) {
	f.Add("accepted", "1", "2", "3")
	f.Add("", "", "", "")
	f.Add("Delivered", "1.5", "-1", "x")
	f.Add("accepted", "0", "00", "0")
	f.Fuzz(func(t *testing.T, state, accepted, updated, ttl string) {
		item := statusKey("cb-1", "0123456789abcdef0123456789abcdef")
		item[attrState] = str(state)
		item[attrAccepted], item[attrUpdated] = &types.AttributeValueMemberN{Value: accepted}, &types.AttributeValueMemberN{Value: updated}
		item[attrTTL] = &types.AttributeValueMemberN{Value: ttl}
		st, _, err := decodeStatus("cb-1", "0123456789abcdef0123456789abcdef", item)
		if err != nil {
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("error %v", err)
			}
			return
		}
		// Numbers compare by value: "00" is 0.
		a, _ := strconv.ParseInt(accepted, 10, 64)
		u, _ := strconv.ParseInt(updated, 10, 64)
		if !st.State.Valid() || string(st.State) != state || st.Accepted.Location() != time.UTC || st.Accepted.Unix() != a || st.Updated.Unix() != u {
			t.Fatalf("decoded %+v", st)
		}
	})
}
