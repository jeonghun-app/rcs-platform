package awsstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// A table that fails is an error of its own, never "no alias", and its
// message names the operation and the code only.
func TestASubscribersTableThatFailsIsAnError(t *testing.T) {
	s := NewSubscribers(&stubDynamo{err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "at 10.0.0.1"}}, "maap-subscribers")
	ctx := context.Background()
	a := storetest.Alias("cb-1", storetest.Subscriber, false, time.Unix(1, 0))
	_, err1 := s.Alias(ctx, a)
	_, err2 := s.Resolve(ctx, a.Chatbot, a.ID, time.Unix(1, 0))
	for _, err := range []error{err1, err2, s.Used(ctx, a, time.Unix(2, 0)), s.DeleteChatbot(ctx, "cb-1"), s.Ready(ctx)} {
		if err == nil || errors.Is(err, store.ErrNotFound) || strings.Contains(err.Error(), "10.0.0.1") ||
			!strings.Contains(err.Error(), "ProvisionedThroughputExceededException") {
			t.Errorf("error %v", err)
		}
	}
}

// A stored alias is read strictly, from either of its items: one that is
// not whole is damaged, never an alias of another form or subscriber.
func FuzzDecodeAlias(f *testing.F) {
	id := strings.Repeat("a2", store.AliasIDBytes/2-1) + "aa" // made at run time, as no alias is written (#714)
	f.Add(id, "tel:+15550100001", true, "1", "2")
	f.Add("", "", false, "", "")
	f.Add(strings.ToUpper(id), "tel:+1x", true, "-1", "1e3")
	// Whole but for the alias ID, or but for the subscriber.
	f.Add(strings.ToUpper(id), "tel:+15550100001", false, "1", "2")
	f.Add(id, "tel:+1x", false, "1", "2")
	f.Fuzz(func(t *testing.T, aliasID, subscriber string, anonymous bool, created, used string) {
		item := key("x", "y")
		item[attrAlias], item[attrSubscriber] = str(aliasID), str(subscriber)
		item[attrAnonymous] = &types.AttributeValueMemberBOOL{Value: anonymous}
		item[attrCreated], item[attrUsed] = &types.AttributeValueMemberN{Value: created}, &types.AttributeValueMemberN{Value: used}
		kind := store.Alias{Chatbot: "cb-1", Subscriber: storetest.Subscriber}
		for i, decode := range []func() (store.Alias, error){
			func() (store.Alias, error) { return decodeAlias(kind, item) },
			func() (store.Alias, error) { return decodeChatbotAlias("cb-1", aliasID, item) },
		} {
			a, err := decode()
			if err != nil {
				if !errors.Is(err, store.ErrInvalid) {
					t.Fatalf("decoder %d: error %v", i, err)
				}
				continue
			}
			wantSubscriber, wantAnonymous := storetest.Subscriber, false
			if i == 1 {
				wantSubscriber, wantAnonymous = subscriber, anonymous
			}
			if a.ID != aliasID || !store.ValidAliasID(a.ID) || a.Chatbot != "cb-1" || a.Subscriber != wantSubscriber ||
				!store.ValidSubscriber(a.Subscriber) || a.Anonymous != wantAnonymous ||
				a.Created.Location() != time.UTC || a.LastUsed.Location() != time.UTC {
				t.Fatalf("decoder %d: %+v from %q %q %q %q", i, a, aliasID, subscriber, created, used)
			}
		}
	})
}

// aliasesStub answers DeleteChatbot's query with n aliases of cb-1 in one
// page, counts reads, and records when each transaction came; after, if
// set, runs after each.
type aliasesStub struct {
	stubDynamo
	n     int
	gets  int
	txAt  []time.Time
	ids   []string
	after func(int)
}

func (s *aliasesStub) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	s.gets++
	return &dynamodb.GetItemOutput{}, nil
}

func (s *aliasesStub) Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	out := &dynamodb.QueryOutput{}
	for range s.n {
		a := storetest.Alias("cb-1", storetest.Subscriber, false, time.Unix(1, 0))
		s.ids = append(s.ids, a.ID)
		item := times(chatbotAliasKey(a.Chatbot, a.ID), a)
		item[attrSubscriber], item[attrAnonymous] = str(a.Subscriber), &types.AttributeValueMemberBOOL{}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

func (s *aliasesStub) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	s.txAt = append(s.txAt, time.Now())
	if s.after != nil {
		s.after(len(s.txAt))
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

// An alias ID no alias can have, or a chatbot ID no chatbot can, costs no
// read (#753 tester's M5).
func TestAMalformedAliasIDOrChatbotIDIsNeverRead(t *testing.T) {
	st := &aliasesStub{}
	s := NewSubscribers(st, "maap-subscribers")
	id := storetest.AliasID()
	for _, tc := range [][2]string{{"cb-1", strings.ToUpper(id)}, {"cb-1", id[:25]}, {"cb-1", id[:25] + "b"}, {"c#x", id}} {
		if _, err := s.Resolve(context.Background(), tc[0], tc[1], time.Unix(1, 0)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Resolve(%q, %q) = %v", tc[0], tc[1], err)
		}
	}
	if _, err := s.Alias(context.Background(), store.Alias{ID: id[:25] + "b", Chatbot: "cb-1", Subscriber: storetest.Subscriber}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Alias with a malformed ID = %v", err)
	}
	if st.gets != 0 {
		t.Fatalf("%d reads", st.gets)
	}
	if _, err := s.Resolve(context.Background(), "cb-1", id, time.Unix(1, 0)); !errors.Is(err, store.ErrNotFound) || st.gets != 1 {
		t.Fatalf("Resolve of a well-formed ID = %v after %d reads", err, st.gets)
	}
}

// A chatbot's deletion spaces its transactions by pace, so that it does
// not throttle other chatbots (#753 review).
func TestADeletionSpacesItsTransactions(t *testing.T) {
	st := &aliasesStub{n: 3}
	s := NewSubscribers(st, "maap-subscribers")
	if s.pace != deletePace {
		t.Fatalf("pace %v", s.pace)
	}
	s.pace = 30 * time.Millisecond
	if err := s.DeleteChatbot(context.Background(), "cb-1"); err != nil || len(st.txAt) != 3 {
		t.Fatalf("DeleteChatbot = %v after %d transactions", err, len(st.txAt))
	}
	if gap := st.txAt[2].Sub(st.txAt[0]); gap < 2*s.pace {
		t.Fatalf("3 transactions in %v", gap)
	}
}

// When its context ends, a deletion stops between two transactions and
// logs how many it deleted, counts only, with the context's error, which
// the operator API answers 503 (#753 review).
func TestADeletionStopsBetweenTransactionsAndLogsItsCount(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &aliasesStub{n: 5, after: func(n int) {
		if n == 2 {
			cancel()
		}
	}}
	err := NewSubscribers(st, "maap-subscribers").DeleteChatbot(ctx, "cb-1")
	out := buf.String()
	if !errors.Is(err, context.Canceled) || len(st.txAt) != 2 || !strings.Contains(out, `"aliases_deleted":2`) || !strings.Contains(out, `"chatbot":"cb-1"`) {
		t.Fatalf("DeleteChatbot = %v after %d transactions, log %s", err, len(st.txAt), out)
	}
	for _, id := range st.ids {
		if strings.Contains(out, id) {
			t.Fatalf("the log names an alias: %s", out)
		}
	}
}
