package awsstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// scriptStub holds a chatbot's record with one credential in slot 1, its
// key item unless keyGone, answers each transaction with the next of txs
// (then success), and records the calls that write or list, in order: a
// transaction of deletes only with what it deletes.
type scriptStub struct {
	stubDynamo
	keyID   string
	keyGone bool
	txs     []func(*dynamodb.TransactWriteItemsInput) error
	calls   []string
}

func (s *scriptStub) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if pk := sv(in.Key[attrPK]); strings.HasPrefix(pk, "k#") {
		if s.keyGone {
			return &dynamodb.GetItemOutput{}, nil
		}
		return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{attrPK: str(pk), attrChatbot: str("cb-1")}}, nil
	}
	item := chatbotKey("cb-1")
	item[attrRegistration], item[attrURI] = str("reg"), str("sip:bot@"+storetest.Domain)
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (s *scriptStub) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	call := "transaction"
	for _, it := range in.TransactItems {
		if it.Delete == nil {
			call = "transaction"
			break
		}
		call += " delete " + sv(it.Delete.Key[attrPK]) + " " + sv(it.Delete.Key[attrSK])
	}
	s.calls = append(s.calls, call)
	if len(s.txs) > 0 {
		tx := s.txs[0]
		s.txs = s.txs[1:]
		if err := tx(in); err != nil {
			return nil, err
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (s *scriptStub) Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	s.calls = append(s.calls, "query")
	slot := slotKey("cb-1", 1)
	slot[attrKey] = str(s.keyID)
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{slot}}, nil
}

func (s *scriptStub) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	s.calls = append(s.calls, "delete "+sv(in.Key[attrPK])+" "+sv(in.Key[attrSK]))
	return &dynamodb.DeleteItemOutput{}, nil
}

func fails(err error) func(*dynamodb.TransactWriteItemsInput) error {
	return func(*dynamodb.TransactWriteItemsInput) error { return err }
}

// The order the #733 review fixed: nothing of a chatbot's credentials goes
// before its tombstone stands, and a tombstone that met another
// transaction is written again.
func TestCredentialsGoOnlyAfterTheTombstone(t *testing.T) {
	keyID := storetest.Credential(storetest.Chatbot(), time.Time{}).KeyID
	ccf := types.CancellationReason{Code: aws.String("ConditionalCheckFailed"), Item: chatbotKey("cb-1")}
	ccf.Item[attrRegistration] = str("another")
	for _, tc := range []struct {
		name  string
		tx    error
		calls []string
	}{
		{"FailedOnce", &smithy.GenericAPIError{Code: "InternalServerError"}, []string{"transaction"}},
		{"RefusedOnce", &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{ccf, {Code: aws.String("None")}}}, []string{"transaction"}},
		{"ConflictOnce", &types.TransactionConflictException{}, []string{
			"transaction", "transaction", "query", "transaction delete k#" + keyID + " key delete c#cb-1 k#1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptStub{keyID: keyID, txs: []func(*dynamodb.TransactWriteItemsInput) error{fails(tc.tx)}}
			err := NewRegistry(s, "maap-registry").DeleteChatbot(context.Background(), "cb-1")
			if (err == nil) != (len(tc.calls) > 1) || !reflect.DeepEqual(s.calls, tc.calls) {
				t.Fatalf("DeleteChatbot = %v, calls %q, want %q", err, s.calls, tc.calls)
			}
		})
	}
}

// An issue whose answer was lost finds its own slot and stands; another
// writer's slot sends it to the next, and with both taken it is refused.
func TestAnIssueSentAgainFindsItsOwnSlot(t *testing.T) {
	c := storetest.Chatbot()
	c.Registration = "reg"
	cred, held := storetest.Credential(c, time.Unix(1, 0)), storetest.Credential(c, time.Unix(1, 0)).KeyID
	slotTaken := func(writer func(sent string) string) func(*dynamodb.TransactWriteItemsInput) error {
		return func(in *dynamodb.TransactWriteItemsInput) error {
			slot := in.TransactItems[1].Put.Item
			old := map[string]types.AttributeValue{attrKey: str(held), attrWriter: str(writer(sv(slot[attrWriter])))}
			none := types.CancellationReason{Code: aws.String("None")}
			return &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
				none, {Code: aws.String("ConditionalCheckFailed"), Item: old}, none,
			}}
		}
	}
	mine := slotTaken(func(sent string) string { return sent })
	theirs := slotTaken(func(string) string { return "another" })
	// A slot naming a key item that is gone is taken over, on the condition
	// that it still names that key and the key item is still absent.
	takeover := func(in *dynamodb.TransactWriteItemsInput) error {
		// The guard is exact (#744 round 2): a condition taking any slot
		// would let concurrent issues pass the limit.
		if len(in.TransactItems) != 4 || sv(in.TransactItems[1].Put.Item[attrSK]) != "k#1" ||
			aws.ToString(in.TransactItems[1].Put.ConditionExpression) != "attribute_not_exists(#pk) OR #key = :stale" ||
			sv(in.TransactItems[1].Put.ExpressionAttributeValues[":stale"]) != held || sv(in.TransactItems[3].ConditionCheck.Key[attrPK]) != "k#"+held {
			return errors.New("not a takeover of slot 1")
		}
		return nil
	}
	for _, tc := range []struct {
		name    string
		txs     []func(*dynamodb.TransactWriteItemsInput) error
		keyGone bool
		want    error
		sent    int
	}{
		{"Mine", []func(*dynamodb.TransactWriteItemsInput) error{mine}, false, nil, 1},
		{"TheirsThenFree", []func(*dynamodb.TransactWriteItemsInput) error{theirs}, false, nil, 2},
		{"BothTaken", []func(*dynamodb.TransactWriteItemsInput) error{theirs, theirs}, false, store.ErrTooMany, 2},
		{"TheirsWithoutAKeyItem", []func(*dynamodb.TransactWriteItemsInput) error{theirs, takeover}, true, nil, 2},
		{"Conflicts", []func(*dynamodb.TransactWriteItemsInput) error{
			fails(&types.TransactionConflictException{}), fails(&types.TransactionConflictException{}), fails(&types.TransactionConflictException{}),
		}, false, store.ErrConflict, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptStub{txs: tc.txs, keyGone: tc.keyGone}
			err := NewRegistry(s, "maap-registry").Credentials().Issue(context.Background(), cred)
			if !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) || len(s.calls) != tc.sent {
				t.Fatalf("Issue = %v after %d sends", err, len(s.calls))
			}
		})
	}
}

// A revoke that failed (#744 review), or one the earlier two-step delete
// cut short after the key item, is finished by the next: the key item and
// its slot go in one transaction, and a slot left without its key item
// goes too. Only when neither is there is the answer ErrNotFound.
func TestARevokeFinishesWhatAFailedOneLeft(t *testing.T) {
	ctx := context.Background()
	keyID := storetest.Credential(storetest.Chatbot(), time.Time{}).KeyID
	both := "transaction delete k#" + keyID + " key delete c#cb-1 k#1"
	for _, keyGone := range []bool{false, true} {
		s := &scriptStub{keyID: keyID, keyGone: keyGone, txs: []func(*dynamodb.TransactWriteItemsInput) error{
			fails(&smithy.GenericAPIError{Code: "InternalServerError"}),
		}}
		cs := NewRegistry(s, "maap-registry").Credentials()
		first, again := cs.Revoke(ctx, "cb-1", keyID), cs.Revoke(ctx, "cb-1", keyID)
		if first == nil || again != nil || !reflect.DeepEqual(s.calls, []string{"query", both, "query", both}) {
			t.Fatalf("key gone %v: Revoke = %v, then %v; calls %q", keyGone, first, again, s.calls)
		}
	}
	// A key item without a slot still authenticates, so it goes too; with
	// neither, the answer is ErrNotFound.
	for _, keyGone := range []bool{false, true} {
		s := &scriptStub{keyID: storetest.Credential(storetest.Chatbot(), time.Time{}).KeyID, keyGone: keyGone}
		err := NewRegistry(s, "maap-registry").Credentials().Revoke(ctx, "cb-1", keyID)
		if want := []string{"query", "delete k#" + keyID + " key"}; !keyGone && (err != nil || !reflect.DeepEqual(s.calls, want)) {
			t.Fatalf("Revoke of a key item without a slot = %v, calls %q", err, s.calls)
		}
		if keyGone && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Revoke of nothing = %v", err)
		}
	}
	// A key item of another chatbot (never, key IDs being random) stops the
	// deletion rather than leaving it half done.
	none := types.CancellationReason{Code: aws.String("None")}
	s := &scriptStub{keyID: keyID, txs: []func(*dynamodb.TransactWriteItemsInput) error{fails(&types.TransactionCanceledException{
		CancellationReasons: []types.CancellationReason{{Code: aws.String("ConditionalCheckFailed")}, none},
	})}}
	if err := NewRegistry(s, "maap-registry").Credentials().Revoke(ctx, "cb-1", keyID); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Revoke over another chatbot's key item = %v", err)
	}
}

// A chatbot's deletion never stops at a damaged slot (#744 round 2):
// with a key item another chatbot's or naming none (the transaction's key
// condition fails), or a key value that is no key ID, the slot goes alone,
// logged without its value. Both deleters do so.
func TestADeletionDeletesADamagedSlotAlone(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	keyID := storetest.Credential(storetest.Chatbot(), time.Time{}).KeyID
	none := types.CancellationReason{Code: aws.String("None")}
	keyRefused := fails(&types.TransactionCanceledException{
		CancellationReasons: []types.CancellationReason{{Code: aws.String("ConditionalCheckFailed")}, none},
	})
	tombstone := func(*dynamodb.TransactWriteItemsInput) error { return nil }
	for _, tc := range []struct {
		name, key string
		txs       []func(*dynamodb.TransactWriteItemsInput) error
		calls     []string
	}{
		{"KeyItemRefused", keyID, []func(*dynamodb.TransactWriteItemsInput) error{keyRefused},
			[]string{"query", "transaction delete k#" + keyID + " key delete c#cb-1 k#1", "delete c#cb-1 k#1"}},
		{"NoKeyID", strings.Repeat("x", 2100), nil, []string{"query", "delete c#cb-1 k#1"}},
	} {
		for _, registry := range []bool{false, true} {
			buf.Reset()
			s := &scriptStub{keyID: tc.key, txs: tc.txs}
			r, want := NewRegistry(s, "maap-registry"), tc.calls
			err := r.Credentials().DeleteChatbot(context.Background(), "cb-1")
			if registry {
				s.txs = append([]func(*dynamodb.TransactWriteItemsInput) error{tombstone}, tc.txs...)
				s.calls, want = nil, append([]string{"transaction"}, tc.calls...)
				err = r.DeleteChatbot(context.Background(), "cb-1")
			}
			if out := buf.String(); err != nil || !reflect.DeepEqual(s.calls, want) || !strings.Contains(out, "damaged credential slot") ||
				strings.Contains(out, tc.key) {
				t.Errorf("%s, registry %v: %v, calls %q, log %s", tc.name, registry, err, s.calls, out)
			}
		}
	}
}

// A stored credential is read strictly: one that is not whole is damaged,
// never a credential with a short digest or another chatbot's ID.
func FuzzDecodeCredential(f *testing.F) {
	f.Add("cb-1", "reg", make([]byte, 32), "1", "2")
	f.Add("", "", []byte{}, "", "")
	f.Add("c#x", "reg", make([]byte, 31), "-1", "x")
	f.Fuzz(func(t *testing.T, chatbot, registration string, digest []byte, created, used string) {
		item := keyKey("AAAAAAAAAAAAAAAAAAAAAAAAAA")
		item[attrChatbot], item[attrRegistration], item[attrDigest] = str(chatbot), str(registration), &types.AttributeValueMemberB{Value: digest}
		item[attrCreated], item[attrUsed] = &types.AttributeValueMemberN{Value: created}, &types.AttributeValueMemberN{Value: used}
		cred, err := decodeCredential("AAAAAAAAAAAAAAAAAAAAAAAAAA", item)
		if err != nil {
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("error %v", err)
			}
			return
		}
		if len(digest) != 32 || string(cred.Digest[:]) != string(digest) || !store.ValidID(cred.Chatbot) || cred.Chatbot != chatbot ||
			cred.Registration != registration || cred.Created.Location() != time.UTC {
			t.Fatalf("decoded %+v from %q %q %x %q", cred, chatbot, registration, digest, created)
		}
	})
}
