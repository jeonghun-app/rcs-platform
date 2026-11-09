package awsstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// scriptStub holds a chatbot's record with one credential in slot 1,
// answers each transaction with the next of txs (then success), and
// records the calls that write or list, in order.
type scriptStub struct {
	stubDynamo
	keyID string
	txs   []func(*dynamodb.TransactWriteItemsInput) error
	calls []string
}

func (s *scriptStub) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	item := chatbotKey("cb-1")
	item[attrRegistration], item[attrURI] = str("reg"), str("sip:bot@"+storetest.Domain)
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (s *scriptStub) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	s.calls = append(s.calls, "transaction")
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
			"transaction", "transaction", "query", "delete k#" + keyID + " key", "delete c#cb-1 k#1",
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
	cred := storetest.Credential(c, time.Unix(1, 0))
	slotTaken := func(writer func(sent string) string) func(*dynamodb.TransactWriteItemsInput) error {
		return func(in *dynamodb.TransactWriteItemsInput) error {
			slot := in.TransactItems[1].Put.Item
			old := map[string]types.AttributeValue{attrKey: slot[attrKey], attrWriter: str(writer(sv(slot[attrWriter])))}
			none := types.CancellationReason{Code: aws.String("None")}
			return &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
				none, {Code: aws.String("ConditionalCheckFailed"), Item: old}, none,
			}}
		}
	}
	mine := slotTaken(func(sent string) string { return sent })
	theirs := slotTaken(func(string) string { return "another" })
	for _, tc := range []struct {
		name string
		txs  []func(*dynamodb.TransactWriteItemsInput) error
		want error
		sent int
	}{
		{"Mine", []func(*dynamodb.TransactWriteItemsInput) error{mine}, nil, 1},
		{"TheirsThenFree", []func(*dynamodb.TransactWriteItemsInput) error{theirs}, nil, 2},
		{"BothTaken", []func(*dynamodb.TransactWriteItemsInput) error{theirs, theirs}, store.ErrTooMany, 2},
		{"Conflicts", []func(*dynamodb.TransactWriteItemsInput) error{
			fails(&types.TransactionConflictException{}), fails(&types.TransactionConflictException{}), fails(&types.TransactionConflictException{}),
		}, store.ErrConflict, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptStub{txs: tc.txs}
			err := NewRegistry(s, "maap-registry").Credentials().Issue(context.Background(), cred)
			if !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) || len(s.calls) != tc.sent {
				t.Fatalf("Issue = %v after %d sends", err, len(s.calls))
			}
		})
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
