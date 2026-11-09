//go:build integration

package awsstore

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// The integration tests run the registry contract against DynamoDB Local
// (make test-integration), which checks the condition expressions and
// error codes the unit tests stub. MAAP_IT_DYNAMODB_ENDPOINT names the
// container.

// registryTable creates maap-registry as docs/maap.md defines it and
// returns the client.
func registryTable(t *testing.T) (*dynamodb.Client, string) { return table(t, "maap-registry") }

// table creates a table of name's key schema, which all of maap's tables
// share, and returns the client.
func table(t *testing.T, name string) (*dynamodb.Client, string) {
	t.Helper()
	endpoint := os.Getenv("MAAP_IT_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Fatal("MAAP_IT_DYNAMODB_ENDPOINT must name the test container")
	}
	ctx := t.Context()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	table := name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	attr := func(name string) types.AttributeDefinition {
		return types.AttributeDefinition{AttributeName: aws.String(name), AttributeType: types.ScalarAttributeTypeS}
	}
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table), BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{attr(attrPK), attr(attrSK)},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
	}); err != nil {
		t.Fatalf("creating the table: %v", err)
	}
	return ddb, table
}

func TestIntegrationRegistryMeetsTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Registry { return NewRegistry(registryTable(t)) })
}

func TestIntegrationCredentialsMeetTheContract(t *testing.T) {
	storetest.RunCredentials(t, func(t *testing.T) (store.Registry, store.Credentials) {
		r := NewRegistry(registryTable(t))
		return r, r.Credentials()
	})
}

// The loader maap runs with reaches the table and finds it ready.
func TestIntegrationNewReachesAReadyTable(t *testing.T) {
	_, table := registryTable(t)
	r, err := New(t.Context(), table, os.Getenv("MAAP_IT_DYNAMODB_ENDPOINT"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(t.Context()); err != nil {
		t.Fatalf("Ready = %v", err)
	}
	c, err := r.Register(t.Context(), storetest.Chatbot())
	if err != nil || c.Version != 1 {
		t.Fatalf("Register = %+v, %v", c, err)
	}
}

// resend sends every write that succeeds a second time, as the SDK does
// when an answer is lost, without the request token, as when DynamoDB no
// longer knows it, and answers what the second send got.
type resend struct{ DynamoAPI }

func (r resend) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if _, err := r.DynamoAPI.PutItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return r.DynamoAPI.PutItem(ctx, in, o...)
}

func (r resend) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if _, err := r.DynamoAPI.TransactWriteItems(ctx, in, o...); err != nil {
		return nil, err
	}
	again := *in
	again.ClientRequestToken = nil
	return r.DynamoAPI.TransactWriteItems(ctx, &again, o...)
}

// resendTable is resend for TableAPI.
type resendTable struct{ TableAPI }

func (r resendTable) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if _, err := r.TableAPI.PutItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return r.TableAPI.PutItem(ctx, in, o...)
}

func (r resendTable) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, o ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if _, err := r.TableAPI.DeleteItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return r.TableAPI.DeleteItem(ctx, in, o...)
}

func (r resendTable) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if _, err := r.TableAPI.UpdateItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return r.TableAPI.UpdateItem(ctx, in, o...)
}

func TestIntegrationAWriteSentAgainAfterItTookEffectStands(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(resend{ddb}, table)
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if c, err = r.Update(ctx, c, c); err != nil || c.Version != 2 {
		t.Fatalf("Update = %+v, %v", c, err)
	}
	// An issue finds its own slot, and takes one only.
	if err := r.Credentials().Issue(ctx, storetest.Credential(c, time.Unix(1, 0))); err != nil {
		t.Fatalf("Issue = %v", err)
	}
	if creds, err := r.Credentials().ChatbotCredentials(ctx, c.ID); len(creds) != 1 || err != nil {
		t.Fatalf("ChatbotCredentials = %v, %v", creds, err)
	}
	// A real conflict is still one.
	stale := c
	stale.Version = 1
	if _, err := r.Update(ctx, stale, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale Update = %v", err)
	}
	if err := r.DeleteChatbot(ctx, c.ID); err != nil {
		t.Fatalf("DeleteChatbot = %v", err)
	}
}

// put writes item behind the store's back.
func put(t *testing.T, ddb *dynamodb.Client, table string, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := ddb.PutItem(t.Context(), &dynamodb.PutItemInput{TableName: aws.String(table), Item: item}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationDeleteChatbotDeletesEveryItemOfItsPartition(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(ddb, table)
	r.pageSize = 1 // every item a page of its own
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	// Items #710 will keep there, and a record a newer release wrote,
	// whose document this one cannot read.
	for _, sk := range []string{"k#one", "k#two", "k#three"} {
		put(t, ddb, table, key("c#"+c.ID, sk))
	}
	newer, _ := r.item(c, c.Version, c.Registration)
	newer[attrDoc] = &types.AttributeValueMemberB{Value: []byte(`{"schema":2}`)}
	put(t, ddb, table, newer)
	if err := r.DeleteChatbot(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	for _, k := range []map[string]types.AttributeValue{key("c#"+c.ID, "k#one"), key("c#"+c.ID, "k#three"), uriKey(c.URI)} {
		out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
		if err != nil || len(out.Item) != 0 {
			t.Errorf("%v left: %v, %v", k[attrSK], out, err)
		}
	}
	out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: chatbotKey(c.ID), ConsistentRead: aws.Bool(true)})
	if err != nil || len(out.Item) != 3 || out.Item[attrDeleted] == nil {
		t.Fatalf("not a tombstone: %v, %v", out, err)
	}
}

func TestIntegrationDeleteChatbotLeavesAnotherChatbotsReservation(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(ddb, table)
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	theirs := uriKey(c.URI)
	theirs[attrChatbot] = str("another")
	put(t, ddb, table, theirs)
	if err := r.DeleteChatbot(ctx, c.ID); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("DeleteChatbot = %v", err)
	}
	out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: uriKey(c.URI), ConsistentRead: aws.Bool(true)})
	if err != nil || sv(out.Item[attrChatbot]) != "another" {
		t.Fatalf("the other chatbot's reservation: %v, %v", out, err)
	}
	if _, err := r.Chatbot(ctx, c.ID); err != nil {
		t.Fatalf("the refused deletion changed the chatbot: %v", err)
	}
}

// meddle runs change once, after the first read that names attributes, as
// DeleteChatbot's read of the record does.
type meddle struct {
	DynamoAPI
	change func()
}

func (m *meddle) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	out, err := m.DynamoAPI.GetItem(ctx, in, o...)
	if f := m.change; in.ProjectionExpression != nil && f != nil {
		m.change = nil
		f()
	}
	return out, err
}

func TestIntegrationADeletionThatMeetsAnUpdateStillDeletesEverything(t *testing.T) {
	ddb, table := registryTable(t)
	r := NewRegistry(ddb, table)
	ctx := t.Context()
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	put(t, ddb, table, key("c#"+c.ID, "k#one"))
	// An update lands between the deletion's read and its tombstone.
	m := &meddle{DynamoAPI: ddb, change: func() {
		if _, err := r.Update(ctx, c, c); err != nil {
			t.Error(err)
		}
	}}
	deleted := func() {
		t.Helper()
		if err := NewRegistry(m, table).DeleteChatbot(ctx, c.ID); err != nil {
			t.Fatalf("DeleteChatbot = %v", err)
		}
		for _, k := range []map[string]types.AttributeValue{key("c#"+c.ID, "k#one"), key("c#"+c.ID, "k#left"), uriKey(c.URI)} {
			out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
			if err != nil || len(out.Item) != 0 {
				t.Fatalf("%v left: %v, %v", k[attrSK], out, err)
			}
		}
		out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: chatbotKey(c.ID), ConsistentRead: aws.Bool(true)})
		if err != nil || len(out.Item) != 3 || out.Item[attrDeleted] == nil {
			t.Fatalf("not a tombstone: %v, %v", out, err)
		}
	}
	deleted()
	// A repeat finishes a clean-up that stopped under the tombstone, and is
	// otherwise a no-op.
	put(t, ddb, table, key("c#"+c.ID, "k#left"))
	deleted()
	deleted()
}

// failTx fails the first transaction it is sent, as a 5xx past the SDK's
// retries or a cancelled request would.
type failTx struct {
	DynamoAPI
	failed bool
}

func (f *failTx) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if !f.failed {
		f.failed = true
		return nil, context.Canceled
	}
	return f.DynamoAPI.TransactWriteItems(ctx, in, o...)
}

// The #744 review: a revoke that failed, or a slot the earlier two-step
// revoke left naming a key item that is gone, never keeps a chatbot from
// its two credentials.
func TestIntegrationAHalfDoneRevokeNeverHoldsASlot(t *testing.T) {
	ddb, table := registryTable(t)
	ctx := t.Context()
	cs := NewRegistry(ddb, table).Credentials()
	c, err := NewRegistry(ddb, table).Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	creds := []store.Credential{storetest.Credential(c, time.Unix(1, 0)), storetest.Credential(c, time.Unix(2, 0))}
	issue := func(want error) {
		t.Helper()
		cred := storetest.Credential(c, time.Unix(3, 0))
		if err := cs.Issue(ctx, cred); !errors.Is(err, want) || (err == nil) != (want == nil) {
			t.Fatalf("Issue = %v, want %v", err, want)
		}
		creds = append(creds, cred)
	}
	for _, cred := range creds {
		if err := cs.Issue(ctx, cred); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewRegistry(&failTx{DynamoAPI: ddb}, table).Credentials().Revoke(ctx, c.ID, creds[0].KeyID); err == nil {
		t.Fatal("the failed revoke succeeded")
	}
	if err := cs.Revoke(ctx, c.ID, creds[0].KeyID); err != nil {
		t.Fatalf("Revoke again = %v", err)
	}
	issue(nil)
	issue(store.ErrTooMany)
	// Both key items gone behind their slots' backs: the next issue takes
	// a slot over (slot 1, creds[2]'s), and a revoke of the other key ID
	// (creds[1], slot 2) clears its slot and succeeds.
	for _, cred := range creds[1:3] {
		if _, err := ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: keyKey(cred.KeyID)}); err != nil {
			t.Fatal(err)
		}
	}
	issue(nil)
	if err := cs.Revoke(ctx, c.ID, creds[1].KeyID); err != nil {
		t.Fatalf("Revoke of a slot without its key item = %v", err)
	}
	if err := cs.Revoke(ctx, c.ID, creds[1].KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Revoke of nothing = %v", err)
	}
	issue(nil)
	issue(store.ErrTooMany)
	if got, err := cs.ChatbotCredentials(ctx, c.ID); len(got) != store.MaxCredentials || err != nil {
		t.Fatalf("%d live, %v", len(got), err)
	}
	// Both slots stale, then four concurrent issues: the takeover's guard
	// (the slot still names the stale key) lets only two win (#744 round
	// 2), and no key item is left without a slot.
	live, _ := cs.ChatbotCredentials(ctx, c.ID)
	for _, cred := range live {
		if _, err := ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: keyKey(cred.KeyID)}); err != nil {
			t.Fatal(err)
		}
	}
	racing := make([]store.Credential, 4)
	errs := make(chan error, len(racing))
	for i := range racing {
		racing[i] = storetest.Credential(c, time.Unix(4, 0))
		go func() { errs <- cs.Issue(ctx, racing[i]) }()
	}
	won := 0
	for range racing {
		switch err := <-errs; {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrTooMany) && !errors.Is(err, store.ErrConflict):
			t.Errorf("a losing Issue = %v", err)
		}
	}
	kept := 0
	for _, cred := range racing {
		if _, err := cs.Credential(ctx, cred.KeyID); err == nil {
			kept++
		}
	}
	if got, _ := cs.ChatbotCredentials(ctx, c.ID); won != store.MaxCredentials || len(got) != won || kept != won {
		t.Fatalf("%d issues won, %d listed, %d key items kept", won, len(got), kept)
	}
}

// A chatbot's deletion finishes over a key item that names no chatbot
// (#744 round 2, the tester's probe): the slot goes alone.
func TestIntegrationADeletionFinishesOverADamagedKeyItem(t *testing.T) {
	ddb, table := registryTable(t)
	ctx := t.Context()
	r := NewRegistry(ddb, table)
	c, err := r.Register(ctx, storetest.Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	cred := storetest.Credential(c, time.Unix(1, 0))
	if err := r.Credentials().Issue(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if _, err := ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(table), Key: keyKey(cred.KeyID), UpdateExpression: aws.String("REMOVE #chatbot"),
		ExpressionAttributeNames: map[string]string{"#chatbot": attrChatbot},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteChatbot(ctx, c.ID); err != nil {
		t.Fatalf("DeleteChatbot = %v", err)
	}
	if got, err := r.Credentials().ChatbotCredentials(ctx, c.ID); len(got) != 0 || err != nil {
		t.Fatalf("left: %v, %v", got, err)
	}
	out, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: slotKey(c.ID, 1), ConsistentRead: aws.Bool(true)})
	if err != nil || len(out.Item) != 0 {
		t.Fatalf("the slot is left: %v, %v", out.Item, err)
	}
}

func TestIntegrationRequestsMeetTheContract(t *testing.T) {
	storetest.RunRequests(t, func(t *testing.T) store.Requests {
		ddb, name := table(t, "maap-requests")
		r := NewRequests(ddb, name, testKey)
		r.pageSize = 7 // pages that end inside a batch
		return r
	})
}

// A request whose put the SDK sent again after it took effect is kept by
// this call; a repeat of it is still a repeat.
func TestIntegrationARememberSentAgainIsStillTheFirst(t *testing.T) {
	ddb, name := table(t, "maap-requests")
	r := NewRequests(resendTable{ddb}, name, testKey)
	rec := storetest.Idempotency(storetest.Chatbot().ID)
	got, fresh, err := r.Remember(t.Context(), rec, storetest.Now)
	if err != nil || !fresh || got.MessageID != rec.MessageID {
		t.Fatalf("Remember = %+v, %v, %v", got, fresh, err)
	}
	writer := got.Writer
	again := rec
	again.MessageID = storetest.MessageID()
	if got, fresh, err := r.Remember(t.Context(), again, storetest.Now); err != nil || fresh || got.MessageID != rec.MessageID {
		t.Fatalf("repeat = %+v, %v, %v", got, fresh, err)
	}
	// A settle and, of another, pending record, a forget sent again stand.
	if err := r.Settle(t.Context(), rec.Chatbot, rec.Key, writer, []byte("{}"), storetest.Now); err != nil {
		t.Fatalf("Settle = %v", err)
	}
	refused := storetest.Idempotency(rec.Chatbot)
	got, _, err = r.Remember(t.Context(), refused, storetest.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Forget(t.Context(), refused.Chatbot, refused.Key, got.Writer); err != nil {
		t.Fatalf("Forget = %v", err)
	}
	if err := r.Ready(t.Context()); err != nil {
		t.Fatalf("Ready = %v", err)
	}
}
