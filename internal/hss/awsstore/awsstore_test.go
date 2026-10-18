package awsstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store/storetest"
)

var testConfig = Config{SubscribersTable: "subscribers", ProfilesTable: "service-profiles"}

func fakeStore(t *testing.T) (*Dynamo, *fakeDynamo) {
	f := newFakeDynamo(t, testConfig.SubscribersTable, testConfig.ProfilesTable)
	return NewDynamo(f, testConfig), f
}

func TestDynamoStoreBehavesAsTheHSSExpects(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { d, _ := fakeStore(t); return d }, storetest.Options{})
}

func TestStateChangesAreOnePutAndIdentityChangesOneTransaction(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	if _, err := d.CreateProfile(ctx, storetest.Profile("p")); err != nil {
		t.Fatal(err)
	}
	v1, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1))
	if err != nil {
		t.Fatal(err)
	}
	next := *v1
	next.ServerName = "sip:scscf.rcs.local"
	puts, txs := f.calls["PutItem"], f.calls["TransactWriteItems"]
	v2, err := d.UpdateSubscription(ctx, v1, &next)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls["PutItem"] != puts+1 || f.calls["TransactWriteItems"] != txs {
		t.Errorf("a state change used %d puts and %d transactions", f.calls["PutItem"]-puts, f.calls["TransactWriteItems"]-txs)
	}
	more := storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1, storetest.TEL1)
	if _, err := d.UpdateSubscription(ctx, v2, more); err != nil {
		t.Fatal(err)
	}
	if f.calls["TransactWriteItems"] != txs+1 {
		t.Error("an identity change was not a transaction")
	}
}

func TestStoreFailuresAreReportedWithoutRequestDetails(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	f.fail = &url.Error{Op: "Post", URL: "https://dynamodb/?impi=" + storetest.IMPI1, Err: errors.New("connection refused")}
	checks := map[string]error{}
	_, checks["get"] = d.Subscription(ctx, storetest.IMPI1)
	_, checks["by IMPU"] = d.SubscriptionByIMPU(ctx, storetest.IMPU1)
	_, checks["create"] = d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1))
	sub := storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1)
	_, checks["update"] = d.UpdateSubscription(ctx, sub, sub)
	checks["delete"] = d.DeleteSubscription(ctx, sub)
	_, checks["list"] = d.SubscriptionsByProfile(ctx, "p", "", 10)
	_, checks["create profile"] = d.CreateProfile(ctx, storetest.Profile("p"))
	_, checks["get profile"] = d.Profile(ctx, "p")
	_, checks["update profile"] = d.UpdateProfile(ctx, storetest.Profile("p"))
	checks["delete profile"] = d.DeleteProfile(ctx, storetest.Profile("p"))
	_, checks["data keys"] = d.DataKeys(ctx)
	checks["add data key"] = d.AddDataKey(ctx, keyring.WrappedKey{ID: "1"})
	checks["ready"] = d.Ready(ctx)
	for op, err := range checks {
		if err == nil {
			t.Errorf("%s succeeded against a failing table", op)
			continue
		}
		if strings.Contains(err.Error(), "15550100001") || strings.Contains(err.Error(), "001010000000001") || strings.Contains(err.Error(), "https://") {
			t.Errorf("%s error leaks the request: %v", op, err)
		}
	}
}

func TestReadyNeedsBothTablesActive(t *testing.T) {
	d, f := fakeStore(t)
	if err := d.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.status = types.TableStatusCreating
	if err := d.Ready(context.Background()); err == nil {
		t.Error("Ready with a table still being created")
	}
}

func TestCorruptItemsAreRefused(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	f.tables["subscribers"]["s#"+storetest.IMPI1] = map[string]types.AttributeValue{attrPK: str("s#" + storetest.IMPI1)}
	f.tables["subscribers"]["u#"+storetest.IMPU1] = map[string]types.AttributeValue{attrPK: str("u#" + storetest.IMPU1)}
	f.tables["subscribers"]["u#"+storetest.IMPU2] = map[string]types.AttributeValue{attrPK: str("u#x"), attrIMPI: str(storetest.IMPI2)}
	f.tables["subscribers"][keyringPK] = map[string]types.AttributeValue{attrPK: str(keyringPK), "key_1": str("not binary")}
	f.tables["service-profiles"]["p"] = map[string]types.AttributeValue{attrPK: str("p"), attrVersion: &types.AttributeValueMemberN{Value: "x"}, attrDoc: &types.AttributeValueMemberB{}}
	for name, err := range map[string]error{
		"subscription without doc": second(d.Subscription(ctx, storetest.IMPI1)),
		"identity without IMPI":    second(d.SubscriptionByIMPU(ctx, storetest.IMPU1)),
		"identity to nothing":      second(d.SubscriptionByIMPU(ctx, storetest.IMPU2)),
		"profile with bad version": second(d.Profile(ctx, "p")),
		"data key not binary":      second(d.DataKeys(ctx)),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIdentityItemOfAnotherSubscriptionIsAnInvariantBreak(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	if _, err := d.CreateProfile(ctx, storetest.Profile("p")); err != nil {
		t.Fatal(err)
	}
	v1, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1, storetest.IMPU2))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the index: IMPU2's item names someone else.
	f.tables["subscribers"]["u#"+storetest.IMPU2][attrIMPI] = str(storetest.IMPI2)
	if _, err := d.UpdateSubscription(ctx, v1, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1)); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("update = %v, want ErrInvalid", err)
	}
	if err := d.DeleteSubscription(ctx, v1); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("delete = %v, want ErrInvalid", err)
	}
	stale := *v1
	stale.Version = 7
	if err := d.DeleteSubscription(ctx, &stale); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale delete = %v, want ErrConflict", err)
	}
}

func second[T any](_ T, err error) error { return err }

type fakeKMS struct {
	keyID    string
	ctx      map[string]string
	failGen  error
	failDec  error
	shortKey bool
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if f.failGen != nil {
		return nil, f.failGen
	}
	f.keyID, f.ctx = aws.ToString(in.KeyId), in.EncryptionContext
	n := keyring.DataKeySize
	if f.shortKey {
		n = 16
	}
	key := make([]byte, n)
	_, _ = rand.Read(key)
	return &kms.GenerateDataKeyOutput{Plaintext: key, CiphertextBlob: append([]byte("blob:"+f.keyID+":"), key...)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.failDec != nil {
		return nil, f.failDec
	}
	prefix := "blob:" + aws.ToString(in.KeyId) + ":"
	if !strings.HasPrefix(string(in.CiphertextBlob), prefix) || !reflect.DeepEqual(in.EncryptionContext, encryptionContext) {
		return nil, &smithy.GenericAPIError{Code: "InvalidCiphertextException"}
	}
	// Like KMS, a fresh buffer: the keyring clears the plaintext it gets.
	return &kms.DecryptOutput{Plaintext: bytes.Clone(in.CiphertextBlob[len(prefix):])}, nil
}

func TestKMSWrapsDataKeysWithItsEncryptionContext(t *testing.T) {
	d, _ := fakeStore(t)
	f := &fakeKMS{}
	ctx := context.Background()
	k, err := keyring.Open(ctx, NewKMS(f, "alias/hss"), d, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if f.keyID != "alias/hss" || !reflect.DeepEqual(f.ctx, encryptionContext) {
		t.Errorf("GenerateDataKey with key %q, context %v", f.keyID, f.ctx)
	}
	sealed, err := k.Seal([]byte("K"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// Another task opens the same keyring from the table.
	again, err := keyring.Open(ctx, NewKMS(f, "alias/hss"), d, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Open(sealed, []byte("aad")); err != nil || string(got) != "K" {
		t.Errorf("second task: %q, %v", got, err)
	}
	// A wrapped key is refused under another master key.
	if _, err := keyring.Open(ctx, NewKMS(f, "alias/other"), d, rand.Reader); err == nil {
		t.Error("a data key unwrapped under another KMS key")
	}
}

func TestKMSFailuresAreSanitised(t *testing.T) {
	ctx := context.Background()
	gen := NewKMS(&fakeKMS{failGen: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "user arn:aws:iam::1:role/x is not authorized"}}, "k")
	_, _, err := gen.GenerateDataKey(ctx)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") || strings.Contains(err.Error(), "arn:") {
		t.Errorf("GenerateDataKey error = %v", err)
	}
	if _, _, err := NewKMS(&fakeKMS{shortKey: true}, "k").GenerateDataKey(ctx); err == nil {
		t.Error("accepted a 128-bit data key")
	}
	if _, err := NewKMS(&fakeKMS{failDec: context.DeadlineExceeded}, "k").Unwrap(ctx, []byte("x")); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Unwrap error = %v, want the deadline", err)
	}
}

func TestSanitizeKeepsOnlyTheCode(t *testing.T) {
	for in, want := range map[error]string{
		&smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "secret detail"}: "op: ProvisionedThroughputExceededException",
		&url.Error{Op: "Post", URL: "https://x/" + storetest.IMPI1, Err: errors.New("dial tcp: refused")}: "op: dial tcp: refused",
		fmt.Errorf("wrapped: %w", context.Canceled):                                                       "op: context canceled",
		errors.New("anything " + storetest.IMPI1):                                                         "op: request failed",
	} {
		if got := sanitize("op", in).Error(); got != "awsstore: "+want {
			t.Errorf("sanitize(%v) = %q", in, got)
		}
	}
}

func TestNewClientsMakesNoRequest(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	c, err := NewClients(context.Background(), Config{DynamoDBEndpoint: "http://127.0.0.1:1", KMSEndpoint: "http://127.0.0.1:1"})
	if err != nil || c.DynamoDB == nil || c.KMS == nil {
		t.Fatalf("NewClients = %+v, %v", c, err)
	}
	sdkLogger{}.Logf("WARN", "retrying %s", storetest.IMPU1)
}

func TestRacingTransactionsAreVersionConflicts(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	if _, err := d.CreateProfile(ctx, storetest.Profile("p")); err != nil {
		t.Fatal(err)
	}
	v1, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1))
	if err != nil {
		t.Fatal(err)
	}
	next := *v1
	next.AuthPending = true
	f.raceNext = true
	if _, err := d.UpdateSubscription(ctx, v1, &next); !errors.Is(err, store.ErrConflict) {
		t.Errorf("PutItem racing a transaction = %v, want ErrConflict", err)
	}
	f.raceNext = true
	if _, err := d.UpdateSubscription(ctx, v1, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1, storetest.TEL1)); !errors.Is(err, store.ErrConflict) {
		t.Errorf("cancelled transaction = %v, want ErrConflict", err)
	}
	f.raceNext = true
	if _, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI2, "p", storetest.IMPU2)); !errors.Is(err, store.ErrConflict) {
		t.Errorf("create racing = %v, want ErrConflict", err)
	}
	f.raceNext = true
	if err := d.DeleteSubscription(ctx, v1); !errors.Is(err, store.ErrConflict) {
		t.Errorf("delete racing = %v, want ErrConflict", err)
	}
}

func TestAWriteWhoseResponseWasLostStands(t *testing.T) {
	d, f := fakeStore(t)
	ctx := context.Background()
	if _, err := d.CreateProfile(ctx, storetest.Profile("p")); err != nil {
		t.Fatal(err)
	}
	v1, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1))
	if err != nil {
		t.Fatal(err)
	}
	next := *v1
	next.ServerName = "sip:scscf.rcs.local"
	f.loseNextResponse = true
	got, err := d.UpdateSubscription(ctx, v1, &next)
	if err != nil || got.Version != 2 {
		t.Fatalf("update whose response was lost = %+v, %v; it was applied", got, err)
	}
	// Another writer's identical document from the same version is still
	// a conflict: only this write's own token proves it applied.
	if _, err := d.UpdateSubscription(ctx, v1, &next); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second writer = %v, want ErrConflict", err)
	}
	p, err := d.Profile(ctx, "p")
	if err != nil {
		t.Fatal(err)
	}
	f.loseNextResponse = true
	if got, err := d.UpdateProfile(ctx, p); err != nil || got.Version != 2 {
		t.Fatalf("profile update whose response was lost = %+v, %v", got, err)
	}
	if _, err := d.CreateSubscription(ctx, storetest.Subscription(storetest.IMPI2, "p", storetest.IMPU2)); err != nil {
		t.Fatal(err)
	}
	if len(f.tokens) != 2 || f.tokens[0] == f.tokens[1] {
		t.Errorf("transactions share a request token: %v", f.tokens)
	}
}
