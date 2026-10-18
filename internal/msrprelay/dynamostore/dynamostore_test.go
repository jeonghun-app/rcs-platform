package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
)

// These tests check what the store asks DynamoDB for and how it reads the
// answers; whether DynamoDB evaluates the expressions as intended is checked
// against DynamoDB Local in integration_test.go.

// scripted is a DynamoDB client that records each request and answers with
// the function the test set.
type scripted struct {
	get      func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	put      func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
	update   func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
	del      func(*dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error)
	describe func(*dynamodb.DescribeTableInput) (*dynamodb.DescribeTableOutput, error)
	calls    []any
}

func (s *scripted) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	s.calls = append(s.calls, in)
	return s.get(in)
}

func (s *scripted) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	s.calls = append(s.calls, in)
	return s.put(in)
}

func (s *scripted) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	s.calls = append(s.calls, in)
	return s.update(in)
}

func (s *scripted) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	s.calls = append(s.calls, in)
	return s.del(in)
}

func (s *scripted) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	s.calls = append(s.calls, in)
	return s.describe(in)
}

var now = time.Date(2026, 3, 1, 12, 0, 0, 500_000_000, time.UTC)

func item(expires time.Time, extra map[string]types.AttributeValue) map[string]types.AttributeValue {
	it := map[string]types.AttributeValue{
		attrPK:        str("b1"),
		attrCoreLocal: str("msrp://10.0.2.9:9/c;tcp"),
		attrExpires:   num(expires.UnixMilli()),
		attrTTL:       num(ttlOf(expires)),
	}
	for k, v := range extra {
		it[k] = v
	}
	return it
}

func ccf(old map[string]types.AttributeValue) error {
	return &types.ConditionalCheckFailedException{Message: aws.String("The conditional request failed"), Item: old}
}

func values(m map[string]types.AttributeValue) string {
	var b strings.Builder
	for k, v := range m {
		switch v := v.(type) {
		case *types.AttributeValueMemberS:
			fmt.Fprintf(&b, "%s=S:%s ", k, v.Value)
		case *types.AttributeValueMemberN:
			fmt.Fprintf(&b, "%s=N:%s ", k, v.Value)
		}
	}
	return b.String()
}

func TestCreateWritesEveryAttributeAndRefusesATakenID(t *testing.T) {
	api := &scripted{}
	var put *dynamodb.PutItemInput
	api.put = func(in *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
		put = in
		return &dynamodb.PutItemOutput{}, nil
	}
	s := NewWithClient(api, "msrp-bindings")
	expires := now.Add(90 * time.Second)
	err := s.Create(context.Background(), store.Binding{ID: "b1", CorePath: "msrp://10.0.1.5:2855/a;tcp", CoreLocal: "msrp://10.0.2.9:9/c;tcp", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(put.TableName) != "msrp-bindings" || aws.ToString(put.ConditionExpression) != "attribute_not_exists(#pk)" {
		t.Fatalf("put %s with %q", aws.ToString(put.TableName), aws.ToString(put.ConditionExpression))
	}
	got := values(put.Item)
	for _, w := range []string{"pk=S:b1 ", "core_path=S:msrp://10.0.1.5:2855/a;tcp ", "expires_at=N:1772366490500 ", "ttl=N:1772366491 "} {
		if !strings.Contains(got, w) {
			t.Fatalf("item %s lacks %s", got, w)
		}
	}
	if _, ok := put.Item[attrClientPath]; ok {
		t.Fatal("an unknown path was written; attribute_exists would then count it as known")
	}

	api.put = func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) { return nil, ccf(nil) }
	if err := s.Create(context.Background(), store.Binding{ID: "b1", ExpiresAt: expires}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("Create = %v, want ErrExists", err)
	}
	if err := s.Create(context.Background(), store.Binding{ID: "b2", ClaimedBy: "x"}); err == nil {
		t.Fatal("Create accepted a claimed binding")
	}
}

func TestTTLIsRoundedUpToTheNextSecond(t *testing.T) {
	if got := ttlOf(time.Unix(100, 1)); got != 101 {
		t.Fatalf("ttlOf(100.000000001) = %d", got)
	}
	if got := ttlOf(time.Unix(100, 0)); got != 100 {
		t.Fatalf("ttlOf(100) = %d", got)
	}
}

func TestGetReadsConsistentlyAndChecksExpiry(t *testing.T) {
	api := &scripted{}
	expires := now.Add(time.Minute)
	api.get = func(in *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: item(expires, map[string]types.AttributeValue{
			attrCorePath: str("msrp://10.0.1.5:2855/a;tcp"), attrClientPath: str("msrp://client.invalid:1/x;tcp"), attrClaimedBy: str("t/1"),
		})}, nil
	}
	s := NewWithClient(api, "t")
	b, err := s.Get(context.Background(), "b1", now)
	if err != nil {
		t.Fatal(err)
	}
	in := api.calls[0].(*dynamodb.GetItemInput)
	if !aws.ToBool(in.ConsistentRead) {
		t.Fatal("Get is not strongly consistent (ADR 0004)")
	}
	want := store.Binding{ID: "b1", CorePath: "msrp://10.0.1.5:2855/a;tcp", ClientEndpointPath: "msrp://client.invalid:1/x;tcp",
		CoreLocal: "msrp://10.0.2.9:9/c;tcp", ExpiresAt: expires.Truncate(time.Millisecond), ClaimedBy: "t/1"}
	if b != want {
		t.Fatalf("Get = %+v\nwant %+v", b, want)
	}
	if _, err := s.Get(context.Background(), "b1", expires); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get at expiry = %v, want ErrNotFound", err)
	}
	api.get = func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) { return &dynamodb.GetItemOutput{}, nil }
	if _, err := s.Get(context.Background(), "b1", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get of nothing = %v, want ErrNotFound", err)
	}
}

func TestMalformedItemsAreErrorsNotBindings(t *testing.T) {
	expires := now.Add(time.Minute)
	for name, it := range map[string]map[string]types.AttributeValue{
		"no id":               {attrCoreLocal: str("u"), attrExpires: num(1)},
		"empty core local":    item(expires, map[string]types.AttributeValue{attrCoreLocal: str("")}),
		"path is a number":    item(expires, map[string]types.AttributeValue{attrCorePath: num(1)}),
		"client is a number":  item(expires, map[string]types.AttributeValue{attrClientPath: num(1)}),
		"claimant is a num":   item(expires, map[string]types.AttributeValue{attrClaimedBy: num(1)}),
		"expiry is a string":  item(expires, map[string]types.AttributeValue{attrExpires: str("soon")}),
		"expiry not a number": item(expires, map[string]types.AttributeValue{attrExpires: &types.AttributeValueMemberN{Value: "1e3"}}),
	} {
		t.Run(name, func(t *testing.T) {
			api := &scripted{get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{Item: it}, nil
			}}
			_, err := NewWithClient(api, "t").Get(context.Background(), "b1", now)
			if err == nil || errors.Is(err, store.ErrNotFound) {
				t.Fatalf("Get = %v, want a malformed-item error", err)
			}
		})
	}
}

func TestUpdateSetsOnlyWhatIsGivenUnderOneCondition(t *testing.T) {
	api := &scripted{}
	expires := now.Add(time.Hour)
	var in *dynamodb.UpdateItemInput
	api.update = func(u *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		in = u
		return &dynamodb.UpdateItemOutput{Attributes: item(expires, map[string]types.AttributeValue{attrClientPath: str("msrp://c.invalid:1/x;tcp")})}, nil
	}
	s := NewWithClient(api, "t")
	b, err := s.Update(context.Background(), "b1", store.Update{ExpiresAt: expires, ClientEndpointPath: "msrp://c.invalid:1/x;tcp"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if b.ClientEndpointPath != "msrp://c.invalid:1/x;tcp" || !b.ExpiresAt.Equal(expires.Truncate(time.Millisecond)) {
		t.Fatalf("Update = %+v", b)
	}
	if got := aws.ToString(in.UpdateExpression); got != "SET #e = :e, #ttl = :ttl, #cl = :cl" {
		t.Fatalf("UpdateExpression = %q", got)
	}
	if got := aws.ToString(in.ConditionExpression); got != "attribute_exists(#pk) AND #e > :now AND (attribute_not_exists(#cl) OR #cl = :cl)" {
		t.Fatalf("ConditionExpression = %q", got)
	}
	if in.ReturnValuesOnConditionCheckFailure != types.ReturnValuesOnConditionCheckFailureAllOld {
		t.Fatal("a refused update would not say why")
	}
	if got := values(in.ExpressionAttributeValues); !strings.Contains(got, ":now=N:1772366400500 ") {
		t.Fatalf("values %s", got)
	}
}

func TestUpdateRefusalsAreClassifiedFromTheOldItem(t *testing.T) {
	alive := item(now.Add(time.Minute), map[string]types.AttributeValue{attrCorePath: str("msrp://10.0.1.5:2855/a;tcp")})
	for _, tt := range []struct {
		name string
		old  map[string]types.AttributeValue
		want error
	}{
		{"missing", nil, store.ErrNotFound},
		{"expired", item(now, nil), store.ErrNotFound},
		{"path conflict", alive, store.ErrConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &scripted{update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) { return nil, ccf(tt.old) }}
			_, err := NewWithClient(api, "t").Update(context.Background(), "b1", store.Update{CorePath: "msrp://10.0.1.6:2855/b;tcp"}, now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Update = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUpdateWithNothingToSetReadsTheBinding(t *testing.T) {
	api := &scripted{get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: item(now.Add(time.Minute), nil)}, nil
	}}
	if _, err := NewWithClient(api, "t").Update(context.Background(), "b1", store.Update{}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.calls[0].(*dynamodb.GetItemInput); !ok || len(api.calls) != 1 {
		t.Fatalf("calls %T", api.calls)
	}
}

func TestClaimIsOneConditionalWrite(t *testing.T) {
	api := &scripted{}
	var in *dynamodb.UpdateItemInput
	claimed := item(now.Add(time.Minute), map[string]types.AttributeValue{
		attrCorePath: str("msrp://10.0.1.5:2855/a;tcp"), attrClientPath: str("msrp://c.invalid:1/x;tcp"), attrClaimedBy: str("task/1"),
	})
	api.update = func(u *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		in = u
		return &dynamodb.UpdateItemOutput{Attributes: claimed}, nil
	}
	b, err := NewWithClient(api, "t").Claim(context.Background(), "b1", "task/1", now)
	if err != nil || b.ClaimedBy != "task/1" {
		t.Fatalf("Claim = %+v, %v", b, err)
	}
	cond := aws.ToString(in.ConditionExpression)
	for _, w := range []string{"attribute_not_exists(#cb)", "#e > :now", "attribute_exists(#cp)", "attribute_exists(#cl)"} {
		if !strings.Contains(cond, w) {
			t.Fatalf("claim condition %q lacks %s", cond, w)
		}
	}
	if in.ExpressionAttributeNames["#cb"] != attrClaimedBy {
		t.Fatal("claim condition names the wrong attribute")
	}
}

func TestClaimRefusalsAreClassifiedFromTheOldItem(t *testing.T) {
	complete := map[string]types.AttributeValue{attrCorePath: str("msrp://10.0.1.5:2855/a;tcp"), attrClientPath: str("msrp://c.invalid:1/x;tcp")}
	claimed := map[string]types.AttributeValue{attrClaimedBy: str("other/2")}
	for k, v := range complete {
		claimed[k] = v
	}
	for _, tt := range []struct {
		name string
		old  map[string]types.AttributeValue
		want error
	}{
		{"missing", nil, store.ErrNotFound},
		{"expired and claimed", item(now, claimed), store.ErrNotFound},
		{"claimed", item(now.Add(time.Minute), claimed), store.ErrClaimed},
		{"incomplete", item(now.Add(time.Minute), nil), store.ErrIncomplete},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &scripted{update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) { return nil, ccf(tt.old) }}
			_, err := NewWithClient(api, "t").Claim(context.Background(), "b1", "task/1", now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Claim = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDeleteTellsLiveFromExpiredBindings(t *testing.T) {
	for _, tt := range []struct {
		name string
		old  map[string]types.AttributeValue
		want error
	}{
		{"live", item(now.Add(time.Minute), nil), nil},
		{"expired", item(now, nil), store.ErrNotFound},
		{"missing", nil, store.ErrNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &scripted{del: func(in *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
				if in.ReturnValues != types.ReturnValueAllOld {
					t.Fatal("Delete cannot tell what it removed")
				}
				return &dynamodb.DeleteItemOutput{Attributes: tt.old}, nil
			}}
			if err := NewWithClient(api, "t").Delete(context.Background(), "b1", now); !errors.Is(err, tt.want) {
				t.Fatalf("Delete = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadyNeedsAnActiveTable(t *testing.T) {
	for _, tt := range []struct {
		name   string
		out    *dynamodb.DescribeTableOutput
		err    error
		wantOK bool
	}{
		{"active", &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: types.TableStatusActive}}, nil, true},
		{"creating", &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: types.TableStatusCreating}}, nil, false},
		{"no description", &dynamodb.DescribeTableOutput{}, nil, false},
		{"error", nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &scripted{describe: func(*dynamodb.DescribeTableInput) (*dynamodb.DescribeTableOutput, error) { return tt.out, tt.err }}
			if err := NewWithClient(api, "t").Ready(context.Background()); (err == nil) != tt.wantOK {
				t.Fatalf("Ready = %v", err)
			}
		})
	}
}

func TestSDKErrorsAreReducedToTheirCode(t *testing.T) {
	secret := "https://dynamodb.example.invalid/?X-Amz-Security-Token=tok3n"
	for _, tt := range []struct {
		name string
		err  error
		want string
		is   error
	}{
		{"API error", &smithy.OperationError{ServiceID: "DynamoDB", OperationName: "GetItem",
			Err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: secret}},
			"dynamostore: get: ProvisionedThroughputExceededException", nil},
		{"transport", &url.Error{Op: "Post", URL: secret, Err: errors.New("connection refused")}, "dynamostore: get: connection refused", nil},
		{"deadline", fmt.Errorf("op: %w", context.DeadlineExceeded), "dynamostore: get: context deadline exceeded", context.DeadlineExceeded},
		{"other", errors.New(secret), "dynamostore: get: request failed", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &scripted{get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) { return nil, tt.err }}
			_, err := NewWithClient(api, "t").Get(context.Background(), "b1", now)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("error %q, want %q", err, tt.want)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Fatalf("%v does not wrap %v", err, tt.is)
			}
		})
	}
}

func TestEveryWriteErrorIsSanitised(t *testing.T) {
	boom := &url.Error{Op: "Post", URL: "https://x.invalid/", Err: errors.New("reset")}
	api := &scripted{
		put:    func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) { return nil, boom },
		update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) { return nil, boom },
		del:    func(*dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) { return nil, boom },
	}
	s := NewWithClient(api, "t")
	ctx := context.Background()
	errs := []error{
		s.Create(ctx, store.Binding{ID: "b1"}),
		func() error { _, err := s.Update(ctx, "b1", store.Update{ExpiresAt: now}, now); return err }(),
		func() error { _, err := s.Claim(ctx, "b1", "t/1", now); return err }(),
		s.Delete(ctx, "b1", now),
	}
	for i, err := range errs {
		if err == nil || strings.Contains(err.Error(), "x.invalid") || !strings.HasSuffix(err.Error(), ": reset") {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

func TestMalformedWriteResultsAreErrors(t *testing.T) {
	api := &scripted{update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		return &dynamodb.UpdateItemOutput{Attributes: map[string]types.AttributeValue{attrPK: str("b1")}}, nil
	}}
	s := NewWithClient(api, "t")
	if _, err := s.Update(context.Background(), "b1", store.Update{ExpiresAt: now}, now); err == nil {
		t.Fatal("Update returned a binding from a malformed item")
	}
	if _, err := s.Claim(context.Background(), "b1", "t/1", now); err == nil {
		t.Fatal("Claim returned a binding from a malformed item")
	}
}

func TestNewLoadsConfigurationWithoutARequest(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	s, err := New(context.Background(), "msrp-bindings", "http://127.0.0.1:1")
	if err != nil || s.table != "msrp-bindings" {
		t.Fatalf("New = %v, %v", s, err)
	}
}
