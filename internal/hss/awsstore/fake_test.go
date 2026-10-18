package awsstore

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeDynamo implements the DynamoDB semantics this package relies on, for
// exactly the expressions it sends: an expression it does not know fails the
// test, so a change to one cannot pass here unnoticed. The integration test
// runs the same store contract against DynamoDB Local.
type fakeDynamo struct {
	t      *testing.T
	mu     sync.Mutex
	tables map[string]map[string]map[string]types.AttributeValue
	fail   error
	status types.TableStatus
	calls  map[string]int
	// raceNext makes the next PutItem or TransactWriteItems lose to a
	// concurrent transaction; loseNextResponse applies the next PutItem but
	// answers as a resent request would, with the condition failed.
	raceNext         bool
	loseNextResponse bool
	tokens           []string
}

func newFakeDynamo(t *testing.T, tables ...string) *fakeDynamo {
	f := &fakeDynamo{t: t, tables: map[string]map[string]map[string]types.AttributeValue{}, status: types.TableStatusActive, calls: map[string]int{}}
	for _, name := range tables {
		f.tables[name] = map[string]map[string]types.AttributeValue{}
	}
	return f
}

func nv(v types.AttributeValue) int64 {
	if n, ok := v.(*types.AttributeValueMemberN); ok {
		i, _ := strconv.ParseInt(n.Value, 10, 64)
		return i
	}
	return -1
}

func (f *fakeDynamo) table(name *string) map[string]map[string]types.AttributeValue {
	tbl, ok := f.tables[aws.ToString(name)]
	if !ok {
		f.t.Fatalf("unknown table %q", aws.ToString(name))
	}
	return tbl
}

// holds evaluates one of the package's condition expressions against the
// current item (nil when absent).
func (f *fakeDynamo) holds(expr *string, names map[string]string, values map[string]types.AttributeValue, cur map[string]types.AttributeValue) bool {
	attr := func(placeholder string) types.AttributeValue {
		name, ok := names[placeholder]
		if !ok {
			f.t.Fatalf("expression placeholder %s not in names", placeholder)
		}
		return cur[name]
	}
	switch e := aws.ToString(expr); e {
	case "":
		return true
	case "attribute_not_exists(#pk)":
		return cur == nil
	case "attribute_exists(#pk)":
		return cur != nil
	case "attribute_not_exists(#k)":
		return attr("#k") == nil
	case "#v = :v":
		return cur != nil && nv(attr("#v")) == nv(values[":v"])
	case "#impi = :impi":
		return cur != nil && sv(attr("#impi")) == sv(values[":impi"])
	case "attribute_not_exists(#pk) OR #impi = :impi":
		return cur == nil || sv(attr("#impi")) == sv(values[":impi"])
	default:
		f.t.Fatalf("condition expression %q is not one the fake knows", e)
		return false
	}
}

func (f *fakeDynamo) enter(op string) error {
	f.calls[op]++
	return f.fail
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetItem"); err != nil {
		return nil, err
	}
	if !aws.ToBool(in.ConsistentRead) {
		f.t.Error("GetItem without ConsistentRead")
	}
	return &dynamodb.GetItemOutput{Item: maps.Clone(f.table(in.TableName)[sv(in.Key[attrPK])])}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("PutItem"); err != nil {
		return nil, err
	}
	if f.raceNext {
		f.raceNext = false
		return nil, &types.TransactionConflictException{}
	}
	tbl := f.table(in.TableName)
	pk := sv(in.Item[attrPK])
	if !f.holds(in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, tbl[pk]) {
		return nil, &types.ConditionalCheckFailedException{}
	}
	tbl[pk] = maps.Clone(in.Item)
	if f.loseNextResponse {
		f.loseNextResponse = false
		return nil, &types.ConditionalCheckFailedException{}
	}
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("UpdateItem"); err != nil {
		return nil, err
	}
	if got := aws.ToString(in.UpdateExpression); got != "SET #k = :k" {
		f.t.Fatalf("update expression %q", got)
	}
	tbl := f.table(in.TableName)
	pk := sv(in.Key[attrPK])
	if !f.holds(in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, tbl[pk]) {
		return nil, &types.ConditionalCheckFailedException{}
	}
	item := maps.Clone(tbl[pk])
	if item == nil {
		item = maps.Clone(in.Key)
	}
	item[in.ExpressionAttributeNames["#k"]] = in.ExpressionAttributeValues[":k"]
	tbl[pk] = item
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDynamo) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteItem"); err != nil {
		return nil, err
	}
	tbl := f.table(in.TableName)
	pk := sv(in.Key[attrPK])
	if !f.holds(in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, tbl[pk]) {
		return nil, &types.ConditionalCheckFailedException{}
	}
	delete(tbl, pk)
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("TransactWriteItems"); err != nil {
		return nil, err
	}
	if len(in.TransactItems) > 100 {
		f.t.Fatalf("transaction of %d items; DynamoDB allows 100", len(in.TransactItems))
	}
	if aws.ToString(in.ClientRequestToken) == "" {
		f.t.Error("a transaction without ClientRequestToken is not idempotent")
	}
	f.tokens = append(f.tokens, aws.ToString(in.ClientRequestToken))
	if f.raceNext {
		f.raceNext = false
		reasons := make([]types.CancellationReason, len(in.TransactItems))
		for i := range reasons {
			reasons[i].Code = aws.String("None")
		}
		reasons[len(reasons)-1].Code = aws.String("TransactionConflict")
		return nil, &types.TransactionCanceledException{CancellationReasons: reasons}
	}
	reasons := make([]types.CancellationReason, len(in.TransactItems))
	failed := false
	seen := map[string]bool{}
	for i, ti := range in.TransactItems {
		var tbl map[string]map[string]types.AttributeValue
		var pk string
		var ok bool
		switch {
		case ti.Put != nil:
			tbl, pk = f.table(ti.Put.TableName), sv(ti.Put.Item[attrPK])
			ok = f.holds(ti.Put.ConditionExpression, ti.Put.ExpressionAttributeNames, ti.Put.ExpressionAttributeValues, tbl[pk])
		case ti.Delete != nil:
			tbl, pk = f.table(ti.Delete.TableName), sv(ti.Delete.Key[attrPK])
			ok = f.holds(ti.Delete.ConditionExpression, ti.Delete.ExpressionAttributeNames, ti.Delete.ExpressionAttributeValues, tbl[pk])
		case ti.ConditionCheck != nil:
			tbl, pk = f.table(ti.ConditionCheck.TableName), sv(ti.ConditionCheck.Key[attrPK])
			ok = f.holds(ti.ConditionCheck.ConditionExpression, ti.ConditionCheck.ExpressionAttributeNames, ti.ConditionCheck.ExpressionAttributeValues, tbl[pk])
		default:
			f.t.Fatal("empty transaction item")
		}
		// DynamoDB refuses two operations on one item in a transaction.
		if seen[pk] {
			f.t.Fatalf("transaction touches %s twice", pk)
		}
		seen[pk] = true
		reasons[i].Code = aws.String("None")
		if !ok {
			reasons[i].Code = aws.String("ConditionalCheckFailed")
			failed = true
		}
	}
	if failed {
		return nil, &types.TransactionCanceledException{CancellationReasons: reasons}
	}
	for _, ti := range in.TransactItems {
		switch {
		case ti.Put != nil:
			f.table(ti.Put.TableName)[sv(ti.Put.Item[attrPK])] = maps.Clone(ti.Put.Item)
		case ti.Delete != nil:
			delete(f.table(ti.Delete.TableName), sv(ti.Delete.Key[attrPK]))
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("Query"); err != nil {
		return nil, err
	}
	if aws.ToString(in.IndexName) != ProfileIndex || aws.ToString(in.KeyConditionExpression) != "#p = :p" {
		f.t.Fatalf("query %q on %q", aws.ToString(in.KeyConditionExpression), aws.ToString(in.IndexName))
	}
	profile := sv(in.ExpressionAttributeValues[":p"])
	var pks []string
	for pk, item := range f.table(in.TableName) {
		if p, ok := item[attrProfile]; ok && sv(p) == profile {
			pks = append(pks, pk)
		}
	}
	slices.Sort(pks)
	if start := sv(in.ExclusiveStartKey[attrPK]); start != "" {
		i, _ := slices.BinarySearch(pks, start)
		for i < len(pks) && pks[i] <= start {
			i++
		}
		pks = pks[i:]
	}
	out := &dynamodb.QueryOutput{}
	limit := int(aws.ToInt32(in.Limit))
	if limit > 0 && len(pks) > limit {
		pks = pks[:limit]
		out.LastEvaluatedKey = map[string]types.AttributeValue{attrPK: str(pks[limit-1]), attrProfile: str(profile)}
	}
	for _, pk := range pks {
		out.Items = append(out.Items, map[string]types.AttributeValue{attrPK: str(pk), attrProfile: str(profile)})
	}
	return out, nil
}

func (f *fakeDynamo) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DescribeTable"); err != nil {
		return nil, err
	}
	f.table(in.TableName)
	return &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: f.status}}, nil
}
