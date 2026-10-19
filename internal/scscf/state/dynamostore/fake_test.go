package dynamostore

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// fakeDynamo implements the DynamoDB semantics this package relies on, for
// exactly the expressions it sends: an expression it does not know fails the
// test, so a change to one cannot pass here unnoticed. The integration test
// runs the same contract against DynamoDB Local.
type fakeDynamo struct {
	t      *testing.T
	mu     sync.Mutex
	tables map[string]map[string]map[string]types.AttributeValue
	// afterUpdate, if set, runs after every UpdateItem, outside the lock, as
	// another instance's write between that request and the next would.
	afterUpdate func()
	// resendNext applies the next write twice, as the SDK does when the
	// response to the first attempt is lost, and answers with the second
	// attempt's outcome.
	resendNext bool
	// fail, when set, is returned by every call.
	fail error
}

func newFakeDynamo(t *testing.T, tables ...string) *fakeDynamo {
	f := &fakeDynamo{t: t, tables: map[string]map[string]map[string]types.AttributeValue{}}
	for _, name := range tables {
		f.tables[name] = map[string]map[string]types.AttributeValue{}
	}
	return f
}

func (f *fakeDynamo) table(name *string) map[string]map[string]types.AttributeValue {
	tbl, ok := f.tables[aws.ToString(name)]
	if !ok {
		f.t.Fatalf("unknown table %q", aws.ToString(name))
	}
	return tbl
}

func itemKey(k map[string]types.AttributeValue) string {
	return sv(k[attrPK]) + "\x00" + sv(k[attrSK])
}

func keyOf(item map[string]types.AttributeValue) map[string]types.AttributeValue {
	k := map[string]types.AttributeValue{attrPK: item[attrPK]}
	if sk, ok := item[attrSK]; ok {
		k[attrSK] = sk
	}
	return k
}

func number(v types.AttributeValue) int64 {
	n, _ := strconv.ParseInt(sv(v), 10, 64)
	return n
}

// holds evaluates one of the package's condition expressions against the
// current item (nil when absent).
func (f *fakeDynamo) holds(expr *string, names map[string]string, values map[string]types.AttributeValue, cur map[string]types.AttributeValue) bool {
	switch aws.ToString(expr) {
	case "":
		return true
	case "attribute_not_exists(#pk)":
		return cur == nil
	case "attribute_not_exists(#pk) OR #rcv <= :rcv":
		return cur == nil || number(cur[names["#rcv"]]) <= number(values[":rcv"])
	case "#v = :v":
		return cur != nil && sv(cur[names["#v"]]) == sv(values[":v"])
	case "attribute_exists(#pk) AND #ttl > :now AND #ttl < :until":
		return cur != nil && number(cur[names["#ttl"]]) > number(values[":now"]) && number(cur[names["#ttl"]]) < number(values[":until"])
	case "attribute_exists(#pk) AND #exp > :now":
		return cur != nil && number(cur[names["#exp"]]) > number(values[":now"])
	case "attribute_exists(#pk) AND (attribute_not_exists(#tok) OR #tok <> :tok) AND #cseq < :max AND #rver < :max":
		if cur == nil {
			return false
		}
		tok, ok := cur[names["#tok"]]
		max := number(values[":max"])
		return (!ok || sv(tok) != sv(values[":tok"])) && number(cur[names["#cseq"]]) < max && number(cur[names["#rver"]]) < max
	}
	f.t.Fatalf("fakeDynamo: unknown condition %q", aws.ToString(expr))
	return false
}

// checkKey refuses keys as DynamoDB does: an empty key attribute, or one over
// 2048 bytes for a partition key and 1024 for a sort key.
func checkKey(k map[string]types.AttributeValue) error {
	pk, sk := sv(k[attrPK]), k[attrSK]
	if pk == "" || len(pk) > 2048 || sk != nil && (sv(sk) == "" || len(sv(sk)) > 1024) {
		return &smithy.GenericAPIError{Code: "ValidationException", Message: "invalid key"}
	}
	return nil
}

// checkIndexKeys refuses an item whose index key attributes are empty strings.
func checkIndexKeys(item map[string]types.AttributeValue) error {
	for _, a := range []string{attrIMPI, attrIMPU, attrShard} {
		if v, ok := item[a]; ok && sv(v) == "" {
			return &smithy.GenericAPIError{Code: "ValidationException", Message: "empty index key"}
		}
	}
	if itemSize(item) > 400<<10 {
		return &smithy.GenericAPIError{Code: "ValidationException", Message: "item size exceeded"}
	}
	return nil
}

func conditionFailed() error {
	return &types.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
}

// write runs op once, or twice when a resend is due.
func (f *fakeDynamo) write(op func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	err := op()
	if f.resendNext {
		f.resendNext = false
		err = op()
	}
	return err
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if !aws.ToBool(in.ConsistentRead) {
		f.t.Fatal("fakeDynamo: every read must be strongly consistent")
	}
	if err := checkKey(in.Key); err != nil {
		return nil, err
	}
	return &dynamodb.GetItemOutput{Item: maps.Clone(f.table(in.TableName)[itemKey(in.Key)])}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if err := checkKey(keyOf(in.Item)); err != nil {
		return nil, err
	}
	if err := checkIndexKeys(in.Item); err != nil {
		return nil, err
	}
	err := f.write(func() error {
		tbl := f.table(in.TableName)
		k := itemKey(keyOf(in.Item))
		if !f.holds(in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, tbl[k]) {
			return conditionFailed()
		}
		tbl[k] = maps.Clone(in.Item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if err := checkKey(in.Key); err != nil {
		return nil, err
	}
	var old map[string]types.AttributeValue
	err := f.write(func() error {
		tbl := f.table(in.TableName)
		k := itemKey(in.Key)
		if !f.holds(in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, tbl[k]) {
			return conditionFailed()
		}
		old = tbl[k]
		delete(tbl, k)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &dynamodb.DeleteItemOutput{}
	if in.ReturnValues == types.ReturnValueAllOld {
		out.Attributes = old
	}
	return out, nil
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	n, v := in.ExpressionAttributeNames, in.ExpressionAttributeValues
	var update func(cur map[string]types.AttributeValue) map[string]types.AttributeValue
	switch aws.ToString(in.UpdateExpression) {
	case "SET #tok = :tok, #v = #v + :one ADD #cseq :one, #rver :one":
		if in.ReturnValues != types.ReturnValueAllNew {
			f.t.Fatal("fakeDynamo: NextNotify must ask for the new values")
		}
		update = func(cur map[string]types.AttributeValue) map[string]types.AttributeValue {
			next := maps.Clone(cur)
			next[n["#tok"]] = v[":tok"]
			for _, a := range []string{"#v", "#cseq", "#rver"} {
				next[n[a]] = num(number(cur[n[a]]) + 1)
			}
			return next
		}
	case "SET #ttl = :until":
		update = func(cur map[string]types.AttributeValue) map[string]types.AttributeValue {
			next := maps.Clone(cur)
			next[n["#ttl"]] = v[":until"]
			return next
		}
	default:
		f.t.Fatalf("fakeDynamo: unknown update %q", aws.ToString(in.UpdateExpression))
	}
	if err := checkKey(in.Key); err != nil {
		return nil, err
	}
	if f.afterUpdate != nil {
		defer f.afterUpdate()
	}
	var updated map[string]types.AttributeValue
	err := f.write(func() error {
		tbl := f.table(in.TableName)
		k := itemKey(in.Key)
		cur := tbl[k]
		if !f.holds(in.ConditionExpression, n, v, cur) {
			return conditionFailed()
		}
		next := update(cur)
		tbl[k] = next
		updated = maps.Clone(next)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if in.ReturnValues != types.ReturnValueAllNew {
		return &dynamodb.UpdateItemOutput{}, nil
	}
	return &dynamodb.UpdateItemOutput{Attributes: updated}, nil
}

// Query serves the package's two index queries in pages of at most Limit
// keys, ordered as DynamoDB orders them (by sort key, then by table key).
func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	n, v := in.ExpressionAttributeNames, in.ExpressionAttributeValues
	var match func(map[string]types.AttributeValue) bool
	switch aws.ToString(in.KeyConditionExpression) {
	case "#shard = :shard AND #exp <= :now":
		if aws.ToString(in.IndexName) != ExpiryIndex {
			f.t.Fatalf("fakeDynamo: expiry query on %q", aws.ToString(in.IndexName))
		}
		match = func(item map[string]types.AttributeValue) bool {
			e, ok := item[n["#exp"]]
			return ok && sv(item[n["#shard"]]) == sv(v[":shard"]) && number(e) <= number(v[":now"])
		}
	case "#a = :a":
		if idx := aws.ToString(in.IndexName); idx != IMPIIndex && idx != IMPUIndex {
			f.t.Fatalf("fakeDynamo: equality query on %q", idx)
		}
		match = func(item map[string]types.AttributeValue) bool {
			a, ok := item[n["#a"]]
			return ok && sv(a) == sv(v[":a"])
		}
	default:
		f.t.Fatalf("fakeDynamo: unknown key condition %q", aws.ToString(in.KeyConditionExpression))
	}
	var keys []map[string]types.AttributeValue
	for _, item := range f.table(in.TableName) {
		if match(item) {
			k := keyOf(item)
			if e, ok := item[attrExpires]; ok {
				k[attrExpires] = e
			}
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b map[string]types.AttributeValue) int {
		if d := number(a[attrExpires]) - number(b[attrExpires]); d != 0 {
			return int(d)
		}
		return compare(itemKey(a), itemKey(b))
	})
	if in.ExclusiveStartKey != nil {
		after := itemKey(in.ExclusiveStartKey)
		i := slices.IndexFunc(keys, func(k map[string]types.AttributeValue) bool { return itemKey(k) == after })
		keys = keys[i+1:]
	}
	out := &dynamodb.QueryOutput{Items: keys}
	if l := int(aws.ToInt32(in.Limit)); l > 0 && len(keys) > l {
		out.Items = keys[:l]
		out.LastEvaluatedKey = keys[l-1]
	}
	return out, nil
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (f *fakeDynamo) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if _, ok := f.tables[aws.ToString(in.TableName)]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("no table")}
	}
	return &dynamodb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: types.TableStatusActive}}, nil
}

var errFake = errors.New("fake failure")
