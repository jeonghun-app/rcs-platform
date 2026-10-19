package awsstore

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// fakeDynamo implements the semantics the store relies on, for exactly the
// expressions it sends: an expression it does not know fails the test, so a
// change to one cannot pass here unnoticed. The integration test runs the
// same contract against DynamoDB Local.
type fakeDynamo struct {
	t        *testing.T
	mu       sync.Mutex
	rows     map[string]map[string]dtypes.AttributeValue
	fail     error
	pageSize int
	status   dtypes.TableStatus
	// queries counts Query calls on the expiry index.
	indexQueries int
}

func newFakeDynamo(t *testing.T) *fakeDynamo {
	return &fakeDynamo{t: t, rows: map[string]map[string]dtypes.AttributeValue{}, pageSize: 2, status: dtypes.TableStatusActive}
}

func sOf(v dtypes.AttributeValue) string {
	if s, ok := v.(*dtypes.AttributeValueMemberS); ok {
		return s.Value
	}
	return ""
}

func nOf(v dtypes.AttributeValue) int64 {
	n, _ := v.(*dtypes.AttributeValueMemberN)
	if n == nil {
		return 0
	}
	i, _ := strconv.ParseInt(n.Value, 10, 64)
	return i
}

func rowKey(item map[string]dtypes.AttributeValue) string {
	return sOf(item[attrPK]) + "\x00" + sOf(item[attrSK])
}

var errCondition = &smithy.GenericAPIError{Code: "ConditionalCheckFailedException", Message: "The conditional request failed"}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if !aws.ToBool(in.ConsistentRead) {
		f.t.Error("GetItem without ConsistentRead")
	}
	return &dynamodb.GetItemOutput{Item: maps.Clone(f.rows[rowKey(in.Key)])}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	k := rowKey(in.Item)
	old, exists := f.rows[k]
	if aws.ToString(in.ConditionExpression) != "attribute_not_exists(#pk) OR #expires <= :now" {
		f.t.Errorf("PutItem condition %q", aws.ToString(in.ConditionExpression))
	}
	if exists && nOf(old[attrExpires]) > nOf(in.ExpressionAttributeValues[":now"]) {
		return nil, errCondition
	}
	f.rows[k] = maps.Clone(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

// free evaluates freeAt.
func free(row map[string]dtypes.AttributeValue, now dtypes.AttributeValue) bool {
	_, held := row[attrOwner]
	return !held || nOf(row[attrLease]) <= nOf(now)
}

func seen(row map[string]dtypes.AttributeValue) map[string]dtypes.AttributeValue {
	m, _ := row[attrSeen].(*dtypes.AttributeValueMemberM)
	if m == nil {
		return nil
	}
	return m.Value
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	k := rowKey(in.Key)
	row, exists := f.rows[k]
	vals := in.ExpressionAttributeValues
	switch cond, upd := aws.ToString(in.ConditionExpression), aws.ToString(in.UpdateExpression); {
	case cond == "attribute_exists(#pk) AND "+freeAt && upd == "SET #owner = :owner, #lease = :until":
		if !exists || !free(row, vals[":now"]) {
			return nil, errCondition
		}
		row[attrOwner], row[attrLease] = vals[":owner"], vals[":until"]
		if in.ReturnValues != dtypes.ReturnValueAllNew {
			f.t.Error("claim without ReturnValues ALL_NEW")
		}
		return &dynamodb.UpdateItemOutput{Attributes: maps.Clone(row)}, nil
	case cond == "#owner = :owner" && upd == "REMOVE #owner, #lease":
		if !exists || sOf(row[attrOwner]) != sOf(vals[":owner"]) {
			return nil, errCondition
		}
		delete(row, attrOwner)
		delete(row, attrLease)
		return &dynamodb.UpdateItemOutput{}, nil
	case cond == "#expires > :now AND (attribute_not_exists(#seen.#k) OR #seen.#k = :token)" && upd == "SET #seen.#k = :token":
		mark := in.ExpressionAttributeNames["#k"]
		if !exists || nOf(row[attrExpires]) <= nOf(vals[":now"]) {
			return nil, errCondition
		}
		if t, ok := seen(row)[mark]; ok && sOf(t) != sOf(vals[":token"]) {
			return nil, errCondition
		}
		seen(row)[mark] = vals[":token"]
		return &dynamodb.UpdateItemOutput{}, nil
	case cond == "#seen.#k = :token" && upd == "REMOVE #seen.#k":
		mark := in.ExpressionAttributeNames["#k"]
		if t, ok := seen(row)[mark]; !exists || !ok || sOf(t) != sOf(vals[":token"]) {
			return nil, errCondition
		}
		delete(seen(row), mark)
		return &dynamodb.UpdateItemOutput{}, nil
	default:
		f.t.Errorf("UpdateItem %q if %q", upd, cond)
		return nil, errCondition
	}
}

func cancelled(failed ...bool) error {
	reasons := make([]dtypes.CancellationReason, len(failed))
	for i, x := range failed {
		code := "None"
		if x {
			code = "ConditionalCheckFailed"
		}
		reasons[i] = dtypes.CancellationReason{Code: aws.String(code)}
	}
	return &dtypes.TransactionCanceledException{Message: aws.String("Transaction cancelled"), CancellationReasons: reasons}
}

// TransactWriteItems knows the two transactions the store sends: enqueue
// (put the message, add to its queue's size) and remove (delete the
// message, take it off the size).
func (f *fakeDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if len(in.TransactItems) != 2 || in.TransactItems[1].Update == nil {
		f.t.Fatalf("transaction %+v", in.TransactItems)
	}
	size := in.TransactItems[1].Update
	sizeRow := f.rows[rowKey(size.Key)]
	vals := size.ExpressionAttributeValues
	switch first := in.TransactItems[0]; {
	case first.Put != nil:
		if aws.ToString(first.Put.ConditionExpression) != "attribute_not_exists(#pk)" ||
			aws.ToString(size.UpdateExpression) != "ADD #count :one, #bytes :size SET #ttl = :ttl" {
			f.t.Errorf("enqueue %q, %q", aws.ToString(first.Put.ConditionExpression), aws.ToString(size.UpdateExpression))
		}
		_, exists := f.rows[rowKey(first.Put.Item)]
		full := false
		if cond := aws.ToString(size.ConditionExpression); cond != "" && sizeRow != nil {
			want := map[string]bool{
				"attribute_not_exists(#count) OR (#count < :maxCount)":                     true,
				"attribute_not_exists(#count) OR (#bytes <= :room)":                        true,
				"attribute_not_exists(#count) OR (#count < :maxCount AND #bytes <= :room)": true,
			}
			if !want[cond] {
				f.t.Errorf("size condition %q", cond)
			}
			if c, ok := vals[":maxCount"]; ok && nOf(sizeRow[attrCount]) >= nOf(c) {
				full = true
			}
			if r, ok := vals[":room"]; ok && nOf(sizeRow[attrBytes]) > nOf(r) {
				full = true
			}
		}
		if exists || full {
			return nil, cancelled(exists, full)
		}
		f.rows[rowKey(first.Put.Item)] = maps.Clone(first.Put.Item)
		f.add(size.Key, vals[":one"], vals[":size"])
		f.rows[rowKey(size.Key)][attrTTL] = vals[":ttl"]
	case first.Delete != nil:
		if aws.ToString(first.Delete.ConditionExpression) != "#owner = :owner" ||
			aws.ToString(size.UpdateExpression) != "ADD #count :minus, #bytes :size" {
			f.t.Errorf("remove %q, %q", aws.ToString(first.Delete.ConditionExpression), aws.ToString(size.UpdateExpression))
		}
		row, ok := f.rows[rowKey(first.Delete.Key)]
		if !ok || sOf(row[attrOwner]) != sOf(first.Delete.ExpressionAttributeValues[":owner"]) {
			return nil, cancelled(true, false)
		}
		delete(f.rows, rowKey(first.Delete.Key))
		f.add(size.Key, vals[":minus"], vals[":size"])
	default:
		f.t.Fatalf("transaction %+v", in.TransactItems)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

// add needs f.mu.
func (f *fakeDynamo) add(k map[string]dtypes.AttributeValue, count, bytes dtypes.AttributeValue) {
	row := f.rows[rowKey(k)]
	if row == nil {
		row = maps.Clone(k)
		f.rows[rowKey(k)] = row
	}
	row[attrCount] = num(nOf(row[attrCount]) + nOf(count))
	row[attrBytes] = num(nOf(row[attrBytes]) + nOf(bytes))
}

// page returns rows in order after start, pageSize at a time, keeping
// those keep accepts, as DynamoDB applies a filter after reading a page.
func (f *fakeDynamo) page(rows []map[string]dtypes.AttributeValue, order func(map[string]dtypes.AttributeValue) string,
	start map[string]dtypes.AttributeValue, keep func(map[string]dtypes.AttributeValue) bool,
	keyOf func(map[string]dtypes.AttributeValue) map[string]dtypes.AttributeValue) ([]map[string]dtypes.AttributeValue, map[string]dtypes.AttributeValue) {
	slices.SortFunc(rows, func(a, b map[string]dtypes.AttributeValue) int { return cmp.Compare(order(a), order(b)) })
	i := 0
	if start != nil {
		i, _ = slices.BinarySearchFunc(rows, order(start), func(r map[string]dtypes.AttributeValue, k string) int {
			return cmp.Compare(order(r), k)
		})
		if i < len(rows) && order(rows[i]) == order(start) {
			i++
		}
	}
	end := min(i+f.pageSize, len(rows))
	var items []map[string]dtypes.AttributeValue
	for _, r := range rows[i:end] {
		if keep(r) {
			items = append(items, maps.Clone(r))
		}
	}
	if end == len(rows) {
		return items, nil
	}
	return items, keyOf(rows[end-1])
}

func tableKey(r map[string]dtypes.AttributeValue) map[string]dtypes.AttributeValue {
	return map[string]dtypes.AttributeValue{attrPK: r[attrPK], attrSK: r[attrSK]}
}

func indexKey(r map[string]dtypes.AttributeValue) map[string]dtypes.AttributeValue {
	return map[string]dtypes.AttributeValue{attrPK: r[attrPK], attrSK: r[attrSK], attrBucket: r[attrBucket], attrExpires: r[attrExpires]}
}

// indexOrder sorts the expiry index: by expiry, then table key.
func indexOrder(r map[string]dtypes.AttributeValue) string {
	return strconv.FormatInt(1e18+nOf(r[attrExpires]), 10) + "\x00" + rowKey(r)
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	vals := in.ExpressionAttributeValues
	if aws.ToString(in.IndexName) == IndexExpiry {
		f.indexQueries++
		if in.ConsistentRead != nil || aws.ToString(in.KeyConditionExpression) != "#xb = :b AND #expires <= :now" || aws.ToString(in.FilterExpression) != freeAt {
			f.t.Errorf("index query %q filter %q", aws.ToString(in.KeyConditionExpression), aws.ToString(in.FilterExpression))
		}
		var rows []map[string]dtypes.AttributeValue
		for _, r := range f.rows {
			if _, ok := r[attrBucket]; ok && sOf(r[attrBucket]) == sOf(vals[":b"]) && nOf(r[attrExpires]) <= nOf(vals[":now"]) {
				// The index projects keys, owner and lease only.
				p := indexKey(r)
				for _, a := range []string{attrOwner, attrLease} {
					if v, ok := r[a]; ok {
						p[a] = v
					}
				}
				rows = append(rows, p)
			}
		}
		items, last := f.page(rows, indexOrder, in.ExclusiveStartKey, func(r map[string]dtypes.AttributeValue) bool { return free(r, vals[":now"]) }, indexKey)
		return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
	}
	if !aws.ToBool(in.ConsistentRead) || !aws.ToBool(in.ScanIndexForward) {
		f.t.Error("Query must be consistent and in key order")
	}
	after, bounded := vals[":after"]
	keyCond := "#pk = :pk"
	if bounded {
		keyCond += " AND #sk > :after"
	}
	if aws.ToString(in.KeyConditionExpression) != keyCond || aws.ToString(in.FilterExpression) != freeAt+" AND #expires > :now" {
		f.t.Errorf("Query %q filter %q", aws.ToString(in.KeyConditionExpression), aws.ToString(in.FilterExpression))
	}
	var rows []map[string]dtypes.AttributeValue
	for _, r := range f.rows {
		if sOf(r[attrPK]) == sOf(vals[":pk"]) && (!bounded || sOf(r[attrSK]) > sOf(after)) {
			rows = append(rows, r)
		}
	}
	items, last := f.page(rows, rowKey, in.ExclusiveStartKey, func(r map[string]dtypes.AttributeValue) bool {
		return free(r, vals[":now"]) && nOf(r[attrExpires]) > nOf(vals[":now"])
	}, tableKey)
	return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
}

func (f *fakeDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &dynamodb.DescribeTableOutput{Table: &dtypes.TableDescription{TableStatus: f.status}}, nil
}
