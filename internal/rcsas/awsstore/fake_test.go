package awsstore

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
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
	switch aws.ToString(in.ConditionExpression) {
	case "attribute_not_exists(#pk)":
	case "attribute_not_exists(#pk) OR #expires <= :now":
		if exists && nOf(old[attrExpires]) <= nOf(in.ExpressionAttributeValues[":now"]) {
			exists = false
		}
	default:
		f.t.Errorf("PutItem condition %q", aws.ToString(in.ConditionExpression))
	}
	if exists {
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
	default:
		f.t.Errorf("UpdateItem %q if %q", upd, cond)
		return nil, errCondition
	}
}

func (f *fakeDynamo) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if aws.ToString(in.ConditionExpression) != "#owner = :owner" {
		f.t.Errorf("DeleteItem condition %q", aws.ToString(in.ConditionExpression))
	}
	k := rowKey(in.Key)
	row, ok := f.rows[k]
	if !ok || sOf(row[attrOwner]) != sOf(in.ExpressionAttributeValues[":owner"]) {
		return nil, errCondition
	}
	delete(f.rows, k)
	return &dynamodb.DeleteItemOutput{}, nil
}

// page returns rows in key order after start, pageSize at a time, keeping
// those keep accepts, as DynamoDB applies a filter after reading a page.
func (f *fakeDynamo) page(rows []map[string]dtypes.AttributeValue, start map[string]dtypes.AttributeValue,
	keep func(map[string]dtypes.AttributeValue) bool) ([]map[string]dtypes.AttributeValue, map[string]dtypes.AttributeValue) {
	slices.SortFunc(rows, func(a, b map[string]dtypes.AttributeValue) int { return cmp.Compare(rowKey(a), rowKey(b)) })
	i := 0
	if start != nil {
		i, _ = slices.BinarySearchFunc(rows, rowKey(start), func(r map[string]dtypes.AttributeValue, k string) int {
			return cmp.Compare(rowKey(r), k)
		})
		i++
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
	return items, map[string]dtypes.AttributeValue{attrPK: rows[end-1][attrPK], attrSK: rows[end-1][attrSK]}
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if !aws.ToBool(in.ConsistentRead) || !aws.ToBool(in.ScanIndexForward) {
		f.t.Error("Query must be consistent and in key order")
	}
	vals := in.ExpressionAttributeValues
	after, bounded := vals[":after"]
	key := "#pk = :pk"
	if bounded {
		key += " AND #sk > :after"
	}
	if aws.ToString(in.KeyConditionExpression) != key || aws.ToString(in.FilterExpression) != freeAt+" AND #expires > :now" {
		f.t.Errorf("Query %q filter %q", aws.ToString(in.KeyConditionExpression), aws.ToString(in.FilterExpression))
	}
	var rows []map[string]dtypes.AttributeValue
	for _, r := range f.rows {
		if sOf(r[attrPK]) == sOf(vals[":pk"]) && (!bounded || sOf(r[attrSK]) > sOf(after)) {
			rows = append(rows, r)
		}
	}
	items, last := f.page(rows, in.ExclusiveStartKey, func(r map[string]dtypes.AttributeValue) bool {
		return free(r, vals[":now"]) && nOf(r[attrExpires]) > nOf(vals[":now"])
	})
	return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
}

func (f *fakeDynamo) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if aws.ToString(in.FilterExpression) != "begins_with(#pk, :q) AND #expires <= :now AND "+freeAt || !aws.ToBool(in.ConsistentRead) {
		f.t.Errorf("Scan filter %q", aws.ToString(in.FilterExpression))
	}
	vals := in.ExpressionAttributeValues
	items, last := f.page(slices.Collect(maps.Values(f.rows)), in.ExclusiveStartKey, func(r map[string]dtypes.AttributeValue) bool {
		return strings.HasPrefix(sOf(r[attrPK]), sOf(vals[":q"])) && nOf(r[attrExpires]) <= nOf(vals[":now"]) && free(r, vals[":now"])
	})
	return &dynamodb.ScanOutput{Items: items, LastEvaluatedKey: last}, nil
}

func (f *fakeDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &dynamodb.DescribeTableOutput{Table: &dtypes.TableDescription{TableStatus: f.status}}, nil
}
