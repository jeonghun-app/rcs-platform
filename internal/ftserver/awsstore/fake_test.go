package awsstore

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	stypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// The fakes implement the semantics this package relies on, for exactly
// the expressions it sends: an expression they do not know fails the test,
// so a change to one cannot pass here unnoticed. The integration test runs
// the same contract against S3 and DynamoDB containers.

type fakeDynamo struct {
	t    *testing.T
	mu   sync.Mutex
	rows map[string]map[string]dtypes.AttributeValue
	fail error
	// pageSize makes Scan return pages this small, to exercise paging.
	pageSize int
	status   dtypes.TableStatus
}

func newFakeDynamo(t *testing.T) *fakeDynamo {
	return &fakeDynamo{t: t, rows: map[string]map[string]dtypes.AttributeValue{}, pageSize: 2, status: dtypes.TableStatusActive}
}

func pkOf(item map[string]dtypes.AttributeValue) string {
	return item[attrPK].(*dtypes.AttributeValueMemberS).Value
}

func n(v dtypes.AttributeValue) int64 {
	i, _ := strconv.ParseInt(v.(*dtypes.AttributeValueMemberN).Value, 10, 64)
	return i
}

func s(v dtypes.AttributeValue) string {
	if v == nil {
		return ""
	}
	return v.(*dtypes.AttributeValueMemberS).Value
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if !aws.ToBool(in.ConsistentRead) {
		f.t.Error("GetItem without ConsistentRead")
	}
	return &dynamodb.GetItemOutput{Item: maps.Clone(f.rows[pkOf(in.Key)])}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if got := aws.ToString(in.ConditionExpression); got != "#v = :v AND #o = :o AND #t = :t" {
		f.t.Fatalf("PutItem condition %q", got)
	}
	cur, ok := f.rows[pkOf(in.Item)]
	v := in.ExpressionAttributeValues
	if !ok || n(cur[attrVersion]) != n(v[":v"]) || s(cur[attrOwner]) != s(v[":o"]) || s(cur[attrTID]) != s(v[":t"]) {
		return nil, &dtypes.ConditionalCheckFailedException{}
	}
	f.rows[pkOf(in.Item)] = maps.Clone(in.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	reasons := make([]dtypes.CancellationReason, len(in.TransactItems))
	failed := false
	for i, ti := range in.TransactItems {
		if got := aws.ToString(ti.Put.ConditionExpression); got != "attribute_not_exists(#pk)" {
			f.t.Fatalf("transaction condition %q", got)
		}
		reasons[i].Code = aws.String("None")
		if _, exists := f.rows[pkOf(ti.Put.Item)]; exists {
			reasons[i].Code = aws.String("ConditionalCheckFailed")
			failed = true
		}
	}
	if failed {
		return nil, &dtypes.TransactionCanceledException{CancellationReasons: reasons}
	}
	for _, ti := range in.TransactItems {
		f.rows[pkOf(ti.Put.Item)] = maps.Clone(ti.Put.Item)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if aws.ToString(in.ConditionExpression) != "attribute_not_exists(#nc) OR #nc < :nc OR #e < :now" ||
		aws.ToString(in.UpdateExpression) != "SET #nc = :nc, #e = :e, #ttl = :ttl" {
		f.t.Fatalf("UpdateItem %q %q", aws.ToString(in.ConditionExpression), aws.ToString(in.UpdateExpression))
	}
	pk := pkOf(in.Key)
	v := in.ExpressionAttributeValues
	cur, ok := f.rows[pk]
	if ok && n(cur[attrNC]) >= n(v[":nc"]) && n(cur[attrExpires]) >= n(v[":now"]) {
		return nil, &dtypes.ConditionalCheckFailedException{}
	}
	f.rows[pk] = map[string]dtypes.AttributeValue{attrPK: in.Key[attrPK], attrNC: v[":nc"], attrExpires: v[":e"], attrTTL: v[":ttl"]}
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDynamo) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if in.ConsistentRead != nil {
		f.t.Error("the sweeper's Scan asks for strong consistency, at twice the cost")
	}
	if got := aws.ToString(in.FilterExpression); got != "begins_with(#pk, :f) AND #e < :now AND #s <> :expired" {
		f.t.Fatalf("Scan filter %q", got)
	}
	v := in.ExpressionAttributeValues
	keys := slices.Sorted(maps.Keys(f.rows))
	if in.ExclusiveStartKey != nil {
		i, _ := slices.BinarySearch(keys, pkOf(in.ExclusiveStartKey))
		keys = keys[i+1:]
	}
	out := &dynamodb.ScanOutput{}
	for i, k := range keys {
		if i == f.pageSize {
			out.LastEvaluatedKey = map[string]dtypes.AttributeValue{attrPK: &dtypes.AttributeValueMemberS{Value: keys[i-1]}}
			break
		}
		row := f.rows[k]
		if strings.HasPrefix(k, s(v[":f"])) && n(row[attrExpires]) < n(v[":now"]) && s(row[attrState]) != s(v[":expired"]) {
			out.Items = append(out.Items, maps.Clone(row))
		}
	}
	return out, nil
}

func (f *fakeDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &dynamodb.DescribeTableOutput{Table: &dtypes.TableDescription{TableStatus: f.status}}, nil
}

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]map[int32][]byte
	next    int
	fail    error
	// sse records the encryption asked for on every object and upload.
	sse []string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}, uploads: map[string]map[int32][]byte{}}
}

func crcOf(b []byte) string {
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(b))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func etagOf(b []byte) string {
	sum := md5.Sum(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	body, _ := io.ReadAll(in.Body)
	f.objects[aws.ToString(in.Key)] = body
	f.sse = append(f.sse, string(in.ServerSideEncryption)+"/"+aws.ToString(in.SSEKMSKeyId))
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) CreateMultipartUpload(_ context.Context, in *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if in.ChecksumAlgorithm != stypes.ChecksumAlgorithmCrc32 {
		return nil, &fakeAPIError{code: "InvalidRequest"}
	}
	f.next++
	id := aws.ToString(in.Key) + "#" + strconv.Itoa(f.next)
	f.uploads[id] = map[int32][]byte{}
	f.sse = append(f.sse, string(in.ServerSideEncryption)+"/"+aws.ToString(in.SSEKMSKeyId))
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String(id)}, nil
}

func (f *fakeS3) upload(key, id string) (map[int32][]byte, error) {
	u, ok := f.uploads[id]
	if !ok || !strings.HasPrefix(id, key+"#") {
		return nil, &stypes.NoSuchUpload{}
	}
	return u, nil
}

func (f *fakeS3) UploadPart(_ context.Context, in *s3.UploadPartInput, _ ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	u, err := f.upload(aws.ToString(in.Key), aws.ToString(in.UploadId))
	if err != nil {
		return nil, err
	}
	if in.ChecksumAlgorithm != stypes.ChecksumAlgorithmCrc32 {
		return nil, &fakeAPIError{code: "InvalidRequest"}
	}
	body, _ := io.ReadAll(in.Body)
	u[aws.ToInt32(in.PartNumber)] = body
	return &s3.UploadPartOutput{ETag: aws.String(etagOf(body)), ChecksumCRC32: aws.String(crcOf(body))}, nil
}

func (f *fakeS3) CompleteMultipartUpload(_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	u, err := f.upload(aws.ToString(in.Key), aws.ToString(in.UploadId))
	if err != nil {
		return nil, err
	}
	var obj []byte
	for _, p := range in.MultipartUpload.Parts {
		data, ok := u[aws.ToInt32(p.PartNumber)]
		// An upload created with CRC32 needs every part's checksum back.
		if !ok || etagOf(data) != aws.ToString(p.ETag) || aws.ToString(p.ChecksumCRC32) != crcOf(data) {
			return nil, &fakeAPIError{code: "InvalidPart"}
		}
		obj = append(obj, data...)
	}
	f.objects[aws.ToString(in.Key)] = obj
	delete(f.uploads, aws.ToString(in.UploadId))
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (f *fakeS3) AbortMultipartUpload(_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	if _, err := f.upload(aws.ToString(in.Key), aws.ToString(in.UploadId)); err != nil {
		return nil, err
	}
	delete(f.uploads, aws.ToString(in.UploadId))
	return &s3.AbortMultipartUploadOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	obj, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, &stypes.NoSuchKey{}
	}
	var first, last int
	if _, err := fmt.Sscanf(aws.ToString(in.Range), "bytes=%d-%d", &first, &last); err != nil || last >= len(obj) {
		return nil, &fakeAPIError{code: "InvalidRange"}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(obj[first : last+1]))}, nil
}

func (f *fakeS3) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &s3.HeadBucketOutput{}, nil
}

type fakeAPIError struct{ code string }

func (e *fakeAPIError) Error() string {
	return "api error " + e.code + ": https://bucket.s3.example/key-that-is-secret"
}
func (e *fakeAPIError) ErrorCode() string             { return e.code }
func (e *fakeAPIError) ErrorMessage() string          { return e.Error() }
func (e *fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }
