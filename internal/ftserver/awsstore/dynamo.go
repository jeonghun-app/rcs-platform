package awsstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// DynamoAPI is the part of the DynamoDB client the stores use;
// *dynamodb.Client has it.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// retention is how long an item outlives its validity before DynamoDB's TTL
// deletes it: long enough for an operator to look into a transfer after the
// fact, short enough that the table does not grow without bound.
const retention = 30 * 24 * time.Hour

// Attribute names of the items.
const (
	attrPK         = "pk"
	attrTTL        = "ttl"
	attrID         = "id"
	attrOwner      = "owner"
	attrTID        = "tid"
	attrState      = "state"
	attrName       = "file_name"
	attrType       = "content_type"
	attrDeclared   = "declared_size"
	attrReceived   = "received"
	attrSize       = "size"
	attrSHA256     = "sha256"
	attrHashState  = "hash_state"
	attrMultipart  = "multipart_id"
	attrParts      = "parts"
	attrThumbSize  = "thumbnail_size"
	attrThumbType  = "thumbnail_type"
	attrCreated    = "created"
	attrCompleted  = "completed"
	attrExpires    = "expires"
	attrLease      = "lease"
	attrLeaseUntil = "lease_until"
	attrVersion    = "version"
	attrNC         = "nc"
)

func fileKey(id string) string { return "f#" + id }

func tidKey(owner, tid string) string {
	return "t#" + strconv.Itoa(len(owner)) + "#" + owner + tid
}

func nonceKey(user, nonce string) string {
	return "n#" + strconv.Itoa(len(user)) + "#" + user + nonce
}

func key(pk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(pk)}
}

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

// ttlOf is the DynamoDB TTL, in epoch seconds, of an item valid until t.
func ttlOf(t time.Time) types.AttributeValue { return num(t.Add(retention).Unix()) }

// Metadata is a store.Metadata in the DynamoDB files table. Reads are
// strongly consistent; writes are conditional on the version read.
type Metadata struct {
	api   DynamoAPI
	table string
}

var _ store.Metadata = (*Metadata)(nil)

// Create implements store.Metadata: the record and its tid item in one
// transaction, each conditional on not existing.
func (m *Metadata) Create(ctx context.Context, r store.Record) (store.Record, error) {
	r = r.Clone()
	r.Version = 1
	notExists := aws.String("attribute_not_exists(#pk)")
	names := map[string]string{"#pk": attrPK}
	_, err := m.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: aws.String(m.table),
				Item: map[string]types.AttributeValue{
					attrPK:  str(tidKey(r.Owner, r.TID)),
					attrID:  str(r.ID),
					attrTTL: ttlOf(r.Expires),
				},
				ConditionExpression:      notExists,
				ExpressionAttributeNames: names,
			}},
			{Put: &types.Put{
				TableName:                aws.String(m.table),
				Item:                     encodeRecord(r),
				ConditionExpression:      notExists,
				ExpressionAttributeNames: names,
			}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		for _, reason := range canceled.CancellationReasons {
			if aws.ToString(reason.Code) == "ConditionalCheckFailed" {
				return store.Record{}, fmt.Errorf("awsstore: create record: %w", store.ErrExists)
			}
		}
	}
	if err != nil {
		return store.Record{}, sanitize("create record", err)
	}
	return r, nil
}

// Get implements store.Metadata.
func (m *Metadata) Get(ctx context.Context, id string) (store.Record, error) {
	item, err := m.get(ctx, fileKey(id))
	if err != nil {
		return store.Record{}, err
	}
	return decodeRecord(item)
}

// GetByTID implements store.Metadata.
func (m *Metadata) GetByTID(ctx context.Context, owner, tid string) (store.Record, error) {
	item, err := m.get(ctx, tidKey(owner, tid))
	if err != nil {
		return store.Record{}, err
	}
	id, ok := item[attrID].(*types.AttributeValueMemberS)
	if !ok {
		return store.Record{}, errors.New("awsstore: tid item without a file id")
	}
	r, err := m.Get(ctx, id.Value)
	if err != nil {
		return store.Record{}, err
	}
	if r.Owner != owner || r.TID != tid {
		return store.Record{}, errors.New("awsstore: tid item points at another owner's record")
	}
	return r, nil
}

func (m *Metadata) get(ctx context.Context, pk string) (map[string]types.AttributeValue, error) {
	out, err := m.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(m.table),
		Key:            key(pk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, sanitize("get item", err)
	}
	if len(out.Item) == 0 {
		return nil, fmt.Errorf("awsstore: get item: %w", store.ErrNotFound)
	}
	return out.Item, nil
}

// Update implements store.Metadata with a PutItem conditional on the stored
// version, owner and tid.
func (m *Metadata) Update(ctx context.Context, r store.Record) (store.Record, error) {
	expected := r.Version
	r = r.Clone()
	r.Version++
	_, err := m.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(m.table),
		Item:                encodeRecord(r),
		ConditionExpression: aws.String("#v = :v AND #o = :o AND #t = :t"),
		ExpressionAttributeNames: map[string]string{
			"#v": attrVersion, "#o": attrOwner, "#t": attrTID,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": num(expected), ":o": str(r.Owner), ":t": str(r.TID),
		},
	})
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		return store.Record{}, fmt.Errorf("awsstore: update record: %w", store.ErrConflict)
	}
	if err != nil {
		return store.Record{}, sanitize("update record", err)
	}
	return r, nil
}

// ListExpired implements store.Metadata with a filtered Scan. The scan reads
// the whole table on every sweep, which is fine at the sweep interval
// (FT_SWEEP_INTERVAL, an hour by default) for the table sizes of a first
// release; docs/ft-server.md records the limit.
func (m *Metadata) ListExpired(ctx context.Context, now time.Time, limit int) ([]store.Record, error) {
	var out []store.Record
	var start map[string]types.AttributeValue
	for len(out) < limit {
		page, err := m.api.Scan(ctx, &dynamodb.ScanInput{
			TableName:        aws.String(m.table),
			FilterExpression: aws.String("begins_with(#pk, :f) AND #e < :now AND #s <> :expired"),
			ExpressionAttributeNames: map[string]string{
				"#pk": attrPK, "#e": attrExpires, "#s": attrState,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":f": str("f#"), ":now": num(now.UnixMilli()), ":expired": str(string(store.Expired)),
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, sanitize("scan", err)
		}
		for _, item := range page.Items {
			if len(out) == limit {
				break
			}
			r, err := decodeRecord(item)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		start = page.LastEvaluatedKey
	}
	return out, nil
}

// NonceCounts is a digest.NonceCountStore in the files table, so every
// ft-server task refuses a nonce-count another task has seen.
type NonceCounts struct {
	api   DynamoAPI
	table string
	now   func() time.Time
}

// Advance implements digest.NonceCountStore with one conditional update:
// written only if no count is stored, the stored one is lower, or it has
// expired (DynamoDB deletes expired items late, so expiry is checked here).
func (n *NonceCounts) Advance(ctx context.Context, username, nonce string, nc uint32, expires time.Time) (bool, error) {
	_, err := n.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(n.table),
		Key:              key(nonceKey(username, nonce)),
		UpdateExpression: aws.String("SET #nc = :nc, #e = :e, #ttl = :ttl"),
		ConditionExpression: aws.String(
			"attribute_not_exists(#nc) OR #nc < :nc OR #e < :now"),
		ExpressionAttributeNames: map[string]string{"#nc": attrNC, "#e": attrExpires, "#ttl": attrTTL},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":nc":  num(int64(nc)),
			":e":   num(expires.UnixMilli()),
			":ttl": num(expires.Add(time.Hour).Unix()),
			":now": num(n.now().UnixMilli()),
		},
	})
	var failed *types.ConditionalCheckFailedException
	if errors.As(err, &failed) {
		return false, nil
	}
	if err != nil {
		return false, sanitize("advance nonce count", err)
	}
	return true, nil
}

// encodeRecord is the item of r. Optional values are left out rather than
// stored empty, and times are epoch milliseconds.
func encodeRecord(r store.Record) map[string]types.AttributeValue {
	item := map[string]types.AttributeValue{
		attrPK:       str(fileKey(r.ID)),
		attrID:       str(r.ID),
		attrOwner:    str(r.Owner),
		attrTID:      str(r.TID),
		attrState:    str(string(r.State)),
		attrName:     str(r.FileName),
		attrType:     str(r.ContentType),
		attrDeclared: num(r.DeclaredSize),
		attrReceived: num(r.Received),
		attrSize:     num(r.Size),
		attrCreated:  num(r.Created.UnixMilli()),
		attrExpires:  num(r.Expires.UnixMilli()),
		attrVersion:  num(r.Version),
		attrTTL:      ttlOf(r.Expires),
	}
	if len(r.SHA256) > 0 {
		item[attrSHA256] = &types.AttributeValueMemberB{Value: r.SHA256}
	}
	if len(r.HashState) > 0 {
		item[attrHashState] = &types.AttributeValueMemberB{Value: r.HashState}
	}
	if r.MultipartID != "" {
		item[attrMultipart] = str(r.MultipartID)
	}
	if len(r.Parts) > 0 {
		parts := make([]types.AttributeValue, len(r.Parts))
		for i, p := range r.Parts {
			parts[i] = &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
				"n": num(int64(p.Number)), "etag": str(p.ETag), "size": num(p.Size),
			}}
		}
		item[attrParts] = &types.AttributeValueMemberL{Value: parts}
	}
	if t := r.Thumbnail; t != nil {
		item[attrThumbSize] = num(t.Size)
		item[attrThumbType] = str(t.ContentType)
	}
	if !r.Completed.IsZero() {
		item[attrCompleted] = num(r.Completed.UnixMilli())
	}
	if r.Lease != "" {
		item[attrLease] = str(r.Lease)
	}
	if !r.LeaseUntil.IsZero() {
		item[attrLeaseUntil] = num(r.LeaseUntil.UnixMilli())
	}
	return item
}

// decodeRecord is the inverse of encodeRecord. A missing required attribute
// or one of the wrong type is an error: the item was not written by this
// package.
func decodeRecord(item map[string]types.AttributeValue) (store.Record, error) {
	d := decoder{item: item}
	r := store.Record{
		ID:           d.str(attrID, true),
		Owner:        d.str(attrOwner, true),
		TID:          d.str(attrTID, true),
		State:        store.State(d.str(attrState, true)),
		FileName:     d.str(attrName, true),
		ContentType:  d.str(attrType, true),
		DeclaredSize: d.num(attrDeclared, true),
		Received:     d.num(attrReceived, true),
		Size:         d.num(attrSize, true),
		SHA256:       d.bin(attrSHA256),
		HashState:    d.bin(attrHashState),
		MultipartID:  d.str(attrMultipart, false),
		Created:      d.time(attrCreated, true),
		Completed:    d.time(attrCompleted, false),
		Expires:      d.time(attrExpires, true),
		Lease:        d.str(attrLease, false),
		LeaseUntil:   d.time(attrLeaseUntil, false),
		Version:      d.num(attrVersion, true),
	}
	if _, ok := item[attrThumbType]; ok {
		r.Thumbnail = &store.Thumbnail{Size: d.num(attrThumbSize, true), ContentType: d.str(attrThumbType, true)}
	}
	if v, ok := item[attrParts]; ok {
		list, ok := v.(*types.AttributeValueMemberL)
		if !ok {
			d.fail(attrParts)
		} else {
			for _, e := range list.Value {
				m, ok := e.(*types.AttributeValueMemberM)
				if !ok {
					d.fail(attrParts)
					break
				}
				pd := decoder{item: m.Value}
				r.Parts = append(r.Parts, store.Part{
					Number: int32(pd.num("n", true)),
					ETag:   pd.str("etag", true),
					Size:   pd.num("size", true),
				})
				if pd.err != nil {
					d.fail(attrParts)
					break
				}
			}
		}
	}
	if d.err != nil {
		return store.Record{}, d.err
	}
	return r, nil
}

// decoder reads typed attributes and remembers the first problem.
type decoder struct {
	item map[string]types.AttributeValue
	err  error
}

func (d *decoder) fail(name string) {
	if d.err == nil {
		d.err = fmt.Errorf("awsstore: record attribute %s is missing or malformed", name)
	}
}

func (d *decoder) str(name string, required bool) string {
	v, ok := d.item[name]
	if !ok {
		if required {
			d.fail(name)
		}
		return ""
	}
	s, ok := v.(*types.AttributeValueMemberS)
	if !ok {
		d.fail(name)
		return ""
	}
	return s.Value
}

func (d *decoder) num(name string, required bool) int64 {
	v, ok := d.item[name]
	if !ok {
		if required {
			d.fail(name)
		}
		return 0
	}
	n, ok := v.(*types.AttributeValueMemberN)
	if !ok {
		d.fail(name)
		return 0
	}
	i, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		d.fail(name)
	}
	return i
}

func (d *decoder) bin(name string) []byte {
	v, ok := d.item[name]
	if !ok {
		return nil
	}
	b, ok := v.(*types.AttributeValueMemberB)
	if !ok {
		d.fail(name)
		return nil
	}
	return b.Value
}

func (d *decoder) time(name string, required bool) time.Time {
	if _, ok := d.item[name]; !ok {
		if required {
			d.fail(name)
		}
		return time.Time{}
	}
	return time.UnixMilli(d.num(name, true)).UTC()
}
