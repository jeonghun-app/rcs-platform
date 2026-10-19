package dynamostore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	mathrand "math/rand/v2"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// DynamoAPI is the part of the DynamoDB client the store uses;
// *dynamodb.Client has it.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Defaults of the Config table names, as docs/architecture.md names them.
const (
	DefaultRegistrationsTable = "registrations"
	DefaultChallengesTable    = "auth-challenges"
	DefaultSubscriptionsTable = "reg-subscriptions"
)

// Attribute and index names; the package documentation has the tables.
const (
	attrPK      = "pk"
	attrSK      = "sk"
	attrVersion = "version"
	attrDoc     = "doc"
	attrWriter  = "writer"
	attrIMPI    = "impi"
	attrIMPU    = "impu"
	attrShard   = "shard"
	attrExpires = "expires"
	attrCSeq    = "cseq"
	attrRver    = "rver"
	attrNToken  = "ntoken"
	// attrReceived orders profiles: when the SAA or PPR arrived, Unix ns.
	attrReceived = "received"

	IMPIIndex   = "impi-index"
	IMPUIndex   = "impu-index"
	ExpiryIndex = "expiry-index"

	// shards is the number of partitions of the expiry index.
	shards = 16
)

// Config names the tables and holds the challenge keys.
type Config struct {
	RegistrationsTable string
	ChallengesTable    string
	SubscriptionsTable string
	// ChallengeKeys are the keys challenges are sealed and opened with
	// (AES-256-GCM, 32 bytes each), shared by every scscf instance through
	// Secrets Manager, and SealKeyID names the one that seals; with a single
	// key it may be empty. Every key opens what it sealed, so a key rotates
	// in three steps, each rolled out to every instance before the next:
	//
	//  1. add the new key to ChallengeKeys, still sealing with the old one;
	//  2. set SealKeyID to the new key;
	//  3. after MaxChallengeLifetime, remove the old key.
	//
	// An instance a step behind then still opens every challenge, and a
	// rollback of one step does too. Rotate at least quarterly: with random
	// 96-bit nonces one GCM key is good for 2^32 seals (NIST SP 800-38D §8.3),
	// far beyond a quarter's registrations, and rotating bounds it whatever
	// the traffic.
	ChallengeKeys []ChallengeKey
	SealKeyID     string
	// Rand is the source of write tokens and nonces; nil is crypto/rand.
	Rand io.Reader
}

// Dynamo is a state.Store in DynamoDB.
type Dynamo struct {
	api           DynamoAPI
	registrations string
	challenges    string
	subscriptions string
	sealer        *sealer
	rand          io.Reader
}

var _ state.Store = (*Dynamo)(nil)

// New returns the store over api.
func New(api DynamoAPI, c Config) (*Dynamo, error) {
	s, err := newSealer(c.ChallengeKeys, c.SealKeyID)
	if err != nil {
		return nil, err
	}
	d := &Dynamo{
		api:           api,
		registrations: or(c.RegistrationsTable, DefaultRegistrationsTable),
		challenges:    or(c.ChallengesTable, DefaultChallengesTable),
		subscriptions: or(c.SubscriptionsTable, DefaultSubscriptionsTable),
		sealer:        s,
		rand:          c.Rand,
	}
	if d.rand == nil {
		d.rand = rand.Reader
	}
	return d, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Ready checks that the three tables are active, for /readyz. It needs
// dynamodb:DescribeTable.
func (d *Dynamo) Ready(ctx context.Context) error {
	for _, table := range []string{d.registrations, d.challenges, d.subscriptions} {
		out, err := d.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err != nil {
			return sanitize("describe table", err)
		}
		if out.Table == nil || out.Table.TableStatus != types.TableStatusActive {
			return errors.New("dynamostore: a table is not active")
		}
	}
	return nil
}

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func bin(b []byte) types.AttributeValue { return &types.AttributeValueMemberB{Value: b} }

func key(pk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(pk)}
}

// sv is the string or number of an attribute, or "".
func sv(v types.AttributeValue) string {
	switch a := v.(type) {
	case *types.AttributeValueMemberS:
		return a.Value
	case *types.AttributeValueMemberN:
		return a.Value
	}
	return ""
}

func nv(item map[string]types.AttributeValue, name string) (int64, error) {
	n, ok := item[name].(*types.AttributeValueMemberN)
	if !ok {
		return 0, fmt.Errorf("%w: item without %s", state.ErrInvalid, name)
	}
	v, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: item with an invalid %s", state.ErrInvalid, name)
	}
	return v, nil
}

func docOf(item map[string]types.AttributeValue) ([]byte, error) {
	b, ok := item[attrDoc].(*types.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("%w: item without doc", state.ErrInvalid)
	}
	return b.Value, nil
}

// shardOf spreads keys over the expiry index's partitions.
func shardOf(pk string) string {
	h := fnv.New32a()
	h.Write([]byte(pk))
	return strconv.Itoa(int(h.Sum32() % shards))
}

// token is 128 random bits in hex, or "" when no randomness is available; see
// the package documentation.
func (d *Dynamo) token() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(d.rand, b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func ccf(err error) bool {
	var e *types.ConditionalCheckFailedException
	return errors.As(err, &e)
}

// sanitize reduces an SDK error to the operation and the AWS error code or the
// transport failure, so that no key reaches a log.
func sanitize(op string, err error) error {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, ctxErr) {
			return fmt.Errorf("dynamostore: %s: %w", op, ctxErr)
		}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("dynamostore: %s: %s", op, api.ErrorCode())
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("dynamostore: %s: %s", op, ue.Err.Error())
	}
	return fmt.Errorf("dynamostore: %s: request failed", op)
}

func (d *Dynamo) get(ctx context.Context, table string, k map[string]types.AttributeValue, op string) (map[string]types.AttributeValue, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: k, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return nil, fmt.Errorf("dynamostore: %s: %w", op, state.ErrNotFound)
	}
	return out.Item, nil
}

// nextVersion is the version a save of an item read at given stores: a random
// first one for a new item (state.FirstVersion), the next one otherwise.
func (d *Dynamo) nextVersion(given int64) (int64, error) {
	if given == 0 {
		return state.FirstVersion(d.rand)
	}
	return given + 1, nil
}

// itemSize is the size DynamoDB counts for an item: every attribute's name and
// value.
func itemSize(item map[string]types.AttributeValue) int {
	n := 0
	for name, v := range item {
		n += len(name)
		switch a := v.(type) {
		case *types.AttributeValueMemberS:
			n += len(a.Value)
		case *types.AttributeValueMemberN:
			n += len(a.Value)
		case *types.AttributeValueMemberB:
			n += len(a.Value)
		}
	}
	return n
}

// checkSize refuses an item larger than state.MaxItemBytes, which DynamoDB
// would refuse at 400 KB with an error of its own.
func checkSize(item map[string]types.AttributeValue, what string) error {
	if itemSize(item) > state.MaxItemBytes {
		return fmt.Errorf("%w: %s is larger than %d bytes stored", state.ErrInvalid, what, state.MaxItemBytes)
	}
	return nil
}

// putVersioned writes item, created when version is 0 and otherwise
// conditional on that version (state.Registrations.SaveRegistration).
func (d *Dynamo) putVersioned(ctx context.Context, table, pk string, version int64, item map[string]types.AttributeValue, op string) error {
	in := &dynamodb.PutItemInput{TableName: aws.String(table), Item: item}
	if version == 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(#pk)")
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK}
	} else {
		in.ConditionExpression = aws.String("#v = :v")
		in.ExpressionAttributeNames = map[string]string{"#v": attrVersion}
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":v": num(version)}
	}
	_, err := d.api.PutItem(ctx, in)
	switch {
	case ccf(err):
		return d.explain(ctx, table, key(pk), item, version == 0, op)
	case err != nil:
		return sanitize(op, err)
	}
	return nil
}

// explain says why a conditional write failed: the stored item carries this
// write's token (an earlier attempt succeeded and only its response was lost:
// nil), the item exists although it was to be created (ErrExists), it is gone
// (ErrNotFound), or another writer was first (ErrConflict).
func (d *Dynamo) explain(ctx context.Context, table string, k, wrote map[string]types.AttributeValue, create bool, op string) error {
	cur, err := d.get(ctx, table, k, op)
	switch {
	case errors.Is(err, state.ErrNotFound) && create:
		// It existed when the write was refused and is gone now.
		return fmt.Errorf("dynamostore: %s: %w", op, state.ErrConflict)
	case err != nil:
		return err
	case sv(cur[attrWriter]) != "" && sv(cur[attrWriter]) == sv(wrote[attrWriter]) && sv(cur[attrVersion]) == sv(wrote[attrVersion]):
		return nil
	case create:
		return fmt.Errorf("dynamostore: %s: %w", op, state.ErrExists)
	}
	return fmt.Errorf("dynamostore: %s: %w", op, state.ErrConflict)
}

// deleteVersioned deletes the item if its version is still the given one.
func (d *Dynamo) deleteVersioned(ctx context.Context, table, pk string, version int64, op string) error {
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(table),
		Key:                       key(pk),
		ConditionExpression:       aws.String("#v = :v"),
		ExpressionAttributeNames:  map[string]string{"#v": attrVersion},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": num(version)},
	})
	switch {
	case ccf(err):
		// A resent delete of an item the first attempt removed also lands
		// here, as ErrNotFound; the sweeps treat both as lost to another
		// instance, which is the safe reading.
		if _, err := d.get(ctx, table, key(pk), op); err != nil {
			return err
		}
		return fmt.Errorf("dynamostore: %s: %w", op, state.ErrConflict)
	case err != nil:
		return sanitize(op, err)
	}
	return nil
}

// expiring lists the keys of up to limit items of an expiry index whose
// expiry is at or before now, then reads each from the table and keeps those
// keep accepts: the index is eventually consistent.
func (d *Dynamo) expiring(ctx context.Context, table string, now time.Time, limit int, keep func(map[string]types.AttributeValue) bool, op string) ([]map[string]types.AttributeValue, error) {
	var out []map[string]types.AttributeValue
	// Starting at a random shard spreads instances sweeping at once over
	// different items, and no shard waits behind a backlog in another.
	first := mathrand.IntN(shards)
	for i := 0; i < shards && len(out) < limit; i++ {
		shard := (first + i) % shards
		var start map[string]types.AttributeValue
		for len(out) < limit {
			q, err := d.api.Query(ctx, &dynamodb.QueryInput{
				TableName:                aws.String(table),
				IndexName:                aws.String(ExpiryIndex),
				KeyConditionExpression:   aws.String("#shard = :shard AND #exp <= :now"),
				ExpressionAttributeNames: map[string]string{"#shard": attrShard, "#exp": attrExpires},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":shard": str(strconv.Itoa(shard)), ":now": num(now.Unix()),
				},
				Limit:             aws.Int32(int32(limit - len(out))),
				ExclusiveStartKey: start,
			})
			if err != nil {
				return nil, sanitize(op, err)
			}
			for _, k := range q.Items {
				item, err := d.get(ctx, table, key(sv(k[attrPK])), op)
				if errors.Is(err, state.ErrNotFound) {
					continue
				}
				if err != nil {
					return nil, err
				}
				if keep(item) {
					out = append(out, item)
				}
			}
			if len(q.LastEvaluatedKey) == 0 {
				break
			}
			start = q.LastEvaluatedKey
		}
	}
	return out, nil
}

// byIndex reads every item an index lists for value, again from the table.
func (d *Dynamo) byIndex(ctx context.Context, table, index, attr, value, op string) ([]map[string]types.AttributeValue, error) {
	var out []map[string]types.AttributeValue
	var start map[string]types.AttributeValue
	for {
		q, err := d.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(table),
			IndexName:                 aws.String(index),
			KeyConditionExpression:    aws.String("#a = :a"),
			ExpressionAttributeNames:  map[string]string{"#a": attr},
			ExpressionAttributeValues: map[string]types.AttributeValue{":a": str(value)},
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, sanitize(op, err)
		}
		for _, k := range q.Items {
			item, err := d.get(ctx, table, key(sv(k[attrPK])), op)
			if errors.Is(err, state.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if sv(item[attr]) == value {
				out = append(out, item)
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = q.LastEvaluatedKey
	}
}
