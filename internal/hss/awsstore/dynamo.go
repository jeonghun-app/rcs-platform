package awsstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// DynamoAPI is the part of the DynamoDB client the store uses;
// *dynamodb.Client has it.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// Attribute and index names; docs/hss.md has the table definitions.
const (
	attrPK      = "pk"
	attrVersion = "version"
	attrProfile = "profile"
	attrDoc     = "doc"
	attrIMPI    = "impi"
	// attrWriter is a random token of the write that stored an item; see
	// conflictOrGone.
	attrWriter   = "writer"
	keyPrefix    = "key_"
	ProfileIndex = "profile-index"

	keyringPK = "keyring"
)

func subscriptionKey(impi string) string { return "s#" + impi }
func identityKey(impu string) string     { return "u#" + impu }

func key(pk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(pk)}
}

func str(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func num(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

// Dynamo is a store.Store in the subscribers and service-profiles tables.
type Dynamo struct {
	api         DynamoAPI
	subscribers string
	profiles    string
	rand        io.Reader
}

var _ store.Store = (*Dynamo)(nil)

// NewDynamo returns the store over api.
func NewDynamo(api DynamoAPI, c Config) *Dynamo {
	return &Dynamo{api: api, subscribers: c.SubscribersTable, profiles: c.ProfilesTable, rand: rand.Reader}
}

// Ready checks that both tables are active, for /readyz. It needs
// dynamodb:DescribeTable.
func (d *Dynamo) Ready(ctx context.Context) error {
	for _, table := range []string{d.subscribers, d.profiles} {
		out, err := d.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err != nil {
			return sanitize("describe table", err)
		}
		if out.Table == nil || out.Table.TableStatus != types.TableStatusActive {
			return errors.New("awsstore: a table is not active")
		}
	}
	return nil
}

func (d *Dynamo) subscriptionItem(s *store.Subscription, version int64) (map[string]types.AttributeValue, error) {
	doc, err := store.EncodeSubscription(s)
	if err != nil {
		return nil, err
	}
	return map[string]types.AttributeValue{
		attrPK:      str(subscriptionKey(s.IMPI)),
		attrVersion: num(version),
		attrProfile: str(s.Profile),
		attrDoc:     &types.AttributeValueMemberB{Value: doc},
		attrWriter:  str(d.token()),
	}, nil
}

func (d *Dynamo) identityPut(impu, impi string) types.TransactWriteItem {
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(d.subscribers),
		Item:      map[string]types.AttributeValue{attrPK: str(identityKey(impu)), attrIMPI: str(impi)},
		// Free, or already this subscription's (a retried write).
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #impi = :impi"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#impi": attrIMPI},
		ExpressionAttributeValues: map[string]types.AttributeValue{":impi": str(impi)},
	}}
}

func (d *Dynamo) identityDelete(impu, impi string) types.TransactWriteItem {
	return types.TransactWriteItem{Delete: &types.Delete{
		TableName:                 aws.String(d.subscribers),
		Key:                       key(identityKey(impu)),
		ConditionExpression:       aws.String("#impi = :impi"),
		ExpressionAttributeNames:  map[string]string{"#impi": attrIMPI},
		ExpressionAttributeValues: map[string]types.AttributeValue{":impi": str(impi)},
	}}
}

func (d *Dynamo) profileCheck(id string) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(d.profiles),
		Key:                      key(id),
		ConditionExpression:      aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	}}
}

// cancelled returns the index of the first item whose condition failed in a
// cancelled transaction, or -1.
func cancelled(err error) int {
	var tc *types.TransactionCanceledException
	if !errors.As(err, &tc) {
		return -1
	}
	for i, r := range tc.CancellationReasons {
		if aws.ToString(r.Code) == "ConditionalCheckFailed" {
			return i
		}
	}
	return -1
}

// raced reports whether a write lost to a concurrent transaction on one of
// its items: a PutItem that met a transaction, or a transaction cancelled
// for another one. The SDK does not retry either; to the HSS it is a version
// conflict, which update retries from a fresh read.
func raced(err error) bool {
	var conflict *types.TransactionConflictException
	if errors.As(err, &conflict) {
		return true
	}
	var tc *types.TransactionCanceledException
	if errors.As(err, &tc) {
		for _, r := range tc.CancellationReasons {
			if aws.ToString(r.Code) == "TransactionConflict" {
				return true
			}
		}
	}
	return false
}

// requestToken makes a transaction idempotent (DynamoDB keeps the token for
// ten minutes): when the SDK resends one whose response was lost, DynamoDB
// answers the first outcome instead of failing its own conditions.
func (d *Dynamo) requestToken() *string { return aws.String(d.token()) }

// token is 128 random bits in hex. Without randomness it is a fixed string,
// which leaves writes conditional but makes lost responses conflicts.
func (d *Dynamo) token() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(d.rand, b); err != nil {
		return "unset"
	}
	return hex.EncodeToString(b)
}

// CreateSubscription implements store.Store: the subscription, its IMPU
// items and a check that the profile exists, in one transaction.
func (d *Dynamo) CreateSubscription(ctx context.Context, s *store.Subscription) (*store.Subscription, error) {
	item, err := d.subscriptionItem(s, 1)
	if err != nil {
		return nil, err
	}
	items := []types.TransactWriteItem{{Put: &types.Put{
		TableName:                aws.String(d.subscribers),
		Item:                     item,
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	}}}
	for _, p := range s.PublicIdentities {
		items = append(items, d.identityPut(p.IMPU, s.IMPI))
	}
	items = append(items, d.profileCheck(s.Profile))
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items, ClientRequestToken: d.requestToken()})
	switch i := cancelled(err); {
	case raced(err):
		return nil, fmt.Errorf("awsstore: create subscription: %w", store.ErrConflict)
	case i == 0:
		return nil, fmt.Errorf("awsstore: create subscription: %w", store.ErrExists)
	case i == len(items)-1:
		return nil, fmt.Errorf("awsstore: create subscription: %w", store.ErrProfileMissing)
	case i > 0:
		return nil, fmt.Errorf("awsstore: create subscription: %w", store.ErrIdentityInUse)
	case err != nil:
		return nil, sanitize("create subscription", err)
	}
	return d.decodeSubscription(item)
}

func (d *Dynamo) decodeSubscription(item map[string]types.AttributeValue) (*store.Subscription, error) {
	doc, ok := item[attrDoc].(*types.AttributeValueMemberB)
	v, okV := item[attrVersion].(*types.AttributeValueMemberN)
	if !ok || !okV {
		return nil, fmt.Errorf("%w: subscription item without doc or version", store.ErrInvalid)
	}
	version, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: subscription item with an invalid version", store.ErrInvalid)
	}
	return store.DecodeSubscription(doc.Value, version)
}

func (d *Dynamo) get(ctx context.Context, table, pk, op string) (map[string]types.AttributeValue, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(table),
		Key:            key(pk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return nil, fmt.Errorf("awsstore: %s: %w", op, store.ErrNotFound)
	}
	return out.Item, nil
}

// Subscription implements store.Store.
func (d *Dynamo) Subscription(ctx context.Context, impi string) (*store.Subscription, error) {
	item, err := d.get(ctx, d.subscribers, subscriptionKey(impi), "get subscription")
	if err != nil {
		return nil, err
	}
	return d.decodeSubscription(item)
}

// SubscriptionByIMPU implements store.Store: the IMPU item, then the
// subscription it names, which must still list the IMPU.
func (d *Dynamo) SubscriptionByIMPU(ctx context.Context, impu string) (*store.Subscription, error) {
	item, err := d.get(ctx, d.subscribers, identityKey(impu), "get identity")
	if err != nil {
		return nil, err
	}
	impi, ok := item[attrIMPI].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("%w: identity item without an IMPI", store.ErrInvalid)
	}
	s, err := d.Subscription(ctx, impi.Value)
	if err != nil {
		return nil, err
	}
	if s.Identity(impu) == nil {
		return nil, fmt.Errorf("%w: identity item points at a subscription without it", store.ErrInvalid)
	}
	return s, nil
}

// UpdateSubscription implements store.Store. A write that keeps the IMPUs
// and the profile, such as every Cx state change, is a single conditional
// PutItem; one that changes them is a transaction like CreateSubscription.
func (d *Dynamo) UpdateSubscription(ctx context.Context, old, s *store.Subscription) (*store.Subscription, error) {
	if old.IMPI != s.IMPI {
		return nil, fmt.Errorf("%w: the IMPI of a subscription cannot change", store.ErrInvalid)
	}
	item, err := d.subscriptionItem(s, old.Version+1)
	if err != nil {
		return nil, err
	}
	cond := aws.String("#v = :v")
	names := map[string]string{"#v": attrVersion}
	values := map[string]types.AttributeValue{":v": num(old.Version)}
	added, removed := store.IdentityChanges(old, s)
	if len(added) == 0 && len(removed) == 0 && old.Profile == s.Profile {
		_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: aws.String(d.subscribers), Item: item,
			ConditionExpression: cond, ExpressionAttributeNames: names, ExpressionAttributeValues: values,
		})
		var ccf *types.ConditionalCheckFailedException
		switch {
		case errors.As(err, &ccf):
			if err := d.conflictOrGone(ctx, d.subscribers, subscriptionKey(s.IMPI), item, "update subscription"); err != nil {
				return nil, err
			}
		case raced(err):
			return nil, fmt.Errorf("awsstore: update subscription: %w", store.ErrConflict)
		case err != nil:
			return nil, sanitize("update subscription", err)
		}
		return d.decodeSubscription(item)
	}
	items := []types.TransactWriteItem{{Put: &types.Put{
		TableName: aws.String(d.subscribers), Item: item,
		ConditionExpression: cond, ExpressionAttributeNames: names, ExpressionAttributeValues: values,
	}}}
	for _, impu := range added {
		items = append(items, d.identityPut(impu, s.IMPI))
	}
	for _, impu := range removed {
		items = append(items, d.identityDelete(impu, s.IMPI))
	}
	checked := old.Profile != s.Profile
	if checked {
		items = append(items, d.profileCheck(s.Profile))
	}
	_, err = d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items, ClientRequestToken: d.requestToken()})
	switch i := cancelled(err); {
	case raced(err):
		return nil, fmt.Errorf("awsstore: update subscription: %w", store.ErrConflict)
	case i == 0:
		if err := d.conflictOrGone(ctx, d.subscribers, subscriptionKey(s.IMPI), item, "update subscription"); err != nil {
			return nil, err
		}
	case checked && i == len(items)-1:
		return nil, fmt.Errorf("awsstore: update subscription: %w", store.ErrProfileMissing)
	case i > 0 && i <= len(added):
		return nil, fmt.Errorf("awsstore: update subscription: %w", store.ErrIdentityInUse)
	case i > 0:
		// A removed IMPU item that is not this subscription's breaks the
		// index invariant; report it rather than guess.
		return nil, fmt.Errorf("%w: an IMPU item of the subscription points elsewhere", store.ErrInvalid)
	case err != nil:
		return nil, sanitize("update subscription", err)
	}
	return d.decodeSubscription(item)
}

// conflictOrGone explains a failed version condition, which DynamoDB
// reports the same way whatever the cause: the item is gone (ErrNotFound),
// another writer was first (ErrConflict), or the stored item carries this
// write's own writer token, which means an earlier attempt of the write
// succeeded and only its response was lost (nil: the write stands). The
// token, not the content, decides: two writers that read the same version
// and computed the same document must not both succeed, or both would
// believe they had reserved the same sequence numbers.
func (d *Dynamo) conflictOrGone(ctx context.Context, table, pk string, wrote map[string]types.AttributeValue, op string) error {
	cur, err := d.get(ctx, table, pk, op)
	if err != nil {
		return err
	}
	if wrote != nil && sv(cur[attrWriter]) != "" && sv(cur[attrWriter]) == sv(wrote[attrWriter]) &&
		sv(cur[attrVersion]) == sv(wrote[attrVersion]) {
		return nil
	}
	return fmt.Errorf("awsstore: %s: %w", op, store.ErrConflict)
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

// DeleteSubscription implements store.Store.
func (d *Dynamo) DeleteSubscription(ctx context.Context, s *store.Subscription) error {
	items := []types.TransactWriteItem{{Delete: &types.Delete{
		TableName:                 aws.String(d.subscribers),
		Key:                       key(subscriptionKey(s.IMPI)),
		ConditionExpression:       aws.String("#v = :v"),
		ExpressionAttributeNames:  map[string]string{"#v": attrVersion},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": num(s.Version)},
	}}}
	for _, p := range s.PublicIdentities {
		items = append(items, d.identityDelete(p.IMPU, s.IMPI))
	}
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items, ClientRequestToken: d.requestToken()})
	switch i := cancelled(err); {
	case raced(err):
		return fmt.Errorf("awsstore: delete subscription: %w", store.ErrConflict)
	case i == 0:
		return d.conflictOrGone(ctx, d.subscribers, subscriptionKey(s.IMPI), nil, "delete subscription")
	case i > 0:
		return fmt.Errorf("%w: an IMPU item of the subscription points elsewhere", store.ErrInvalid)
	case err != nil:
		return sanitize("delete subscription", err)
	}
	return nil
}

// SubscriptionsByProfile implements store.Store with a query of the profile
// index. The cursor is the last IMPI returned.
func (d *Dynamo) SubscriptionsByProfile(ctx context.Context, profile, cursor string, limit int) (store.Page, error) {
	if limit <= 0 || limit > store.MaxPageSize {
		limit = store.MaxPageSize
	}
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(d.subscribers),
		IndexName:                 aws.String(ProfileIndex),
		KeyConditionExpression:    aws.String("#p = :p"),
		ExpressionAttributeNames:  map[string]string{"#p": attrProfile},
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": str(profile)},
		Limit:                     aws.Int32(int32(limit)),
	}
	if cursor != "" {
		in.ExclusiveStartKey = map[string]types.AttributeValue{attrPK: str(subscriptionKey(cursor)), attrProfile: str(profile)}
	}
	out, err := d.api.Query(ctx, in)
	if err != nil {
		return store.Page{}, sanitize("query profile index", err)
	}
	var p store.Page
	for _, item := range out.Items {
		pk, ok := item[attrPK].(*types.AttributeValueMemberS)
		impi, isSub := strings.CutPrefix(pkValue(pk, ok), "s#")
		if !isSub {
			continue
		}
		p.IMPIs = append(p.IMPIs, impi)
	}
	if last, ok := out.LastEvaluatedKey[attrPK].(*types.AttributeValueMemberS); ok {
		p.Next = strings.TrimPrefix(last.Value, "s#")
	}
	return p, nil
}

func pkValue(pk *types.AttributeValueMemberS, ok bool) string {
	if !ok {
		return ""
	}
	return pk.Value
}

func (d *Dynamo) profileItem(p *store.ServiceProfile, version int64) (map[string]types.AttributeValue, error) {
	doc, err := store.EncodeProfile(p)
	if err != nil {
		return nil, err
	}
	return map[string]types.AttributeValue{
		attrPK:      str(p.ID),
		attrVersion: num(version),
		attrDoc:     &types.AttributeValueMemberB{Value: doc},
		attrWriter:  str(d.token()),
	}, nil
}

func decodeProfile(item map[string]types.AttributeValue) (*store.ServiceProfile, error) {
	doc, ok := item[attrDoc].(*types.AttributeValueMemberB)
	v, okV := item[attrVersion].(*types.AttributeValueMemberN)
	if !ok || !okV {
		return nil, fmt.Errorf("%w: profile item without doc or version", store.ErrInvalid)
	}
	version, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: profile item with an invalid version", store.ErrInvalid)
	}
	return store.DecodeProfile(doc.Value, version)
}

// CreateProfile implements store.Store.
func (d *Dynamo) CreateProfile(ctx context.Context, p *store.ServiceProfile) (*store.ServiceProfile, error) {
	item, err := d.profileItem(p, 1)
	if err != nil {
		return nil, err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.profiles), Item: item,
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return nil, fmt.Errorf("awsstore: create profile: %w", store.ErrExists)
	}
	if err != nil {
		return nil, sanitize("create profile", err)
	}
	return decodeProfile(item)
}

// Profile implements store.Store.
func (d *Dynamo) Profile(ctx context.Context, id string) (*store.ServiceProfile, error) {
	item, err := d.get(ctx, d.profiles, id, "get profile")
	if err != nil {
		return nil, err
	}
	return decodeProfile(item)
}

// UpdateProfile implements store.Store.
func (d *Dynamo) UpdateProfile(ctx context.Context, p *store.ServiceProfile) (*store.ServiceProfile, error) {
	item, err := d.profileItem(p, p.Version+1)
	if err != nil {
		return nil, err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.profiles), Item: item,
		ConditionExpression:       aws.String("#v = :v"),
		ExpressionAttributeNames:  map[string]string{"#v": attrVersion},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": num(p.Version)},
	})
	var ccf *types.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf):
		if err := d.conflictOrGone(ctx, d.profiles, p.ID, item, "update profile"); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, sanitize("update profile", err)
	}
	return decodeProfile(item)
}

// DeleteProfile implements store.Store. The in-use check reads the profile
// index, which is eventually consistent: a subscription created a moment
// before may not be seen, and the HSS answers Cx requests for a subscription
// whose profile is gone with DIAMETER_UNABLE_TO_COMPLY (docs/hss.md).
func (d *Dynamo) DeleteProfile(ctx context.Context, p *store.ServiceProfile) error {
	page, err := d.SubscriptionsByProfile(ctx, p.ID, "", 1)
	if err != nil {
		return err
	}
	if len(page.IMPIs) > 0 {
		if _, err := d.Profile(ctx, p.ID); err != nil {
			return err
		}
		return fmt.Errorf("awsstore: delete profile: %w", store.ErrProfileInUse)
	}
	_, err = d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(d.profiles),
		Key:                       key(p.ID),
		ConditionExpression:       aws.String("#v = :v"),
		ExpressionAttributeNames:  map[string]string{"#v": attrVersion},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": num(p.Version)},
	})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return d.conflictOrGone(ctx, d.profiles, p.ID, nil, "delete profile")
	}
	if err != nil {
		return sanitize("delete profile", err)
	}
	return nil
}

// DataKeys implements keyring.Store.
func (d *Dynamo) DataKeys(ctx context.Context) ([]keyring.WrappedKey, error) {
	item, err := d.get(ctx, d.subscribers, keyringPK, "get data keys")
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []keyring.WrappedKey
	for name, v := range item {
		id, ok := strings.CutPrefix(name, keyPrefix)
		if !ok {
			continue
		}
		b, ok := v.(*types.AttributeValueMemberB)
		if !ok {
			return nil, fmt.Errorf("%w: data key %s is not binary", store.ErrInvalid, id)
		}
		keys = append(keys, keyring.WrappedKey{ID: id, Ciphertext: b.Value})
	}
	return keys, nil
}

// AddFirstDataKey implements keyring.Store: the keyring item is created
// with the key only if it does not exist, so two tasks starting together
// cannot both store a first key.
func (d *Dynamo) AddFirstDataKey(ctx context.Context, k keyring.WrappedKey) error {
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.subscribers),
		Item: map[string]types.AttributeValue{
			attrPK:           str(keyringPK),
			keyPrefix + k.ID: &types.AttributeValueMemberB{Value: k.Ciphertext},
		},
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return fmt.Errorf("awsstore: add data key: %w", keyring.ErrExists)
	}
	if err != nil {
		return sanitize("add data key", err)
	}
	return nil
}

// HasSubscriptions implements store.Store with one item of the profile
// index, which holds only subscriptions.
func (d *Dynamo) HasSubscriptions(ctx context.Context) (bool, error) {
	out, err := d.api.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(d.subscribers),
		IndexName: aws.String(ProfileIndex),
		Limit:     aws.Int32(1),
	})
	if err != nil {
		return false, sanitize("scan profile index", err)
	}
	return len(out.Items) > 0, nil
}
