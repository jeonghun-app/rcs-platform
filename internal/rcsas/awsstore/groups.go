package awsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
)

// The groupchats table has the same key schema as messages (pk, sk, TTL
// attribute ttl) and one item per group:
//
//	pk g#<len(uri)>#<uri>  sk group
//
// holding the participants as a list, and the identities of removed ones
// the roster no longer lists (removed): groupstore.MaxEntries and
// groupstore.MaxRemoved of them with
// every field at its longest stay under DynamoDB's 400 KB item limit
// (TestTheLargestGroupFitsInOneItem). Every change rewrites the
// item on the condition that its revision (rev) is the one the change was
// computed from, with a token (wtoken) that tells a repeat of the write
// from another writer's. Touch updates only active, expires and ttl.

// Attribute names of group items.
const (
	attrSubject      = "subject"
	attrCreator      = "creator"
	attrParticipants = "participants"
	attrVersion      = "version"
	attrCreated      = "created"
	attrActive       = "active"
	attrRev          = "rev"
	attrToken        = "wtoken"
	attrIdentity     = "id"
	attrName         = "name"
	attrRole         = "role"
	attrState        = "state"
	attrAddedBy      = "added_by"
	attrSince        = "since"
	attrRemoved      = "removed"
)

const (
	groupPrefix = "g#"
	groupSK     = "group"
)

// Groups is a groupstore.Store in the DynamoDB groupchats table.
type Groups struct {
	api   DynamoAPI
	table string
}

var _ groupstore.Store = (*Groups)(nil)

// NewGroups loads the AWS configuration from the environment and returns
// the groups store; it makes no request.
func NewGroups(ctx context.Context, c Config) (*Groups, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("awsstore: loading the AWS configuration: %w", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	return NewGroupsWithClient(c.Table, ddb), nil
}

// NewGroupsWithClient returns a groups store over the given client.
func NewGroupsWithClient(table string, api DynamoAPI) *Groups { return &Groups{api: api, table: table} }

// Ready checks that the table can be reached, for /readyz.
func (s *Groups) Ready(ctx context.Context) error {
	return NewWithClient(s.table, s.api).Ready(ctx)
}

func groupKey(uri string) map[string]types.AttributeValue {
	return key(identityKey(groupPrefix, uri), groupSK)
}

// retained is how long a group item outlives its own expiry before
// DynamoDB's TTL deletes it; Get checks the expiry itself.
const retained = 24 * time.Hour

func encodeGroup(g groupstore.Group, rev int64, token string) map[string]types.AttributeValue {
	item := groupKey(g.URI)
	for name, v := range map[string]string{attrConversation: g.Conversation, attrSubject: g.Subject, attrCreator: g.Creator, attrToken: token} {
		if v != "" {
			item[name] = str(v)
		}
	}
	item[attrVersion] = num(int64(g.Version))
	item[attrCreated] = stamp(g.Created)
	item[attrActive] = stamp(g.Active)
	item[attrExpires] = stamp(g.Expires)
	item[attrTTL] = ttlOf(g.Expires.Add(retained))
	item[attrRev] = num(rev)
	list := make([]types.AttributeValue, len(g.Participants))
	for i, p := range g.Participants {
		m := map[string]types.AttributeValue{
			attrIdentity: str(p.Identity), attrRole: str(string(p.Role)), attrState: num(int64(p.State)), attrSince: stamp(p.Since),
		}
		if p.DisplayName != "" {
			m[attrName] = str(p.DisplayName)
		}
		if p.AddedBy != "" {
			m[attrAddedBy] = str(p.AddedBy)
		}
		list[i] = &types.AttributeValueMemberM{Value: m}
	}
	item[attrParticipants] = &types.AttributeValueMemberL{Value: list}
	if len(g.Removed) > 0 {
		removed := make([]types.AttributeValue, len(g.Removed))
		for i, id := range g.Removed {
			removed[i] = str(id)
		}
		item[attrRemoved] = &types.AttributeValueMemberL{Value: removed}
	}
	return item
}

func decodeGroup(uri string, item map[string]types.AttributeValue) (groupstore.Group, string, error) {
	g := groupstore.Group{URI: uri}
	var version int64
	var token string
	err := errors.Join(
		getString(item, attrConversation, &g.Conversation, false),
		getString(item, attrSubject, &g.Subject, false),
		getString(item, attrCreator, &g.Creator, false),
		getString(item, attrToken, &token, false),
		getNum(item, attrVersion, &version),
		getNum(item, attrRev, &g.Rev),
		getTime(item, attrCreated, &g.Created),
		getTime(item, attrActive, &g.Active),
		getTime(item, attrExpires, &g.Expires),
	)
	list, ok := item[attrParticipants].(*types.AttributeValueMemberL)
	if !ok {
		err = errors.Join(err, errors.New("participants missing"))
	} else {
		for _, v := range list.Value {
			m, ok := v.(*types.AttributeValueMemberM)
			if !ok {
				err = errors.Join(err, errors.New("participant is not a map"))
				continue
			}
			var p groupstore.Participant
			var role string
			var state int64
			err = errors.Join(err,
				getString(m.Value, attrIdentity, &p.Identity, true),
				getString(m.Value, attrName, &p.DisplayName, false),
				getString(m.Value, attrRole, &role, true),
				getString(m.Value, attrAddedBy, &p.AddedBy, false),
				getNum(m.Value, attrState, &state),
				getTime(m.Value, attrSince, &p.Since),
			)
			p.Role, p.State = groupstore.Role(role), groupstore.State(state)
			g.Participants = append(g.Participants, p)
		}
	}
	if l, ok := item[attrRemoved].(*types.AttributeValueMemberL); ok {
		for _, v := range l.Value {
			id, ok := v.(*types.AttributeValueMemberS)
			if !ok {
				err = errors.Join(err, errors.New("removed identity is not a string"))
				continue
			}
			g.Removed = append(g.Removed, id.Value)
		}
	}
	if err != nil {
		return groupstore.Group{}, "", fmt.Errorf("awsstore: decoding a group: %w", err)
	}
	g.Version = uint32(version)
	return g, token, nil
}

// Create implements groupstore.Store.
func (s *Groups) Create(ctx context.Context, g groupstore.Group, token string, now time.Time) error {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(s.table),
		Item:                      encodeGroup(g, 1, token),
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #expires <= :now"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpires},
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": stamp(now)},
	})
	if errorCode(err) == conditionFailed {
		cur, curToken, err := s.read(ctx, "create group", g.URI)
		if err != nil {
			return err
		}
		if cur.Rev == 1 && curToken == token {
			// The SDK repeated a create whose answer was lost.
			return nil
		}
		return fmt.Errorf("awsstore: create group: %w", groupstore.ErrExists)
	}
	if err != nil {
		return sanitize("create group", err)
	}
	return nil
}

func (s *Groups) read(ctx context.Context, op, uri string) (groupstore.Group, string, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: groupKey(uri), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return groupstore.Group{}, "", sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return groupstore.Group{}, "", fmt.Errorf("awsstore: %s: %w", op, groupstore.ErrNotFound)
	}
	return decodeGroup(uri, out.Item)
}

// Get implements groupstore.Store.
func (s *Groups) Get(ctx context.Context, uri string, now time.Time) (groupstore.Group, error) {
	g, _, err := s.read(ctx, "get group", uri)
	if err != nil {
		return groupstore.Group{}, err
	}
	if !g.Expires.After(now) {
		return groupstore.Group{}, fmt.Errorf("awsstore: get group: %w", groupstore.ErrNotFound)
	}
	return g, nil
}

// Update implements groupstore.Store.
func (s *Groups) Update(ctx context.Context, g groupstore.Group, token string) error {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(s.table),
		Item:                      encodeGroup(g, g.Rev+1, token),
		ConditionExpression:       aws.String("#rev = :rev"),
		ExpressionAttributeNames:  map[string]string{"#rev": attrRev},
		ExpressionAttributeValues: map[string]types.AttributeValue{":rev": num(g.Rev)},
	})
	if errorCode(err) == conditionFailed {
		cur, curToken, err := s.read(ctx, "update group", g.URI)
		if err != nil {
			return err
		}
		if cur.Rev == g.Rev+1 && curToken == token {
			// The SDK repeated an update whose answer was lost.
			return nil
		}
		return fmt.Errorf("awsstore: update group: %w", groupstore.ErrConflict)
	}
	if err != nil {
		return sanitize("update group", err)
	}
	return nil
}

// Touch implements groupstore.Store.
func (s *Groups) Touch(ctx context.Context, uri string, active, expires time.Time) error {
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              groupKey(uri),
		UpdateExpression: aws.String("SET #active = :active, #expires = :expires, #ttl = :ttl"),
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND #expires > :active AND #active < :active AND #expires < :expires"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#active": attrActive, "#expires": attrExpires, "#ttl": attrTTL,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":active": stamp(active), ":expires": stamp(expires), ":ttl": ttlOf(expires.Add(retained)),
		},
	})
	if errorCode(err) == conditionFailed {
		g, _, err := s.read(ctx, "touch group", uri)
		if err != nil {
			return err
		}
		if !g.Expires.After(active) {
			return fmt.Errorf("awsstore: touch group: %w", groupstore.ErrNotFound)
		}
		// Already as recent: nothing to move.
		return nil
	}
	if err != nil {
		return sanitize("touch group", err)
	}
	return nil
}
