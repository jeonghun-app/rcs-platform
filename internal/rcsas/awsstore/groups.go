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
//
// Next to it, a small item names the group's owner (#121), so that the
// fence of every write reads a few hundred bytes, not the group:
//
//	pk g#<len(uri)>#<uri>  sk owner      task, sip, epoch, wtoken, ttl
//
// Create, Update and Touch are transactions of the group's write and an
// update of the owner item's ttl on the condition that it still names the
// writer's task and epoch; TakeOver is a conditional update of it. Each
// task's heartbeat is an item of its own:
//
//	pk t#<len(id)>#<id>    sk task       sip, alive_until, ttl

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
	attrTask         = "task"
	attrSIP          = "sip"
	attrEpoch        = "epoch"
	attrAliveUntil   = "alive_until"
)

const (
	groupPrefix = "g#"
	groupSK     = "group"
	ownerSK     = "owner"
	taskPrefix  = "t#"
	taskSK      = "task"
)

// fenceCondition is the owner item's condition in every group write.
const fenceCondition = "#task = :task AND #epoch = :epoch"

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

func ownerKey(uri string) map[string]types.AttributeValue {
	return key(identityKey(groupPrefix, uri), ownerSK)
}

// fence is the update of uri's owner item that a write by owner carries:
// it moves the item's ttl along with the group's, if the item still names
// owner.
func (s *Groups) fence(uri string, owner groupstore.Owner, expires time.Time) types.TransactWriteItem {
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                aws.String(s.table),
		Key:                      ownerKey(uri),
		UpdateExpression:         aws.String("SET #ttl = :ttl"),
		ConditionExpression:      aws.String(fenceCondition),
		ExpressionAttributeNames: map[string]string{"#task": attrTask, "#epoch": attrEpoch, "#ttl": attrTTL},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":task": str(owner.Task), ":epoch": num(owner.Epoch), ":ttl": ttlOf(expires.Add(retained)),
		},
	}}
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
func (s *Groups) Create(ctx context.Context, g groupstore.Group, owner groupstore.Owner, token string, now time.Time) error {
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:                 aws.String(s.table),
			Item:                      encodeGroup(g, 1, token),
			ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #expires <= :now"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpires},
			ExpressionAttributeValues: map[string]types.AttributeValue{":now": stamp(now)},
		}},
		// An expired group's owner, if its item is still there, is
		// replaced: the new group is its creator's, at the epoch after
		// the old one's, which a late write of the old group still holds.
		{Update: &types.Update{
			TableName:        aws.String(s.table),
			Key:              ownerKey(g.URI),
			UpdateExpression: aws.String("SET #task = :task, #sip = :sip, #token = :token, #ttl = :ttl ADD #epoch :one"),
			ExpressionAttributeNames: map[string]string{
				"#task": attrTask, "#sip": attrSIP, "#token": attrToken, "#ttl": attrTTL, "#epoch": attrEpoch,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":task": str(owner.Task), ":sip": str(owner.SIP), ":token": str(token), ":ttl": ttlOf(g.Expires.Add(retained)), ":one": num(1),
			},
		}},
	}})
	if failed, ok := canceled(err); ok && len(failed) > 0 && failed[0] {
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
	if conflicted(err) {
		return fmt.Errorf("awsstore: create group: %w", groupstore.ErrConflict)
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
func (s *Groups) Update(ctx context.Context, g groupstore.Group, owner groupstore.Owner, token string) error {
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:                 aws.String(s.table),
			Item:                      encodeGroup(g, g.Rev+1, token),
			ConditionExpression:       aws.String("#rev = :rev"),
			ExpressionAttributeNames:  map[string]string{"#rev": attrRev},
			ExpressionAttributeValues: map[string]types.AttributeValue{":rev": num(g.Rev)},
		}},
		s.fence(g.URI, owner, g.Expires),
	}})
	failed, ok := canceled(err)
	if ok && len(failed) == 2 && (failed[0] || failed[1]) {
		cur, curToken, err := s.read(ctx, "update group", g.URI)
		switch {
		case err != nil:
			return err
		case cur.Rev == g.Rev+1 && curToken == token:
			// The SDK repeated an update whose answer was lost.
			return nil
		case failed[1]:
			return fmt.Errorf("awsstore: update group: %w", groupstore.ErrNotOwner)
		}
		return fmt.Errorf("awsstore: update group: %w", groupstore.ErrConflict)
	}
	if conflicted(err) {
		return fmt.Errorf("awsstore: update group: %w", groupstore.ErrConflict)
	}
	if err != nil {
		return sanitize("update group", err)
	}
	return nil
}

// Touch implements groupstore.Store.
func (s *Groups) Touch(ctx context.Context, uri string, owner groupstore.Owner, active, expires time.Time) error {
	_, err := s.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
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
		}},
		s.fence(uri, owner, expires),
	}})
	failed, ok := canceled(err)
	if ok && len(failed) == 2 && (failed[0] || failed[1]) {
		g, _, err := s.read(ctx, "touch group", uri)
		switch {
		case err != nil:
			return err
		case !g.Expires.After(active):
			return fmt.Errorf("awsstore: touch group: %w", groupstore.ErrNotFound)
		case failed[1]:
			return fmt.Errorf("awsstore: touch group: %w", groupstore.ErrNotOwner)
		}
		// Already as recent: nothing to move.
		return nil
	}
	if conflicted(err) {
		return fmt.Errorf("awsstore: touch group: %w", groupstore.ErrConflict)
	}
	if err != nil {
		return sanitize("touch group", err)
	}
	return nil
}

// Owner implements groupstore.Store.
func (s *Groups) Owner(ctx context.Context, uri string) (groupstore.Owner, error) {
	o, _, err := s.readOwner(ctx, "group owner", uri)
	return o, err
}

func (s *Groups) readOwner(ctx context.Context, op, uri string) (groupstore.Owner, string, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: ownerKey(uri), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return groupstore.Owner{}, "", sanitize(op, err)
	}
	if len(out.Item) == 0 {
		return groupstore.Owner{}, "", nil
	}
	var o groupstore.Owner
	var token string
	if err := errors.Join(
		getString(out.Item, attrTask, &o.Task, true),
		getString(out.Item, attrSIP, &o.SIP, false),
		getString(out.Item, attrToken, &token, false),
		getNum(out.Item, attrEpoch, &o.Epoch),
	); err != nil {
		return groupstore.Owner{}, "", fmt.Errorf("awsstore: decoding a group owner: %w", err)
	}
	return o, token, nil
}

// TakeOver implements groupstore.Store.
func (s *Groups) TakeOver(ctx context.Context, uri string, from, to groupstore.Owner, expires time.Time, token string) (groupstore.Owner, error) {
	to.Epoch = from.Epoch + 1
	cond, names := "attribute_not_exists(#pk)", map[string]string{"#pk": attrPK}
	values := map[string]types.AttributeValue{
		":to": str(to.Task), ":sip": str(to.SIP), ":next": num(to.Epoch), ":token": str(token), ":ttl": ttlOf(expires.Add(retained)),
	}
	if from.Task != "" {
		cond, names = fenceCondition, map[string]string{}
		values[":task"], values[":epoch"] = str(from.Task), num(from.Epoch)
	}
	names["#task"], names["#sip"], names["#epoch"], names["#token"], names["#ttl"] = attrTask, attrSIP, attrEpoch, attrToken, attrTTL
	_, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       ownerKey(uri),
		UpdateExpression:          aws.String("SET #task = :to, #sip = :sip, #epoch = :next, #token = :token, #ttl = :ttl"),
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if errorCode(err) == conditionFailed || conflicted(err) {
		cur, curToken, rerr := s.readOwner(ctx, "take over group", uri)
		if rerr != nil {
			return groupstore.Owner{}, rerr
		}
		if cur.Task == to.Task && cur.Epoch == to.Epoch && curToken == token {
			// The SDK repeated a takeover whose answer was lost.
			return cur, nil
		}
		return groupstore.Owner{}, fmt.Errorf("awsstore: take over group: %w", groupstore.ErrConflict)
	}
	if err != nil {
		return groupstore.Owner{}, sanitize("take over group", err)
	}
	return to, nil
}

func taskKey(id string) map[string]types.AttributeValue {
	return key(identityKey(taskPrefix, id), taskSK)
}

// Beat implements groupstore.Store. A task's item outlives its last
// heartbeat by a day, then DynamoDB's TTL deletes it.
func (s *Groups) Beat(ctx context.Context, t groupstore.Task) error {
	item := taskKey(t.ID)
	item[attrAliveUntil], item[attrTTL] = stamp(t.AliveUntil), ttlOf(t.AliveUntil.Add(retained))
	if t.SIP != "" {
		item[attrSIP] = str(t.SIP)
	}
	if _, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item}); err != nil {
		return sanitize("task heartbeat", err)
	}
	return nil
}

// Task implements groupstore.Store.
func (s *Groups) Task(ctx context.Context, id string) (groupstore.Task, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: taskKey(id), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return groupstore.Task{}, sanitize("task", err)
	}
	if len(out.Item) == 0 {
		return groupstore.Task{}, fmt.Errorf("awsstore: task: %w", groupstore.ErrNotFound)
	}
	t := groupstore.Task{ID: id}
	if err := errors.Join(getString(out.Item, attrSIP, &t.SIP, false), getTime(out.Item, attrAliveUntil, &t.AliveUntil)); err != nil {
		return groupstore.Task{}, fmt.Errorf("awsstore: decoding a task: %w", err)
	}
	return t, nil
}
