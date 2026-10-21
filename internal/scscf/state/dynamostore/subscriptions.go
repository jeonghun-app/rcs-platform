package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

func (d *Dynamo) subscriptionItem(s *state.Subscription, version int64) (map[string]types.AttributeValue, error) {
	doc, err := encodeSubscription(s)
	if err != nil {
		return nil, err
	}
	item := map[string]types.AttributeValue{
		attrPK:         str(s.ID),
		attrVersion:    num(version),
		attrDoc:        bin(doc),
		attrWriter:     str(d.token()),
		attrIMPU:       str(s.IMPU),
		attrCSeq:       num(int64(s.CSeq)),
		attrRver:       num(int64(s.ReginfoVersion)),
		attrNotifiedOf: num(s.NotifiedOf),
		attrShard:      str(shardOf(s.ID)),
		attrExpires:    num(s.Expires.Unix()),
	}
	return item, checkSize(item, "subscription")
}

func decodeSubscriptionItem(item map[string]types.AttributeValue) (*state.Subscription, error) {
	doc, err := docOf(item)
	if err != nil {
		return nil, err
	}
	version, err := nv(item, attrVersion)
	if err != nil {
		return nil, err
	}
	cseq, err := counter(item, attrCSeq)
	if err != nil {
		return nil, err
	}
	rver, err := counter(item, attrRver)
	if err != nil {
		return nil, err
	}
	var of int64
	if _, ok := item[attrNotifiedOf]; ok {
		if of, err = nv(item, attrNotifiedOf); err != nil {
			return nil, err
		}
	}
	s, err := decodeSubscription(doc, version, cseq, rver)
	if err != nil {
		return nil, err
	}
	s.NotifiedOf = of
	return s, nil
}

func counter(item map[string]types.AttributeValue, name string) (uint32, error) {
	v, err := nv(item, name)
	if err != nil {
		return 0, err
	}
	if v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %s out of range", state.ErrInvalid, name)
	}
	return uint32(v), nil
}

// Subscription implements state.Subscriptions.
func (d *Dynamo) Subscription(ctx context.Context, id string) (*state.Subscription, error) {
	if !state.KeyOK(id, state.MaxKey) {
		return nil, fmt.Errorf("dynamostore: get subscription: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.subscriptions, key(id), "get subscription")
	if err != nil {
		return nil, err
	}
	return decodeSubscriptionItem(item)
}

// SubscriptionsOf implements state.Subscriptions.
func (d *Dynamo) SubscriptionsOf(ctx context.Context, impu string) ([]*state.Subscription, error) {
	if !state.KeyOK(impu, state.MaxKey) {
		return nil, nil
	}
	items, err := d.byIndex(ctx, d.subscriptions, IMPUIndex, attrIMPU, impu, "query subscriptions of an IMPU")
	if err != nil {
		return nil, err
	}
	out, err := decodeAll(items, decodeSubscriptionItem)
	slices.SortFunc(out, func(a, b *state.Subscription) int { return strings.Compare(a.ID, b.ID) })
	return out, err
}

// SaveSubscription implements state.Subscriptions.
func (d *Dynamo) SaveSubscription(ctx context.Context, s *state.Subscription) (*state.Subscription, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	version, err := d.nextVersion(s.Version)
	if err != nil {
		return nil, err
	}
	item, err := d.subscriptionItem(s, version)
	if err != nil {
		return nil, err
	}
	if err := d.putVersioned(ctx, d.subscriptions, s.ID, s.Version, item, "save subscription"); err != nil {
		return nil, err
	}
	saved := s.Clone()
	saved.Version = version
	return saved, nil
}

// DeleteSubscription implements state.Subscriptions.
func (d *Dynamo) DeleteSubscription(ctx context.Context, s *state.Subscription) error {
	if !state.KeyOK(s.ID, state.MaxKey) {
		return fmt.Errorf("dynamostore: delete subscription: %w", state.ErrNotFound)
	}
	return d.deleteVersioned(ctx, d.subscriptions, s.ID, s.Version, "delete subscription")
}

// NextNotify implements state.Subscriptions with one UpdateItem that adds 1
// to both counters and the version, below state.MaxCounter. The token makes it
// idempotent: a resent update finds its own token and fails its condition, and
// the values the first attempt produced are read back.
func (d *Dynamo) NextNotify(ctx context.Context, id string, of int64) (uint32, uint32, error) {
	if !state.KeyOK(id, state.MaxKey) {
		return 0, 0, fmt.Errorf("dynamostore: next notify: %w", state.ErrNotFound)
	}
	tok := d.token()
	out, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(d.subscriptions),
		Key:                 key(id),
		UpdateExpression:    aws.String("SET #tok = :tok, #v = #v + :one, #of = :of ADD #cseq :one, #rver :one"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND (attribute_not_exists(#tok) OR #tok <> :tok) AND #cseq < :max AND #rver < :max AND (attribute_not_exists(#of) OR (#of <= :of AND #of < :final))"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#tok": attrNToken, "#v": attrVersion, "#cseq": attrCSeq, "#rver": attrRver, "#of": attrNotifiedOf,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{":tok": str(tok), ":one": num(1), ":max": num(state.MaxCounter), ":of": num(of), ":final": num(state.FinalNotify)},
		ReturnValues:              types.ReturnValueAllNew,
	})
	var item map[string]types.AttributeValue
	switch {
	case ccf(err):
		cur, err := d.get(ctx, d.subscriptions, key(id), "next notify")
		if err != nil {
			return 0, 0, err
		}
		c, _ := nv(cur, attrCSeq)
		r, _ := nv(cur, attrRver)
		last, _ := nv(cur, attrNotifiedOf)
		switch {
		case tok != "" && sv(cur[attrNToken]) == tok:
			// An earlier attempt of this call succeeded.
		case c >= state.MaxCounter || r >= state.MaxCounter:
			return 0, 0, fmt.Errorf("dynamostore: next notify: %w", state.ErrExhausted)
		case last > of || last == state.FinalNotify:
			return 0, 0, fmt.Errorf("dynamostore: next notify: %w", state.ErrStale)
		default:
			// Unreachable unless the item went and came back between the two
			// requests; the caller asks again.
			return 0, 0, fmt.Errorf("dynamostore: next notify: %w", state.ErrConflict)
		}
		item = cur
	case err != nil:
		return 0, 0, sanitize("next notify", err)
	default:
		item = out.Attributes
	}
	cseq, err := counter(item, attrCSeq)
	if err != nil {
		return 0, 0, err
	}
	rver, err := counter(item, attrRver)
	if err != nil {
		return 0, 0, err
	}
	return cseq, rver, nil
}

// ExpiringSubscriptions implements state.Subscriptions.
func (d *Dynamo) ExpiringSubscriptions(ctx context.Context, now time.Time, limit int) ([]*state.Subscription, error) {
	var out []*state.Subscription
	var decodeErr error
	_, err := d.expiring(ctx, d.subscriptions, now, limit, func(item map[string]types.AttributeValue) bool {
		s, err := decodeSubscriptionItem(item)
		if err != nil {
			decodeErr = errors.Join(decodeErr, err)
			return false
		}
		if s.Expires.After(now) {
			return false
		}
		out = append(out, s)
		return true
	}, "query expiring subscriptions")
	if err != nil {
		return nil, err
	}
	return out, decodeErr
}
