package dynamostore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

func challengeKey(impi, nonce string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: str(impi), attrSK: str(nonce)}
}

// challengeAAD binds a sealed challenge to its key. The length prefix keeps
// two different splits of the same bytes apart.
func challengeAAD(impi, nonce string) []byte {
	return fmt.Appendf(nil, "challenge:%d:%s%s", len(impi), impi, nonce)
}

// AddChallenge implements state.Challenges.
func (d *Dynamo) AddChallenge(ctx context.Context, c *state.Challenge) error {
	if err := c.Validate(); err != nil {
		return err
	}
	doc, err := encodeChallenge(c)
	if err != nil {
		return err
	}
	sealed, err := d.sealer.seal(d.rand, doc, challengeAAD(c.IMPI, c.Nonce))
	if err != nil {
		return err
	}
	item := challengeKey(c.IMPI, c.Nonce)
	item[attrDoc] = bin(sealed)
	item[attrWriter] = str(d.token())
	item[attrExpires] = num(c.Expires.Unix())
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                aws.String(d.challenges),
		Item:                     item,
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	switch {
	case ccf(err):
		return d.explain(ctx, d.challenges, challengeKey(c.IMPI, c.Nonce), item, true, "add challenge")
	case err != nil:
		return sanitize("add challenge", err)
	}
	return nil
}

func (d *Dynamo) decodeChallengeItem(item map[string]types.AttributeValue, impi, nonce string, now time.Time) (*state.Challenge, error) {
	doc, err := docOf(item)
	if err != nil {
		return nil, err
	}
	plain, err := d.sealer.open(doc, challengeAAD(impi, nonce))
	if err != nil {
		return nil, err
	}
	c, err := decodeChallenge(plain, impi, nonce)
	if err != nil {
		return nil, err
	}
	if !c.Expires.After(now) {
		return nil, fmt.Errorf("dynamostore: challenge: %w", state.ErrNotFound)
	}
	return c, nil
}

// TakeChallenge implements state.Challenges with one conditional delete that
// returns the deleted item: DynamoDB applies it to the item once, so of two
// instances taking the same challenge only one gets it back.
func (d *Dynamo) TakeChallenge(ctx context.Context, impi, nonce string, now time.Time) (*state.Challenge, error) {
	if !state.KeyOK(impi, state.MaxKey) || !state.KeyOK(nonce, state.MaxNonce) || strings.HasPrefix(nonce, state.ReservedNoncePrefix) {
		// A key DynamoDB would refuse names no challenge, such as the empty
		// nonce of a first REGISTER (TS 24.229 §5.1.1.2.1), and neither does
		// an attempt count's: a client must not take, and so reset, one.
		return nil, fmt.Errorf("dynamostore: take challenge: %w", state.ErrNotFound)
	}
	out, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(d.challenges),
		Key:                      challengeKey(impi, nonce),
		ConditionExpression:      aws.String("attribute_exists(#pk) AND #exp > :now"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK, "#exp": attrExpires},
		// Whole seconds: a challenge in its last second is refused, never
		// one that has expired.
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": num(now.Unix())},
		ReturnValues:              types.ReturnValueAllOld,
	})
	switch {
	case ccf(err):
		return nil, fmt.Errorf("dynamostore: take challenge: %w", state.ErrNotFound)
	case err != nil:
		return nil, sanitize("take challenge", err)
	}
	if len(out.Attributes) == 0 {
		return nil, fmt.Errorf("dynamostore: take challenge: %w", state.ErrNotFound)
	}
	return d.decodeChallengeItem(out.Attributes, impi, nonce, now)
}

// attemptKey is the item of impi's count of kind for window, beside its
// challenges: sort key #count#<kind>#<window in Unix seconds>.
func attemptKey(impi, kind string, window time.Time) map[string]types.AttributeValue {
	return challengeKey(impi, state.ReservedNoncePrefix+"count#"+kind+"#"+strconv.FormatInt(window.Unix(), 10))
}

// CountAttempt implements state.Challenges with one UpdateItem that adds 1.
// expires is the table's TTL attribute, so DynamoDB removes old windows.
func (d *Dynamo) CountAttempt(ctx context.Context, impi, kind string, window, expires time.Time) (int64, error) {
	if err := state.ValidAttempt(impi, kind, window, expires); err != nil {
		return 0, err
	}
	out, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.challenges),
		Key:                       attemptKey(impi, kind, window),
		UpdateExpression:          aws.String("ADD #n :one SET #exp = :exp"),
		ExpressionAttributeNames:  map[string]string{"#n": attrCount, "#exp": attrExpires},
		ExpressionAttributeValues: map[string]types.AttributeValue{":one": num(1), ":exp": num(expires.Unix())},
		ReturnValues:              types.ReturnValueUpdatedNew,
	})
	if err != nil {
		return 0, sanitize("count attempt", err)
	}
	return nv(out.Attributes, attrCount)
}
