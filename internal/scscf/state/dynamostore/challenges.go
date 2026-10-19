package dynamostore

import (
	"context"
	"fmt"
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

// Challenge implements state.Challenges.
func (d *Dynamo) Challenge(ctx context.Context, impi, nonce string, now time.Time) (*state.Challenge, error) {
	item, err := d.get(ctx, d.challenges, challengeKey(impi, nonce), "get challenge")
	if err != nil {
		return nil, err
	}
	return d.decodeChallengeItem(item, impi, nonce, now)
}

// TakeChallenge implements state.Challenges with one conditional delete that
// returns the deleted item: DynamoDB applies it to the item once, so of two
// instances taking the same challenge only one gets it back.
func (d *Dynamo) TakeChallenge(ctx context.Context, impi, nonce string, now time.Time) (*state.Challenge, error) {
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
