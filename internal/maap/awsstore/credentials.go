package awsstore

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Credentials is a store.Credentials in the maap-registry table, beside
// the registry (see the package documentation): a credential is a slot
// item in its chatbot's partition, sk k#1 or k#2, naming its key ID, and
// its key item, pk k#<key ID>, which a lookup by key ID reads. Issuing
// writes both in one transaction with a check of the chatbot's
// registration; taking a free slot is what keeps a chatbot at
// store.MaxCredentials.
type Credentials struct{ r *Registry }

var _ store.Credentials = Credentials{}

// Credentials returns the credentials kept in r's table.
func (r *Registry) Credentials() Credentials { return Credentials{r} }

// Attribute names of credential items.
const (
	attrKey     = "key"
	attrDigest  = "digest"
	attrCreated = "created"
	attrUsed    = "last_used"
	skKey       = "key"
	skSlot      = "k#"
)

func keyKey(keyID string) map[string]types.AttributeValue { return key("k#"+keyID, skKey) }

func slotKey(chatbotID string, slot int) map[string]types.AttributeValue {
	return key("c#"+chatbotID, skSlot+strconv.Itoa(slot))
}

// Issue implements store.Credentials. A slot taken by this call's own
// earlier send, whose answer was lost, is found by its writer token.
func (c Credentials) Issue(ctx context.Context, cred store.Credential) error {
	if !store.ValidKeyID(cred.KeyID) || !store.ValidID(cred.Chatbot) {
		return fmt.Errorf("%w: a malformed key ID or chatbot ID", store.ErrInvalid)
	}
	writer := rand.Text()
	keyItem := keyKey(cred.KeyID)
	keyItem[attrChatbot], keyItem[attrRegistration] = str(cred.Chatbot), str(cred.Registration)
	keyItem[attrDigest] = &types.AttributeValueMemberB{Value: cred.Digest[:]}
	keyItem[attrCreated], keyItem[attrWriter] = num(cred.Created.Unix()), str(writer)
	absent, names := aws.String("attribute_not_exists(#pk)"), map[string]string{"#pk": attrPK}
	// stale is the key ID a slot names whose key item is gone: the issue
	// takes the slot over, on the condition that it still names it.
	for slot, attempts, stale := 1, 0, ""; slot <= store.MaxCredentials; attempts++ {
		slotItem := slotKey(cred.Chatbot, slot)
		slotItem[attrKey], slotItem[attrWriter] = str(cred.KeyID), str(writer)
		take := &types.Put{
			TableName: aws.String(c.r.table), Item: slotItem, ConditionExpression: absent, ExpressionAttributeNames: names,
			ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
		}
		items := []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.r.table), Key: chatbotKey(cred.Chatbot),
				ConditionExpression:       aws.String("#reg = :reg"),
				ExpressionAttributeNames:  map[string]string{"#reg": attrRegistration},
				ExpressionAttributeValues: map[string]types.AttributeValue{":reg": str(cred.Registration)},
			}},
			{Put: take},
			{Put: &types.Put{TableName: aws.String(c.r.table), Item: keyItem, ConditionExpression: absent, ExpressionAttributeNames: names}},
		}
		if stale != "" {
			take.ConditionExpression = aws.String("attribute_not_exists(#pk) OR #key = :stale")
			take.ExpressionAttributeNames = map[string]string{"#pk": attrPK, "#key": attrKey}
			take.ExpressionAttributeValues = map[string]types.AttributeValue{":stale": str(stale)}
			items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.r.table), Key: keyKey(stale), ConditionExpression: absent, ExpressionAttributeNames: names,
			}})
		}
		_, err := c.r.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: aws.String(rand.Text()), TransactItems: items,
		})
		reasons := cancelled(err)
		switch {
		case len(reasons) >= 3 && failed(reasons[0]):
			// No record, a tombstone, or (never, as IDs are not used
			// again) another registration.
			return fmt.Errorf("awsstore: issue credential: %w", store.ErrNotFound)
		case len(reasons) >= 3 && failed(reasons[1]) && sv(reasons[1].Item[attrWriter]) == writer:
			return nil // the SDK sent again an issue that had taken effect
		case len(reasons) >= 3 && failed(reasons[1]):
			held := sv(reasons[1].Item[attrKey])
			if held != stale && store.ValidKeyID(held) {
				gone, err := c.r.keyGone(ctx, held)
				if err != nil {
					return err
				}
				if gone {
					stale = held
					continue
				}
			}
			slot, stale = slot+1, ""
		case len(reasons) == 4 && failed(reasons[3]):
			slot, stale = slot+1, ""
		case len(reasons) >= 3 && failed(reasons[2]):
			return fmt.Errorf("%w: the key ID is taken", store.ErrInvalid)
		case raced(err) && attempts < conflictAttempts-1:
			// Another write on the record or the slot: the same slot again.
		case raced(err):
			return fmt.Errorf("awsstore: issue credential: %w", store.ErrConflict)
		case err != nil:
			return sanitize("issue credential", err)
		default:
			return nil
		}
	}
	return fmt.Errorf("awsstore: issue credential: %w", store.ErrTooMany)
}

// Credential implements store.Credentials.
func (c Credentials) Credential(ctx context.Context, keyID string) (store.Credential, error) {
	if !store.ValidKeyID(keyID) {
		return store.Credential{}, fmt.Errorf("awsstore: get credential: %w", store.ErrNotFound)
	}
	out, err := c.r.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(c.r.table), Key: keyKey(keyID), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return store.Credential{}, sanitize("get credential", err)
	}
	if len(out.Item) == 0 {
		return store.Credential{}, fmt.Errorf("awsstore: get credential: %w", store.ErrNotFound)
	}
	return decodeCredential(keyID, out.Item)
}

func decodeCredential(keyID string, item map[string]types.AttributeValue) (store.Credential, error) {
	cred := store.Credential{KeyID: keyID, Chatbot: sv(item[attrChatbot]), Registration: sv(item[attrRegistration])}
	digest, ok := item[attrDigest].(*types.AttributeValueMemberB)
	created, err := strconv.ParseInt(sv(item[attrCreated]), 10, 64)
	if !ok || len(digest.Value) != sha256.Size || err != nil || !store.ValidID(cred.Chatbot) {
		return store.Credential{}, fmt.Errorf("%w: a damaged credential", store.ErrInvalid)
	}
	copy(cred.Digest[:], digest.Value)
	cred.Created = time.Unix(created, 0).UTC()
	if used, err := strconv.ParseInt(sv(item[attrUsed]), 10, 64); err == nil {
		cred.LastUsed = time.Unix(used, 0).UTC()
	}
	return cred, nil
}

// ChatbotCredentials implements store.Credentials.
func (c Credentials) ChatbotCredentials(ctx context.Context, chatbotID string) ([]store.Credential, error) {
	var creds []store.Credential
	err := c.r.eachItem(ctx, chatbotID, skSlot, func(slot map[string]types.AttributeValue) error {
		cred, err := c.Credential(ctx, sv(slot[attrKey]))
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil // revoked or deleted after this read, or half deleted
		case err != nil:
			return err
		}
		creds = append(creds, cred)
		return nil
	})
	slices.SortFunc(creds, func(a, b store.Credential) int {
		return cmp.Or(a.Created.Compare(b.Created), cmp.Compare(a.KeyID, b.KeyID))
	})
	return creds, err
}

// Revoke implements store.Credentials. It reads the key item's chatbot
// only, so a damaged credential can be revoked too, then deletes every slot
// of the chatbot naming the key ID with its key item. A slot whose key item
// is gone is deleted too, and the answer is nil, so a revoke can always
// finish; ErrNotFound only when neither is there.
func (c Credentials) Revoke(ctx context.Context, chatbotID, keyID string) error {
	notFound := fmt.Errorf("awsstore: revoke credential: %w", store.ErrNotFound)
	if !store.ValidKeyID(keyID) {
		return notFound
	}
	out, err := c.r.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.r.table), Key: keyKey(keyID), ConsistentRead: aws.Bool(true),
		ProjectionExpression: aws.String("#chatbot"), ExpressionAttributeNames: map[string]string{"#chatbot": attrChatbot},
	})
	if err != nil {
		return sanitize("revoke credential", err)
	}
	if len(out.Item) != 0 && sv(out.Item[attrChatbot]) != chatbotID {
		return notFound
	}
	found := false
	err = c.r.eachItem(ctx, chatbotID, skSlot, func(slot map[string]types.AttributeValue) error {
		if sv(slot[attrKey]) != keyID {
			return nil
		}
		found = true
		return c.r.deleteSlot(ctx, chatbotID, slot)
	})
	switch {
	case err != nil:
		return err
	case found:
		return nil
	case len(out.Item) != 0:
		// A key item without a slot, which no write leaves, still
		// authenticates: it goes all the same.
		_, err := c.r.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.r.table), Key: keyKey(keyID)})
		if err != nil {
			return sanitize("revoke credential", err)
		}
		return nil
	}
	return notFound
}

// keyGone reports whether the key item of keyID is absent.
func (r *Registry) keyGone(ctx context.Context, keyID string) (bool, error) {
	out, err := r.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.table), Key: keyKey(keyID), ConsistentRead: aws.Bool(true),
		ProjectionExpression: aws.String("#pk"), ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	})
	if err != nil {
		return false, sanitize("issue credential", err)
	}
	return len(out.Item) == 0, nil
}

// Used implements store.Credentials.
func (c Credentials) Used(ctx context.Context, keyID string, at time.Time) error {
	if !store.ValidKeyID(keyID) {
		return nil
	}
	_, err := c.r.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.r.table), Key: keyKey(keyID),
		UpdateExpression:          aws.String("SET #used = :at"),
		ConditionExpression:       aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames:  map[string]string{"#used": attrUsed, "#pk": attrPK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":at": num(at.Unix())},
	})
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return sanitize("record credential use", err)
	}
	return nil
}

// DeleteChatbot implements store.ChatbotDeleter. It does what the
// registry's deletion did after the tombstone, so it finds nothing then,
// but finishes a deletion that stopped part way.
func (c Credentials) DeleteChatbot(ctx context.Context, chatbotID string) error {
	return c.r.eachItem(ctx, chatbotID, skSlot, func(slot map[string]types.AttributeValue) error {
		return c.r.deleteSlot(ctx, chatbotID, slot)
	})
}

// deleteSlot deletes a credential: its key item and its slot in one
// transaction (#744 review: two steps could leave a slot naming no key),
// on the conditions that the key item is not another chatbot's (never, as
// key IDs are random) and that the slot still names the key ID. A slot
// without a key ID is deleted as it is.
func (r *Registry) deleteSlot(ctx context.Context, chatbotID string, slot map[string]types.AttributeValue) error {
	keyID, slotKey := sv(slot[attrKey]), key(sv(slot[attrPK]), sv(slot[attrSK]))
	if keyID == "" {
		if _, err := r.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.table), Key: slotKey}); err != nil {
			return sanitize("delete chatbot", err)
		}
		return nil
	}
	for attempt := 0; ; attempt++ {
		_, err := r.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: aws.String(rand.Text()),
			TransactItems: []types.TransactWriteItem{
				{Delete: &types.Delete{
					TableName: aws.String(r.table), Key: keyKey(keyID),
					ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #chatbot = :id"),
					ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#chatbot": attrChatbot},
					ExpressionAttributeValues: map[string]types.AttributeValue{":id": str(chatbotID)},
				}},
				{Delete: &types.Delete{
					TableName: aws.String(r.table), Key: slotKey,
					ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #key = :key"),
					ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#key": attrKey},
					ExpressionAttributeValues: map[string]types.AttributeValue{":key": str(keyID)},
				}},
			},
		})
		switch reasons := cancelled(err); {
		case len(reasons) == 2 && failed(reasons[0]):
			return fmt.Errorf("%w: a key item of another chatbot", store.ErrInvalid)
		case len(reasons) == 2 && failed(reasons[1]):
			// The slot names another key since: this one went with its slot.
			return nil
		case raced(err) && attempt < conflictAttempts-1:
			continue
		case err != nil:
			return sanitize("delete credential", err)
		}
		return nil
	}
}

// eachItem calls f on each item of the chatbot's partition whose sort key
// starts with prefix, with its key and key ID only.
func (r *Registry) eachItem(ctx context.Context, chatbotID, prefix string, f func(map[string]types.AttributeValue) error) error {
	in := &dynamodb.QueryInput{
		TableName: aws.String(r.table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#pk, #sk, #key"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK, "#key": attrKey},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str("c#" + chatbotID)},
	}
	if prefix != "" {
		in.KeyConditionExpression = aws.String("#pk = :pk AND begins_with(#sk, :prefix)")
		in.ExpressionAttributeValues[":prefix"] = str(prefix)
	}
	if r.pageSize > 0 {
		in.Limit = aws.Int32(r.pageSize)
	}
	for {
		out, err := r.api.Query(ctx, in)
		if err != nil {
			return sanitize("query chatbot", err)
		}
		for _, it := range out.Items {
			if err := f(it); err != nil {
				return err
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}
