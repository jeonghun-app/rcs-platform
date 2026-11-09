package awsstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

// A table that fails is an error of its own, never "no alias", and its
// message names the operation and the code only.
func TestASubscribersTableThatFailsIsAnError(t *testing.T) {
	s := NewSubscribers(&stubDynamo{err: &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "at 10.0.0.1"}}, "maap-subscribers")
	ctx := context.Background()
	a := storetest.Alias("cb-1", storetest.Subscriber, false, time.Unix(1, 0))
	_, err1 := s.Alias(ctx, a)
	_, err2 := s.Resolve(ctx, a.Chatbot, a.ID, time.Unix(1, 0))
	for _, err := range []error{err1, err2, s.Used(ctx, a, time.Unix(2, 0)), s.DeleteChatbot(ctx, "cb-1"), s.Ready(ctx)} {
		if err == nil || errors.Is(err, store.ErrNotFound) || strings.Contains(err.Error(), "10.0.0.1") ||
			!strings.Contains(err.Error(), "ProvisionedThroughputExceededException") {
			t.Errorf("error %v", err)
		}
	}
}

// A stored alias is read strictly, from either of its items: one that is
// not whole is damaged, never an alias of another form or subscriber.
func FuzzDecodeAlias(f *testing.F) {
	id := strings.Repeat("a2", store.AliasIDBytes/2) // made at run time, as no alias is written (#714)
	f.Add(id, "tel:+15550100001", true, "1", "2")
	f.Add("", "", false, "", "")
	f.Add(strings.ToUpper(id), "tel:+1x", true, "-1", "1e3")
	// Whole but for the alias ID, or but for the subscriber.
	f.Add(strings.ToUpper(id), "tel:+15550100001", false, "1", "2")
	f.Add(id, "tel:+1x", false, "1", "2")
	f.Fuzz(func(t *testing.T, aliasID, subscriber string, anonymous bool, created, used string) {
		item := key("x", "y")
		item[attrAlias], item[attrSubscriber] = str(aliasID), str(subscriber)
		item[attrAnonymous] = &types.AttributeValueMemberBOOL{Value: anonymous}
		item[attrCreated], item[attrUsed] = &types.AttributeValueMemberN{Value: created}, &types.AttributeValueMemberN{Value: used}
		kind := store.Alias{Chatbot: "cb-1", Subscriber: storetest.Subscriber}
		for i, decode := range []func() (store.Alias, error){
			func() (store.Alias, error) { return decodeAlias(kind, item) },
			func() (store.Alias, error) { return decodeChatbotAlias("cb-1", aliasID, item) },
		} {
			a, err := decode()
			if err != nil {
				if !errors.Is(err, store.ErrInvalid) {
					t.Fatalf("decoder %d: error %v", i, err)
				}
				continue
			}
			wantSubscriber, wantAnonymous := storetest.Subscriber, false
			if i == 1 {
				wantSubscriber, wantAnonymous = subscriber, anonymous
			}
			if a.ID != aliasID || !store.ValidAliasID(a.ID) || a.Chatbot != "cb-1" || a.Subscriber != wantSubscriber ||
				!store.ValidSubscriber(a.Subscriber) || a.Anonymous != wantAnonymous ||
				a.Created.Location() != time.UTC || a.LastUsed.Location() != time.UTC {
				t.Fatalf("decoder %d: %+v from %q %q %q %q", i, a, aliasID, subscriber, created, used)
			}
		}
	})
}
