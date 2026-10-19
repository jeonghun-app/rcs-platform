package awsstore

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

func TestTheGroupsStoreMeetsTheContractOverTheFake(t *testing.T) {
	storetest.Run(t, func(t *testing.T) groupstore.Store { return NewGroupsWithClient("groupchats", newFakeDynamo(t)) })
}

func TestARepeatedGroupUpdateThatTookEffectIsNotAConflict(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewGroupsWithClient("groupchats", lostAnswers{f})
	ctx := context.Background()
	g := groupstore.Group{URI: "sip:chat-1@conf.example.net", Version: 1, Created: t0, Active: t0, Expires: t0.Add(time.Hour),
		Participants: []groupstore.Participant{{Identity: "a", Role: groupstore.Chairman, State: groupstore.Joined, Since: t0}}}
	if err := NewGroupsWithClient("groupchats", putTwice{f}).Create(ctx, g, "c", t0); err != nil {
		t.Fatalf("repeated Create = %v", err)
	}
	got, err := s.Get(ctx, g.URI, t0)
	if err != nil {
		t.Fatal(err)
	}
	got.Subject = "x"
	// The fake applies the put and then answers a second time: the
	// second answer is the failed condition the SDK's retry would meet.
	if err := NewGroupsWithClient("groupchats", putTwice{f}).Update(ctx, got, "tok"); err != nil {
		t.Fatalf("Update = %v", err)
	}
	if err := s.Touch(ctx, g.URI, t0.Add(time.Minute), t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("Touch = %v", err)
	}
}

// putTwice performs every put twice and returns the second answer.
type putTwice struct{ *fakeDynamo }

func (p putTwice) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if _, err := p.fakeDynamo.PutItem(ctx, in, o...); err != nil {
		return nil, err
	}
	return p.fakeDynamo.PutItem(ctx, in, o...)
}

func TestEveryGroupOperationReportsAFailedRequest(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewGroupsWithClient("groupchats", f)
	ctx := context.Background()
	f.fail = &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException"}
	g := groupstore.Group{URI: "sip:chat-1@conf.example.net"}
	for name, op := range map[string]func() error{
		"Create": func() error { return s.Create(ctx, g, "c", t0) },
		"Get":    func() error { _, err := s.Get(ctx, g.URI, t0); return err },
		"Update": func() error { return s.Update(ctx, g, "t") },
		"Touch":  func() error { return s.Touch(ctx, g.URI, t0, t0) },
		"Ready":  func() error { return s.Ready(ctx) },
	} {
		if err := op(); err == nil || !strings.Contains(err.Error(), "ProvisionedThroughputExceededException") {
			t.Errorf("%s = %v", name, err)
		}
	}
}

func TestADamagedGroupIsReportedNotGuessed(t *testing.T) {
	f := newFakeDynamo(t)
	s := NewGroupsWithClient("groupchats", f)
	uri := "sip:chat-1@conf.example.net"
	base := encodeGroup(groupstore.Group{URI: uri, Expires: t0.Add(time.Hour),
		Participants: []groupstore.Participant{{Identity: "a", Role: groupstore.Member, State: groupstore.Joined}}}, 1, "")
	for name, damage := range map[string]func(map[string]dtypes.AttributeValue){
		"no participants": func(m map[string]dtypes.AttributeValue) { delete(m, attrParticipants) },
		"a participant not a map": func(m map[string]dtypes.AttributeValue) {
			m[attrParticipants] = &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{str("x")}}
		},
		"no revision": func(m map[string]dtypes.AttributeValue) { delete(m, attrRev) },
		"a participant without identity": func(m map[string]dtypes.AttributeValue) {
			m[attrParticipants] = &dtypes.AttributeValueMemberL{Value: []dtypes.AttributeValue{&dtypes.AttributeValueMemberM{Value: map[string]dtypes.AttributeValue{}}}}
		},
	} {
		item := map[string]dtypes.AttributeValue{}
		for k, v := range base {
			item[k] = v
		}
		damage(item)
		f.rows[rowKey(item)] = item
		if _, err := s.Get(context.Background(), uri, t0); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	t.Setenv("AWS_REGION", "us-east-1")
	if _, err := NewGroups(context.Background(), Config{Table: "groupchats", Endpoint: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
}

// largestGroup is a group of groupstore.MaxEntries participants with every
// field as long as rcs-as lets it be.
func largestGroup(at time.Time) groupstore.Group {
	long := func(prefix string, n int) string { return prefix + strings.Repeat("x", n-len(prefix)) }
	g := groupstore.Group{
		URI: "sip:chat-" + strings.Repeat("f", 32) + "@conf.example.net", Conversation: long("c", messaging.MaxIDLength),
		Subject: long("s", group.MaxSubjectLength), Creator: long("sip:creator", messaging.MaxIdentityLength),
		Version: 1, Created: at, Active: at, Expires: at.Add(time.Hour),
	}
	for i := range groupstore.MaxEntries {
		g.Participants = append(g.Participants, groupstore.Participant{
			Identity: long(fmt.Sprintf("sip:p%d", i), messaging.MaxIdentityLength), DisplayName: long("n", group.MaxDisplayNameLength),
			Role: groupstore.Chairman, State: groupstore.Removed, AddedBy: long("sip:adder", messaging.MaxIdentityLength), Since: at,
		})
	}
	return g
}

// itemSize is an upper bound on DynamoDB's size of an item: attribute
// names and string values count their bytes, a number at most 21, and a
// list or map 3 bytes plus 1 per element.
func itemSize(item map[string]dtypes.AttributeValue) int {
	n := 0
	for name, v := range item {
		n += len(name) + valueSize(v)
	}
	return n
}

func valueSize(v dtypes.AttributeValue) int {
	switch v := v.(type) {
	case *dtypes.AttributeValueMemberS:
		return len(v.Value)
	case *dtypes.AttributeValueMemberN:
		return 21
	case *dtypes.AttributeValueMemberL:
		n := 3
		for _, e := range v.Value {
			n += 1 + valueSize(e)
		}
		return n
	case *dtypes.AttributeValueMemberM:
		return 3 + len(v.Value) + itemSize(v.Value)
	}
	panic(fmt.Sprintf("no size for %T", v))
}

// The roster of a group is one item: the largest group rcs-as keeps must
// fit under DynamoDB's 400 KB item limit, with room to spare.
func TestTheLargestGroupFitsInOneItem(t *testing.T) {
	const limit = 400 * 1024
	if n := itemSize(encodeGroup(largestGroup(t0), 1, "0123456789abcdef")); n > limit*9/10 {
		t.Fatalf("the largest group is %d bytes, over 90%% of %d", n, limit)
	}
}
