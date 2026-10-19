package awsstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore/storetest"
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
