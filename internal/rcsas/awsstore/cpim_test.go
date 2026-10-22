package awsstore

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// A message's CPIM is stored as the binary attribute it was before #547,
// held in a content.Body: the same octets, whatever they are, and an empty
// one as an empty binary, never nil, which the SDK would send as null. It
// reads back as it went in.
func TestACPIMIsStoredAsItsOctets(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for name, cpim := range map[string][]byte{
		"a chat message": []byte("From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>\r\n\r\nContent-Type: text/plain\r\n\r\nhi"),
		"every octet":    all,
		"one octet":      {0},
		"empty":          {},
		"the largest":    bytes.Repeat([]byte("x"), MaxCPIMSize),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDynamo(t)
			s := NewWithClient("messages", f)
			m := store.Message{Recipient: "r", ID: "1", Sender: "s", Mode: store.Standalone,
				CPIM: content.BodyOf(cpim), Enqueued: t0, Expires: t0.Add(time.Hour)}
			if err := s.Enqueue(context.Background(), m, store.Limit{}); err != nil {
				t.Fatal(err)
			}
			b, ok := queuedRow(t, f, "1")[attrCPIM].(*dtypes.AttributeValueMemberB)
			if !ok || b.Value == nil || !bytes.Equal(b.Value, cpim) {
				t.Fatalf("stored %s, want the %d octets as they were", describeB(b, ok), len(cpim))
			}
			got, err := s.Pending(context.Background(), "r", "", t0, 1)
			if err != nil || len(got) != 1 || !bytes.Equal(got[0].CPIM.Bytes(), cpim) || got[0].Size() != int64(len(cpim)) {
				t.Fatalf("read back %d messages, %v", len(got), err)
			}
		})
	}
}

// queuedRow is the fake's row of the queued message id.
func queuedRow(t *testing.T, f *fakeDynamo, id string) map[string]dtypes.AttributeValue {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if strings.HasPrefix(sOf(row[attrPK]), queuePrefix) && sOf(row[attrSK]) == id {
			return row
		}
	}
	t.Fatalf("no queued row %s", id)
	return nil
}

func describeB(b *dtypes.AttributeValueMemberB, ok bool) string {
	switch {
	case !ok:
		return "no binary attribute"
	case b.Value == nil:
		return "a nil binary"
	}
	return fmt.Sprintf("%d octets", len(b.Value))
}
