package scenario

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/chat"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
)

func document(infos ...ft.FileInfo) ft.FileDocument { return ft.FileDocument{Infos: infos} }

func info(kind string, size int64, ct, link string) ft.FileInfo {
	i := ft.FileInfo{Type: kind, Size: size, ContentType: ct}
	i.Data.URL, i.Data.Until = link, "2026-01-01T00:00:00Z"
	return i
}

func TestDocumentsAreCheckedAgainstTheUpload(t *testing.T) {
	up := ft.Upload{Data: make([]byte, 10), ContentType: "image/jpeg", Thumbnail: make([]byte, 3)}
	good := document(info("file", 10, "image/jpeg", "u"), info("thumbnail", 3, "image/jpeg", "t"))
	if err := checkDocument(good, up); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]ft.FileDocument{
		"no file":        document(info("thumbnail", 3, "image/jpeg", "t")),
		"wrong size":     document(info("file", 9, "image/jpeg", "u"), info("thumbnail", 3, "image/jpeg", "t")),
		"wrong type":     document(info("file", 10, "image/png", "u"), info("thumbnail", 3, "image/jpeg", "t")),
		"no link":        document(info("file", 10, "image/jpeg", ""), info("thumbnail", 3, "image/jpeg", "t")),
		"no thumbnail":   document(info("file", 10, "image/jpeg", "u")),
		"thumbnail size": document(info("file", 10, "image/jpeg", "u"), info("thumbnail", 4, "image/jpeg", "t")),
	} {
		if err := checkDocument(d, up); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestContentIsComparedWhole(t *testing.T) {
	if sameContent([]byte("abc"), []byte("abc")) != nil {
		t.Fatal("equal content refused")
	}
	if sameContent([]byte("ab"), []byte("abc")) == nil || sameContent([]byte("abd"), []byte("abc")) == nil {
		t.Fatal("different content accepted")
	}
}

func TestReportsDecideDelivery(t *testing.T) {
	e := chat.NewEndpoint(cpim.Address{URI: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"})
	e.Reports <- msrp.Report{MessageID: "m1", Code: msrp.StatusOK, Range: msrp.ByteRange{Start: 1, End: 5, Total: 10}}
	e.Reports <- msrp.Report{MessageID: "m1", Code: msrp.StatusMessageTooLarge}
	if err := waitReport(context.Background(), e, "m1"); err == nil {
		t.Fatal("a failure report counted as delivery")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitReport(ctx, e, "m1"); err == nil {
		t.Fatal("no report counted as delivery")
	}
}

func TestOnlyTheSentMessagesReportCounts(t *testing.T) {
	e := chat.NewEndpoint(cpim.Address{URI: "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"})
	// A second copy of an earlier message's success report.
	e.Reports <- msrp.Report{MessageID: "earlier", Code: msrp.StatusOK, Range: msrp.ByteRange{Start: 1, End: 10, Total: 10}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := waitReport(ctx, e, "this"); err == nil {
		t.Fatal("another message's report counted as this one's")
	}
	e.Reports <- msrp.Report{MessageID: "earlier", Code: msrp.StatusOK, Range: msrp.ByteRange{Start: 1, End: 10, Total: 10}}
	e.Reports <- msrp.Report{MessageID: "this", Code: msrp.StatusOK, Range: msrp.ByteRange{Start: 1, End: 4, Total: 4}}
	if err := waitReport(context.Background(), e, "this"); err != nil {
		t.Fatal(err)
	}
}

func TestOnlySendStartLinesCountAsKeepAlives(t *testing.T) {
	for _, tt := range []struct {
		wire string
		want int
	}{
		{"MSRP a1b2 SEND\r\nTo-Path: msrp://relay.example.com:2855/s;tcp\r\nFrom-Path: msrp://rcs-sim.invalid:9/c;tcp\r\nMessage-ID: m1\r\nByte-Range: 1-0/0\r\n-------a1b2$\r\n", 1},
		// The client's answer to the relay's keep-alive.
		{"MSRP r3l4y 200 OK\r\nTo-Path: msrp://relay.example.com:2855/s;tcp\r\nFrom-Path: msrp://rcs-sim.invalid:9/c;tcp\r\n-------r3l4y$\r\n", 0},
		{"MSRP r3l4y 200 OK\r\n-------r3l4y$\r\nMSRP a1b2 SEND\r\n-------a1b2$\r\n", 1},
		{"MSRP a1b2 REPORT\r\n-------a1b2$\r\n", 0},
		// QA's probes on #102: a line in a body that looks like a start
		// line has no end-line of its own.
		{"MSRP m1 SEND\r\nContent-Type: text/plain\r\n\r\nhello\r\nMSRP x9 SEND\r\nbye\r\n-------m1$\r\n", 1},
		{"chunk of body\r\nMSRP x9 SEND\r\nmore", 0},
		// A start line split across two writes is missed, not miscounted.
		{"MSRP a1b2 SE", 0},
		{"ND\r\nTo-Path: x\r\n-------a1b2$\r\n", 0},
		// Not RFC 4975's separators.
		{"MSRP\ta1b2\tSEND\r\n-------a1b2$\r\n", 0},
		{"MSRP a1b2 SEND\nTo-Path: x\n-------a1b2$\n", 0},
		// A response whose comment says SEND.
		{"MSRP a1b2 200 SEND\r\n-------a1b2$\r\n", 0},
		{"MSRP a1b2 SEND\r\n-------a1b3$\r\n", 0},
	} {
		if got := sendStartLines([]byte(tt.wire)); got != tt.want {
			t.Errorf("%q: %d SENDs, want %d", tt.wire, got, tt.want)
		}
	}
}
