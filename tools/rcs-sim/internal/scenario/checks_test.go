package scenario

import (
	"context"
	"testing"

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
	e.Reports <- msrp.Report{Code: msrp.StatusOK, Range: msrp.ByteRange{Start: 1, End: 5, Total: 10}}
	e.Reports <- msrp.Report{Code: msrp.StatusMessageTooLarge}
	if err := waitReport(context.Background(), e); err == nil {
		t.Fatal("a failure report counted as delivery")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitReport(ctx, e); err == nil {
		t.Fatal("no report counted as delivery")
	}
}
