package ftserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// uploaded uploads data with a thumbnail and returns the file and thumbnail
// download targets.
func uploaded(t *testing.T, e *env, data string) (file, thumb string) {
	t.Helper()
	rec := e.user(alice).upload(multipartBody(tidPart("dl-"+strconv.Itoa(len(data))), thumbPart("THUMB"),
		filePart("report final.pdf", "application/pdf", data)))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d", rec.Code)
	}
	doc := parseFileDocument(t, rec.Body.Bytes())
	return downloadTarget(t, doc.Infos[1].Data.URL), downloadTarget(t, doc.Infos[0].Data.URL)
}

func get(e *env, target string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return e.do(r)
}

func TestDownloadServesTheDeclaredTypeAsAnAttachment(t *testing.T) {
	e := newEnv(t)
	data := pattern(2*testPart + 3)
	file, _ := uploaded(t, e, data)
	rec := get(e, file)
	if rec.Code != http.StatusOK || rec.Body.String() != data {
		t.Fatalf("download = %d, %d bytes", rec.Code, rec.Body.Len())
	}
	h := rec.Header()
	for name, want := range map[string]string{
		"Content-Type":            "application/pdf",
		"Content-Length":          strconv.Itoa(len(data)),
		"Content-Disposition":     `attachment; filename="report final.pdf"`,
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Cache-Control":           "private, no-store",
		"Accept-Ranges":           "bytes",
		"Last-Modified":           e.clock.Now().Format(http.TimeFormat),
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if etag := h.Get("ETag"); len(etag) != 66 || etag[0] != '"' {
		t.Errorf("ETag = %q", etag)
	}
	if e.metric("download.served") != 1 || e.metric("download.bytes") != float64(len(data)) {
		t.Error("download not counted")
	}
}

func TestThumbnailDownloadsUnderItsOwnLink(t *testing.T) {
	e := newEnv(t)
	file, thumb := uploaded(t, e, "data")
	rec := get(e, thumb)
	if rec.Code != http.StatusOK || rec.Body.String() != "THUMB" || rec.Header().Get("Content-Type") != "image/jpeg" ||
		rec.Header().Get("Content-Disposition") != "attachment" {
		t.Fatalf("thumbnail = %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if rec.Header().Get("ETag") == get(e, file).Header().Get("ETag") {
		t.Fatal("thumbnail and file share an ETag")
	}
}

func TestThumbnailLinkOfAFileWithoutOneIsNotFound(t *testing.T) {
	e := newEnv(t)
	f := fileOf(t, e.user(alice).uploadFile("no-thumb", "x"))
	if rec := get(e, downloadTarget(t, f.Data.URL)+thumbnailSuffix); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHeadDescribesTheFileWithoutContent(t *testing.T) {
	e := newEnv(t)
	file, _ := uploaded(t, e, "0123456789")
	rec := e.do(httptest.NewRequest(http.MethodHead, file, nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "10" {
		t.Fatalf("HEAD = %d, %d bytes, length %q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Length"))
	}
}

func TestRangeRequestsResumeADownload(t *testing.T) {
	e := newEnv(t)
	data := pattern(3*testPart + 7)
	file, _ := uploaded(t, e, data)
	size := len(data)
	etag := get(e, file).Header().Get("ETag")
	for _, c := range []struct {
		name, rng, ifRange string
		code               int
		want               string
		contentRange       string
	}{
		{"first bytes", "bytes=0-9", "", 206, data[:10], "bytes 0-9/" + strconv.Itoa(size)},
		{"across parts", "bytes=1020-1030", "", 206, data[1020:1031], "bytes 1020-1030/" + strconv.Itoa(size)},
		{"open ended", "bytes=3000-", "", 206, data[3000:], "bytes 3000-" + strconv.Itoa(size-1) + "/" + strconv.Itoa(size)},
		{"suffix", "bytes=-5", "", 206, data[size-5:], "bytes " + strconv.Itoa(size-5) + "-" + strconv.Itoa(size-1) + "/" + strconv.Itoa(size)},
		{"last byte past the end", "bytes=10-99999", "", 206, data[10:], "bytes 10-" + strconv.Itoa(size-1) + "/" + strconv.Itoa(size)},
		{"matching If-Range", "bytes=0-0", etag, 206, data[:1], "bytes 0-0/" + strconv.Itoa(size)},
		{"stale If-Range", "bytes=0-0", `"other"`, 200, data, ""},
		{"date If-Range", "bytes=0-0", e.clock.Now().Format(http.TimeFormat), 200, data, ""},
		{"several ranges", "bytes=0-0,-1", "", 200, data, ""},
		{"invalid", "bytes=9-1", "", 200, data, ""},
		{"other unit", "items=0-1", "", 200, data, ""},
		{"past the end", "bytes=" + strconv.Itoa(size) + "-", "", 416, "", "bytes */" + strconv.Itoa(size)},
		{"empty suffix", "bytes=-0", "", 416, "", "bytes */" + strconv.Itoa(size)},
		{"huge first byte", "bytes=99999999999999999999-", "", 416, "", "bytes */" + strconv.Itoa(size)},
	} {
		h := []string{"Range", c.rng}
		if c.ifRange != "" {
			h = append(h, "If-Range", c.ifRange)
		}
		rec := get(e, file, h...)
		if rec.Code != c.code || rec.Header().Get("Content-Range") != c.contentRange {
			t.Errorf("%s: %d Content-Range %q, want %d %q", c.name, rec.Code, rec.Header().Get("Content-Range"), c.code, c.contentRange)
			continue
		}
		if c.code != 416 && (rec.Body.String() != c.want || rec.Header().Get("Content-Length") != strconv.Itoa(len(c.want))) {
			t.Errorf("%s: body is %d bytes, want %d", c.name, rec.Body.Len(), len(c.want))
		}
	}
	if e.metric("download.partial") != 6 || e.metric("download.unsatisfiable") != 3 {
		t.Errorf("partial %v, unsatisfiable %v", e.metric("download.partial"), e.metric("download.unsatisfiable"))
	}
}

func TestRangeOnHeadIsIgnored(t *testing.T) {
	e := newEnv(t)
	file, _ := uploaded(t, e, "0123456789")
	r := httptest.NewRequest(http.MethodHead, file, nil)
	r.Header.Set("Range", "bytes=0-1")
	if rec := e.do(r); rec.Code != http.StatusOK || rec.Header().Get("Content-Length") != "10" {
		t.Fatalf("HEAD with Range = %d %q", rec.Code, rec.Header().Get("Content-Length"))
	}
}

func TestDownloadOfAnythingButALiveFileIsNotFound(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	file, _ := uploaded(t, e, "x")
	breakUpload(t, e, u, "partial", pattern(3*testPart), 2*testPart)
	partial, _ := e.meta.GetByTID(t.Context(), alice, "partial")
	for name, target := range map[string]string{
		"no id":         "/dl",
		"short id":      "/dl?id=abc",
		"bad character": "/dl?id=" + strings.Repeat("*", idLength),
		"unknown":       "/dl?id=" + strings.Repeat("A", idLength),
		"two ids":       file + "&id=" + strings.Repeat("A", idLength),
		"incomplete":    "/dl?id=" + partial.ID,
	} {
		if rec := get(e, target); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", name, rec.Code)
		}
	}
	e.clock.Advance(e.opts.Validity)
	if rec := get(e, file); rec.Code != http.StatusNotFound {
		t.Fatalf("expired file = %d, want 404", rec.Code)
	}
}

func TestExpiredMarkedFileIsNotFound(t *testing.T) {
	e := newEnv(t)
	file, _ := uploaded(t, e, "x")
	id, _, _ := parseDownloadID(strings.TrimPrefix(file, "/dl?id="))
	r, _ := e.meta.Get(t.Context(), id)
	r.State = store.Expired
	if _, err := e.meta.Update(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if rec := get(e, file); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDownloadStorageFailureIsAnInternalError(t *testing.T) {
	e := newEnv(t)
	file, _ := uploaded(t, e, "data")
	e.blobs.SetFailure(errFileTooLarge)
	rec := get(e, file)
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("status = %d, disposition %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
	if e.metric("download.failed.storage") != 1 {
		t.Fatal("failure not counted")
	}
}

func TestDownloadAuthenticationIsOptional(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.DownloadAuth = true })
	file, _ := uploaded(t, e, "secret")
	if rec := get(e, file); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous download with FT_DOWNLOAD_AUTH = %d, want 401", rec.Code)
	}
	// Any subscriber may download: the recipient is not known to the server.
	if rec := e.user(bob).get(file); rec.Code != http.StatusOK || rec.Body.String() != "secret" {
		t.Fatalf("authenticated download = %d", rec.Code)
	}
}

// deadlineRecorder is a ResponseRecorder that records the connection
// deadlines a handler sets, and can fail writes like a connection whose
// write deadline passed.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	reads, writes []time.Time
	failWrites    bool
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.reads = append(d.reads, t)
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.writes = append(d.writes, t)
	return nil
}

func (d *deadlineRecorder) Write(p []byte) (int, error) {
	if d.failWrites {
		return 0, os.ErrDeadlineExceeded
	}
	return d.ResponseRecorder.Write(p)
}

func TestDownloadWritesRunUnderTheIdleDeadline(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = 30 * time.Second })
	file, _ := uploaded(t, e, pattern(100))
	before := time.Now()
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, file, nil))
	if rec.Code != http.StatusOK || len(rec.writes) < 2 {
		t.Fatalf("status %d, %d write deadlines", rec.Code, len(rec.writes))
	}
	for _, d := range rec.writes {
		if d.Before(before.Add(30*time.Second)) || d.After(time.Now().Add(30*time.Second)) {
			t.Fatalf("write deadline %v is not the idle timeout from now", d)
		}
	}
}

func TestStalledDownloadIsCutShort(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = time.Second })
	file, _ := uploaded(t, e, pattern(100))
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder(), failWrites: true}
	e.srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, file, nil))
	if e.metric("download.failed.interrupted") != 1 || e.metric("download.served") != 0 {
		t.Fatal("a download whose writes failed was not counted as interrupted")
	}
}

func TestAttachmentEncodesNamesItCanAndDropsOthers(t *testing.T) {
	for name, want := range map[string]string{
		"":          "attachment",
		"a b.txt":   `attachment; filename="a b.txt"`,
		"사진.jpg":    "attachment; filename*=utf-8''%EC%82%AC%EC%A7%84.jpg",
		"quote\".x": `attachment; filename="quote\".x"`,
	} {
		if got := attachment(name); got != want {
			t.Errorf("attachment(%q) = %q, want %q", name, got, want)
		}
	}
}

// vanishingBlobs lose every object, like a lifecycle rule set shorter than
// the validity.
type vanishingBlobs struct{ store.Blobs }

func (vanishingBlobs) Open(context.Context, string, int64, int64) (io.ReadCloser, error) {
	return nil, store.ErrNotFound
}

func TestValidFileWhoseObjectIsGoneIsNotFound(t *testing.T) {
	e := newEnv(t)
	file, _ := uploaded(t, e, "data")
	e.srv.o.Blobs = vanishingBlobs{e.blobs}
	rec := get(e, file)
	if rec.Code != http.StatusNotFound || rec.Header().Get("ETag") != "" || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("status = %d, headers %v", rec.Code, rec.Header())
	}
}

// brokenMetadata fails every read like an unreachable table.
type brokenMetadata struct{ store.Metadata }

func (brokenMetadata) Get(context.Context, string) (store.Record, error) {
	return store.Record{}, errors.New("table unreachable")
}

func (brokenMetadata) GetByTID(context.Context, string, string) (store.Record, error) {
	return store.Record{}, errors.New("table unreachable")
}

func TestUnreachableTableIsAnInternalError(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Metadata = brokenMetadata{store.NewMemory()} })
	u := e.user(alice)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"download": get(e, "/dl?id="+strings.Repeat("A", idLength)),
		"info":     u.get("/ft?tid=x&get_upload_info"),
		"resume":   u.put("/ft/x", "bytes 0-0/1", "x"),
		"upload":   u.upload(multipartBody(tidPart("x"), filePart("a", "text/plain", "x"))),
	} {
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500", name, rec.Code)
		}
	}
}
