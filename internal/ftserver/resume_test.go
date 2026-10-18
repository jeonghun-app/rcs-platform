package ftserver

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// errReader fails every read, like a connection that broke.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// breakUpload posts data under tid but breaks the body off after n bytes of
// file content, as a client losing its radio link does. The File part
// declares its length, as RCS clients do.
func breakUpload(t *testing.T, e *env, u *user, tid, data string, n int) {
	t.Helper()
	p := filePart("a.bin", "application/octet-stream", data)
	p.header += "Content-Length: " + strconv.Itoa(len(data)) + "\r\n"
	body := multipartBody(tidPart(tid), p)
	cut := strings.Index(body, data) + n
	r := httptest.NewRequest(http.MethodPost, "/ft", io.MultiReader(strings.NewReader(body[:cut]), errReader{io.ErrUnexpectedEOF}))
	r.Header.Set("Content-Type", formType)
	if rec := e.do(u.sign(r)); rec.Code != http.StatusBadRequest {
		t.Fatalf("broken upload = %d %s, want 400", rec.Code, rec.Body)
	}
}

func rangeHeader(first, total int) string {
	return "bytes " + strconv.Itoa(first) + "-" + strconv.Itoa(total-1) + "/" + strconv.Itoa(total)
}

func TestBrokenUploadResumesFromTheLastStoredPart(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(4*testPart + 100)
	breakUpload(t, e, u, "resume-me", data, 2*testPart+300)
	if e.metric("upload.failed.interrupted") != 1 {
		t.Fatal("broken upload not counted")
	}

	info := u.get("/ft?tid=resume-me&get_upload_info")
	if info.Code != http.StatusOK || info.Header().Get("Content-Type") != ContentType {
		t.Fatalf("upload info = %d %q", info.Code, info.Header().Get("Content-Type"))
	}
	d := parseResumeDocument(t, info.Body.Bytes())
	// Only whole parts are durable: the 300 bytes after them are lost.
	if d.Range.Start != "0" || d.Range.End != strconv.Itoa(2*testPart-1) {
		t.Fatalf("file-range = %+v, want 0-%d", d.Range, 2*testPart-1)
	}
	if d.Data.URL != "https://ft.example.test/ft/resume-me" {
		t.Fatalf("resume URL = %q", d.Data.URL)
	}

	put := u.put("/ft/resume-me", rangeHeader(2*testPart, len(data)), data[2*testPart:])
	if put.Code != http.StatusOK {
		t.Fatalf("resume = %d %s", put.Code, put.Body)
	}
	f := fileOf(t, parseFileDocument(t, put.Body.Bytes()))
	if f.Size != int64(len(data)) || f.Name != "a.bin" {
		t.Fatalf("file info = %+v", f)
	}
	if got := u.get(downloadTarget(t, f.Data.URL)).Body.String(); got != data {
		t.Fatal("resumed file differs from the original")
	}
	id, _, _ := parseDownloadID(strings.TrimPrefix(f.Data.URL, "https://ft.example.test/dl?id="))
	r, _ := e.meta.Get(t.Context(), id)
	if string(r.SHA256) != string(sha(data)) {
		t.Fatal("the hash did not continue across the resume")
	}
	if e.metric("upload.resumed") != 1 {
		t.Fatal("resume not counted")
	}
}

func TestUploadBrokenOverTheNetworkResumes(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.IdleTimeout = 5 * time.Second })
	srv := e.serve()
	u := e.user(alice)
	data := pattern(3 * testPart)
	body := multipartBody(tidPart("tcp"), filePart("a.bin", "application/octet-stream", data))
	cut := strings.Index(body, data) + testPart + 10

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ft", nil)
	u.sign(req)
	head := "POST /ft HTTP/1.1\r\nHost: ft\r\nContent-Type: " + formType +
		"\r\nAuthorization: " + req.Header.Get("Authorization") +
		"\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, head+body[:cut]); err != nil {
		t.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	conn.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken upload = %d", resp.StatusCode)
	}

	d := parseResumeDocument(t, u.get("/ft?tid=tcp&get_upload_info").Body.Bytes())
	if d.Range.End != strconv.Itoa(testPart-1) {
		t.Fatalf("file-range = %+v", d.Range)
	}
	if put := u.put("/ft/tcp", rangeHeader(testPart, len(data)), data[testPart:]); put.Code != http.StatusOK {
		t.Fatalf("resume = %d", put.Code)
	}
}

func TestUploadInfoWithNothingStoredIsNotFound(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	breakUpload(t, e, u, "nothing", pattern(3*testPart), 10)
	if rec := u.get("/ft?tid=nothing&get_upload_info"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 so the client posts again", rec.Code)
	}
}

func TestUploadInfoOfACompleteFileCoversEveryByte(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(100)
	u.uploadFile("complete", data)
	d := parseResumeDocument(t, u.get("/ft?tid=complete&get_upload_info").Body.Bytes())
	if d.Range.Start != "0" || d.Range.End != "99" {
		t.Fatalf("file-range = %+v, want 0-99", d.Range)
	}
}

func TestDownloadInfoReturnsTheFileInfoAgain(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	first := u.uploadFile("again", "content")
	rec := u.get("/ft?tid=again&get_download_info")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if fileOf(t, parseFileDocument(t, rec.Body.Bytes())).Data.URL != fileOf(t, first).Data.URL {
		t.Fatal("download info names another file")
	}
	breakUpload(t, e, u, "partial", pattern(3*testPart), 2*testPart)
	if rec := u.get("/ft?tid=partial&get_download_info"); rec.Code != http.StatusNotFound {
		t.Fatalf("download info of an incomplete upload = %d", rec.Code)
	}
}

func TestInfoOfAnotherUsersTIDIsNotFound(t *testing.T) {
	e := newEnv(t)
	e.user(alice).uploadFile("private", "x")
	b := e.user(bob)
	for _, q := range []string{"get_upload_info", "get_download_info"} {
		if rec := b.get("/ft?tid=private&" + q); rec.Code != http.StatusNotFound {
			t.Fatalf("%s for another user's tid = %d", q, rec.Code)
		}
	}
	if rec := b.put("/ft/private", "bytes 0-0/1", "x"); rec.Code != http.StatusNotFound {
		t.Fatalf("resume of another user's tid = %d", rec.Code)
	}
}

func TestMalformedInfoQueriesAreBadRequests(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	for _, q := range []string{
		"", "tid=x", "get_upload_info", "tid=x&get_upload_info&get_download_info",
		"tid=x&tid=y&get_upload_info", "tid=a%2Fb&get_upload_info", "tid=x&get_upload_info&%zz",
	} {
		if rec := u.get("/ft?" + q); rec.Code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, rec.Code)
		}
	}
}

func TestInfoNeedsAuthentication(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(httptest.NewRequest(http.MethodGet, "/ft?tid=x&get_upload_info", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestResumeOutsideTheHeldRangeIsRefused(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(3 * testPart)
	breakUpload(t, e, u, "ranges", data, testPart+1)
	total := len(data)
	for _, c := range []struct {
		name, contentRange, body string
		code                     int
	}{
		{"missing", "", "x", http.StatusBadRequest},
		{"unknown length", "bytes 1024-3071/*", data[testPart:], http.StatusBadRequest},
		{"not to the end", "bytes 1024-2047/" + strconv.Itoa(total), data[testPart : 2*testPart], http.StatusBadRequest},
		{"gap", rangeHeader(testPart+1, total), data[testPart+1:], http.StatusConflict},
		{"overlap", rangeHeader(testPart-1, total), data[testPart-1:], http.StatusConflict},
		{"other size", rangeHeader(testPart, total+1), data[testPart:] + "x", http.StatusConflict},
		{"too large", rangeHeader(testPart, int(e.opts.MaxSize)+1), "", http.StatusRequestEntityTooLarge},
		{"body shorter than range", rangeHeader(testPart, total), data[testPart : total-1], http.StatusBadRequest},
	} {
		if rec := u.put("/ft/ranges", c.contentRange, c.body); rec.Code != c.code {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.code)
		}
	}
	if rec := u.put("/ft/ranges", rangeHeader(testPart, total), data[testPart:]); rec.Code != http.StatusOK {
		t.Fatalf("correct resume after the refusals = %d %s", rec.Code, rec.Body)
	}
}

func TestResumeBodyLongerThanItsRangeIsRefused(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(2 * testPart)
	breakUpload(t, e, u, "long", data, testPart+1)
	// Chunked, so Content-Length cannot give it away first.
	r := httptest.NewRequest(http.MethodPut, "/ft/long", struct{ io.Reader }{strings.NewReader(data[testPart:] + "extra")})
	r.ContentLength = -1
	r.Header.Set("Content-Range", rangeHeader(testPart, len(data)))
	if rec := e.do(u.sign(r)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestResumeOfACompleteOrExpiredUploadConflicts(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.uploadFile("finished", "abc")
	if rec := u.put("/ft/finished", "bytes 0-2/3", "abc"); rec.Code != http.StatusConflict {
		t.Fatalf("resume of a complete upload = %d", rec.Code)
	}
	breakUpload(t, e, u, "stale", pattern(2*testPart), testPart)
	e.clock.Advance(e.opts.Validity + time.Second)
	u.challenge()
	if rec := u.put("/ft/stale", rangeHeader(testPart, 2*testPart), pattern(2 * testPart)[testPart:]); rec.Code != http.StatusConflict {
		t.Fatalf("resume past validity = %d", rec.Code)
	}
}

func TestResumeIntoAVanishedMultipartUploadStartsOver(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	data := pattern(3 * testPart)
	breakUpload(t, e, u, "gone", data, 2*testPart)
	r, _ := e.meta.GetByTID(t.Context(), alice, "gone")
	// What the bucket's lifecycle rule or a crash after completion leaves.
	if err := e.blobs.AbortMultipart(t.Context(), r.ID, r.MultipartID); err != nil {
		t.Fatal(err)
	}
	if rec := u.put("/ft/gone", rangeHeader(2*testPart, len(data)), data[2*testPart:]); rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if rec := u.get("/ft?tid=gone&get_upload_info"); rec.Code != http.StatusNotFound {
		t.Fatalf("upload info after the reset = %d, want 404", rec.Code)
	}
	u.uploadFile("gone", data)
}

func TestSweepExpiresOldRecordsAndAbortsTheirUploads(t *testing.T) {
	e := newEnv(t)
	u := e.user(alice)
	u.uploadFile("done", "x")
	breakUpload(t, e, u, "abandoned", pattern(3*testPart), 2*testPart)
	if e.blobs.OpenUploads() != 1 {
		t.Fatal("no open multipart upload to abandon")
	}
	if n, err := e.srv.Sweep(t.Context()); err != nil || n != 0 {
		t.Fatalf("sweep before expiry = %d, %v", n, err)
	}
	e.clock.Advance(e.opts.Validity + time.Second)
	n, err := e.srv.Sweep(t.Context())
	if err != nil || n != 2 {
		t.Fatalf("sweep = %d, %v; want 2", n, err)
	}
	for _, tid := range []string{"done", "abandoned"} {
		r, _ := e.meta.GetByTID(t.Context(), alice, tid)
		if r.State != store.Expired {
			t.Fatalf("%s is %s", tid, r.State)
		}
	}
	if e.blobs.OpenUploads() != 0 {
		t.Fatal("the abandoned multipart upload is still open")
	}
	if e.metric("sweep.expired") != 2 {
		t.Fatal("sweep not counted")
	}
}

func TestSweepLeavesAnUploadWithALiveLease(t *testing.T) {
	e := newEnv(t)
	r, err := e.meta.Create(t.Context(), store.Record{
		ID: "leased-file-id-000000000", Owner: alice, TID: "busy", State: store.Uploading, DeclaredSize: -1,
		Expires: e.clock.Now().Add(-time.Second), Lease: "live", LeaseUntil: e.clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := e.srv.Sweep(t.Context()); n != 0 {
		t.Fatal("swept an upload being written")
	}
	if got, _ := e.meta.Get(t.Context(), r.ID); got.State != store.Uploading {
		t.Fatal("state changed")
	}
}

// replacedParts refuse every completion, like an upload one of whose parts
// another writer overwrote.
type replacedParts struct{ store.Blobs }

func (replacedParts) CompleteMultipart(context.Context, string, string, []store.Part) error {
	return store.ErrInvalidParts
}

func TestUploadWhosePartsNoLongerMatchStartsOver(t *testing.T) {
	e := newEnv(t)
	e.srv.o.Blobs = replacedParts{e.blobs}
	u := e.user(alice)
	data := pattern(2*testPart + 1)
	breakUpload(t, e, u, "replaced", data, testPart+1)
	if rec := u.put("/ft/replaced", rangeHeader(testPart, len(data)), data[testPart:]); rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	r, _ := e.meta.GetByTID(t.Context(), alice, "replaced")
	if r.Received != 0 || r.MultipartID != "" || r.Lease != "" {
		t.Fatalf("record not reset: %+v", r)
	}
}
