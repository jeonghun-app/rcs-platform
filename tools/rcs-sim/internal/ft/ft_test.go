package ft_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

const part = 64 << 10

func newClient(t *testing.T, s *simtest.FT, password string) *ft.Client {
	t.Helper()
	return &ft.Client{HTTP: s.Server.Client(), UploadURL: s.UploadURL, User: simtest.FTUser, Password: ft.NewSecret(password)}
}

func content(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestUploadThenDownloadAsRcsjtaDoes(t *testing.T) {
	s := simtest.StartFT(t, part)
	c := newClient(t, s, simtest.FTPassword)
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	up := ft.Upload{TID: "tid-1", Name: "a photo.jpg", ContentType: "image/jpeg", Data: content(t, 3*part+5),
		Thumbnail: content(t, 100), ThumbnailType: "image/png"}
	doc, err := c.Send(ctx(t), nil, up)
	if err != nil {
		t.Fatal(err)
	}
	file, ok := doc.Info("file")
	if !ok || file.Size != int64(len(up.Data)) || file.ContentType != "image/jpeg" || file.Name != "a+photo.jpg" {
		t.Fatalf("file-info %+v", file)
	}
	thumb, ok := doc.Info("thumbnail")
	if !ok || thumb.Size != 100 || thumb.ContentType != "image/png" {
		t.Fatalf("thumbnail info %+v", thumb)
	}
	got, err := c.Download(ctx(t), file.Data.URL, "", int64(len(up.Data)))
	if err != nil || got.Status != http.StatusOK || !bytes.Equal(got.Body, up.Data) || strings.Trim(got.ETag, `"`) != ft.SHA256(up.Data) {
		t.Fatalf("download: %v, status %d, %d bytes, etag ok %v", err, got.Status, len(got.Body), strings.Trim(got.ETag, `"`) == ft.SHA256(up.Data))
	}
	part2, err := c.Download(ctx(t), file.Data.URL, ft.RangeHeader(10, 19), 10)
	if err != nil || part2.Status != http.StatusPartialContent || !bytes.Equal(part2.Body, up.Data[10:20]) {
		t.Fatalf("range download: %v, %d", err, part2.Status)
	}
	if _, err := c.Download(ctx(t), file.Data.URL, "", 10); err == nil {
		t.Fatal("a download over the expected size was accepted")
	}
	again, err := c.DownloadInfo(ctx(t), "tid-1")
	if err != nil {
		t.Fatal(err)
	}
	if f, _ := again.Info("file"); f.Data.URL != file.Data.URL {
		t.Fatal("get_download_info names another link")
	}
}

func TestBrokenUploadIsResumedFromWhatTheServerHolds(t *testing.T) {
	s := simtest.StartFT(t, part)
	c := newClient(t, s, simtest.FTPassword)
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	up := ft.Upload{TID: "tid-resume", Name: "v.mp4", ContentType: "video/mp4", Data: content(t, 5*part+11)}
	if err := c.SendInterrupted(ctx(t), up, 4*part); err != nil {
		t.Fatal(err)
	}
	// The scenario's rule: the same bytes held for a quiet time, so the
	// server has noticed the break and released the upload. The PUT is then
	// sent once, as rcsjta sends it.
	info, _, err := c.SettledUploadInfo(ctx(t), up.TID, 10*time.Second, 100*time.Millisecond, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("get_upload_info = %v", err)
	}
	held, err := info.Held()
	if err != nil || held <= 0 || held%part != 0 || held >= int64(len(up.Data)) {
		t.Fatalf("held %d, %v", held, err)
	}
	doc, err := c.Resume(ctx(t), info, up.ContentType, up.Data)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := doc.Info("file")
	got, err := c.Download(ctx(t), file.Data.URL, "", int64(len(up.Data)))
	if err != nil || !bytes.Equal(got.Body, up.Data) {
		t.Fatalf("resumed download: %v", err)
	}
}

func TestUploadInfoOfAnUnknownTransferHoldsNothing(t *testing.T) {
	s := simtest.StartFT(t, part)
	c := newClient(t, s, simtest.FTPassword)
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadInfo(ctx(t), "never"); !errors.Is(err, ft.ErrNothingHeld) {
		t.Fatalf("get_upload_info = %v, want ErrNothingHeld", err)
	}
	if _, err := c.DownloadInfo(ctx(t), "never"); !ft.IsStatus(err, http.StatusNotFound) {
		t.Fatalf("get_download_info = %v, want 404", err)
	}
}

func TestWrongPasswordIsA401WithoutTheCredentials(t *testing.T) {
	s := simtest.StartFT(t, part)
	c := newClient(t, s, "not-the-password")
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	_, err := c.Send(ctx(t), nil, ft.Upload{TID: "x", Name: "x", ContentType: "text/plain", Data: []byte("x")})
	if !ft.IsStatus(err, http.StatusUnauthorized) {
		t.Fatalf("Send = %v, want 401", err)
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", c, c, c.Password)} {
		if strings.Contains(s, "not-the-password") {
			t.Fatalf("the password was printed: %s", s)
		}
	}
}

func TestRequestsBeforeAChallengeAreRefused(t *testing.T) {
	c := &ft.Client{HTTP: http.DefaultClient, UploadURL: &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/ft"}}
	if _, err := c.UploadInfo(ctx(t), "x"); err == nil {
		t.Fatal("a request went out without a challenge")
	}
	if err := c.Precheck(ctx(t), nil); err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("Precheck = %v; want a transport error without the address", err)
	}
}

// fakeServer answers with whatever the test sets, for the paths a real
// ft-server never takes.
func fakeServer(t *testing.T, h http.HandlerFunc) *ft.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/ft")
	return &ft.Client{HTTP: srv.Client(), UploadURL: u, User: "u", Password: ft.NewSecret("p")}
}

const challenge = `Digest realm="r", nonce="n", qop="auth", opaque="o"`

func TestInfoRequestsGoOutUnauthenticatedFirstAndUseTheFreshNonce(t *testing.T) {
	// rcsjta's sendGetInfo: a GET without credentials, then the same GET
	// signed under the nonce of its 401, which starts again at nc 1.
	var seen []string
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seen = append(seen, auth)
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="r", nonce="n`+strconv.Itoa(len(seen))+`", qop="auth", opaque="o"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadInfo(ctx(t), "x"); !errors.Is(err, ft.ErrNothingHeld) {
		t.Fatalf("UploadInfo = %v", err)
	}
	if len(seen) != 3 || seen[1] != "" || !strings.Contains(seen[2], `nonce="n2"`) || !strings.Contains(seen[2], "nc=00000001") ||
		!strings.Contains(seen[2], `uri="/ft"`) {
		t.Fatalf("requests %q", seen)
	}
}

func TestABusyServerIsAFailureNotARetry(t *testing.T) {
	// rcsjta retries nothing on the resume path; neither does the client.
	signed := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		signed++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if _, err := c.UploadInfo(ctx(t), "x"); !ft.IsStatus(err, http.StatusServiceUnavailable) || signed != 1 {
		t.Fatalf("UploadInfo = %v after %d signed requests", err, signed)
	}
}

// fileDocument is a minimal file-info document a fake server answers with.
const fileDocument = `<?xml version="1.0"?><file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-info type="file">` +
	`<file-size>1</file-size><file-name>x</file-name><content-type>text/plain</content-type>` +
	`<data url="https://ft.example.test/dl?id=x" until="2026-01-01T00:00:00Z"/></file-info></file>`

// script answers the requests a fake server gets with statuses in turn (the
// last one repeats), a 401 with the challenge, any other status with
// retryAfter as Retry-After when set, and 200 with fileDocument.
func script(t *testing.T, retryAfter string, statuses ...int) (*ft.Client, *int) {
	t.Helper()
	calls := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		st := statuses[min(calls, len(statuses)-1)]
		calls++
		switch st {
		case http.StatusUnauthorized:
			w.Header().Set("WWW-Authenticate", challenge)
		case http.StatusOK:
			w.Header().Set("Content-Type", ft.ContentType)
			w.WriteHeader(st)
			_, _ = io.WriteString(w, fileDocument)
			return
		default:
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
		}
		w.WriteHeader(st)
	})
	return c, &calls
}

func TestTheEmptyPostIsSentAgainAsRcsjtaDoes(t *testing.T) {
	// HttpUploadManager.uploadFile: a 503 is waited out, and any answer but
	// 401 or 204 is sent again, up to RETRY_MAX (3).
	ft.ShortRetryAfter(t)
	c, calls := script(t, "1", http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusUnauthorized)
	var tr ft.Transfer
	if err := c.Precheck(ctx(t), &tr); err != nil || tr.BusyRetries != 2 || *calls != 3 {
		t.Fatalf("Precheck = %v, %d retries, %d calls", err, tr.BusyRetries, *calls)
	}
	c, calls = script(t, "1", http.StatusServiceUnavailable)
	tr = ft.Transfer{}
	if err := c.Precheck(ctx(t), &tr); !ft.IsStatus(err, http.StatusServiceUnavailable) || tr.BusyRetries != 3 || *calls != 4 {
		t.Fatalf("Precheck = %v, %d retries, %d calls; want 503 after 3 retries", err, tr.BusyRetries, *calls)
	}
	c, calls = script(t, "", http.StatusNoContent)
	if err := c.Precheck(ctx(t), nil); !ft.IsStatus(err, http.StatusNoContent) || *calls != 1 {
		t.Fatalf("Precheck = %v after %d calls; a server that asks for no authentication is an error", err, *calls)
	}
}

func TestTheUploadPostWaitsOutA503WithRetryAfterOnly(t *testing.T) {
	// HttpUploadManager.sendMultipartPost: a 503 is sent again only when its
	// Retry-After is above zero; anything else but 200 aborts.
	ft.ShortRetryAfter(t)
	up := ft.Upload{TID: "x", Name: "x", ContentType: "text/plain", Data: []byte("x")}
	c, calls := script(t, "1", http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusOK)
	var tr ft.Transfer
	if err := c.Precheck(ctx(t), &tr); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(ctx(t), &tr, up); err != nil || tr.BusyRetries != 1 || *calls != 3 {
		t.Fatalf("Send = %v, %d retries, %d calls", err, tr.BusyRetries, *calls)
	}
	for _, retryAfter := range []string{"", "0", "-1", "soon"} {
		c, calls := script(t, retryAfter, http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusOK)
		tr := ft.Transfer{}
		if err := c.Precheck(ctx(t), &tr); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Send(ctx(t), &tr, up); !ft.IsStatus(err, http.StatusServiceUnavailable) || tr.BusyRetries != 0 || *calls != 2 {
			t.Fatalf("Retry-After %q: Send = %v, %d retries, %d calls", retryAfter, err, tr.BusyRetries, *calls)
		}
	}
	c, calls = script(t, "1", http.StatusUnauthorized, http.StatusInternalServerError, http.StatusOK)
	if _, err := c.Send(ctx(t), nil, up); err == nil {
		t.Fatal("Send before a challenge succeeded")
	}
	if err := c.Precheck(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(ctx(t), nil, up); !ft.IsStatus(err, http.StatusInternalServerError) || *calls != 2 {
		t.Fatalf("Send = %v after %d calls; a 500 is not retried", err, *calls)
	}
}

func TestOneTransferHasThreeRetriesInAll(t *testing.T) {
	ft.ShortRetryAfter(t)
	// Three spent on the empty POST leave none for the upload's 503.
	c, calls := script(t, "1", http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable,
		http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusOK)
	var tr ft.Transfer
	if err := c.Precheck(ctx(t), &tr); err != nil || tr.BusyRetries != 3 {
		t.Fatalf("Precheck = %v, %d retries", err, tr.BusyRetries)
	}
	_, err := c.Send(ctx(t), &tr, ft.Upload{TID: "x", Name: "x", ContentType: "text/plain", Data: []byte("x")})
	if !ft.IsStatus(err, http.StatusServiceUnavailable) || *calls != 5 {
		t.Fatalf("Send = %v after %d calls", err, *calls)
	}
}

func TestRetryAfterIsWholeSecondsCapped(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"5": 5 * time.Second, "+2": 2 * time.Second, "0": 0, "-1": 0, "": 0, " 5": 0,
		"Fri, 31 Dec 1999 23:59:59 GMT": 0, "3600": time.Minute, "99999999999999999999": 0, "9223372036854775807": time.Minute,
	} {
		if got := ft.RetryAfter(v); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}

// resumeInfo is an upload-info document holding held bytes.
func resumeInfo(held int) string {
	return `<?xml version="1.0"?><file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">` +
		`<file-range start="0" end="` + strconv.Itoa(held-1) + `"/><data url="/ft/x"/></file-resume-info>`
}

func TestUploadInfoSettlesOnlyAfterAQuietTime(t *testing.T) {
	// 404, then 12 and 13 bytes, then 20 from the fourth answer on: the
	// quiet time starts again whenever the bytes held change.
	var mu sync.Mutex
	var signed []time.Time
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		signed = append(signed, time.Now())
		n := len(signed)
		mu.Unlock()
		switch {
		case n == 1:
			w.WriteHeader(http.StatusNotFound)
			return
		case n <= 3:
			w.Header().Set("Content-Type", ft.ContentType)
			_, _ = io.WriteString(w, resumeInfo(10+n))
		default:
			w.Header().Set("Content-Type", ft.ContentType)
			_, _ = io.WriteString(w, resumeInfo(20))
		}
	})
	const quiet = 50 * time.Millisecond
	info, st, err := c.SettledUploadInfo(ctx(t), "x", 5*time.Second, 5*time.Millisecond, quiet)
	if err != nil {
		t.Fatal(err)
	}
	held, _ := info.Held()
	mu.Lock()
	defer mu.Unlock()
	if held != 20 || st.NotHeld != 1 || st.Retries != int64(len(signed)-1) {
		t.Fatalf("held %d, %+v after %d answers", held, st, len(signed))
	}
	// The request it settled on reached the server at least a quiet time
	// after the last answer naming other bytes (the third): the quiet time
	// runs from the request that first got 20 bytes, which was sent after
	// that answer.
	if gap := signed[len(signed)-1].Sub(signed[2]); gap < quiet {
		t.Fatalf("settled %v after the bytes held last changed, want at least %v", gap, quiet)
	}
}

func TestUploadInfoTimesTheServerShowingWhatItHoldsNotItsAnswers(t *testing.T) {
	// #286: a server that holds the parts from the start shows them to the
	// first request, however slowly it answers; one that answers 404 first
	// shows them only to a later request.
	for _, c := range []struct {
		name     string
		notFirst bool
	}{{"held at once", false}, {"404 first", true}} {
		t.Run(c.name, func(t *testing.T) {
			const answer = 100 * time.Millisecond
			var mu sync.Mutex
			n := 0
			cl := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				time.Sleep(answer)
				mu.Lock()
				n++
				first := n == 1
				mu.Unlock()
				if first && c.notFirst {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", ft.ContentType)
				_, _ = io.WriteString(w, resumeInfo(20))
			})
			start := time.Now()
			_, st, err := cl.SettledUploadInfo(ctx(t), "x", 10*time.Second, 5*time.Millisecond, 50*time.Millisecond)
			took := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case took < 2*answer:
				t.Fatalf("took %v for two answers of %v", took, answer)
			case !c.notFirst && st.Showed >= answer:
				t.Fatalf("Showed %v for parts held from the first answer", st.Showed)
			case c.notFirst && st.Showed < answer:
				t.Fatalf("Showed %v, sooner than the 404 came back", st.Showed)
			}
		})
	}
}

func TestUploadInfoThatNeverHoldsAnythingEndsAsNothingHeld(t *testing.T) {
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	_, st, err := c.SettledUploadInfo(ctx(t), "x", 30*time.Millisecond, 5*time.Millisecond, time.Second)
	// Every answer was a 404 and was counted, however few came in time.
	if !errors.Is(err, ft.ErrNothingHeld) || st.NotHeld < 1 || st.NotHeld != st.Retries+1 {
		t.Fatalf("SettledUploadInfo = %v, %+v", err, st)
	}
}

func TestUploadInfoStillChangingWhenTimeRunsOutIsNotSettled(t *testing.T) {
	// Every answer holds more: the server is still storing.
	var mu sync.Mutex
	n := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		n++
		held := 10 * n
		mu.Unlock()
		w.Header().Set("Content-Type", ft.ContentType)
		_, _ = io.WriteString(w, resumeInfo(held))
	})
	info, _, err := c.SettledUploadInfo(ctx(t), "x", 50*time.Millisecond, 5*time.Millisecond, time.Second)
	if held, _ := info.Held(); !errors.Is(err, ft.ErrNotSettled) || held == 0 {
		t.Fatalf("SettledUploadInfo = %v, held %d", err, held)
	}
}

// brokenChunks answers every request with status, contentType and a body
// whose chunked encoding breaks after a few bytes, quoting secret where Go
// would read a chunk length. The header must go out raw, so the handler
// takes the connection over.
func brokenChunks(t *testing.T, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && r.URL.Query().Has("tid") {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\nsecret-host\r\n")
		_ = buf.Flush()
	}
}

func TestABrokenBodyIsAFixedReasonForDownloadsAndDocuments(t *testing.T) {
	c := fakeServer(t, brokenChunks(t, "application/octet-stream"))
	_, err := c.Download(ctx(t), c.UploadURL.String(), "", 1<<20)
	if !errors.Is(err, safeerr.ErrBadBody) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Download = %v", err)
	}
	c = fakeServer(t, brokenChunks(t, ft.ContentType))
	_, err = c.DownloadInfo(ctx(t), "x")
	if !errors.Is(err, safeerr.ErrBadBody) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("DownloadInfo = %v", err)
	}
}

func TestASecondChallengeIsAnAuthenticationFailure(t *testing.T) {
	calls := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	})
	if _, err := c.DownloadInfo(ctx(t), "x"); !ft.IsStatus(err, http.StatusUnauthorized) || calls != 2 {
		t.Fatalf("DownloadInfo = %v after %d calls, want the unauthenticated GET, the signed one, then 401", err, calls)
	}
}

func TestAnUploadInfoEndThatWouldOverflowIsRefused(t *testing.T) {
	var d ft.ResumeDocument
	d.Range.Start, d.Range.End = "0", "9223372036854775807"
	if held, err := d.Held(); err == nil {
		t.Fatalf("Held = %d", held)
	}
}

func TestPrecheckNeedsAChallenge(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"200":          func(w http.ResponseWriter, _ *http.Request) {},
		"no challenge": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"garbage": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", "Basic realm=x")
			w.WriteHeader(http.StatusUnauthorized)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := fakeServer(t, h).Precheck(ctx(t), nil); err == nil {
				t.Fatal("Precheck accepted it")
			}
		})
	}
}

func TestMalformedDocumentsAreErrors(t *testing.T) {
	for name, body := range map[string]string{
		"doctype":      `<!DOCTYPE x><file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"/>`,
		"not xml":      `{}`,
		"too large":    strings.Repeat(" ", 70<<10),
		"bad range":    `<file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-range start="5" end="9"/><data url="/ft/x"/></file-resume-info>`,
		"wrong status": "",
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if name == "wrong status" {
					w.WriteHeader(http.StatusTeapot)
					return
				}
				_, _ = w.Write([]byte(body))
			})
			if err := c.Precheck(ctx(t), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.UploadInfo(ctx(t), "x"); err == nil {
				t.Fatal("UploadInfo accepted it")
			}
		})
	}
}

func TestFileDocumentsMustBeTheRightTypeAndNameTheFile(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"other type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"/>`))
		},
		"no file": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ft.ContentType)
			_, _ = w.Write([]byte(`<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp"><file-info type="thumbnail"/></file>`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				h(w, r)
			})
			if err := c.Precheck(ctx(t), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.DownloadInfo(ctx(t), "x"); err == nil {
				t.Fatal("DownloadInfo accepted it")
			}
		})
	}
}

func TestResumeRefusesWhatCannotBeResumed(t *testing.T) {
	c := &ft.Client{HTTP: http.DefaultClient, UploadURL: &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/ft"}}
	var whole ft.ResumeDocument
	whole.Range.Start, whole.Range.End = "0", "9"
	if _, err := c.Resume(ctx(t), whole, "x/y", make([]byte, 10)); err == nil {
		t.Fatal("Resume of a file the server holds whole")
	}
	var bad ft.ResumeDocument
	if _, err := c.Resume(ctx(t), bad, "x/y", make([]byte, 10)); err == nil {
		t.Fatal("Resume of a document without a range")
	}
	if err := c.SendInterrupted(ctx(t), ft.Upload{TID: "x", Name: "x", ContentType: "a/b", Data: []byte("x")}, 0); err == nil {
		t.Fatal("a cut outside the body was accepted")
	}
}

func TestUploadInfoMeasuresItsQuietTimeAndDeadlineOnItsClock(t *testing.T) {
	// A clock that moves an hour each time it is read: the quiet time is
	// over at the second answer and the deadline at the next read, both
	// whatever the real time between requests (#197).
	var mu sync.Mutex
	n := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", ft.ContentType)
		_, _ = io.WriteString(w, resumeInfo(20))
	})
	var reads atomic.Int64
	c.Now = func() time.Time { return time.Unix(0, 0).Add(time.Duration(reads.Add(1)) * time.Hour) }
	if _, _, err := c.SettledUploadInfo(ctx(t), "x", 10*time.Hour, time.Millisecond, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 2 {
		t.Fatalf("%d answers, want 2: the quiet time was not taken from the clock", n)
	}
}

func TestUploadInfoEndsAtTheDeadlineOnItsClock(t *testing.T) {
	// The deadline as well comes from the clock: the bytes held keep
	// changing, the clock moves an hour per read and the settle time is
	// 3 h, so the second answer finds the deadline passed (QA on #203).
	var mu sync.Mutex
	n := 0
	c := fakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		n++
		held := 10 + n
		mu.Unlock()
		w.Header().Set("Content-Type", ft.ContentType)
		_, _ = io.WriteString(w, resumeInfo(held))
	})
	var reads atomic.Int64
	c.Now = func() time.Time { return time.Unix(0, 0).Add(time.Duration(reads.Add(1)) * time.Hour) }
	if _, _, err := c.SettledUploadInfo(ctx(t), "x", 3*time.Hour, time.Millisecond, 30*time.Minute); !errors.Is(err, ft.ErrNotSettled) {
		t.Fatalf("SettledUploadInfo = %v, want ErrNotSettled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 2 {
		t.Fatalf("%d answers before the deadline, want 2", n)
	}
}
