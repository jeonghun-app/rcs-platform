package ft_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
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
	if err := c.Precheck(ctx(t)); err != nil {
		t.Fatal(err)
	}
	up := ft.Upload{TID: "tid-1", Name: "a photo.jpg", ContentType: "image/jpeg", Data: content(t, 3*part+5),
		Thumbnail: content(t, 100), ThumbnailType: "image/png"}
	doc, err := c.Send(ctx(t), up)
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
	if err := c.Precheck(ctx(t)); err != nil {
		t.Fatal(err)
	}
	up := ft.Upload{TID: "tid-resume", Name: "v.mp4", ContentType: "video/mp4", Data: content(t, 5*part+11)}
	if err := c.SendInterrupted(ctx(t), up, 4*part); err != nil {
		t.Fatal(err)
	}
	var info ft.ResumeDocument
	// The server notices the break on its own time; until then it may hold
	// less, which is what get_upload_info reports.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		info, err = c.UploadInfo(ctx(t), up.TID)
		if err == nil {
			break
		}
		if !errors.Is(err, ft.ErrNothingHeld) || time.Now().After(deadline) {
			t.Fatalf("get_upload_info = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	held, err := info.Held()
	if err != nil || held <= 0 || held%part != 0 || held >= int64(len(up.Data)) {
		t.Fatalf("held %d, %v", held, err)
	}
	// While the server is still storing the broken upload, a PUT from
	// what it reported a moment ago gets 409; the client asks again.
	doc, err := c.Resume(ctx(t), info, up.ContentType, up.Data)
	for attempt := 0; ft.IsStatus(err, http.StatusConflict) && attempt < 10; attempt++ {
		time.Sleep(50 * time.Millisecond)
		if info, err = c.UploadInfo(ctx(t), up.TID); err == nil {
			doc, err = c.Resume(ctx(t), info, up.ContentType, up.Data)
		}
	}
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
	if err := c.Precheck(ctx(t)); err != nil {
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
	if err := c.Precheck(ctx(t)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Send(ctx(t), ft.Upload{TID: "x", Name: "x", ContentType: "text/plain", Data: []byte("x")})
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
	if err := c.Precheck(ctx(t)); err == nil || strings.Contains(err.Error(), "127.0.0.1") {
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
	if err := c.Precheck(ctx(t)); err != nil {
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
			if err := fakeServer(t, h).Precheck(ctx(t)); err == nil {
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
			if err := c.Precheck(ctx(t)); err != nil {
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
			if err := c.Precheck(ctx(t)); err != nil {
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
