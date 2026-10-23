package ftserver

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// rcsjta answers challenges the way the GSMA rcsjta reference client does
// (HttpAuthenticationAgent, HttpUploadManager): it reads only the last
// WWW-Authenticate field, answers it as MD5 without an algorithm parameter,
// quotes qop, and signs only the path of the URL in uri.
type rcsjta struct {
	t        *testing.T
	e        *env
	user     string
	password string
	realm    string
	nonce    string
	opaque   string
	nc       int
}

func (c *rcsjta) readChallenge(h http.Header) {
	c.t.Helper()
	values := h.Values("WWW-Authenticate")
	if len(values) == 0 {
		c.t.Fatal("no challenge")
	}
	ch, err := digest.ParseChallenge(values[len(values)-1])
	if err != nil {
		c.t.Fatal(err)
	}
	c.realm, c.nonce, c.opaque, c.nc = ch.Realm, ch.Nonce, ch.Opaque, 0
}

func (c *rcsjta) authorization(method, path string) string {
	c.nc++
	h := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
	nc := fmt.Sprintf("%08x", c.nc)
	cnonce := "rcsjta-cnonce-" + strconv.Itoa(c.nc)
	ha1 := h(c.user + ":" + c.realm + ":" + c.password)
	response := h(ha1 + ":" + c.nonce + ":" + nc + ":" + cnonce + ":auth:" + h(method+":"+path))
	return `Digest username="` + c.user + `",realm="` + c.realm + `",nonce="` + c.nonce + `",uri="` + path +
		`",nc=` + nc + `,cnonce="` + cnonce + `",opaque="` + c.opaque + `",qop="auth",response="` + response + `"`
}

// do sends a request for target, signing only its path.
func (c *rcsjta) do(method, target, contentType, body string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	u, _ := url.Parse(target)
	r.Header.Set("Authorization", c.authorization(method, u.Path))
	return c.e.do(r)
}

// getInfo is rcsjta's sendGetInfo (HttpUploadManager), used for
// get_upload_info and get_download_info: a GET without credentials first,
// whose 401 brings a fresh nonce, then the same GET signed for the path only.
// rcsjta's agent starts a new nonce at nc 1
// (HttpDigestMd5Authentication.updateNonceParameters), as readChallenge does.
func (c *rcsjta) getInfo(target string) *httptest.ResponseRecorder {
	c.t.Helper()
	first := c.e.do(httptest.NewRequest(http.MethodGet, target, nil))
	if first.Code != http.StatusUnauthorized {
		c.t.Fatalf("unauthenticated %s = %d, want 401", target, first.Code)
	}
	c.readChallenge(first.Header())
	return c.do(http.MethodGet, target, "", "")
}

// rcsjtaForm builds the multipart body rcsjta writes: tid, then File, each
// part with its own Content-Length, the file name URL-encoded.
func rcsjtaForm(tid, name, data string) string {
	return "--boundary1\r\nContent-Disposition: form-data; name=\"tid\"\r\nContent-Type: text/plain\r\nContent-Length: " +
		strconv.Itoa(len(tid)) + "\r\n\r\n" + tid + "\r\n" +
		"--boundary1\r\nContent-Disposition: form-data; name=\"File\"; filename=\"" + url.QueryEscape(name) +
		"\"\r\nContent-Type: image/jpeg\r\nContent-Length: " + strconv.Itoa(len(data)) + "\r\n\r\n" + data + "\r\n--boundary1--"
}

func TestRCSJTAUploadBreaksResumesAndFetchesTheDownloadInfo(t *testing.T) {
	e := newEnv(t)
	c := &rcsjta{t: t, e: e, user: alice, password: password}

	pre := e.do(httptest.NewRequest(http.MethodPost, "/ft", nil))
	if pre.Code != http.StatusUnauthorized {
		t.Fatalf("pre-check = %d", pre.Code)
	}
	c.readChallenge(pre.Header())

	data := pattern(3*testPart + 7)
	body := rcsjtaForm("rcsjta-1", "my photo.jpg", data)
	cut := strings.Index(body, data) + 2*testPart + 100
	r := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(body[:cut]))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary1")
	r.Header.Set("Authorization", c.authorization(http.MethodPost, "/ft"))
	if rec := e.do(r); rec.Code != http.StatusBadRequest {
		t.Fatalf("broken upload = %d", rec.Code)
	}

	// resumeUpload: get_upload_info, unauthenticated first, then signed for
	// "/ft" only under the fresh nonce.
	info := c.getInfo("/ft?tid=rcsjta-1&get_upload_info")
	if info.Code != http.StatusOK {
		t.Fatalf("get_upload_info with a path-only uri = %d", info.Code)
	}
	d := parseResumeDocument(t, info.Body.Bytes())
	end, _ := strconv.Atoi(d.Range.End)
	resume, _ := url.Parse(d.Data.URL)
	// sendPutForResumingUpload: Content-Range from end+1, signed for the
	// resume URL's path.
	put := c.do(http.MethodPut, resume.Path, "image/jpeg", data[end+1:],
		"Content-Range", "bytes "+strconv.Itoa(end+1)+"-"+strconv.Itoa(len(data)-1)+"/"+strconv.Itoa(len(data)))
	if put.Code != http.StatusOK {
		t.Fatalf("resume PUT = %d %s", put.Code, put.Body)
	}
	// sendGetDownloadInfo after the PUT, the same way: unauthenticated first,
	// then signed for "/ft" only.
	dl := c.getInfo("/ft?tid=rcsjta-1&get_download_info")
	if dl.Code != http.StatusOK {
		t.Fatalf("get_download_info with a path-only uri = %d", dl.Code)
	}
	f := fileOf(t, parseFileDocument(t, dl.Body.Bytes()))
	if f.Name != "my+photo.jpg" || f.Size != int64(len(data)) {
		t.Fatalf("file info = %+v", f)
	}
	if got := get(e, downloadTarget(t, f.Data.URL)).Body.String(); got != data {
		t.Fatal("the resumed file differs")
	}
	if e.metric("auth.uri_path_only") != 2 {
		t.Fatalf("auth.uri_path_only = %v, want 2", e.metric("auth.uri_path_only"))
	}
}

func TestRCSJTABrokenUploadVerifiedAfterItsResumeStartsStillCounts(t *testing.T) {
	// The ordering behind #66: the client gives up on a broken POST as soon
	// as its body fails, so its next request can be verified before the
	// server has read the POST. rcsjta's next request, get_upload_info, goes
	// out without credentials and its 401 starts a fresh nonce, so the late
	// POST's nonce-count competes with nothing and the POST keeps its whole
	// parts. (A client that reuses the POST's nonce is covered by
	// TestBrokenUploadVerifiedAfterTheNextRequestOnItsNonceIsKept.)
	e := newEnv(t)
	c := &rcsjta{t: t, e: e, user: alice, password: password}
	c.readChallenge(e.do(httptest.NewRequest(http.MethodPost, "/ft", nil)).Header())
	data := pattern(3*testPart + 7)
	body := rcsjtaForm("rcsjta-late", "clip.mp4", data)
	cut := strings.Index(body, data) + 2*testPart + 100
	late := httptest.NewRequest(http.MethodPost, "/ft", strings.NewReader(body[:cut]))
	late.Header.Set("Content-Type", "multipart/form-data; boundary=boundary1")
	late.Header.Set("Authorization", c.authorization(http.MethodPost, "/ft"))

	if early := c.getInfo("/ft?tid=rcsjta-late&get_upload_info"); early.Code != http.StatusNotFound {
		t.Fatalf("get_upload_info before the POST is read = %d, want 404", early.Code)
	}
	if rec := e.do(late); rec.Code != http.StatusBadRequest {
		t.Fatalf("late broken upload = %d, want 400 (accepted, then broken)", rec.Code)
	}
	info := c.getInfo("/ft?tid=rcsjta-late&get_upload_info")
	if info.Code != http.StatusOK {
		t.Fatalf("get_upload_info = %d", info.Code)
	}
	if end, _ := strconv.Atoi(parseResumeDocument(t, info.Body.Bytes()).Range.End); end+1 != 2*testPart {
		t.Fatalf("held %d bytes, want the two whole parts", end+1)
	}
}

func TestPathOnlyURIIsAcceptedOnlyForTheSamePathAndMethod(t *testing.T) {
	e := newEnv(t)
	e.user(alice).uploadFile("paths", "x")
	c := &rcsjta{t: t, e: e, user: alice, password: password}
	c.readChallenge(e.do(httptest.NewRequest(http.MethodPost, "/ft", nil)).Header())
	for name, auth := range map[string]string{
		"other path":   c.authorization(http.MethodGet, "/dl"),
		"other query":  c.authorization(http.MethodGet, "/ft?tid=other&get_upload_info"),
		"other method": c.authorization(http.MethodPost, "/ft"),
	} {
		r := httptest.NewRequest(http.MethodGet, "/ft?tid=paths&get_upload_info", nil)
		r.Header.Set("Authorization", auth)
		if rec := e.do(r); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
}
