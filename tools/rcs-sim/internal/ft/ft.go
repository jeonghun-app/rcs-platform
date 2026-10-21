// Package ft is the client side of RCS File Transfer via HTTP (GSMA RCC.07),
// written to behave like the GSMA rcsjta reference client, so that tests of
// ft-server exercise what deployed devices actually send rather than what
// the server's own tests assume.
//
// Like rcsjta (HttpAuthenticationAgent, HttpDigestMd5Authentication,
// HttpUploadManager), the client:
//
//   - starts an upload with an empty POST and reads the challenge of the
//     401;
//   - answers the last WWW-Authenticate field only, as MD5 without an
//     algorithm parameter, with qop quoted, counting nc from 1 for each new
//     nonce;
//   - sends get_upload_info and get_download_info without credentials
//     first, takes the fresh nonce of their 401, and signs the repeated GET
//     for the path of the URL only (RFC 7616 §3.4.6 allows that
//     absolute-path);
//   - sends the form as tid, then Thumbnail, then File, each part with its
//     own Content-Length;
//   - resumes a broken upload with get_upload_info and a PUT with
//     Content-Range from the first byte the server does not hold.
//
// It retries what rcsjta retries and nothing else (HttpUploadManager). The
// empty POST is sent again on any answer but 401, after the Retry-After of
// a 503; the multipart POST is sent again on a 503 with a Retry-After above
// zero. Both count against one budget of three per transfer (RETRY_MAX),
// which the caller sees in Transfer.BusyRetries. A second 401, any other
// failure of the upload POST, and a PUT answered other than 200 are
// failures. (rcsjta restarts the upload from the beginning when
// get_upload_info answers anything but 200; this client reports that as
// ErrNothingHeld and leaves the restart to the caller.)
//
// Nothing here logs. Errors name the operation and the HTTP status or a
// fixed network reason (safeerr), never the user name, the password, a URL
// or an address: download URLs are capabilities.
package ft

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// ContentType is the media type of the file-info and upload-info documents.
const ContentType = "application/vnd.gsma.rcs-ft-http+xml"

// maxDocument bounds a document read from the server.
const maxDocument = 64 << 10

// Client talks to one ft-server upload URI as one user.
type Client struct {
	// HTTP sends requests; it must not follow redirects for uploads.
	HTTP *http.Client
	// UploadURL is the ftHTTPCSURI acs provisions.
	UploadURL *url.URL
	// User and Password are ftHTTPCSUser and ftHTTPCSPwd. Password is never
	// printed: see secret.
	User     string
	Password Secret
	// Random supplies client nonces; crypto/rand when nil.
	Random io.Reader
	// Now is the clock SettledUploadInfo measures its quiet time and its
	// deadline by; time.Now when nil. The waits between requests are real.
	Now func() time.Time

	mu        sync.Mutex
	challenge *digest.Challenge
	nc        uint32
}

// Secret is a password that prints as a placeholder, so a Client in a log
// line or an error cannot reveal it.
type Secret struct{ b []byte }

// NewSecret wraps a password.
func NewSecret(p string) Secret { return Secret{b: []byte(p)} }

func (Secret) String() string   { return "[redacted]" }
func (Secret) GoString() string { return "[redacted]" }

// StatusError is a response the client did not expect.
type StatusError struct {
	Op     string
	Status int
}

func (e *StatusError) Error() string { return "ft: " + e.Op + ": HTTP " + strconv.Itoa(e.Status) }

// IsStatus reports whether err is a StatusError with code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == code
}

// maxRetries is rcsjta's RETRY_MAX: how often one transfer's upload POSTs
// are sent again.
const maxRetries = 3

// maxRetryAfter caps the seconds a Retry-After asks for. rcsjta has no cap;
// a step's timeout usually ends the wait sooner.
const maxRetryAfter = 60

// retryUnit is what one Retry-After second waits; tests shorten it.
var retryUnit = time.Second

// Transfer is the state rcsjta keeps for one file transfer across its
// requests (an HttpUploadManager).
type Transfer struct {
	// BusyRetries counts the upload POSTs sent again, at most three.
	BusyRetries int
}

// retry spends one retry of t, if one is left.
func (t *Transfer) retry() bool {
	if t.BusyRetries >= maxRetries {
		return false
	}
	t.BusyRetries++
	return true
}

// retryAfter reads Retry-After as rcsjta does (getRetryTimeout): whole
// seconds, and no wait for anything else. It is capped before multiplying,
// so a large value cannot overflow.
func retryAfter(v string) time.Duration {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(min(n, maxRetryAfter)) * retryUnit
}

// sleep waits d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Precheck sends the empty POST rcsjta starts every upload with and keeps
// the challenge of its 401. As rcsjta does, it sends the POST again on any
// other answer, after the Retry-After of a 503, while t has retries left. A
// 204 (rcsjta's "authentication not required") is an error here: ft-server
// always asks. A nil t gives the call a transfer of its own.
func (c *Client) Precheck(ctx context.Context, t *Transfer) error {
	if t == nil {
		t = &Transfer{}
	}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.UploadURL.String(), nil)
		if err != nil {
			return err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("ft: pre-check: %w", safeerr.Reason(err))
		}
		drain(resp)
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return c.readChallenge(resp.Header)
		case resp.StatusCode == http.StatusNoContent || !t.retry():
			return &StatusError{Op: "pre-check", Status: resp.StatusCode}
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			if err := sleep(ctx, retryAfter(resp.Header.Get("Retry-After"))); err != nil {
				return fmt.Errorf("ft: pre-check: %w", err)
			}
		}
	}
}

// readChallenge keeps the last WWW-Authenticate field, the only one rcsjta
// reads, and restarts the nonce-count.
func (c *Client) readChallenge(h http.Header) error {
	values := h.Values("WWW-Authenticate")
	if len(values) == 0 {
		return errors.New("ft: 401 without a challenge")
	}
	ch, err := digest.ParseChallenge(values[len(values)-1])
	if err != nil {
		return fmt.Errorf("ft: unreadable challenge: %w", err)
	}
	c.mu.Lock()
	c.challenge, c.nc = &ch, 0
	c.mu.Unlock()
	return nil
}

// authorize signs r for uri, the path rcsjta puts in the credentials.
func (c *Client) authorize(r *http.Request, uri string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.challenge == nil {
		return errors.New("ft: no challenge yet; call Precheck")
	}
	c.nc++
	cnonce, err := digest.NewCNonce(c.random())
	if err != nil {
		return err
	}
	// rcsjta answers as MD5 whatever the field offers, without an
	// algorithm parameter.
	ch := *c.challenge
	ch.Algorithm = ""
	cred, err := digest.Respond(ch, digest.ClientParams{
		Username: c.User, Password: c.Password.b, Method: r.Method, URI: uri, CNonce: cnonce, NC: c.nc,
	})
	if err != nil {
		return fmt.Errorf("ft: answering the challenge: %w", err)
	}
	r.Header.Set("Authorization", cred.Header())
	return nil
}

func (c *Client) random() io.Reader {
	if c.Random != nil {
		return c.Random
	}
	return rand.Reader
}

// do sends one request built by build, signed for uri under the current
// challenge.
func (c *Client) do(ctx context.Context, op, uri string, build func() (*http.Request, error)) (*http.Response, error) {
	req, err := build()
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.authorize(req, uri); err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	switch {
	case errors.Is(err, errCut):
		// The break SendInterrupted made on purpose, not a network failure.
		return nil, fmt.Errorf("ft: %s: %w", op, errCut)
	case err != nil:
		return nil, fmt.Errorf("ft: %s: %w", op, safeerr.Reason(err))
	}
	return resp, nil
}

// getInfo is rcsjta's sendGetInfo: target without credentials first; a 401
// brings the challenge, and the GET is repeated signed for the path. An
// answer other than 401 to the first GET is returned as it is.
func (c *Client) getInfo(ctx context.Context, op, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ft: %s: %w", op, safeerr.Reason(err))
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	drain(resp)
	if err := c.readChallenge(resp.Header); err != nil {
		return nil, err
	}
	resp, err = c.do(ctx, op, c.UploadURL.Path, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, target, nil)
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// rcsjta: "got 401 for the second time. Authentication rejected."
		drain(resp)
		return nil, &StatusError{Op: op, Status: resp.StatusCode}
	}
	return resp, nil
}

// Upload is one file to send.
type Upload struct {
	// TID is the transfer id the client chooses (1 to 128 URI unreserved
	// characters).
	TID         string
	Name        string
	ContentType string
	Data        []byte
	// Thumbnail and ThumbnailType are optional.
	Thumbnail     []byte
	ThumbnailType string
}

// form builds the multipart body the way rcsjta writes it.
func (u Upload) form() (body []byte, contentType string, err error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part := func(h textproto.MIMEHeader, data []byte) error {
		h.Set("Content-Length", strconv.Itoa(len(data)))
		p, err := w.CreatePart(h)
		if err != nil {
			return err
		}
		_, err = p.Write(data)
		return err
	}
	if err := part(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="tid"`},
		"Content-Type":        {"text/plain"},
	}, []byte(u.TID)); err != nil {
		return nil, "", err
	}
	if u.Thumbnail != nil {
		if err := part(textproto.MIMEHeader{
			"Content-Disposition": {`form-data; name="Thumbnail"; filename="thumbnail"`},
			"Content-Type":        {u.ThumbnailType},
		}, u.Thumbnail); err != nil {
			return nil, "", err
		}
	}
	if err := part(textproto.MIMEHeader{
		// rcsjta URL-encodes the file name.
		"Content-Disposition": {`form-data; name="File"; filename="` + url.QueryEscape(u.Name) + `"`},
		"Content-Type":        {u.ContentType},
	}, u.Data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// Send uploads u whole as part of transfer t and returns the file-info
// document. As rcsjta does, a 503 with a Retry-After above zero is waited
// out and the POST sent again while t has retries left; any other answer
// but 200 is a failure. A nil t gives the call a transfer of its own.
func (c *Client) Send(ctx context.Context, t *Transfer, u Upload) (FileDocument, error) {
	if t == nil {
		t = &Transfer{}
	}
	body, ct, err := u.form()
	if err != nil {
		return FileDocument{}, err
	}
	for {
		resp, err := c.do(ctx, "upload", c.UploadURL.Path, func() (*http.Request, error) {
			r, err := http.NewRequest(http.MethodPost, c.UploadURL.String(), bytes.NewReader(body))
			if err == nil {
				r.Header.Set("Content-Type", ct)
			}
			return r, err
		})
		if err != nil {
			return FileDocument{}, err
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			if wait := retryAfter(resp.Header.Get("Retry-After")); wait > 0 && t.retry() {
				drain(resp)
				if err := sleep(ctx, wait); err != nil {
					return FileDocument{}, fmt.Errorf("ft: upload: %w", err)
				}
				continue
			}
		}
		return readFileDocument(resp, "upload")
	}
}

// errCut is the read error that breaks an interrupted upload.
var errCut = errors.New("upload cut by the simulator")

// SendInterrupted starts uploading u and breaks the connection after cut
// octets of the body, the way a phone changing networks does. It reports an
// error only if the upload could not even start; the transport failure that
// breaking it causes is the expected outcome.
func (c *Client) SendInterrupted(ctx context.Context, u Upload, cut int) error {
	body, ct, err := u.form()
	if err != nil {
		return err
	}
	if cut <= 0 || cut >= len(body) {
		return errors.New("ft: cut must fall inside the body")
	}
	resp, err := c.do(ctx, "interrupted upload", c.UploadURL.Path, func() (*http.Request, error) {
		r, err := http.NewRequest(http.MethodPost, c.UploadURL.String(), io.MultiReader(bytes.NewReader(body[:cut]), failing{}))
		if err == nil {
			r.Header.Set("Content-Type", ct)
			r.ContentLength = int64(len(body))
		}
		return r, err
	})
	if err == nil {
		drain(resp)
		return &StatusError{Op: "interrupted upload", Status: resp.StatusCode}
	}
	if !errors.Is(err, errCut) {
		return err
	}
	return nil
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errCut }

// UploadInfo asks what the server holds of tid (get_upload_info) the way
// rcsjta does (getInfo). ErrNothingHeld is a 404: no byte is held, and
// rcsjta would upload the file again from the start.
func (c *Client) UploadInfo(ctx context.Context, tid string) (ResumeDocument, error) {
	resp, err := c.getInfo(ctx, "get_upload_info", c.infoURL(tid, "get_upload_info"))
	if err != nil {
		return ResumeDocument{}, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return ResumeDocument{}, ErrNothingHeld
	}
	if resp.StatusCode != http.StatusOK {
		return ResumeDocument{}, &StatusError{Op: "get_upload_info", Status: resp.StatusCode}
	}
	var d ResumeDocument
	if err := decode(resp.Body, &d); err != nil {
		return ResumeDocument{}, fmt.Errorf("ft: get_upload_info: %w", err)
	}
	if _, err := d.Held(); err != nil {
		return ResumeDocument{}, err
	}
	return d, nil
}

// ErrNothingHeld is get_upload_info's 404: start the upload again.
var ErrNothingHeld = errors.New("ft: the server holds nothing of the upload")

// ErrNotSettled is SettledUploadInfo's answer when the bytes held were still
// changing as its time ran out: the server is still storing the broken
// upload, and a resume now would likely get 409 or 503.
var ErrNotSettled = errors.New("ft: the server is still storing the broken upload")

// Settled says how SettledUploadInfo got its answer: how often it asked
// again, and how many answers were 404.
type Settled struct {
	Retries, NotHeld int64
}

// SettledUploadInfo is the simulator's own wait, not rcsjta's. A device
// asks get_upload_info once it is back on a network, seconds after the
// break; a test asks at once, before the server may have noticed the break,
// stored what it keeps and released the upload. So this asks every poll
// until the same bytes held have been reported for at least quiet: two
// answers in a row can agree while the server still holds the upload, and
// a resume then gets 503. The server reads what it holds somewhere between
// a request and its answer, so the quiet time runs from the answer that
// first named the value to a later request that gets it again: time the
// server is known to have held the value, which a slow answer's wait is not
// (#377). within bounds when the requests are sent: a 404 is asked again
// until a request sent after within has passed gets one too, and is then
// returned as ErrNothingHeld. Bytes held that such a request names are
// given, once, the rest of their quiet time; bytes held still changing
// after that are returned with ErrNotSettled.
//
// Nothing the server sends says the upload is released: its lease lasts
// minutes when the process holding it dies, and ft-server's upload-info
// document is RCC.07's, which has no such field. The quiet time is what a
// device's reconnection gives the server anyway.
func (c *Client) SettledUploadInfo(ctx context.Context, tid string, within, poll, quiet time.Duration) (ResumeDocument, Settled, error) {
	var st Settled
	now := c.Now
	if now == nil {
		now = time.Now
	}
	deadline := now().Add(within)
	last := int64(-1)
	var since time.Time
	extended := false
	for {
		asked := now()
		info, err := c.UploadInfo(ctx, tid)
		answered := now()
		held := int64(-1)
		switch {
		case errors.Is(err, ErrNothingHeld):
			st.NotHeld++
		case err != nil:
			return info, st, err
		default:
			held, _ = info.Held()
			if held == last && asked.Sub(since) >= quiet {
				return info, st, nil
			}
		}
		if held != last {
			last, since = held, answered
		}
		// within bounds when a request is sent, not when its answer comes:
		// one slow answer on a loaded host says nothing about the server
		// still storing, and the next request may confirm what it holds
		// (#344). A request sent past the deadline that does not settle
		// ends the wait, except that the bytes held it names get, once, the
		// rest of their quiet time. The slow answer is most often the 404
		// to a request sent before the server noticed the break, and the
		// server may well be done storing by now; ending here would fail
		// the step on one slow answer after all.
		if asked.After(deadline) {
			if err == nil && !extended {
				deadline, extended = since.Add(quiet), true
			} else {
				if err == nil {
					err = ErrNotSettled
				}
				return info, st, err
			}
		}
		if err := sleep(ctx, poll); err != nil {
			return info, st, err
		}
		st.Retries++
	}
}

// Resume sends the rest of data from the first byte d says is missing, with
// a PUT to the resume URL, signed for its path.
func (c *Client) Resume(ctx context.Context, d ResumeDocument, contentType string, data []byte) (FileDocument, error) {
	held, err := d.Held()
	if err != nil {
		return FileDocument{}, err
	}
	if held >= int64(len(data)) {
		return FileDocument{}, errors.New("ft: the server reports holding the whole file")
	}
	target, err := c.UploadURL.Parse(d.Data.URL)
	if err != nil {
		return FileDocument{}, errors.New("ft: unusable resume URL")
	}
	rest := data[held:]
	contentRange := "bytes " + strconv.FormatInt(held, 10) + "-" + strconv.Itoa(len(data)-1) + "/" + strconv.Itoa(len(data))
	resp, err := c.do(ctx, "resume", target.Path, func() (*http.Request, error) {
		r, err := http.NewRequest(http.MethodPut, target.String(), bytes.NewReader(rest))
		if err == nil {
			r.Header.Set("Content-Type", contentType)
			r.Header.Set("Content-Range", contentRange)
		}
		return r, err
	})
	if err != nil {
		return FileDocument{}, err
	}
	return readFileDocument(resp, "resume")
}

// DownloadInfo fetches the file-info document of a completed upload
// (get_download_info) the way rcsjta does (getInfo).
func (c *Client) DownloadInfo(ctx context.Context, tid string) (FileDocument, error) {
	resp, err := c.getInfo(ctx, "get_download_info", c.infoURL(tid, "get_download_info"))
	if err != nil {
		return FileDocument{}, err
	}
	return readFileDocument(resp, "get_download_info")
}

func (c *Client) infoURL(tid, which string) string {
	u := *c.UploadURL
	u.RawQuery = "tid=" + url.QueryEscape(tid) + "&" + which
	return u.String()
}

// RangeHeader returns a Range header value for the inclusive range
// first-last.
func RangeHeader(first, last int64) string {
	return "bytes=" + strconv.FormatInt(first, 10) + "-" + strconv.FormatInt(last, 10)
}

// Downloaded is what a download returned.
type Downloaded struct {
	Status int
	Body   []byte
	// ETag is the server's strong ETag, the SHA-256 of the whole content.
	ETag string
}

// Download fetches link, which a recipient takes from a file-info document,
// sending rangeHeader as the Range header when it is not empty. Downloads
// carry no credentials, as recipients' clients send none (ft-server's
// default).
func (c *Client) Download(ctx context.Context, link, rangeHeader string, max int64) (Downloaded, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return Downloaded{}, errors.New("ft: unusable download URL")
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Downloaded{}, fmt.Errorf("ft: download: %w", safeerr.Reason(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return Downloaded{}, &StatusError{Op: "download", Status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return Downloaded{}, fmt.Errorf("ft: download: %w", safeerr.Body(err))
	}
	if int64(len(body)) > max {
		return Downloaded{}, errors.New("ft: download larger than expected")
	}
	return Downloaded{Status: resp.StatusCode, Body: body, ETag: resp.Header.Get("ETag")}, nil
}

// SHA256 returns the lower-case hex SHA-256 of b, the form of ft-server's
// ETag (inside its quotes).
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileDocument is a file-info document.
type FileDocument struct {
	XMLName xml.Name   `xml:"urn:gsma:params:xml:ns:rcs:rcs:fthttp file"`
	Infos   []FileInfo `xml:"file-info"`
}

// FileInfo is one file-info element: the file or its thumbnail.
type FileInfo struct {
	Type        string `xml:"type,attr"`
	Size        int64  `xml:"file-size"`
	Name        string `xml:"file-name"`
	ContentType string `xml:"content-type"`
	Data        struct {
		URL   string `xml:"url,attr"`
		Until string `xml:"until,attr"`
	} `xml:"data"`
}

// Info returns the file-info of kind ("file" or "thumbnail").
func (d FileDocument) Info(kind string) (FileInfo, bool) {
	for _, i := range d.Infos {
		if i.Type == kind {
			return i, true
		}
	}
	return FileInfo{}, false
}

// ResumeDocument is an upload-info document.
type ResumeDocument struct {
	XMLName xml.Name `xml:"urn:gsma:params:xml:ns:rcs:rcs:fthttp file-resume-info"`
	Range   struct {
		Start string `xml:"start,attr"`
		End   string `xml:"end,attr"`
	} `xml:"file-range"`
	Data struct {
		URL string `xml:"url,attr"`
	} `xml:"data"`
}

// Held returns how many leading bytes the server holds. The document always
// starts at byte 0 (ft-server keeps only whole leading parts). An end at the
// largest int64 is refused rather than overflowing into a negative count.
func (d ResumeDocument) Held() (int64, error) {
	end, err := strconv.ParseInt(d.Range.End, 10, 64)
	if d.Range.Start != "0" || err != nil || end < 0 || end == math.MaxInt64 {
		return 0, errors.New("ft: upload-info range is not 0-<end>")
	}
	return end + 1, nil
}

func readFileDocument(resp *http.Response, op string) (FileDocument, error) {
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return FileDocument{}, &StatusError{Op: op, Status: resp.StatusCode}
	}
	if mt := resp.Header.Get("Content-Type"); !strings.HasPrefix(mt, ContentType) {
		return FileDocument{}, fmt.Errorf("ft: %s: answer is not %s", op, ContentType)
	}
	var d FileDocument
	if err := decode(resp.Body, &d); err != nil {
		return FileDocument{}, fmt.Errorf("ft: %s: %w", op, err)
	}
	if _, ok := d.Info("file"); !ok {
		return FileDocument{}, fmt.Errorf("ft: %s: document without a file-info for the file", op)
	}
	return d, nil
}

// decode reads one document. The server is the platform's own, but a
// simulator run against a deployed stack still bounds what it reads and
// refuses a document type declaration, as the platform's parsers do.
func decode(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxDocument+1))
	if err != nil {
		return safeerr.Body(err)
	}
	if len(data) > maxDocument {
		return errors.New("document too large")
	}
	if bytes.Contains(data, []byte("<!DOCTYPE")) {
		return errors.New("document type declarations are refused")
	}
	if err := xml.Unmarshal(data, v); err != nil {
		return errors.New("malformed document")
	}
	return nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
