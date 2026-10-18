// Package ft is the client side of RCS File Transfer via HTTP (GSMA RCC.07),
// written to behave like the GSMA rcsjta reference client, so that tests of
// ft-server exercise what deployed devices actually send rather than what
// the server's own tests assume.
//
// Like rcsjta (HttpAuthenticationAgent, HttpUploadManager), the client:
//
//   - starts with an empty POST and reads the challenge of the 401;
//   - answers the last WWW-Authenticate field only, as MD5 without an
//     algorithm parameter, with qop quoted;
//   - signs only the path of the URL for get_upload_info and
//     get_download_info (RFC 7616 §3.4.6 allows that absolute-path);
//   - sends the form as tid, then Thumbnail, then File, each part with its
//     own Content-Length;
//   - resumes a broken upload with get_upload_info and a PUT with
//     Content-Range from the first byte the server does not hold.
//
// Nothing here logs. Errors name the operation and the HTTP status, never the
// user name, the password or a URL, because download URLs are capabilities.
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
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
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

// Precheck sends the empty POST rcsjta starts every upload with and keeps
// the challenge of its 401. A server that answers anything else is not
// asking for authentication, which is an error here.
func (c *Client) Precheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.UploadURL.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("ft: pre-check: %w", transport(err))
	}
	drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		return &StatusError{Op: "pre-check", Status: resp.StatusCode}
	}
	return c.readChallenge(resp.Header)
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

// maxBusyRetries bounds how often a 503 is retried. ft-server answers 503
// with Retry-After while another request holds the upload's lease, which is
// what a client sees right after its own broken upload, before the server
// has noticed the break; RCS clients retry it (docs/ft-server.md).
const maxBusyRetries = 10

// maxRetryAfter caps the wait a Retry-After asks for.
const maxRetryAfter = 5 * time.Second

// do sends a signed request built by build, signing uri. A 401 renews the
// challenge (a stale or expired nonce) and the request is sent once more,
// as rcsjta does; a 503 is retried after its Retry-After.
func (c *Client) do(ctx context.Context, op, uri string, build func() (*http.Request, error)) (*http.Response, error) {
	renewed, busy := false, 0
	for {
		req, err := build()
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		if err := c.authorize(req, uri); err != nil {
			return nil, err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ft: %s: %w", op, transport(err))
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized && !renewed:
			renewed = true
			drain(resp)
			if err := c.readChallenge(resp.Header); err != nil {
				return nil, err
			}
		case resp.StatusCode == http.StatusServiceUnavailable && busy < maxBusyRetries:
			busy++
			wait := retryAfter(resp.Header.Get("Retry-After"))
			drain(resp)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("ft: %s: %w", op, ctx.Err())
			}
		default:
			return resp, nil
		}
	}
}

// retryAfter reads a delay-seconds Retry-After (RFC 9110 §10.2.3), capped;
// anything else means a short pause.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 200 * time.Millisecond
	}
	// Compared before multiplying: a large value would overflow.
	if n >= int(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return time.Duration(n) * time.Second
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

// Send uploads u whole and returns the file-info document.
func (c *Client) Send(ctx context.Context, u Upload) (FileDocument, error) {
	body, ct, err := u.form()
	if err != nil {
		return FileDocument{}, err
	}
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
	return readFileDocument(resp, "upload")
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
	// The transport gives up as soon as the body breaks, possibly before
	// the server has even read the request's headers. A next request under
	// the same nonce with a higher nonce-count could then be verified
	// first, and the broken one refused as a replay (RFC 7616 §3.4.1)
	// before it stored anything. A fresh challenge, as rcsjta starts every
	// upload attempt with, takes the two out of one count sequence.
	return c.Precheck(ctx)
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errCut }

// UploadInfo asks what the server holds of tid (get_upload_info), signing
// only the path. ErrNothingHeld means no byte is held and the client posts
// again.
func (c *Client) UploadInfo(ctx context.Context, tid string) (ResumeDocument, error) {
	target := c.infoURL(tid, "get_upload_info")
	resp, err := c.do(ctx, "get_upload_info", c.UploadURL.Path, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, target, nil)
	})
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
// (get_download_info), signing only the path.
func (c *Client) DownloadInfo(ctx context.Context, tid string) (FileDocument, error) {
	target := c.infoURL(tid, "get_download_info")
	resp, err := c.do(ctx, "get_download_info", c.UploadURL.Path, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, target, nil)
	})
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

// Range is an inclusive byte range for Download; the zero value asks for
// the whole file.
type Range struct{ First, Last int64 }

// Downloaded is what a download returned.
type Downloaded struct {
	Status int
	Body   []byte
	// ETag is the server's strong ETag, the SHA-256 of the whole content.
	ETag string
}

// Download fetches link, which a recipient takes from a file-info document;
// with r set it asks for that range alone. Downloads carry no credentials,
// as recipients' clients send none (ft-server's default).
func (c *Client) Download(ctx context.Context, link string, r Range, max int64) (Downloaded, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return Downloaded{}, errors.New("ft: unusable download URL")
	}
	if r != (Range{}) {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(r.First, 10)+"-"+strconv.FormatInt(r.Last, 10))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Downloaded{}, fmt.Errorf("ft: download: %w", transport(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return Downloaded{}, &StatusError{Op: "download", Status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return Downloaded{}, fmt.Errorf("ft: download: %w", transport(err))
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
// starts at byte 0 (ft-server keeps only whole leading parts).
func (d ResumeDocument) Held() (int64, error) {
	end, err := strconv.ParseInt(d.Range.End, 10, 64)
	if d.Range.Start != "0" || err != nil || end < 0 {
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
		return transport(err)
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

// transport strips a *url.Error down to its cause: the URL in it may be a
// download capability.
func transport(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
