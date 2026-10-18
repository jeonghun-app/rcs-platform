package ftserver

import (
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"unicode/utf8"
)

// The form fields of an upload (RCC.07 FT via HTTP, upload to the HTTP
// content server): the transaction id, then the optional thumbnail, then the
// file, in that order. The order is what lets the server stream: by the time
// the file's bytes arrive it knows which upload they belong to.
const (
	fieldTID       = "tid"
	fieldThumbnail = "Thumbnail"
	fieldFile      = "File"
)

// Limits on the parts of an upload form that are not file content.
const (
	// maxPartHeader bounds the header block of one part, plus the boundary
	// line before it and what the multipart reader buffers ahead (4 KiB).
	// mime/multipart itself allows 10 MiB of part header.
	maxPartHeader = 16 << 10
	// maxBoundary is the longest boundary RFC 2046 §5.1.1 allows.
	maxBoundary = 70
	// maxFileName bounds the declared file name.
	maxFileName = 512
	// maxMediaType bounds a declared content type.
	maxMediaType = 256
)

// defaultContentType is stored when a part declares none. RFC 7578 §4.4
// makes text/plain the default for a form part, but for file content a type
// nobody declared is not text: application/octet-stream is what the same
// clause recommends for a file of unknown type.
const defaultContentType = "application/octet-stream"

// formError is a rejected upload form. status is the HTTP answer and reason a
// fixed metric suffix; neither repeats client data.
type formError struct {
	status int
	reason string
}

func (e *formError) Error() string { return "ftserver: upload form: " + e.reason }

func badForm(reason string) error { return &formError{status: http.StatusBadRequest, reason: reason} }

var errFormTooLarge = &formError{status: http.StatusRequestEntityTooLarge, reason: "too_large"}

// formLimits are the size limits of one upload.
type formLimits struct {
	maxFile      int64
	maxThumbnail int64
}

// uploadForm is an upload form read up to the start of the file content.
type uploadForm struct {
	tid       string
	thumbnail *formPart
	file      formFile
	mr        *multipart.Reader
	budget    *budgetReader
}

// formPart is a part read whole: the thumbnail.
type formPart struct {
	contentType string
	data        []byte
}

// formFile is the File part, whose content the caller streams from body.
type formFile struct {
	name        string
	contentType string
	// declaredSize is the part's Content-Length, which some clients send
	// (RFC 7578 §4.8 lets a receiver ignore it), or -1.
	declaredSize int64
	body         io.Reader
}

// readUploadHead reads an upload form from body, of media type contentType,
// up to the start of the File part's content: the tid, the thumbnail if any,
// and the File part's header. The caller then reads the file from
// form.file.body to the end and calls finish.
//
// Every read is budgeted: a part header may take maxPartHeader bytes, the tid
// maxTIDLength, the thumbnail limits.maxThumbnail and the file
// limits.maxFile, so no client can make the parser hold or skip more than
// that whatever it sends (a preamble that never ends, a huge part header, a
// boundary that never comes).
func readUploadHead(contentType string, body io.Reader, lim formLimits) (*uploadForm, error) {
	boundary, err := formBoundary(contentType)
	if err != nil {
		return nil, err
	}
	b := &budgetReader{r: body}
	f := &uploadForm{mr: multipart.NewReader(b, boundary), budget: b}

	p, name, err := f.next()
	if err != nil {
		return nil, err
	}
	if name != fieldTID {
		return nil, badForm("tid_not_first")
	}
	tid, err := readAll(p, b, maxTIDLength)
	if err == errFormTooLarge {
		return nil, badForm("bad_tid")
	} else if err != nil {
		return nil, err
	}
	if !validTID(string(tid)) {
		return nil, badForm("bad_tid")
	}
	f.tid = string(tid)

	p, name, err = f.next()
	if err != nil {
		return nil, err
	}
	if name == fieldThumbnail {
		ct, err := declaredType(p.Header)
		if err != nil {
			return nil, err
		}
		data, err := readAll(p, b, lim.maxThumbnail)
		if err != nil {
			return nil, err
		}
		f.thumbnail = &formPart{contentType: ct, data: data}
		if p, name, err = f.next(); err != nil {
			return nil, err
		}
	}
	if name != fieldFile {
		return nil, badForm("file_missing")
	}
	file, err := fileHead(p, lim)
	if err != nil {
		return nil, err
	}
	b.allow(lim.maxFile + maxPartHeader)
	file.body = &countedPart{p: p, max: lim.maxFile, budget: b}
	f.file = file
	return f, nil
}

// finish checks that the form ends after the File part. A second File part,
// a thumbnail after the file or any other part is refused rather than
// ignored: it would be ambiguous which content the client meant.
func (f *uploadForm) finish() error {
	f.budget.allow(maxPartHeader)
	_, err := f.mr.NextRawPart()
	switch {
	case err == io.EOF:
		return nil
	case f.budget.failure() != nil:
		return f.budget.failure()
	case err == nil:
		return badForm("extra_part")
	}
	return badForm("malformed")
}

// next reads the next part header and returns the part and its field name.
// The end of the form is an error here: every caller still expects a part.
func (f *uploadForm) next() (*multipart.Part, string, error) {
	f.budget.allow(maxPartHeader)
	// NextRawPart, not NextPart: NextPart silently decodes quoted-printable,
	// and content is stored exactly as sent.
	p, err := f.mr.NextRawPart()
	switch {
	case f.budget.failure() != nil:
		return nil, "", f.budget.failure()
	case err == io.EOF:
		return nil, "", badForm("file_missing")
	case err != nil:
		return nil, "", badForm("malformed")
	}
	switch strings.ToLower(p.Header.Get("Content-Transfer-Encoding")) {
	case "", "binary", "8bit", "7bit":
	default:
		// Deprecated for form data (RFC 7578 §4.7); decoding it would mean
		// storing something other than what was sent.
		return nil, "", badForm("transfer_encoding")
	}
	disposition, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil || disposition != "form-data" {
		return nil, "", badForm("disposition")
	}
	name, ok := params["name"]
	if !ok {
		return nil, "", badForm("disposition")
	}
	// Clients differ in the case of the field names; matching them
	// case-insensitively keeps them working and cannot merge two different
	// fields of this form.
	for _, known := range []string{fieldTID, fieldThumbnail, fieldFile} {
		if strings.EqualFold(name, known) {
			return p, known, nil
		}
	}
	return nil, "", badForm("unknown_part")
}

// fileHead validates the header of the File part.
func fileHead(p *multipart.Part, lim formLimits) (formFile, error) {
	ct, err := declaredType(p.Header)
	if err != nil {
		return formFile{}, err
	}
	// mime.ParseMediaType decodes RFC 2231 (filename*) as well; Part.FileName
	// is not used because it reduces the name to its last path element,
	// which is not what the client sent.
	_, params, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	name, ok := params["filename"]
	if !ok || !validFileName(name) {
		return formFile{}, badForm("bad_file_name")
	}
	size := int64(-1)
	if v := p.Header.Get("Content-Length"); v != "" {
		n, big, ok := parseDecimal(v)
		switch {
		case !ok:
			return formFile{}, badForm("bad_content_length")
		case big || n > lim.maxFile:
			return formFile{}, errFormTooLarge
		}
		size = n
	}
	return formFile{name: name, contentType: ct, declaredSize: size}, nil
}

// declaredType returns the part's declared content type in canonical form,
// or defaultContentType. The type is stored and served as declared, never
// sniffed; only its syntax is checked, so that it cannot carry anything but a
// media type into the download's Content-Type.
func declaredType(h textproto.MIMEHeader) (string, error) {
	values := h.Values("Content-Type")
	switch len(values) {
	case 0:
		return defaultContentType, nil
	case 1:
	default:
		return "", badForm("content_type")
	}
	if len(values[0]) > maxMediaType {
		return "", badForm("content_type")
	}
	mt, params, err := mime.ParseMediaType(values[0])
	if err != nil || strings.Count(mt, "/") != 1 || strings.HasPrefix(mt, "/") || strings.HasSuffix(mt, "/") {
		return "", badForm("content_type")
	}
	// FormatMediaType gives "" for what it cannot write back, such as a
	// parameter name ParseMediaType let through.
	if v := mime.FormatMediaType(mt, params); v != "" {
		return v, nil
	}
	return "", badForm("content_type")
}

// validFileName accepts a non-empty UTF-8 name of at most maxFileName bytes
// without control characters. The name is echoed in the file-info document
// and in the download's Content-Disposition, so anything that could break out
// of either is refused rather than repaired.
func validFileName(name string) bool {
	if name == "" || len(name) > maxFileName || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || 0x80 <= r && r < 0xa0 {
			return false
		}
	}
	return true
}

// formBoundary returns the boundary of a multipart/form-data content type.
func formBoundary(contentType string) (string, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || mt != "multipart/form-data" {
		return "", &formError{status: http.StatusUnsupportedMediaType, reason: "not_multipart"}
	}
	b := params["boundary"]
	if !validBoundary(b) {
		return "", badForm("boundary")
	}
	return b, nil
}

// validBoundary applies RFC 2046 §5.1.1: 1 to 70 bchars, not ending in a
// space.
func validBoundary(b string) bool {
	if b == "" || len(b) > maxBoundary || strings.HasSuffix(b, " ") {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !(isBase64URL(c) || strings.IndexByte("'()+,./:=? ", c) >= 0) {
			return false
		}
	}
	return true
}

// readAll reads a whole part of at most max bytes. The budget also covers the
// delimiter the reader must see to know the part has ended.
func readAll(p *multipart.Part, b *budgetReader, max int64) ([]byte, error) {
	b.allow(max + maxPartHeader)
	data, err := io.ReadAll(io.LimitReader(p, max+1))
	switch {
	case b.failure() != nil:
		return nil, b.failure()
	case int64(len(data)) > max:
		return nil, errFormTooLarge
	case err != nil:
		return nil, badForm("malformed")
	}
	return data, nil
}

// errFileTooLarge is returned by a countedPart that has delivered max bytes
// and has more.
var errFileTooLarge = errors.New("ftserver: file larger than the maximum size")

// countedPart passes on the File part's content and fails once it exceeds
// max, so the size limit holds without a Content-Length. A failure of the
// body itself is reported as such rather than as whatever mime/multipart
// made of it, so that a deadline is told apart from a broken connection.
type countedPart struct {
	p      *multipart.Part
	max    int64
	read   int64
	budget *budgetReader
}

func (c *countedPart) Read(b []byte) (int, error) {
	n, err := c.p.Read(b)
	c.read += int64(n)
	switch {
	case c.read > c.max:
		return n, errFileTooLarge
	case err != nil && err != io.EOF && c.budget.failure() != nil:
		return n, c.budget.failure()
	}
	return n, err
}

// budgetReader stops reading the request body when the bytes read reach a
// limit the form reader raises step by step (see readUploadHead). exceeded
// records that the limit, not the client, ended the input, and err the
// body's own failure (a broken connection, a deadline), because
// mime/multipart does not always pass either through.
type budgetReader struct {
	r        io.Reader
	read     int64
	limit    int64
	exceeded bool
	err      error
}

// failure returns why reading stopped, if the form's syntax was not the
// reason: the budget, or the body's own error.
func (b *budgetReader) failure() error {
	if b.exceeded {
		return errFormTooLarge
	}
	return b.err
}

// allow lets n more bytes be read, counted from what has been read so far.
func (b *budgetReader) allow(n int64) {
	b.limit = b.read + n
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.read >= b.limit {
		b.exceeded = true
		return 0, errFormTooLarge
	}
	if rest := b.limit - b.read; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}
