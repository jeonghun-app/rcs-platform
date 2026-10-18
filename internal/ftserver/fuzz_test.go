package ftserver

import (
	"io"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// FuzzReadUploadForm checks that any body and content type either fails or
// yields a form within the limits, and that the parser never reads more of
// the body than the budgets allow.
func FuzzReadUploadForm(f *testing.F) {
	f.Add(formType, multipartBody(tidPart("t"), thumbPart("th"), filePart("a.jpg", "image/jpeg", "data")))
	f.Add(formType, multipartBody(tidPart("t"), filePart("a", "", "x")))
	f.Add(formType, "--boundary1\r\nContent-Disposition: form-data; name=tid\r\n\r\nx\r\n--boundary1--")
	f.Add("multipart/form-data; boundary=\"a b\"", "--a b\nContent-Disposition: form-data; name=\"File\"; filename*=UTF-8''%E2%82%AC\n\n\n--a b--")
	f.Add(formType, "--boundary1\r\n"+strings.Repeat("X: y\r\n", 100)+"\r\n")
	lim := formLimits{maxFile: 256, maxThumbnail: 32}
	f.Fuzz(func(t *testing.T, contentType, body string) {
		r := &countingReader{r: strings.NewReader(body)}
		form, err := readUploadHead(contentType, r, lim)
		if err != nil {
			return
		}
		if !validTID(form.tid) || !validFileName(form.file.name) {
			t.Fatalf("accepted tid %q, file name %q", form.tid, form.file.name)
		}
		if form.thumbnail != nil && int64(len(form.thumbnail.data)) > lim.maxThumbnail {
			t.Fatalf("thumbnail of %d bytes accepted", len(form.thumbnail.data))
		}
		data, err := io.ReadAll(form.file.body)
		if err == nil {
			_ = form.finish()
		}
		if int64(len(data)) > lim.maxFile+maxPartHeader {
			t.Fatalf("file part delivered %d bytes", len(data))
		}
		if budget := int64(7*maxPartHeader) + maxTIDLength + lim.maxThumbnail + lim.maxFile; int64(r.n) > budget {
			t.Fatalf("read %d bytes, budget %d", r.n, budget)
		}
	})
}

// FuzzParseRange checks that a satisfiable range always lies inside the
// representation.
func FuzzParseRange(f *testing.F) {
	for _, v := range []string{"bytes=0-0", "bytes=-5", "bytes=5-", "bytes=1-0", "bytes=0-0,1-1", "bytes=99999999999999999999-"} {
		f.Add(v, int64(10))
	}
	f.Fuzz(func(t *testing.T, v string, size int64) {
		r, result := parseRange(v, size)
		if result == rangeSatisfiable && (r.start < 0 || r.length <= 0 || r.start+r.length > size || r.start+r.length < r.start) {
			t.Fatalf("parseRange(%q, %d) = %+v", v, size, r)
		}
	})
}

// FuzzParseContentRange checks that an accepted Content-Range is ordered and
// inside its complete length.
func FuzzParseContentRange(f *testing.F) {
	for _, v := range []string{"bytes 0-9/10", "bytes 9-9/10", "bytes 0-9/*", "bytes */10", "bytes 1-0/2"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		c, ok := parseContentRange(v)
		if ok && (c.first < 0 || c.last < c.first || c.total <= c.last) {
			t.Fatalf("parseContentRange(%q) = %+v", v, c)
		}
	})
}

// FuzzParseHSSCredential checks that whatever an HSS answers, an accepted
// credential has an owner and was for the realm and algorithm asked.
func FuzzParseHSSCredential(f *testing.F) {
	f.Add([]byte(`{"impi":"` + alice + `","impu":"sip:a@b","realm":"` + realm + `","algorithm":"MD5","ha1":"00112233445566778899aabbccddeeff"}`))
	f.Add([]byte(`{"impu":1}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		c, err := parseHSSCredential(body, alice, realm, digest.MD5)
		if err == nil && c.Owner == "" {
			t.Fatal("credential without an owner accepted")
		}
	})
}

// FuzzParseDownloadID checks that an accepted id is a file id of the issued
// form.
func FuzzParseDownloadID(f *testing.F) {
	f.Add(strings.Repeat("A", idLength))
	f.Add(strings.Repeat("A", idLength) + thumbnailSuffix)
	f.Fuzz(func(t *testing.T, v string) {
		id, thumb, ok := parseDownloadID(v)
		if ok && (len(id) != idLength || id+map[bool]string{true: thumbnailSuffix}[thumb] != v) {
			t.Fatalf("parseDownloadID(%q) = %q %v", v, id, thumb)
		}
	})
}
