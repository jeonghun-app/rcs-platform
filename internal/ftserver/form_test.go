package ftserver

import (
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

var testLimits = formLimits{maxFile: 4096, maxThumbnail: 64}

// readForm reads a whole upload form the way handleUpload does and returns
// the file content.
func readForm(contentType, body string, lim formLimits) (*uploadForm, string, error) {
	f, err := readUploadHead(contentType, strings.NewReader(body), lim)
	if err != nil {
		return nil, "", err
	}
	data, err := io.ReadAll(f.file.body)
	if err != nil {
		return f, string(data), err
	}
	return f, string(data), f.finish()
}

func statusOf(err error) int {
	var fe *formError
	if errors.As(err, &fe) {
		return fe.status
	}
	if errors.Is(err, errFileTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return 0
}

func TestFormInRCSOrderIsRead(t *testing.T) {
	file := filePart("Hello world.txt", "text/plain; charset=UTF-8", "the content\r\n--boundary1x is not a delimiter")
	file.header += "Content-Length: 42\r\n"
	f, data, err := readForm(formType, multipartBody(tidPart("tid-1"), thumbPart("thumb"), file), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if f.tid != "tid-1" || f.thumbnail == nil || string(f.thumbnail.data) != "thumb" || f.thumbnail.contentType != "image/jpeg" {
		t.Fatalf("form = %+v", f)
	}
	if f.file.name != "Hello world.txt" || f.file.contentType != "text/plain; charset=UTF-8" || f.file.declaredSize != 42 {
		t.Fatalf("file = %+v", f.file)
	}
	if data != "the content\r\n--boundary1x is not a delimiter" {
		t.Fatalf("content = %q", data)
	}
}

func TestFormWithoutThumbnailIsRead(t *testing.T) {
	f, data, err := readForm(formType, multipartBody(tidPart("t"), filePart("a", "image/png", "png")), testLimits)
	if err != nil || f.thumbnail != nil || data != "png" || f.file.declaredSize != -1 {
		t.Fatalf("form = %+v, %q, %v", f, data, err)
	}
}

func TestFormFieldNamesMatchWhateverTheirCase(t *testing.T) {
	body := strings.NewReplacer(`name="tid"`, `name="TID"`, `name="File"`, `name="file"`).
		Replace(multipartBody(tidPart("t"), filePart("a", "text/plain", "x")))
	if _, _, err := readForm(formType, body, testLimits); err != nil {
		t.Fatal(err)
	}
}

func TestPreambleAndEpilogueAreIgnored(t *testing.T) {
	body := "preamble line\r\n" + multipartBody(tidPart("t"), filePart("a", "text/plain", "x")) + "epilogue"
	if _, data, err := readForm(formType, body, testLimits); err != nil || data != "x" {
		t.Fatalf("%q, %v", data, err)
	}
}

func TestMissingFileContentTypeIsOctetStream(t *testing.T) {
	p := part{header: "Content-Disposition: form-data; name=\"File\"; filename=\"a\"\r\n", body: "x"}
	f, _, err := readForm(formType, multipartBody(tidPart("t"), p), testLimits)
	if err != nil || f.file.contentType != "application/octet-stream" {
		t.Fatalf("%+v, %v", f, err)
	}
}

func TestFileNameIsKeptAsSentIncludingRFC2231(t *testing.T) {
	for header, want := range map[string]string{
		`filename="name.txt"`:                     "name.txt",
		`filename*=UTF-8''%EC%82%AC%EC%A7%84.jpg`: "사진.jpg",
		`filename="My%20Photo.jpg"`:               "My%20Photo.jpg",
		`filename="東京 ü (1).txt"`:                 "東京 ü (1).txt",
	} {
		p := part{header: "Content-Disposition: form-data; name=\"File\"; " + header + "\r\n", body: "x"}
		f, _, err := readForm(formType, multipartBody(tidPart("t"), p), testLimits)
		if err != nil || f.file.name != want {
			t.Errorf("%s: %v; want %q", header, err, want)
		}
	}
}

func TestFileNamesThatAreNotOnePlainNameAreRefused(t *testing.T) {
	for _, name := range []string{
		"../../etc/passwd", "..\\..\\x.bat", "/abs/path", "dir/name.txt", ".", "..",
		"invoice\u202efdp.exe", "a\u200bb", "a\u2066b", "a\u061cb", "a\u200eb", "\ufeffname", "tab\tname",
	} {
		if validFileName(name) {
			t.Errorf("validFileName(%q) = true", name)
		}
	}
	for _, name := range []string{"a.b.c", "...", "東京.txt", "résumé (final).pdf", "a\u00a0b"} {
		if !validFileName(name) {
			t.Errorf("validFileName(%q) = false", name)
		}
	}
}

func TestMalformedFormsAreRefused(t *testing.T) {
	tid, file := tidPart("t"), filePart("a", "text/plain", "x")
	long := strings.Repeat("x", 600)
	for name, c := range map[string]struct {
		contentType, body string
		status            int
	}{
		"not multipart":          {"application/json", "{}", 415},
		"other multipart":        {"multipart/mixed; boundary=boundary1", multipartBody(tid, file), 415},
		"no boundary":            {"multipart/form-data", multipartBody(tid, file), 400},
		"boundary too long":      {"multipart/form-data; boundary=" + strings.Repeat("b", 71), "", 400},
		"boundary bad char":      {"multipart/form-data; boundary=\"a\x01\"", "", 400},
		"boundary ends space":    {"multipart/form-data; boundary=\"ab \"", "", 400},
		"empty body":             {formType, "", 400},
		"only closing":           {formType, "--boundary1--\r\n", 400},
		"missing tid":            {formType, multipartBody(file), 400},
		"tid after thumbnail":    {formType, multipartBody(thumbPart("t"), tid, file), 400},
		"tid twice":              {formType, multipartBody(tid, tid, file), 400},
		"tid too long":           {formType, multipartBody(tidPart(strings.Repeat("a", 129)), file), 400},
		"tid with slash":         {formType, multipartBody(tidPart("a/b"), file), 400},
		"tid dot dot":            {formType, multipartBody(tidPart(".."), file), 400},
		"no file":                {formType, multipartBody(tid), 400},
		"no file after thumb":    {formType, multipartBody(tid, thumbPart("t")), 400},
		"two files":              {formType, multipartBody(tid, file, file), 400},
		"thumbnail after file":   {formType, multipartBody(tid, file, thumbPart("t")), 400},
		"two thumbnails":         {formType, multipartBody(tid, thumbPart("t"), thumbPart("t"), file), 400},
		"unknown part":           {formType, multipartBody(tid, part{header: "Content-Disposition: form-data; name=\"x\"\r\n"}, file), 400},
		"no disposition":         {formType, multipartBody(tid, part{header: "Content-Type: text/plain\r\n", body: "x"}, file), 400},
		"attachment disposition": {formType, multipartBody(tid, part{header: "Content-Disposition: attachment; name=\"File\"; filename=\"a\"\r\n"}), 400},
		"no name":                {formType, multipartBody(part{header: "Content-Disposition: form-data\r\n"}), 400},
		"quoted printable":       {formType, multipartBody(tid, part{header: file.header + "Content-Transfer-Encoding: quoted-printable\r\n", body: "x"}), 400},
		"base64":                 {formType, multipartBody(part{header: tid.header + "Content-Transfer-Encoding: base64\r\n", body: "dA=="}, file), 400},
		"no filename":            {formType, multipartBody(tid, part{header: "Content-Disposition: form-data; name=\"File\"\r\n", body: "x"}), 400},
		"empty filename":         {formType, multipartBody(tid, filePart("", "text/plain", "x")), 400},
		"control in filename":    {formType, multipartBody(tid, filePart("a\x7fb", "text/plain", "x")), 400},
		"long filename":          {formType, multipartBody(tid, filePart(long, "text/plain", "x")), 400},
		"bad content type":       {formType, multipartBody(tid, filePart("a", "image", "x")), 400},
		"empty subtype":          {formType, multipartBody(tid, filePart("a", "image/", "x")), 400},
		"two content types":      {formType, multipartBody(tid, part{header: file.header + "Content-Type: text/html\r\n", body: "x"}), 400},
		"long content type":      {formType, multipartBody(tid, filePart("a", "text/plain; x="+long, "x")), 400},
		"bad thumbnail type":     {formType, multipartBody(tid, part{header: "Content-Disposition: form-data; name=\"Thumbnail\"\r\nContent-Type: ;\r\n", body: "t"}, file), 400},
		"bad content length":     {formType, multipartBody(tid, part{header: file.header + "Content-Length: 1x\r\n", body: "x"}), 400},
		"huge content length":    {formType, multipartBody(tid, part{header: file.header + "Content-Length: 99999999999999999999\r\n", body: "x"}), 413},
		"declared too large":     {formType, multipartBody(tid, part{header: file.header + "Content-Length: 4097\r\n", body: "x"}), 413},
		"thumbnail too large":    {formType, multipartBody(tid, thumbPart(strings.Repeat("t", 65)), file), 413},
		"garbage between":        {formType, "--boundary1\r\n" + tid.header + "\r\nt\r\nGARBAGE\r\n--boundary1--\r\n", 400},
	} {
		_, _, err := readForm(c.contentType, c.body, testLimits)
		if got := statusOf(err); got != c.status {
			t.Errorf("%s: %v (status %d), want status %d", name, err, got, c.status)
		}
	}
}

func TestFileLargerThanTheLimitStopsTheRead(t *testing.T) {
	_, data, err := readForm(formType, multipartBody(tidPart("t"), filePart("a", "text/plain", strings.Repeat("x", 4097))), testLimits)
	if !errors.Is(err, errFileTooLarge) || len(data) > 4097 {
		t.Fatalf("%d bytes, %v", len(data), err)
	}
	if _, data, err := readForm(formType, multipartBody(tidPart("t"), filePart("a", "text/plain", strings.Repeat("x", 4096))), testLimits); err != nil || len(data) != 4096 {
		t.Fatalf("a file of exactly the limit: %d bytes, %v", len(data), err)
	}
}

func TestHugePartHeaderIsRefusedWithinItsBudget(t *testing.T) {
	huge := "X-Padding: " + strings.Repeat("a", 1000) + "\r\n"
	header := strings.Repeat(huge, 1000) // 1 MB of header lines
	body := multipartBody(part{header: tidPart("t").header + header, body: "t"}, filePart("a", "text/plain", "x"))
	r := &countingReader{r: strings.NewReader(body)}
	_, err := readUploadHead(formType, r, testLimits)
	if statusOf(err) != http.StatusRequestEntityTooLarge {
		t.Fatalf("err = %v", err)
	}
	if r.n > 2*maxPartHeader {
		t.Fatalf("read %d bytes of a huge header, budget %d", r.n, maxPartHeader)
	}
}

func TestEndlessPreambleIsRefusedWithinItsBudget(t *testing.T) {
	r := &countingReader{r: strings.NewReader(strings.Repeat("no boundary here\r\n", 1<<16))}
	_, err := readUploadHead(formType, r, testLimits)
	if statusOf(err) != http.StatusRequestEntityTooLarge || r.n > 2*maxPartHeader {
		t.Fatalf("err %v after %d bytes", err, r.n)
	}
}

func TestBodyEndingInsideTheFileIsAnError(t *testing.T) {
	body := multipartBody(tidPart("t"), filePart("a", "text/plain", "content"))
	cut := body[:strings.Index(body, "content")+3]
	_, _, err := readForm(formType, cut, testLimits)
	if err == nil {
		t.Fatal("a truncated body was read as a complete form")
	}
}

func TestBoundaryLookalikesInContentAreData(t *testing.T) {
	content := "--boundary1x\r\n--boundary\r\n--boundary2\r\n-boundary1\r\n\n--boundary1x not at line start: --boundary1--"
	_, data, err := readForm(formType, multipartBody(tidPart("t"), filePart("a", "text/plain", content)), testLimits)
	if err != nil || data != content {
		t.Fatalf("%q, %v", data, err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestValidBoundaryFollowsRFC2046(t *testing.T) {
	for b, want := range map[string]bool{
		"boundary1": true, "a'()+_,-./:=? b": true, strings.Repeat("b", 70): true,
		"": false, "trailing ": false, strings.Repeat("b", 71): false, "semi;colon": false, "quote\"": false,
	} {
		if got := validBoundary(b); got != want {
			t.Errorf("validBoundary(%q) = %v", b, got)
		}
	}
}

// lookalikeReader yields a File part of n bytes made entirely of boundary
// lookalikes, the input that makes a multipart scanner work hardest, without
// holding it in memory.
type lookalikeReader struct {
	head, tail string
	n          int64
	sent       int64
}

const lookalike = "\r\n--boundary1x"

func (l *lookalikeReader) Read(p []byte) (int, error) {
	switch {
	case l.head != "":
		k := copy(p, l.head)
		l.head = l.head[k:]
		return k, nil
	case l.sent < l.n:
		k := 0
		for k < len(p) && l.sent < l.n {
			c := copy(p[k:], lookalike[l.sent%int64(len(lookalike)):])
			c = min(c, int(l.n-l.sent))
			k += c
			l.sent += int64(c)
		}
		return k, nil
	case l.tail != "":
		k := copy(p, l.tail)
		l.tail = l.tail[k:]
		return k, nil
	}
	return 0, io.EOF
}

// parseLookalikes parses a form whose file is n bytes of boundary
// lookalikes.
func parseLookalikes(t *testing.T, n int64) {
	t.Helper()
	body := &lookalikeReader{
		head: "--boundary1\r\n" + tidPart("t").header + "\r\nt\r\n--boundary1\r\n" + filePart("a", "text/plain", "").header + "\r\n",
		n:    n,
		tail: "\r\n--boundary1--\r\n",
	}
	f, err := readUploadHead(formType, body, formLimits{maxFile: DefaultMaxSize, maxThumbnail: 1})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.Copy(io.Discard, f.file.body)
	if err != nil || got != n {
		t.Fatalf("read %d of %d bytes: %v", got, n, err)
	}
	if err := f.finish(); err != nil {
		t.Fatal(err)
	}
}

func TestMaximumSizeAdversarialFormParsesInLinearTime(t *testing.T) {
	// docs/architecture.md §8: a parser is shown linear on a maximum-size
	// adversarial input. The same total is parsed both ways: the maximum
	// size once, and an eighth of it eight times, so a linear parser takes
	// about as long for either and a quadratic one eight times as long for
	// the one. Two timings that last about as long are stretched alike by a
	// loaded host, which one small parse against one large did not (#190:
	// 3.9 s against 76 ms at load 569). The time is the process's CPU time,
	// as in internal/cpim and internal/sip/reginfo, so time spent waiting
	// for a CPU is not counted. Linear code comes to at most about 1.13
	// (QA of #513), so the bound is 2, which a moderate quadratic term
	// already passes. A first timing of each side fails at once when it is
	// far past that, as in internal/cpim, so a strongly quadratic parser
	// fails with its numbers rather than at the package's timeout. Then each
	// of three attempts times each side three times and keeps the shortest;
	// only all three over the bound fail. Under the race detector, which
	// times its own instrumentation as much as the parser, only allocations
	// are compared.
	cpu := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatal(err)
		}
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	const parts = 8
	once := func() { parseLookalikes(t, DefaultMaxSize) }
	inParts := func() {
		for range parts {
			parseLookalikes(t, DefaultMaxSize/parts)
		}
	}
	allocated := func(f func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	// Streaming allocates a few KiB either way; a parser that copies what it
	// has read so far allocates eight times as much for the one, and at the
	// maximum size far more than the 1 MiB of slack.
	if large, small := allocated(once), allocated(inParts); large > small+1<<20 {
		t.Fatalf("the maximum size allocated %d bytes against %d for the same total in eighths: not linear", large, small)
	}
	if raceEnabled {
		return
	}
	timed := func(f func()) time.Duration {
		start := cpu()
		f()
		return cpu() - start
	}
	best := func(f func()) time.Duration {
		d := timed(f)
		for range 2 {
			d = min(d, timed(f))
		}
		return d
	}
	const bound, farPast = 2, 6
	if large, small := timed(once), timed(inParts); large > farPast*small {
		t.Fatalf("the maximum size took %v of CPU against %v for the same total in eighths, more than %d times: not linear", large, small, farPast)
	}
	var large, small time.Duration
	for range 3 {
		large, small = best(once), best(inParts)
		if large <= bound*small {
			return
		}
	}
	t.Fatalf("the maximum size took %v of CPU against %v for the same total in eighths: not linear", large, small)
}
