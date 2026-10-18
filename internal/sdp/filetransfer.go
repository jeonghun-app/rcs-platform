package sdp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Attributes of MSRP file transfer (RFC 5547 §6). rcs-as reads them from an
// offer and echoes file-selector and file-transfer-id in its answer
// (RFC 5547 §8), so only getters are provided.

// FileSelector is a=file-selector: the properties that identify the file
// being offered or requested. Every field is optional.
type FileSelector struct {
	// Name is the file name with percent-encoding removed. It comes from the
	// peer: never use it as a filesystem path.
	Name string
	// Type is the media type with any parameters, as written.
	Type string
	// Size is the file size in bytes, or -1 when the selector has none.
	Size   int64
	Hashes []FileHash
}

// FileHash is one hash selector, for example sha-1 with colon-separated hex.
type FileHash struct {
	Algorithm string
	Value     string
}

// FileSelector parses a=file-selector. The attribute may have no value
// (RFC 5547 §6), which yields a selector with no fields set.
func (m *Media) FileSelector() (FileSelector, error) {
	v, err := m.Attributes.single("file-selector")
	if err != nil {
		return FileSelector{}, err
	}
	fs, err := parseFileSelector(v)
	if err != nil {
		return FileSelector{}, fmt.Errorf("sdp: a=file-selector: %w", err)
	}
	return fs, nil
}

func parseFileSelector(v string) (FileSelector, error) {
	fs := FileSelector{Size: -1}
	params, err := splitParams(v)
	if err != nil {
		return FileSelector{}, err
	}
	seen := map[string]bool{}
	for _, p := range params {
		key, val, ok := strings.Cut(p, ":")
		key = strings.ToLower(key)
		if !ok || val == "" {
			return FileSelector{}, fmt.Errorf("selector %.32q has no value", key)
		}
		// Hashes may repeat, one per algorithm; the others describe the one
		// file and may not.
		if seen[key] && key != "hash" {
			return FileSelector{}, fmt.Errorf("more than one %s selector", key)
		}
		seen[key] = true
		switch key {
		case "name":
			fs.Name, err = parseFileName(val)
		case "type":
			fs.Type, err = val, validateFileType(val)
		case "size":
			var ok bool
			if fs.Size, ok = parseInt64(val); !ok {
				err = errors.New("size must be a number of bytes")
			}
		case "hash":
			var h FileHash
			h, err = parseFileHash(val)
			fs.Hashes = append(fs.Hashes, h)
		default:
			err = fmt.Errorf("unknown selector %.32q", key)
		}
		if err != nil {
			return FileSelector{}, err
		}
	}
	return fs, nil
}

// parseFileName unquotes and percent-decodes a name selector. RFC 5547 §6
// percent-encodes the double quote and the percent sign inside the quotes,
// so the first closing quote ends the name.
func parseFileName(v string) (string, error) {
	if len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' || strings.IndexByte(v[1:len(v)-1], '"') >= 0 {
		return "", errors.New("name must be a non-empty quoted string")
	}
	name, err := url.PathUnescape(v[1 : len(v)-1])
	if err != nil {
		return "", errors.New("name has a malformed percent-encoding")
	}
	return name, nil
}

func validateFileType(v string) error {
	typ, _, _ := strings.Cut(v, ";")
	if !isMediaRange(typ) || strings.Contains(typ, "*") {
		return errors.New("type must be a media type")
	}
	return nil
}

func parseFileHash(v string) (FileHash, error) {
	algo, hex, ok := strings.Cut(v, ":")
	if !ok || !isToken(algo) || !isHexPairs(hex) {
		return FileHash{}, errors.New("hash must be <algorithm>:<hex>:<hex>...")
	}
	return FileHash{Algorithm: algo, Value: hex}, nil
}

// isHexPairs reports whether s is two hex digits followed by any number of
// ":" and two more, the hash-value form of RFC 5547 §6.
func isHexPairs(s string) bool {
	if len(s)%3 != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !('0' <= c && c <= '9' || 'A' <= c && c <= 'F' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// FileTransferID returns a=file-transfer-id, which tells a new transfer from
// a re-offer of the same one (RFC 5547 §6, §8).
func (m *Media) FileTransferID() (string, error) {
	return singleToken(m.Attributes, "file-transfer-id")
}

// FileDisposition returns a=file-disposition, for example "render" or
// "attachment".
func (m *Media) FileDisposition() (string, error) {
	return singleToken(m.Attributes, "file-disposition")
}

func singleToken(as Attributes, name string) (string, error) {
	v, err := as.singleValue(name)
	if err != nil {
		return "", err
	}
	if !isToken(v) {
		return "", fmt.Errorf("sdp: a=%s: %.64q is not a token", name, v)
	}
	return v, nil
}

// FileDate is a=file-date. Each field is the RFC 5322 date-time text from
// inside the quotes, empty when absent; it is not converted to a time.Time
// because nothing here acts on it and the text is what an answer would echo.
type FileDate struct {
	Creation     string
	Modification string
	Read         string
}

// FileDate parses a=file-date.
func (m *Media) FileDate() (FileDate, error) {
	v, err := m.Attributes.singleValue("file-date")
	if err != nil {
		return FileDate{}, err
	}
	fd, err := parseFileDate(v)
	if err != nil {
		return FileDate{}, fmt.Errorf("sdp: a=file-date: %w", err)
	}
	return fd, nil
}

func parseFileDate(v string) (FileDate, error) {
	params, err := splitParams(v)
	if err != nil {
		return FileDate{}, err
	}
	var fd FileDate
	for _, p := range params {
		key, val, _ := strings.Cut(p, ":")
		var field *string
		switch strings.ToLower(key) {
		case "creation":
			field = &fd.Creation
		case "modification":
			field = &fd.Modification
		case "read":
			field = &fd.Read
		default:
			return FileDate{}, fmt.Errorf("unknown date parameter %.32q", key)
		}
		if *field != "" {
			return FileDate{}, fmt.Errorf("more than one %s date", strings.ToLower(key))
		}
		if len(val) < 3 || val[0] != '"' || val[len(val)-1] != '"' {
			return FileDate{}, errors.New("a date must be a non-empty quoted string")
		}
		*field = val[1 : len(val)-1]
	}
	return fd, nil
}

// FileIcon returns a=file-icon, a cid: URL naming a body part of the SIP
// request that carries a preview of the file.
func (m *Media) FileIcon() (string, error) {
	v, err := m.Attributes.singleValue("file-icon")
	if err != nil {
		return "", err
	}
	if scheme, rest, ok := strings.Cut(v, ":"); !ok || !strings.EqualFold(scheme, "cid") || !isNonWS(rest) {
		return "", fmt.Errorf("sdp: a=file-icon: %.64q is not a cid: URL", v)
	}
	return v, nil
}

// FileRange is a=file-range: 1-based inclusive byte offsets, used to resume
// a partial transfer (RFC 5547 §6).
type FileRange struct {
	Start int64
	// Stop is the last octet, or -1 for "*" (up to the end of the file).
	Stop int64
}

// FileRange parses a=file-range.
func (m *Media) FileRange() (FileRange, error) {
	v, err := m.Attributes.singleValue("file-range")
	if err != nil {
		return FileRange{}, err
	}
	start, stop, ok := strings.Cut(v, "-")
	r := FileRange{Stop: -1}
	var okStart, okStop bool
	r.Start, okStart = parseInt64(start)
	if stop == "*" {
		okStop = true
	} else {
		r.Stop, okStop = parseInt64(stop)
	}
	if !ok || !okStart || !okStop || r.Start < 1 || (r.Stop != -1 && r.Stop < r.Start) {
		return FileRange{}, fmt.Errorf("sdp: a=file-range: %.64q is not <start>-<stop> with 1 <= start <= stop", v)
	}
	return r, nil
}

// splitParams splits a space-separated parameter list, keeping spaces inside
// double quotes (file names and dates contain them). A backslash is not an
// escape: RFC 5547 §6 percent-encodes a quote inside a file name, and a
// backslash there is an ordinary character.
func splitParams(v string) ([]string, error) {
	if v == "" {
		return nil, nil
	}
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '"':
			quoted = !quoted
		case c == ' ' && !quoted:
			if i == start {
				return nil, errors.New("empty parameter")
			}
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	if quoted {
		return nil, errors.New("unterminated quoted string")
	}
	if start == len(v) {
		return nil, errors.New("empty parameter")
	}
	return append(out, v[start:]), nil
}
