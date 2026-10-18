package ftserver

import (
	"strconv"
	"strings"
)

// maxRangeField bounds the Range and Content-Range values parsed; anything
// longer is not one byte range.
const maxRangeField = 200

// rangeResult says how a download answers a Range field.
type rangeResult int

const (
	// rangeIgnored: send the whole representation with 200.
	rangeIgnored rangeResult = iota
	// rangeSatisfiable: send the range with 206.
	rangeSatisfiable
	// rangeUnsatisfiable: answer 416.
	rangeUnsatisfiable
)

// byteRange is a range resolved against a representation: first byte and
// length, both within it.
type byteRange struct {
	start, length int64
}

// parseRange interprets a Range field value for a representation of size
// bytes (RFC 9110 §14.1.2, §14.2).
//
// Only a single bytes range is served. A client resuming a download asks for
// one range; a set of ranges is answered with the whole file, which §14.2
// allows (a server MAY ignore Range) and which removes the overlapping-range
// amplification of §17.15. An invalid value or another unit is ignored the
// same way, and so is any range on an empty file. Numbers too large for int64
// are not parse errors (§14.1.2 asks recipients to expect them): a first-pos
// that large is past the end, a last-pos or suffix-length that large covers
// the rest.
func parseRange(v string, size int64) (byteRange, rangeResult) {
	if len(v) > maxRangeField || size <= 0 {
		return byteRange{}, rangeIgnored
	}
	unit, set, ok := strings.Cut(v, "=")
	// The range unit is case-insensitive (RFC 9110 §14.1).
	if !ok || !strings.EqualFold(unit, "bytes") {
		return byteRange{}, rangeIgnored
	}
	spec := strings.Trim(set, " \t")
	if spec == "" || strings.Contains(spec, ",") {
		return byteRange{}, rangeIgnored
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok {
		return byteRange{}, rangeIgnored
	}
	if first == "" {
		n, big, ok := parseDecimal(last)
		switch {
		case !ok:
			return byteRange{}, rangeIgnored
		case n == 0 && !big:
			return byteRange{}, rangeUnsatisfiable
		case big || n >= size:
			return byteRange{start: 0, length: size}, rangeSatisfiable
		}
		return byteRange{start: size - n, length: n}, rangeSatisfiable
	}
	start, startBig, ok := parseDecimal(first)
	if !ok {
		return byteRange{}, rangeIgnored
	}
	end := size - 1
	if last != "" {
		n, endBig, ok := parseDecimal(last)
		if !ok || !endBig && startBig || !endBig && !startBig && n < start {
			// last-pos below first-pos makes the whole field invalid
			// (§14.1.1).
			return byteRange{}, rangeIgnored
		}
		if !endBig && n < end {
			end = n
		}
	}
	if startBig || start >= size {
		return byteRange{}, rangeUnsatisfiable
	}
	return byteRange{start: start, length: end - start + 1}, rangeSatisfiable
}

// parseDecimal parses 1*DIGIT. big reports a value above math.MaxInt64; ok is
// false for anything that is not digits.
func parseDecimal(s string) (n int64, big, ok bool) {
	if s == "" {
		return 0, false, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, true, true
	}
	return v, false, true
}

// contentRange is the Content-Range of a resumed upload: bytes first to last
// of a file of total bytes.
type contentRange struct {
	first, last, total int64
}

// parseContentRange parses the Content-Range of a partial PUT (RFC 9110
// §14.4, §14.5): "bytes first-last/total". The complete length is required
// and the range must lie inside it, because the server needs to know when the
// file is complete; "*" and the unsatisfied-range form are refused.
func parseContentRange(v string) (contentRange, bool) {
	if len(v) > maxRangeField {
		return contentRange{}, false
	}
	unit, rest, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(unit, "bytes") {
		return contentRange{}, false
	}
	span, total, ok := strings.Cut(rest, "/")
	if !ok {
		return contentRange{}, false
	}
	first, last, ok := strings.Cut(span, "-")
	if !ok {
		return contentRange{}, false
	}
	var c contentRange
	for _, f := range []struct {
		s string
		v *int64
	}{{first, &c.first}, {last, &c.last}, {total, &c.total}} {
		n, big, ok := parseDecimal(f.s)
		if !ok || big {
			return contentRange{}, false
		}
		*f.v = n
	}
	if c.last < c.first || c.total <= c.last {
		return contentRange{}, false
	}
	return c, true
}
