package ftserver

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// idBytes is the entropy of a file id. Download links are bearer
// capabilities (FT_DOWNLOAD_AUTH is off by default), so an id must not be
// guessable: 144 bits is above the 128 the issue requires and encodes to
// exactly 24 base64url characters, with no padding.
const idBytes = 18

// idLength is the encoded length of a file id.
const idLength = 24

// thumbnailSuffix turns a file id into its thumbnail's id. The thumbnail is
// listed in the same file-info document as the file, so deriving one from the
// other reveals nothing the recipient does not already have, and it saves a
// second lookup item. '.' is outside the base64url alphabet, so the two forms
// cannot be confused.
const thumbnailSuffix = ".t"

// maxTIDLength bounds the client's transaction id. RCC.07 clients send a
// UUID-like value; the bound keeps a hostile one out of keys and URLs.
const maxTIDLength = 128

// newID returns a random file id or lease token read from random.
func newID(random io.Reader) (string, error) {
	b := make([]byte, idBytes)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("ftserver: generating an id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseDownloadID splits the id query parameter of a download URL into the
// file id and whether the thumbnail is meant. ok is false for anything that is
// not an id this server issued, which is answered like an unknown id.
func parseDownloadID(v string) (id string, thumbnail, ok bool) {
	id, thumbnail = strings.CutSuffix(v, thumbnailSuffix)
	if len(id) != idLength {
		return "", false, false
	}
	for i := 0; i < len(id); i++ {
		if !isBase64URL(id[i]) {
			return "", false, false
		}
	}
	return id, thumbnail, true
}

func isBase64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// validTID accepts 1 to maxTIDLength URI unreserved characters (RFC 3986
// §2.3) except the dot segments "." and "..". The tid appears in the resume
// URL path and in query strings, so this keeps it out of the way of path
// normalisation and escaping.
func validTID(v string) bool {
	if v == "" || len(v) > maxTIDLength || v == "." || v == ".." {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(isBase64URL(c) || c == '.' || c == '~') {
			return false
		}
	}
	return true
}
