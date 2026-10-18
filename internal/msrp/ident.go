package msrp

import (
	"encoding/base32"
	"fmt"
	"io"
)

// Lower-case RFC 4648 base32 without padding: every character is legal in
// an ident and in a session-id (§9), and the text survives case-folding
// systems even though MSRP compares these values exactly.
var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Random bytes behind each kind of identifier.
const (
	// §7.1 asks for at least 64 bits of randomness in a transaction id.
	transactionIDBytes = 10
	// §7.1.1 asks that a Message-ID is never repeated by any instance.
	messageIDBytes = 16
	// ADR 0004: the session id is the only secret binding a client
	// connection to a relay binding, so it carries 160 bits; that is
	// comfortably above the 128 the ADR requires and encodes to exactly
	// 32 characters.
	sessionIDBytes = 20
)

func newID(rand io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand, b); err != nil {
		return "", fmt.Errorf("msrp: reading randomness: %w", err)
	}
	return idEncoding.EncodeToString(b), nil
}

// NewTransactionID returns a fresh transaction identifier (§7.1).
func NewTransactionID(rand io.Reader) (string, error) {
	return newID(rand, transactionIDBytes)
}

// NewMessageID returns a fresh Message-ID value (§7.1.1).
func NewMessageID(rand io.Reader) (string, error) {
	return newID(rand, messageIDBytes)
}

// NewSessionID returns a session-id for a local MSRP URI. It carries 160
// random bits so that knowing a relay's address does not let anyone guess
// a session on it (ADR 0004, RFC 4975 §14.1).
func NewSessionID(rand io.Reader) (string, error) {
	return newID(rand, sessionIDBytes)
}

// validIdent follows the §9 ident rule used by transaction ids and
// Message-ID values: 4 to 32 characters starting with a letter or digit.
func validIdent(s string) bool {
	if len(s) < 4 || len(s) > 32 || !isAlnum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '-' && c != '+' && c != '%' && c != '=' {
			return false
		}
	}
	return true
}
