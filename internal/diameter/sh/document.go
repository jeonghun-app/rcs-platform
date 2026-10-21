package sh

import (
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// MaxDataSize bounds an Sh-Data document. Repository data is an AS's own
// service data and an HSS limits it (TS 29.328 §6.1.2 lets it refuse more
// with DIAMETER_ERROR_TOO_MUCH_DATA); 64 KiB is far above what `rcs-as`
// stores.
const MaxDataSize = 64 << 10

// maxDepth bounds element nesting: Sh-Data is shallow, but ServiceData holds
// the AS's own XML.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or expand
	// input without bound (docs/architecture.md §8).
	ErrDTD = fmt.Errorf("sh: %w", xmlsafe.ErrDTD)
	// ErrTooLarge reports a document beyond MaxDataSize.
	ErrTooLarge = fmt.Errorf("sh: %w", xmlsafe.ErrTooLarge)
	// ErrMalformed reports a document that is not well-formed XML or does
	// not follow the TS 29.328 Annex D schema. The wrapping error says what
	// is wrong, but never quotes the document.
	ErrMalformed = errors.New("sh: malformed user data")
)

// document is what this package checks its documents for and the errors
// it reports (internal/xmlsafe).
var document = xmlsafe.Doc{MaxSize: MaxDataSize, MaxDepth: maxDepth, DTD: ErrDTD, TooLarge: ErrTooLarge, Malformed: ErrMalformed}
