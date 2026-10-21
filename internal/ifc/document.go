package ifc

import (
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// MaxDocumentSize bounds an IMSSubscription document. A profile with tens of
// filter criteria is a few tens of KiB; 128 KiB keeps the document well
// inside the 256 KiB Diameter message limit the S-CSCF and HSS use. A larger
// one is what DIAMETER_ERROR_TOO_MUCH_DATA (TS 29.229 §6.2.2.8) is for.
const MaxDocumentSize = 128 << 10

// maxDepth bounds element nesting. The deepest element of the schema is nine
// levels down (five PublicIdentity extensions); the margin leaves room for
// extensions this package skips while keeping a hostile document from driving
// the decoder's recursion.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or expand
	// input without bound (docs/architecture.md §8).
	ErrDTD = fmt.Errorf("ifc: %w", xmlsafe.ErrDTD)
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = fmt.Errorf("ifc: %w", xmlsafe.ErrTooLarge)
	// ErrMalformed reports a document that is not well-formed XML or does
	// not follow the TS 29.228 Annex E schema. The wrapping error says what
	// is wrong and where, but never quotes the document.
	ErrMalformed = errors.New("ifc: malformed user data")
)

// document is what this package checks its documents for and the errors
// it reports (internal/xmlsafe).
var document = xmlsafe.Doc{MaxSize: MaxDocumentSize, MaxDepth: maxDepth, DTD: ErrDTD, TooLarge: ErrTooLarge, Malformed: ErrMalformed}
