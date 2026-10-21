package imdn

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// MaxDocumentSize bounds a notification document. A real one is a few hundred
// bytes; the margin covers a long subject and extension elements.
const MaxDocumentSize = 16 << 10

// maxDepth bounds element nesting. A notification is four levels deep; the
// margin leaves room for extensions while keeping a hostile document from
// driving the decoder's recursion.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or
	// expand input without bound (docs/architecture.md §8).
	ErrDTD = fmt.Errorf("imdn: %w", xmlsafe.ErrDTD)
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = fmt.Errorf("imdn: %w", xmlsafe.ErrTooLarge)
)

// document is what this package checks its documents for and the errors
// it reports (internal/xmlsafe).
var document = xmlsafe.Doc{MaxSize: MaxDocumentSize, MaxDepth: maxDepth, DTD: ErrDTD, TooLarge: ErrTooLarge, Malformed: ErrMalformed}
