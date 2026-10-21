package conference

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// MaxDocumentSize bounds a conference-info document. A full document for a
// 100-member group chat is a few tens of kilobytes; the limit leaves room for
// larger groups and extension data without letting a peer make us buffer
// megabytes.
const MaxDocumentSize = 256 << 10

// maxDepth bounds element nesting. The elements this package reads are five
// levels deep; the margin leaves room for extensions while keeping a hostile
// document from driving the decoder's recursion.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or
	// expand input without bound (docs/architecture.md §8).
	ErrDTD = fmt.Errorf("conference: %w", xmlsafe.ErrDTD)
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = fmt.Errorf("conference: %w", xmlsafe.ErrTooLarge)
)

// document is what this package checks its documents for and the errors
// it reports (internal/xmlsafe).
var document = xmlsafe.Doc{MaxSize: MaxDocumentSize, MaxDepth: maxDepth, DTD: ErrDTD, TooLarge: ErrTooLarge, Malformed: ErrMalformed}
