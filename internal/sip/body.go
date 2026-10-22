package sip

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Body is a SIP message body. A pager-mode MESSAGE carries chat content in
// it (message/cpim), so it prints as redacted under every valid fmt verb,
// logs as its length and encodes to JSON as its length (#573). Request and
// Response print as their LogValue does, without header values or the body
// (logvalue.go). Body is a []byte all the same: a []byte is assignable to
// and from it, so the code that reads and writes bodies is unchanged.
//
// fmt prints some values field by field without calling any method, and a
// []byte cannot hide its octets there. Each such case has a guard:
//   - the invalid verbs %w, and %p on a message value: go vet's printf
//     check, which make check runs, refuses %w outside fmt.Errorf or with
//     an argument that is not an error, and %p on a non-pointer;
//   - an unexported field holding a *Request or *Response, printed with a
//     verb a pointer has no meaning for (%s, %q, %t, ...): vet refuses
//     those verbs on such a struct; %v prints the pointer as an address;
//   - an unexported field holding a Request, Response or Body by value,
//     which %v prints field by field and vet lets through:
//     TestNoStructHoldsAMessageOrBodyByValueUnexported refuses such fields
//     in the module's code.
//
// What vet cannot check, a format that is not a constant or a wrapper it
// does not recognise as printf-like, is not guarded. internal/content
// holds the module's other chat content behind a pointer, which closes
// these cases too; a SIP body is read and written as bytes throughout the
// SIP layer and every service, so this type keeps it as bytes (#573).
type Body []byte

const redactedBody = "[redacted body]"

func (Body) String() string             { return redactedBody }
func (Body) GoString() string           { return redactedBody }
func (Body) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedBody) }

// LogValue logs the length, as Request's and Response's body_bytes do.
func (b Body) LogValue() slog.Value { return slog.IntValue(len(b)) }

// MarshalJSON writes the length.
func (b Body) MarshalJSON() ([]byte, error) { return json.Marshal(map[string]int{"octets": len(b)}) }
