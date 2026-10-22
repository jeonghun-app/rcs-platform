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
// []byte cannot hide its octets there. The guards:
//   - go vet's printf check, which make check runs, refuses %w outside
//     fmt.Errorf or with an argument that is not an error, %p on a message
//     value, and %s, %q, %x and %X on a struct with an unexported message
//     pointer;
//   - tools/printguard, which make check runs too, refuses every call to a
//     print function (fmt's, log's, slog's, testing's) in the module's code
//     whose argument can reach a message through an unexported field, at
//     any depth and through local, generic and interface types (Message,
//     any), or that prints a Request or Response value with a format that
//     is not a constant (#599);
//   - TestNoStructHoldsAMessageOrBodyByValueUnexported refuses a struct
//     field that holds a message or a Body by value, unexported, as written.
//
// Not guarded: _test.go files; a value already of an interface type at the
// call, whose dynamic type is unknown; a spread []any; generic code
// printing a value of a type parameter; and printing through reflection,
// a function value or a wrapper printguard does not list. internal/content
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
