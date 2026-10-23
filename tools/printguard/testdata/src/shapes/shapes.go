// Package shapes holds print calls printguard must refuse, each marked
// with a want comment holding part of the finding, and calls it must let
// through, unmarked.
package shapes

import (
	"fmt"
	"log"
	"log/slog"
	"testing"

	"sip"
)

type unexportedPointer struct{ req *sip.Request }
type unexportedValue struct{ res sip.Response }
type unexportedBody struct{ b sip.Body }
type unexportedMessage struct{ m sip.Message }
type unexportedAny struct{ v any }
type inner struct{ R *sip.Request }
type unexportedInner struct{ in inner }
type box[T any] struct{ v T }
type unexportedSlice struct{ rs []*sip.Request }
type unexportedArray struct{ rs [1]*sip.Request }
type unexportedMap struct{ m map[string]sip.Response }
type unexportedKey struct{ m map[*sip.Request]int }

type requestAlias = sip.Request
type bodyAlias = sip.Body
type unexportedAlias struct{ b bodyAlias }

// stringer has a String of its own, which fmt calls only on a path of
// exported fields.
type stringer struct{ R *sip.Request }

func (stringer) String() string { return "stringer" }

type unexportedStringer struct{ s stringer }

type ownString struct{ r *sip.Request }

func (ownString) String() string { return "own" }

// String serves %v, %s, %q, %x and %X only: transaction.server, say, with a
// String added for debugging.
type txn struct{ req *sip.Request }

func (txn) String() string { return "txn" }

type bodyInner struct{ B sip.Body }
type outer struct{ in bodyInner }

func (outer) String() string { return "outer" }

type lastAny struct{ last any }

func (lastAny) String() string { return "last" }

type ownFormat struct{ r sip.Request }

func (ownFormat) Format(fmt.State, rune) {}

// valueFormat's Format serves every verb but %p, which fmt handles first.
type valueFormat struct{ in bodyInner }

func (valueFormat) Format(fmt.State, rune) {}

// pointerFormat has Format on its pointer only: a value of it is printed
// field by field.
type pointerFormat struct{ r sip.Request }

func (*pointerFormat) Format(fmt.State, rune) {}

// errHolder's Error serves the verbs String does.
type errHolder struct{ req *sip.Request }

func (errHolder) Error() string { return "errHolder" }

// logHolder's LogValue serves slog, which calls it on the argument only.
type logHolder struct{ req *sip.Request }

func (logHolder) LogValue() slog.Value { return slog.StringValue("holder") }

// fmt and slog call a method only with their interface's signature.
type wrongFormat struct{ req *sip.Request }

func (wrongFormat) Format(a, b int) {}

type myString string

type wrongString struct{ req *sip.Request }

func (wrongString) String() myString { return "wrong" }

type wrongLogValue struct{ req *sip.Request }

func (wrongLogValue) LogValue() string { return "wrong" }

// slog calls LogValue on the argument only, not on a field of it.
type nestedLog struct{ L logHolder }

type exported struct {
	R *sip.Request
	V sip.Response
	B sip.Body
	S stringer
}

type plain struct{ R sip.Request }
type viaPointer struct{ P *plain }
type exportedBody struct{ B sip.Body }
type exportedAny struct{ V any }

func refused(t testing.TB, tt *testing.T, format string, r *sip.Request) {
	_ = fmt.Sprintf("%t", unexportedPointer{})          // want "*sip.Request in an unexported field (req)"
	fmt.Println(unexportedValue{})                      // want "sip.Response in an unexported field (res)"
	log.Print(unexportedBody{})                         // want "sip.Body in an unexported field (b)"
	_ = fmt.Sprint(unexportedMessage{})                 // want "interface that may hold a *sip.Request in an unexported field (m)"
	slog.Info("m", "v", unexportedAny{})                // want "interface that may hold a sip.Request in an unexported field (v)"
	_ = fmt.Sprintf("%v", unexportedInner{})            // want "*sip.Request in an unexported field (in.R)"
	_ = fmt.Sprint(box[sip.Request]{})                  // want "sip.Request in an unexported field (v)"
	_ = fmt.Sprintf("%s", unexportedStringer{})         // want "*sip.Request in an unexported field (s.R)"
	_ = fmt.Sprintf(format, sip.Request{})              // want "sip.Request value with a format that is not a constant"
	_ = fmt.Sprintf(format, exported{})                 // want "sip.Response value with a format that is not a constant (V)"
	_ = fmt.Sprintf(format, ownString{})                // want "*sip.Request in an unexported field (r)"
	_ = fmt.Sprintf(format, ownFormat{})                // want "sip.Request in an unexported field (r)"
	_ = fmt.Sprintf(format, r)                          // want "*sip.Request with a format that is not a constant"
	_ = fmt.Sprintf(format, sip.Body(nil))              // want "sip.Body value with a format that is not a constant"
	_ = fmt.Sprintf(format, requestAlias{})             // want "sip.Request value with a format that is not a constant"
	fmt.Println(unexportedAlias{})                      // want "sip.Body in an unexported field (b)"
	_ = fmt.Sprint(unexportedSlice{})                   // want "*sip.Request in an unexported field (rs[])"
	_ = fmt.Sprint(unexportedArray{})                   // want "*sip.Request in an unexported field (rs[])"
	_ = fmt.Sprint(unexportedMap{})                     // want "sip.Response in an unexported field (m[])"
	_ = fmt.Sprint(unexportedKey{})                     // want "*sip.Request in an unexported field (m[key])"
	t.Errorf("%v", unexportedPointer{})                 // want "*sip.Request in an unexported field (req)"
	tt.Errorf("%v", unexportedPointer{})                // want "*sip.Request in an unexported field (req)"
	_ = slog.Any("v", unexportedValue{})                // want "sip.Response in an unexported field (res)"
	_ = slog.AnyValue(unexportedValue{})                // want "sip.Response in an unexported field (res)"
	_ = slog.With("v", unexportedValue{})               // want "sip.Response in an unexported field (res)"
	_ = fmt.Errorf("%v", &unexportedPointer{})          // want "*sip.Request in an unexported field (req)"
	slog.Default().Error("m", "v", unexportedBody{})    // want "sip.Body in an unexported field (b)"
	log.New(nil, "", 0).Printf("%v", unexportedValue{}) // want "sip.Response in an unexported field (res)"
	_ = fmt.Sprint(pointerFormat{})                     // want "sip.Request in an unexported field (r)"

	// The verb decides which method fmt calls, if any (#613's reviews).
	_ = fmt.Sprintf("%t", txn{})               // want "*sip.Request in an unexported field (req)"
	_ = fmt.Sprintf("%#v", outer{})            // want "sip.Body in an unexported field (in.B)"
	_ = fmt.Sprintf("%d", outer{})             // want "sip.Body in an unexported field (in.B)"
	_ = fmt.Sprintf("%#v", lastAny{})          // want "interface that may hold a sip.Request in an unexported field (last)"
	_ = fmt.Sprintf("%p", valueFormat{})       // want "sip.Body in an unexported field (in.B)"
	_ = fmt.Sprintf("%#v", errHolder{})        // want "*sip.Request in an unexported field (req)"
	_ = fmt.Sprint(logHolder{})                // want "*sip.Request in an unexported field (req)"
	_ = fmt.Sprintf("%v %[1]d", sip.Request{}) // want "sip.Request value with %d"
	_ = fmt.Sprintf("%[2]v", sip.Request{})    // want "sip.Request value with a format that is not a constant"
	_ = fmt.Errorf("%w", r)                    // want "*sip.Request with %w"
	_ = fmt.Sprintf("%w", errHolder{})         // want "*sip.Request in an unexported field (req)"
	_ = fmt.Sprintf("%s", viaPointer{})        // want "sip.Request value with %s (P.R)"
	_ = fmt.Sprintf("%p", exportedBody{})      // want "sip.Body value with %p (B)"
	_ = fmt.Sprintf("%d", exportedAny{})       // want "interface that may hold a sip.Request value with %d (V)"
	var rec slog.Record
	rec.Add("v", unexportedValue{})           // want "sip.Response in an unexported field (res)"
	_ = fmt.Sprint(wrongFormat{})             // want "*sip.Request in an unexported field (req)"
	_ = fmt.Sprint(wrongString{})             // want "*sip.Request in an unexported field (req)"
	slog.Info("m", "v", wrongLogValue{})      // want "*sip.Request in an unexported field (req)"
	slog.Info("m", "v", nestedLog{})          // want "*sip.Request in an unexported field (L.req)"
	_ = fmt.Sprintf("%w", &unexportedValue{}) // want "sip.Response in an unexported field (res)"
	_ = fmt.Errorf("%#w", errHolder{})        // want "*sip.Request in an unexported field (req)"
	log.Fatal(unexportedValue{})              // want "sip.Response in an unexported field (res)"
}

func allowed(format string) {
	r, res := &sip.Request{}, &sip.Response{}
	_ = fmt.Sprintf("%v %s", r, res)
	_ = fmt.Sprintf("%s %v %#v %q %x", *r, *res, *r, *r, *r)
	_ = fmt.Sprintf("%t %p %d", r, r, sip.Body(nil))
	fmt.Println(sip.Request{}, exported{})
	_ = fmt.Sprintf("%+v %#v %d", exported{}, exported{}, struct{ R *sip.Request }{})
	_ = fmt.Sprintf("%s", ownString{})
	_ = fmt.Sprintf("%s %x", txn{}, txn{})
	_ = fmt.Sprintf("%v", errHolder{})
	_ = fmt.Errorf("%w", errHolder{})
	_ = fmt.Sprintf("%T", unexportedPointer{})
	_ = fmt.Sprintf("%*d %-8.3s", sip.Request{}, 1, sip.Request{})
	_ = fmt.Sprintf("%v", viaPointer{})
	_ = fmt.Sprintf("%p", inner{})
	_ = fmt.Sprint(&pointerFormat{})
	slog.Info("m", "r", r, "res", *res, "h", logHolder{})
	// Not checked: a spread []any, and a value already of an interface type.
	args := []any{unexportedPointer{}}
	fmt.Println(args...)
	var v any = unexportedPointer{}
	fmt.Println(v)
}
