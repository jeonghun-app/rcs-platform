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
type unexportedMap struct{ m map[string]sip.Response }

// stringer has a String of its own, which fmt calls only on a path of
// exported fields.
type stringer struct{ R *sip.Request }

func (stringer) String() string { return "stringer" }

type unexportedStringer struct{ s stringer }

type ownString struct{ r *sip.Request }

func (ownString) String() string { return "own" }

type ownFormat struct{ r sip.Request }

func (ownFormat) Format(fmt.State, rune) {}

// pointerFormat has Format on its pointer only: a value of it is printed
// field by field.
type pointerFormat struct{ r sip.Request }

func (*pointerFormat) Format(fmt.State, rune) {}

type exported struct {
	R *sip.Request
	V sip.Response
	B sip.Body
	S stringer
}

func refused(t testing.TB, format string) {
	_ = fmt.Sprintf("%t", unexportedPointer{})          // want "*sip.Request in an unexported field (req)"
	fmt.Println(unexportedValue{})                      // want "sip.Response in an unexported field (res)"
	log.Print(unexportedBody{})                         // want "sip.Body in an unexported field (b)"
	_ = fmt.Sprint(unexportedMessage{})                 // want "interface that may hold a message in an unexported field (m)"
	slog.Info("m", "v", unexportedAny{})                // want "interface that may hold a message in an unexported field (v)"
	_ = fmt.Sprintf("%v", unexportedInner{})            // want "*sip.Request in an unexported field (in.R)"
	_ = fmt.Sprint(box[sip.Request]{})                  // want "sip.Request in an unexported field (v)"
	_ = fmt.Sprintf("%s", unexportedStringer{})         // want "*sip.Request in an unexported field (s.R)"
	_ = fmt.Sprintf(format, sip.Request{})              // want "sip.Request value with a format that is not a constant"
	_ = fmt.Sprintf(format, exported{})                 // want "sip.Response value with a format that is not a constant (V)"
	_ = fmt.Sprintf(format, ownString{})                // want "*sip.Request in an unexported field (r)"
	_ = fmt.Sprint(unexportedSlice{})                   // want "*sip.Request in an unexported field (rs[])"
	_ = fmt.Sprint(unexportedMap{})                     // want "sip.Response in an unexported field (m[])"
	t.Errorf("%v", unexportedPointer{})                 // want "*sip.Request in an unexported field (req)"
	_ = slog.Any("v", unexportedValue{})                // want "sip.Response in an unexported field (res)"
	_ = fmt.Errorf("%v", &unexportedPointer{})          // want "*sip.Request in an unexported field (req)"
	slog.Default().Error("m", "v", unexportedBody{})    // want "sip.Body in an unexported field (b)"
	log.New(nil, "", 0).Printf("%v", unexportedValue{}) // want "sip.Response in an unexported field (res)"
	_ = fmt.Sprint(pointerFormat{})                     // want "sip.Request in an unexported field (r)"
}

func allowed(format string) {
	r, res := &sip.Request{}, &sip.Response{}
	_ = fmt.Sprintf("%v %s", r, res)
	_ = fmt.Sprintf("%s %v", *r, *res)
	_ = fmt.Sprintf(format, r, sip.Body(nil))
	fmt.Println(sip.Request{}, exported{})
	_ = fmt.Sprintf("%+v", exported{})
	_ = fmt.Sprintf("%s", ownString{})
	_ = fmt.Sprintf(format, ownFormat{})
	_ = fmt.Sprint(&pointerFormat{})
	slog.Info("m", "r", r, "res", *res)
	// Not checked: a spread []any, and a value already of an interface type.
	args := []any{unexportedPointer{}}
	fmt.Println(args...)
	var v any = unexportedPointer{}
	fmt.Println(v)
}
