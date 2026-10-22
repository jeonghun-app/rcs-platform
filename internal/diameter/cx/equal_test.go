package cx

import (
	"bytes"
	"reflect"

	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

var keyType = reflect.TypeOf(secret.Key{})

// deepEqual is reflect.DeepEqual with a secret.Key compared by its bytes,
// nil and empty apart, as the AVP it encodes is absent or empty (#570):
// DeepEqual cannot compare the closure a Key keeps its bytes in.
func deepEqual(a, b any) bool { return equalValues(reflect.ValueOf(a), reflect.ValueOf(b)) }

func equalValues(a, b reflect.Value) bool {
	if a.IsValid() != b.IsValid() {
		return false
	}
	if !a.IsValid() {
		return true
	}
	if a.Type() != b.Type() {
		return false
	}
	if a.Type() == keyType {
		x, y := a.Interface().(secret.Key).Reveal(), b.Interface().(secret.Key).Reveal()
		return (x == nil) == (y == nil) && bytes.Equal(x, y)
	}
	switch a.Kind() {
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return equalValues(a.Elem(), b.Elem())
	case reflect.Struct:
		for i := range a.NumField() {
			if !equalValues(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !equalValues(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Array:
		for i := range a.Len() {
			if !equalValues(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return false
		}
		for _, k := range a.MapKeys() {
			if !equalValues(a.MapIndex(k), b.MapIndex(k)) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(valueOf(a), valueOf(b))
	}
}

// valueOf reads a field reflect cannot hand out, as an unexported one.
func valueOf(v reflect.Value) any {
	if v.CanInterface() {
		return v.Interface()
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.String:
		return v.String()
	}
	return nil
}
