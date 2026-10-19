package hss

import (
	"errors"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

var errProfileID = errors.New("not a profile ID of 1 to 64 characters a-z, 0-9, '.', '_' or '-'")

// ValidProfileID checks a service profile identifier.
func ValidProfileID(id string) error {
	if id == "" || len(id) > store.MaxProfileIDLength {
		return errProfileID
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return errProfileID
		}
	}
	return nil
}
