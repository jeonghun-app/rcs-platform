package ft

import (
	"testing"
	"time"
)

// RetryAfter exposes retryAfter to the tests.
var RetryAfter = retryAfter

// ShortRetryAfter makes a Retry-After second last a millisecond for t.
func ShortRetryAfter(t *testing.T) {
	retryUnit = time.Millisecond
	t.Cleanup(func() { retryUnit = time.Second })
}
