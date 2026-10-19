//go:build race

package msrp

// raceEnabled: the race detector slows this package's code five to ten
// times, so tests that move real data over TCP move less of it.
const raceEnabled = true
