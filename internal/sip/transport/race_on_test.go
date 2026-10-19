//go:build race

package transport

// raceEnabled relaxes the timing tests under the race detector, which slows
// them tenfold.
const raceEnabled = true
