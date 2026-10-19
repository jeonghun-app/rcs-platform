//go:build race

package transaction

// raceEnabled shrinks the load tests under the race detector, which slows them
// tenfold.
const raceEnabled = true
