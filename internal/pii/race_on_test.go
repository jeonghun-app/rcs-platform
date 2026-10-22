//go:build race

package pii

// raceEnabled: the race detector's instrumentation makes timings say more
// about itself than about the scan.
const raceEnabled = true
