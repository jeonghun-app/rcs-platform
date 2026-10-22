//go:build race

package cpim

// raceEnabled: the race detector's instrumentation makes timings say more
// about itself than about the parser.
const raceEnabled = true
