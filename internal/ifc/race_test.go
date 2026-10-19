//go:build race

package ifc

// raceEnabled shortens the generated-pattern checks under the race
// detector, which slows matching about tenfold and adds nothing to them:
// they run in one goroutine.
const raceEnabled = true
