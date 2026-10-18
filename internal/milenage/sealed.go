package milenage

// sealed holds a pointer to secret state where fmt cannot reach it.
//
// Format and LogValue cover a value fmt or slog is handed directly, but not
// one in an unexported field of another struct: fmt cannot call methods
// there, prints the fields by reflection, and for a mismatched verb such as
// %s it even prints a nested pointer's target in full. A func value is the one
// kind fmt prints only as an address, under every verb and at every depth,
// so the state is reached through a closure.
type sealed[T any] func() *T

func seal[T any](v *T) sealed[T] { return func() *T { return v } }
