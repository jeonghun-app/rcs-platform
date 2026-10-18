// Package buildinfo carries the release version stamped into every service
// binary, so a running task can report exactly which build it is.
package buildinfo

// Version is set at link time with -X; "dev" means an unstamped local build.
var Version = "dev"

// String reports the version in the form every service prints for -version.
func String(service string) string {
	return service + " " + Version
}
