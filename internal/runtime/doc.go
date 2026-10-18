// Package runtime is the process scaffolding every service binary shares:
// configuration from the environment, the JSON logger, CloudWatch EMF metrics,
// the admin server with /healthz and /readyz, graceful shutdown, and the
// -version and -healthcheck modes.
//
// Building this once keeps the services consistent in the ways operators depend
// on (docs/architecture.md §8): every service refuses the same unsafe settings
// in production, logs the same fields, answers the same health endpoints and
// stops the same way when ECS sends SIGTERM.
//
// A service's main function is a single call:
//
//	func main() {
//		runtime.Main(runtime.Service[config]{
//			Name:      "pcscf",
//			EnvPrefix: "PCSCF_",
//			Configure: loadConfig,
//			Run:       run,
//		})
//	}
//
// Run registers readiness checks and shutdown hooks on its *Runtime, calls
// rt.Ready once it can take work (/readyz answers 503 "starting" until then),
// and returns when its context is cancelled. Service packages test their Run
// function with internal/runtime/runtimetest instead of a process.
//
// The shared settings, all optional except RCS_ENV:
//
//	RCS_ENV               dev, test, staging or prod; staging and prod refuse
//	                      settings declared unsafe with Settings.ForbidInProduction
//	RCS_LOG_LEVEL         debug, info (default), warn or error
//	RCS_ADMIN_ADDR        admin listener, IP:port or :port (default :8080)
//	RCS_SHUTDOWN_TIMEOUT  drain deadline after SIGTERM (default 20s)
//	RCS_METRICS_NAMESPACE CloudWatch namespace for EMF metrics (default RCS)
//	RCS_PII_HMAC_KEY      at least 32 bytes; keys the correlation hints of
//	                      internal/pii; required in staging and prod (unkeyed
//	                      hints, allowed in dev and test, show the last two
//	                      characters of each identifier)
//
// The package name shadows the standard library's runtime; import it under
// another name where both are needed.
package runtime
