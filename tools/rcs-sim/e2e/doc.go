// Package e2e runs rcs-sim against the built service binaries, as the
// stack runs them: ft-server on its memory stores and msrp-relay on its
// memory store, each a process of its own configured from the environment,
// with rcs-sim standing in for pcscf and rcs-as around the relay. make e2e
// runs it (build tag e2e); it is kept out of make check because it builds
// and starts three binaries.
package e2e
