// Package e2e runs rcs-sim end to end, in two ways kept out of make check.
//
// make e2e (build tag e2e) runs it against the built service binaries:
// ft-server on its memory stores and msrp-relay on its memory store, each a
// process of its own configured from the environment, with rcs-sim standing
// in for pcscf and rcs-as around the relay.
//
// make e2e-compose (build tag e2ecompose) runs it against the local compose
// stack (docs/local-stack.md): the platform image on DynamoDB Local and
// S3Mock, ft-server's credentials from hss, and the pinned acs, whose
// configuration document must point at the stack.
package e2e
