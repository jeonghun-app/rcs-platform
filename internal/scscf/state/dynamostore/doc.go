// Package dynamostore keeps the S-CSCF's shared state (internal/scscf/state)
// in DynamoDB, so that any scscf instance can serve any user (ADR 0005). It is
// the only scscf package that imports the AWS SDK: the S-CSCF talks to the
// state interfaces, tested against the memory backend, and this package is
// tested against a strict fake in unit tests and DynamoDB Local in make
// test-integration, both running the contract in state/statetest.
//
// # Tables
//
// registrations, partition key pk (string), holds three kinds of item. A
// set's registration, pk set#<IMPI>#<default IMPU>:
//
//	version  number   optimistic concurrency; a new item starts at a random
//	                  value, so a deleted and recreated one never repeats one
//	doc      binary   the registration as JSON
//	writer   string   random token of the write that stored it
//	impi     string   key of impi-index (keys only): RegistrationsOf
//	shard    string   0 to 15, from the key
//	expires  number   SweepAt in Unix seconds: the earliest contact expiry, or
//	                  without contacts the end of the deregistration lease, or
//	                  else the end of an unregistered user's state
//
// An identity, pk = the canonical IMPU, holds version, writer and a doc
// naming its set and the set's incarnation, and no index attribute. The
// profiles, one per set, pk profile#<IMPI>#<default IMPU>, hold the
// User-Data in doc, received
// (number, Unix ns) ordering them, and ttl (number, Unix seconds), the table's
// TTL attribute, holding KeepUntil. They have no index attribute, so no index
// lists them. Registrations have no ttl: DynamoDB must never delete one, only
// a sweep, which sends the SAR.
//
// with global secondary indexes impi-index (partition impi) and expiry-index
// (partition shard, sort expires), both keys only. The shard spreads the
// expiry index over sixteen partitions so that registration writes, which all
// touch it, never meet one partition's throughput limit.
//
// auth-challenges, partition key pk (string = IMPI), sort key sk (string =
// nonce): doc (binary, the challenge sealed with AES-256-GCM: the key's ID,
// the nonce, the ciphertext), writer, and
// expires (number), which is also the table's TTL attribute: DynamoDB removes
// challenges nobody answered, and a read checks the expiry itself because TTL
// deletion can lag by days.
//
// reg-subscriptions, partition key pk (string = subscription ID): version, doc,
// writer, shard and expires as for registrations, impu (string, key of
// impu-index), and the counters cseq and rver (numbers) with ntoken (string),
// the token of the last NextNotify.
//
// Reads are strongly consistent; the indexes are eventually consistent, so
// every item an index names is read again from the table before it is
// returned. A key no item can have (empty, or over state.MaxKey or
// state.MaxNonce) is answered ErrNotFound without a request, and an item over
// state.MaxItemBytes is refused with ErrInvalid before one: DynamoDB would
// refuse both with a ValidationException of its own.
//
// docs/scscf-state.md has the capacity, cost and key rotation for operators.
//
// # Idempotent writes
//
// The SDK resends a request whose response was lost. Every conditional write
// therefore carries a fresh random token, and a write whose condition fails is
// checked against the stored token: the same token means the earlier attempt
// succeeded, so the write stands, while another token means another writer
// was first (ErrConflict). Content is never compared: two writers that read
// the same version and wrote the same document must not both succeed. A token
// that cannot be drawn is empty and never matches, so such a write fails
// safe as a conflict. TakeChallenge is the exception: a resent delete finds
// nothing and reports ErrNotFound, so a lost response costs the client one
// challenge but never lets a response be checked twice.
//
// # Credentials
//
// Challenges hold authentication vectors and HA1 values (TS 33.203 §6.1, RFC
// 2617). They are sealed with a key the S-CSCF instances share, with the
// table key as additional data, so a copy of the table, a backup or an item
// moved to another key yields nothing usable. Errors carry the operation and
// the AWS error code, never a key: keys are subscriber identities.
package dynamostore
