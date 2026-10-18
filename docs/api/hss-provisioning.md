# HSS provisioning API: callers and scopes

The operations are specified in [hss-provisioning.yaml](hss-provisioning.yaml);
[../hss.md](../hss.md) describes the HSS. This page is the scope table ADR 0007 §3
asks for next to the API.

## Callers

| Caller | Token variables | Allowed |
|---|---|---|
| operator | `HSS_ADMIN_TOKEN`, `HSS_ADMIN_TOKEN_NEXT` | all provisioning, including writing keys; keys are never returned |
| `acs` | `HSS_ACS_TOKEN`, `HSS_ACS_TOKEN_NEXT` | for subscriptions with `acs_managed`: read the subscription (which credentials exist, never their values) and issue its IMS and FT credentials; rate limited per token |
| `ft-server` | `HSS_FT_TOKEN`, `HSS_FT_TOKEN_NEXT` | read the FT credential (HA1 for the FT realm and the owning IMPU) |

## Operations

| Operation | admin | acs | ft-server |
|---|---|---|---|
| `POST /v1/subscriptions` | yes | | |
| `GET /v1/subscriptions/{impi}` | yes | `acs_managed` only | |
| `PUT /v1/subscriptions/{impi}` | yes | | |
| `DELETE /v1/subscriptions/{impi}` | yes | | |
| `PUT /v1/subscriptions/{impi}/aka` | yes | | |
| `POST /v1/subscriptions/{impi}/digest-credential` | yes | `acs_managed` only | |
| `POST /v1/subscriptions/{impi}/ft-credential` | yes | `acs_managed` only | |
| `GET /v1/subscriptions/{impi}/ft-credential` | | | yes |
| `POST /v1/service-profiles` | yes | | |
| `GET`, `PUT`, `DELETE /v1/service-profiles/{id}` | yes | | |

The FT credential's HA1 is readable by `ft-server` alone: the operator and `acs`
can issue a new password but never read a stored credential.

## Answers

| Status | When |
|---|---|
| 503 | no token is configured that may use the operation (also: the store is unavailable; both with `Retry-After`) |
| 401 | no bearer token, or one that is not accepted (`WWW-Authenticate: Bearer`) |
| 403 | the token's caller is not allowed the operation, or `acs` asks about a subscription without `acs_managed` |
| 429 | an `acs` token is over `HSS_ACS_RATE` requests per second (burst `HSS_ACS_BURST`), with `Retry-After` |

## Tokens

- Random, at least 256 bits (43 base64url characters), distinct per caller and
  from the admin token; `staging` and `prod` refuse to start otherwise.
- The HSS hashes the presented token and compares the digest with every accepted
  token's digest in constant time, without stopping at a match.
- Two tokens per caller are accepted, so a token rotates without downtime: set the
  new one as `..._TOKEN_NEXT` and deploy; switch the caller to it and deploy; move
  it to `..._TOKEN`, clear `..._TOKEN_NEXT` and deploy. The audit log names the
  slot (`current` or `next`) each request used, which shows when the old token is
  no longer in use.
- Every request is audited (`audit: provisioning request`): operation, caller, token
  slot, status and the masked IMPI. Tokens, bodies and paths are never logged.
