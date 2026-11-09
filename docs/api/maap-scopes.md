# maap internal API: callers and scopes

The routes are specified in [maap.yaml](maap.yaml); [../maap.md](../maap.md)
describes the service. This page is the scope table ADR 0007 §3 asks for next
to the API, from ADR 0009 §7.

## Callers

| Caller | Token variables | Allowed |
|---|---|---|
| operator | `MAAP_OPERATOR_TOKEN`, `MAAP_OPERATOR_TOKEN_NEXT` | registry, credentials, webhook settings, permissions, limits, blocks, number recycling |

`rcs-as`'s row (admissions and delivery checks; messages and notifications
for chatbots) comes with its API in #683. The chatbot API is on the public
listener, which never mounts these routes, and chatbots authenticate there
with their own credentials (ADR 0009 §7).

## Operations

| Operation | Route | Caller |
|---|---|---|
| `register_chatbot` | `POST /v1/chatbots` | operator |
| `read_chatbot` | `GET /v1/chatbots/{id}` | operator |
| `change_chatbot` | `PATCH /v1/chatbots/{id}` | operator |
| `suspend_chatbot`, `resume_chatbot` | `POST /v1/chatbots/{id}/suspend`, `.../resume` | operator |
| `delete_chatbot` | `DELETE /v1/chatbots/{id}` | operator |

The operation is the audit line's `operation` and the metric's name
(`api.<operation>.<status>`). The operator's other routes come with their
tables (#710–#713), each added here and to maap.yaml by its PR. The
operator's token is refused on every route outside its scope (403), and a
path no route serves is 404.

## Tokens

- Random, at least 256 bits (43 base64url characters or 64 hex digits);
  `staging` and `prod` refuse to start otherwise, or without
  `MAAP_OPERATOR_TOKEN`. `hss`'s `HSS_ADMIN_TOKEN` is a different setting and
  is never accepted here.
- `maap` hashes the presented token and compares the digest with every
  accepted token's digest in constant time, without stopping at a match.
- Two tokens per caller are accepted, so a token rotates without downtime
  ([maap](../maap.md#configuration)). The audit log names the slot (`current`
  or `next`) each request used.
