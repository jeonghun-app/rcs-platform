# rcs-sim

`tools/rcs-sim` simulates an RCS client for end-to-end tests: it transfers
files over HTTP with `ft-server` and chats over MSRP through `msrp-relay`, with
delivery and display notifications. It runs in CI (`make e2e`) and is meant to
run against a deployed stack as well.

This is step 1 (#62). There is no SIP yet. So for chat the simulator also
takes the two parts SIP will later give to the network:

- **pcscf**: it allocates and completes the relay binding through the relay's
  control API, in the order pcscf follows while it rewrites SDP
  ([msrp-relay](msrp-relay.md), "How a session is anchored").
- **rcs-as**: it listens as the passive MSRP end the relay connects to, with
  the session registered as rcs-as registers one when it answers an INVITE.

The control API is internal ([ADR 0007](adr/0007-internal-transport.md)), so
the chat scenarios work against a local stack only. Against a deployed stack,
only the file transfer scenarios apply until step 2 (SIP REGISTER, INVITE and
MESSAGE through pcscf) replaces both parts.

## Scenarios

| Scenario | Steps | Checks |
|---|---|---|
| `ft` | pre-check, upload (with a thumbnail), get_download_info, download, download-range, download-thumbnail | 401 before credentials; file-info sizes, type and links; content by SHA-256, against the server's strong ETag too; a single range gets 206 |
| `ft-resume` | pre-check, interrupted-upload, get_upload_info, resume, get_download_info, download | the server keeps whole leading parts of a broken upload; the PUT with `Content-Range` completes it; the file comes back whole by SHA-256 |
| `chat-client-originated` | listen-core, allocate (client path), answer (core path), connect, client-to-core, core-to-client, chunked-message, keep-alive, clean, release | ADR 0004's first row: messages both ways with CPIM and IMDN, delivered and displayed notifications, success reports, a 100 KiB message in 2 KiB chunks, keep-alives on a quiet session |
| `chat-core-originated` | listen-core, allocate (core path), answer (client path), connect, core-sends-first, then as above | ADR 0004's second row: the client connects as soon as it has answered, and the network speaks first |

`all` runs every scenario. A scenario stops at its first failed step.

### What the clients do

The FT client follows the GSMA rcsjta reference client
(HttpAuthenticationAgent, HttpUploadManager):

- It starts each attempt with an empty POST and reads the challenge of the
  401.
- It answers only the last `WWW-Authenticate` field, as MD5 without an
  algorithm parameter.
- It signs only the path for `get_upload_info` and `get_download_info`.
- It sends the form as `tid`, `Thumbnail`, `File`, each part with its own
  `Content-Length`, and URL-encodes the file name.
- It retries a 503 after its `Retry-After`.
- It resumes with `get_upload_info` and a PUT from the first byte not held,
  and asks again on 409.

The chat client connects actively, as a device behind NAT does: over TLS for
an `msrps:` path, plain for `msrp:`. It binds the session with a bodiless SEND
(RFC 4975 §5.4) and wraps every message in CPIM (RFC 3862) with an IMDN
request (RFC 5438). It answers delivery requests at once. Display
notifications go out when the scenario reads the message, as a user would.
The rcs-as stand-in answers both at once.

## Running it

```bash
export RCS_SIM_FT_PASSWORD=...       # ftHTTPCSPwd
export RCS_SIM_RELAY_TOKEN=...       # pcscf's control token (local stacks only)
rcs-sim -ft-upload-url http://127.0.0.1:8081/ft \
        -ft-user 001010000000001@ims.mnc001.mcc001.3gppnetwork.org \
        -resume-size $((12 << 20)) \
        -relay-control http://127.0.0.1:8082 -core-listen 127.0.0.1:2855 \
        all
```

| Flag | Default | Meaning |
|---|---|---|
| `-ft-upload-url` | none | ft-server's upload URI (`ftHTTPCSURI`); the FT scenarios fail without it |
| `-ft-user` | `RCS_SIM_FT_USER` | FT user name (`ftHTTPCSUser`) |
| `-file-size` | 256 KiB | size of the `ft` file |
| `-resume-size` | 12 MiB | size of the `ft-resume` file; must exceed the server's `FT_PART_SIZE`, since only whole parts survive a break |
| `-relay-control` | none | msrp-relay control API base URL; the chat scenarios fail without it |
| `-core-listen` | `127.0.0.1:0` | where the rcs-as stand-in listens; the port must be in the relay's `RELAY_CORE_PORTS` |
| `-core-advertise` | the listener's address | host the relay is told to connect to |
| `-msrp-keepalive` | 240s | MSRP keep-alive interval of both ends (ADR 0003) |
| `-idle-wait` | 0 (skip) | stay quiet this long in the chat scenarios, to see keep-alives go out; set it above `-msrp-keepalive` |
| `-self`, `-peer` | `+15550100001`, `+15550100002` in the MCC 001 test domain | the CPIM addresses of the two ends |
| `-step-timeout` | 30s | bound on each step |
| `-list`, `-version` | | print the scenarios or the version |

Secrets are read from the environment only, never from flags, because flags
are visible in process listings: `RCS_SIM_FT_PASSWORD` and
`RCS_SIM_RELAY_TOKEN`. The user name may also come from `RCS_SIM_FT_USER`.

### Output

One JSON line per step on standard output:

```json
{"scenario":"ft-resume","step":"get_upload_info","ok":true,"ms":52,"detail":{"held":5242880}}
{"scenario":"chat-core-originated","step":"keep-alive","ok":true,"ms":1500,"detail":{"bytes_while_quiet":514}}
```

A failed step has `"ok":false` and an `error` naming the operation and the
status or cause. Results never carry a URL, a session id, a user name, a
password, a token or an address: download URLs and MSRP session ids are
capabilities, and the run's output goes to CI logs.

The exit status is 0 when every step succeeded, 1 when one failed, and 2 for a
usage error.

## make e2e

`make e2e` (CI job "end to end (rcs-sim)") builds `ft-server`, `msrp-relay`
and `rcs-sim`. It starts the two services as processes of their own,
configured from the environment as a test stack configures them:

- `ft-server` on its memory stores, with static credentials and 5 MiB parts
  (the smallest, as on S3);
- `msrp-relay` on its memory store, with a plain public listener on loopback
  (no NLB, so no PROXY header and no TLS) and the core side limited to
  loopback and the stand-in's port.

It then runs `rcs-sim all` against them and checks every result line. The
unit tests of `tools/rcs-sim` run the same scenarios against the same service
code inside the test process (`internal/simtest`).

## Findings

- A client that breaks an upload and at once sends another request under the
  same nonce can lose the whole upload. The transport gives up on the broken
  request as soon as its body fails, possibly before ft-server has read its
  headers. If the next request, with a higher nonce-count, is verified first,
  the broken one is refused as a replay (RFC 7616 §3.4.1) and stores nothing.
  `get_upload_info` then answers 404, and the client starts over. The
  simulator takes a fresh challenge after a break, as rcsjta does before every
  upload attempt. rcsjta's resume reuses the nonce, though (as modelled in
  `internal/ftserver/rcsjta_test.go`), so a real device can hit this (#66).
