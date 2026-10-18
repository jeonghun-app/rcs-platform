# ft-server

`ft-server` is the HTTP content server of RCS File Transfer via HTTP (GSMA
RCC.07, FT via HTTP). `acs` provisions it to clients as `ftHTTPCSURI` (upload)
and `ftHTTPDLURI` (download). A sending client uploads a file, receives a
file-info document and forwards that document to the recipient over chat or
standalone messaging. The recipient downloads from the links in it. Content is
kept in S3 and metadata in the DynamoDB `files` table
([architecture](architecture.md) §7, [ADR 0003](adr/0003-aws-topology.md)).

The code is in `internal/ftserver` (service), `internal/ftserver/store`
(storage interfaces and memory backends) and `internal/ftserver/awsstore` (S3
and DynamoDB). `cmd/ft-server` only wires them together.

## Flows

| Request | Answer | RCC.07 FT via HTTP flow |
|---|---|---|
| `POST <upload URI>` with no body | `401` with Digest challenges, then `204` once authenticated | authentication before upload |
| `POST <upload URI>`, `multipart/form-data` with `tid`, optional `Thumbnail`, `File`, in that order | `200`, file-info document | upload |
| `GET <upload URI>?tid=<tid>&get_upload_info` | `200`, upload-info document; `404` if no byte is held | resume upload |
| `PUT <resume URL>` with `Content-Range: bytes <first>-<last>/<total>` | `200`, file-info document | resume upload |
| `GET <upload URI>?tid=<tid>&get_download_info` | `200`, file-info document of a complete upload | resume upload |
| `GET` or `HEAD <download URI>?id=<file id>` (file) or `?id=<file id>.t` (thumbnail) | `200`, or `206` for one byte range | download |

Both documents use the media type `application/vnd.gsma.rcs-ft-http+xml`. A
file-info document looks like this (the server's own output):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">
  <file-info type="thumbnail">
    <file-size>7427</file-size>
    <content-type>image/jpeg</content-type>
    <data url="https://ft.example.test/dl?id=Qm9yaW5nRXhhbXBsZUlkMDAw.t" until="2026-05-08T09:00:00Z"></data>
  </file-info>
  <file-info type="file">
    <file-size>183524</file-size>
    <file-name>beach.jpg</file-name>
    <content-type>image/jpeg</content-type>
    <data url="https://ft.example.test/dl?id=Qm9yaW5nRXhhbXBsZUlkMDAw" until="2026-05-08T09:00:00Z"></data>
  </file-info>
</file>
```

With `FT_BRANDED_URI` set, the file's `file-info` also carries a `branded-url`
with the same id. An upload-info document names the bytes held, always from
byte 0, and the resume URL:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<file-resume-info xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">
  <file-range start="0" end="10485759"></file-range>
  <data url="https://ft.example.test/ft/f81d4fae-7dec-11d0-a765-00a0c91e6bf6"></data>
</file-resume-info>
```

### Upload rules

- An empty `POST` is the pre-check, whatever `Content-Type` it carries and
  whether or not it is chunked. It is recognised before any upload limit, so it
  uses no rate-limit token.
- The form is read in order and streamed. The `tid` (1 to 128 URI unreserved
  characters, not `.` or `..`) comes first. An optional `Thumbnail` follows. It
  is held in memory, up to `FT_MAX_THUMBNAIL_SIZE`, and stored before the file.
  Then comes the `File`, whose content goes to storage part by part. Field
  names match regardless of case.
- Refused with `400`:
  - a missing or misplaced `tid`, or a second `tid`, `File` or `Thumbnail`;
  - any other part, or a part after `File`;
  - a `Content-Transfer-Encoding` other than binary, 7bit or 8bit;
  - a `File` part without a file name;
  - a content type that is not one media type;
  - a `Content-Length` on the `File` part that the content does not match. RFC
    7578 §4.8 has receivers ignore that field; it is used on purpose, because
    RCS clients send it.
- A file name must be one plain name of at most 512 bytes. Names with these
  characters are refused:
  - control characters;
  - `/` or `\`, and the names `.` and `..`, which a recipient saving the file
    under its name would take as a path;
  - Unicode format characters (category Cf). These include the bidirectional
    controls that make `invoice<U+202E>fdp.exe` display as `invoiceexe.pdf`.
- Refused with `413`: a file over `FT_MAX_SIZE`, a thumbnail over its limit, or
  a part header over 16 KiB. A body that is not `multipart/form-data` gets
  `415`.
- The declared content type is stored and served as declared, after a syntax
  check. It is never sniffed. A part without one is stored as
  `application/octet-stream`.
- A `tid` still uploading may be posted again: the upload starts over from the
  first byte. That is what a client does when it cannot resume. A completed or
  expired `tid` gets `409`. Each owner has its own `tid` space.

### Resume rules

- Only whole parts are durable. When an upload breaks, whatever arrived after
  the last stored part is lost. A part is stored only once a byte after it has
  arrived, so the last part of a file stays in memory until the request
  completes. An incomplete upload therefore always holds fewer bytes than the
  file has, including when it broke right after the last byte or its completion
  failed, and the client always has a non-empty rest to send.
- `get_upload_info` reports the durable bytes. If there are none it answers
  `404`, and the client posts again.
- The resume URL is the upload URI plus `/<tid>`. It is a path with no query,
  because some clients compute the Digest `uri` from the path alone.
- A `PUT` must continue exactly where the held bytes end and must run to the
  last byte. Its total must match any size declared earlier. A range that starts
  elsewhere gets `409`, so the client asks for the upload info again. One that
  ends early gets `400`, because only the end of a file completes it.
- One upload has one writer at a time. A request that writes content first
  takes the record's lease with a conditional update.
  - Another request for the same upload gets `503` with `Retry-After` set to
    the time left on the lease. Typically that request comes from a client
    whose old connection went half-open when it changed networks. RCS clients
    retry a `503`, but give up on a `409`.
  - A lease lasts twice `FT_IDLE_TIMEOUT` plus `FT_STORAGE_TIMEOUT` (3 minutes
    with the defaults). It is renewed while content flows, at least every
    quarter of that, and every stored part renews it too.
  - The lease is released when its request ends, and at shutdown (see
    Operations notes). A task that crashes leaves it to lapse within the lease
    time.
- The update that completes an upload depends on the version the writer holds,
  so two tasks cannot both complete the same `tid`. Content is safe even if a
  lease is broken, for example by a writer stalled past it or by clocks far
  apart:
  - each upload attempt writes its multipart upload under its own key;
  - each single-object completion writes under its own key;
  - S3 joins a multipart object only from parts whose ETags match the list
    given.

  The record's update commits exactly one of these, and a loser's object is
  left for the lifecycle rule.

### Download rules

- Every answer except a live, complete file is `404`: an unknown or malformed
  id, an upload in progress, a file past its validity, or an expired record.
- A task serves at most `FT_MAX_CONCURRENT_DOWNLOADS` at once, and at most
  `FT_MAX_DOWNLOADS_PER_FILE` of one file. Beyond either limit it answers `503`
  with `Retry-After`. The per-file limit matters because with
  `FT_DOWNLOAD_AUTH` off, anyone holding a link can open connections; a
  recipient resuming a download needs one or two.
- A download read more slowly than `FT_MIN_DOWNLOAD_RATE`, measured over each
  minute, is cut off. Otherwise a reader that reads just enough to beat the
  write deadline could hold a slot for hours. The client sees a broken download,
  which it can resume with a range.
- Headers:
  - the declared `Content-Type`;
  - `Content-Disposition: attachment` with the file name (RFC 6266);
  - `X-Content-Type-Options: nosniff`, which every answer of the server carries;
  - `Content-Security-Policy: default-src 'none'; sandbox`;
  - `Referrer-Policy: no-referrer`;
  - `Cache-Control: private, no-store`;
  - `Accept-Ranges: bytes`;
  - a strong `ETag` (the SHA-256 of the content);
  - `Last-Modified`.
- Ranges (RFC 9110 §14):
  - One `bytes` range is served with `206`.
  - Several ranges, an invalid value, another unit, or a range on an empty file
    get the whole file with `200`, as §14.2 allows.
  - An unsatisfiable range gets `416` with `Content-Range: bytes */<size>`.
  - `If-Range` holds only for the exact `ETag`. A date never matches, so the
    whole file is sent.

### Authentication

Uploads, info requests and resumes require HTTP Digest (RFC 7616) through
`internal/sip/digest`. Each 401 offers SHA-256 first and MD5 last. The order is
fixed: the rcsjta reference client reads only the last `WWW-Authenticate` field
and answers it as MD5.

- **Credential failures get one answer.** A missing credential, an unknown
  user, a wrong password, a replayed nonce-count and a wrong `uri` all get the
  same 401 with fresh challenges, so a client cannot learn which user names
  exist. The one exception is a correct response with an expired nonce, which
  gets `stale=true`.
- **Unusable records get the same 401.** Sometimes the HSS answers `200` but the
  record cannot be used: it is for another realm or algorithm, it has no IMPU,
  its HA1 is malformed, or the body is not a credential. That is the fault of
  one subscriber's record, so the client gets the uniform 401 and cannot tell
  such users apart. The operator gets `auth.bad_credential_record` and a log
  line without the user name.
- **Backend failures get 503.** A transport error, a timeout, or an HSS status
  other than `200` and `404` gets `503` with `Retry-After`. It is counted in
  `auth.backend_error` and logged without the user name. It says nothing about
  the user, and clients retry a 503 but give up after a second 401.
- **Lookups are bounded.** Each task runs at most `FT_MAX_CONCURRENT_LOOKUPS` at
  once and answers `503` beyond that (`auth.lookup_busy`). Anyone who has
  fetched a nonce can trigger a lookup with a made-up user name. The HSS client
  uses its own connection pool of the same size.
- **A path-only `uri` is accepted.** For `get_upload_info` and
  `get_download_info` the rcsjta client signs only the path of the URL. RFC
  7616 §3.4.6 allows the `uri` to be that absolute-path, so the server accepts a
  `uri` equal to the request target up to its `?`, and nothing else. The method
  and path remain covered by the response, and a nonce-count still cannot be
  reused. Each such request is counted in `auth.uri_path_only`.

Credentials come from a `CredentialSource`:

- `FT_CREDENTIALS=hss` (the default). The HSS provisioning API answers
  `GET /v1/subscriptions/{impi}/ft-credential?algorithm=SHA-256|MD5` with the
  HA1 for the FT realm and the IMPU that owns the uploads. The contract is
  [docs/api/hss.yaml](api/hss.yaml); the HSS side is #12.
  - The Digest user name is the IMPI. The answer must name the same IMPI byte
    for byte, or the user counts as unknown.
  - Clients get the user name and password from `acs`, which provisions them as
    `ftHTTPCSUser` and `ftHTTPCSPwd` (ACS integration, Phase 7). Behind them is
    the HSS's HA1 for the FT realm.
  - The HSS API is internal. ADR 0007 allows plain `http://` in staging and
    prod only to a private host, together with the service bearer token
    `FT_HSS_TOKEN` from Secrets Manager. A private host is an RFC 1918 or ULA
    address, or a name inside the Cloud Map namespace `RCS_SERVICE_NAMESPACE`.
    Anything else must be `https://`.
- `FT_CREDENTIALS=static`. `FT_STATIC_USERS=user=password,...`, for dev and
  test stacks. It is refused in staging and prod.

Nonces are stateless and keyed by `FT_NONCE_KEY`, so every task must have the
same key. Nonce-counts live in the files table, so a replay is refused by
every task.

#### Downloads without authentication

`FT_DOWNLOAD_AUTH` is off by default. The download URL then works as a bearer
capability:

- Anyone holding the link can fetch the file until it expires. The 144-bit
  random id is the only protection.
- This is the common deployment. Recipients' clients fetch the bare URL from
  the file-info document, and many do not answer a challenge on download.
- A link can be forwarded, or leak through logs that record full URLs, such as
  ALB access logs.

With `FT_DOWNLOAD_AUTH=true` a download also needs Digest credentials. Any
provisioned subscriber is accepted, because the server does not know who the
recipient is. The file is then out of reach of anyone without an account, but
clients that cannot authenticate downloads stop working.

## Settings

Shared `RCS_` settings are described in `internal/runtime`. ft-server also
reads `RCS_SERVICE_NAMESPACE`, the Cloud Map namespace (for example
`rcs.local`), to recognise a private HSS host. The `FT_` settings:

| Variable | Default | Meaning |
|---|---|---|
| `FT_LISTEN_ADDR` | `:8081` | Public HTTP listener, behind the ALB, which terminates TLS |
| `FT_UPLOAD_URI` | required | Public `ftHTTPCSURI`, absolute, https in staging and prod, with a path that does not end in `/` |
| `FT_DOWNLOAD_URI` | required | Public `ftHTTPDLURI`, the same rules. Its path must differ from the upload path and must not lie below it |
| `FT_BRANDED_URI` | none | Base of the optional `branded-url` |
| `FT_REALM` | required | Digest realm of the FT credentials |
| `FT_NONCE_KEY` | random per start | At least 32 bytes, shared by every task. Required in staging and prod |
| `FT_CREDENTIALS` | `hss` | `hss` or `static` (refused in staging and prod) |
| `FT_HSS_URL`, `FT_HSS_TOKEN` | required with `hss` | HSS provisioning API base and service bearer token. `https`, or `http` to a private host (see above). In staging and prod the token must be at least 43 characters: 256 random bits, such as 32 bytes in base64 (ADR 0007 §4) |
| `FT_HSS_TIMEOUT` | `2s` | Per lookup |
| `FT_MAX_CONCURRENT_LOOKUPS` | `16` | Credential lookups in progress per task, and HSS connections |
| `FT_STATIC_USERS` | required with `static` | `user=password,...` |
| `FT_STORE` | `aws` | `aws` or `memory` (refused in staging and prod) |
| `FT_S3_BUCKET` | required with `aws` | Content bucket |
| `FT_S3_PREFIX` | empty | Prepended to every object key |
| `FT_SSE` | `AES256` | `AES256` (SSE-S3) or `aws:kms` (SSE-KMS) on every object |
| `FT_SSE_KMS_KEY_ID` | account `aws/s3` key | KMS key with `aws:kms` |
| `FT_DYNAMODB_TABLE` | `files` | Metadata table |
| `FT_S3_ENDPOINT`, `FT_DYNAMODB_ENDPOINT` | AWS | Local containers only |
| `FT_MAX_SIZE` | `104857600` (100 MiB) | Largest file. At least what `acs` publishes as `MaxSizeFileTr` (in KiB) × 1024 |
| `FT_MAX_THUMBNAIL_SIZE` | `524288` (512 KiB) | Largest thumbnail |
| `FT_PART_SIZE` | `8388608` (8 MiB) | Stored part size and per-upload memory. At least 5 MiB with `aws`. `FT_MAX_SIZE` may need at most 4999 parts |
| `FT_VALIDITY` | `168h` | Download links are valid this long after completion. An incomplete upload can be resumed this long after it started |
| `FT_DOWNLOAD_AUTH` | `false` | Require Digest on downloads (see above) |
| `FT_UPLOADS_PER_MINUTE` | `20` | New uploads per user and task (token bucket). `0` turns the limit off |
| `FT_MAX_CONCURRENT_UPLOADS` | `32` | Uploads and resumes in progress per task |
| `FT_MAX_UPLOADS_PER_USER` | `4` | Uploads and resumes in progress per user and task |
| `FT_MIN_UPLOAD_RATE` | `1024` | Bytes per second, measured over each minute. A slower upload is cut off with `408`. `0` turns the check off |
| `FT_MAX_CONCURRENT_DOWNLOADS` | `256` | Downloads in progress per task |
| `FT_MAX_DOWNLOADS_PER_FILE` | `4` | Downloads of one file in progress per task |
| `FT_MIN_DOWNLOAD_RATE` | `1024` | Bytes per second, measured over each minute. A slower download is cut off. `0` turns the check off |
| `FT_IDLE_TIMEOUT` | `30s` | A transfer that moves no byte for this long is cut off |
| `FT_UPLOAD_TIMEOUT` | `30m` | Longest upload request |
| `FT_STORAGE_TIMEOUT` | `1m` | Each S3 or DynamoDB call |
| `FT_SWEEP_INTERVAL` | `1h` | How often expired records are marked |
| `FT_DRAIN_TIMEOUT` | `10s` | At shutdown, how long running requests may finish before uploads are cut off. Keep it a few seconds below `RCS_SHUTDOWN_TIMEOUT` |

The rate limit and the per-task and per-user upload limits answer `503` with
`Retry-After`, because RCS clients wait and retry on that.

### Memory

Size the task at about
`2 × FT_MAX_CONCURRENT_UPLOADS × (FT_PART_SIZE + FT_MAX_THUMBNAIL_SIZE) + 128 MiB`.
That is about 1 GiB with the defaults. Each running upload holds one part
buffer and possibly a thumbnail. The factor 2 is the Go collector's headroom
(GOGC=100), plus buffers the part pool frees only over two collections. Set
`GOMEMLIMIT` to about 85% of the task memory in the task definition (Phase 7),
so the collector works harder before the task reaches its limit, instead of
letting ECS stop it for memory.

## Storage

### S3

Every attempt at storing a file gets an object key of its own:
`FT_S3_PREFIX` plus `<file id>.<random>`. That covers each multipart upload and
each single-object completion. The record names the key that was committed. A
thumbnail's key is formed the same way with `.t` appended.

An upload larger than one part uses an S3 multipart upload, one part per
`FT_PART_SIZE`. The upload is created with the CRC32 checksum algorithm, every
part carries its CRC32, and the completion lists the checksums of all parts. A
smaller file is stored with one `PutObject`. Every object and multipart upload
asks for `FT_SSE` explicitly.

The infrastructure (Phase 7) must add these to the bucket. Compute the lifecycle
days in CloudFormation from the same parameter that sets `FT_VALIDITY`, so the
two cannot drift apart:

- **Lifecycle expiration** of current objects under the prefix after twice
  `FT_VALIDITY` plus one day, rounded up to whole days (15 days with the
  defaults).
  - S3 dates an object from the start of its multipart upload, and an upload may
    complete up to `FT_VALIDITY` after it started. One validity would delete
    files that are still valid.
  - The server never deletes complete content itself. It only aborts the
    multipart uploads of expired, incomplete records.
  - Downloads refuse expired files whatever is still in the bucket.
  - A valid file whose object has gone gets `404`, and is counted separately as
    `download.failed.missing_object`.
- **AbortIncompleteMultipartUpload** after `FT_VALIDITY` plus one day as well,
  for uploads abandoned on a task that died. The sweeper aborts the ones it
  finds earlier.
- Block Public Access, and default encryption that matches `FT_SSE`.

### DynamoDB `files` table

The partition key is `pk` (string). The TTL attribute is `ttl` (epoch
seconds). Billing is on demand. There is no sort key and no index. The table
holds three kinds of item:

| `pk` | Item |
|---|---|
| `f#<file id>` | The upload record: owner, tid, state, file name, content type, sizes, SHA-256, hash state, object key, multipart id and parts (number, ETag, size, CRC32), thumbnail, times, lease, version |
| `t#<len(owner)>#<owner><tid>` | The owner's tid, pointing at the file id. It is created in one transaction with the record |
| `n#<len(user)>#<user><nonce>` | Highest Digest nonce-count seen for (user, nonce) |

Every record write is conditional on the version read. Request reads are
strongly consistent; the sweeper's scan is not (see below). Records and tid
items expire 30 days after their validity ends. Nonce-counts expire one hour
after their nonce. An upload has at most 4999 parts, which keeps a record well
inside DynamoDB's 400 KB item limit.

### IAM

The task role needs these permissions:

- On the bucket: `s3:PutObject`, `s3:GetObject`, `s3:AbortMultipartUpload` and
  `s3:ListBucket`. `ListBucket` is what `HeadBucket` in `/readyz` needs. With
  SSE-KMS it also needs `kms:GenerateDataKey` and `kms:Decrypt` on the key.
- On the table: `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `Scan` and
  `DescribeTable`. `TransactWriteItems` is covered by `PutItem`.

## Expiry and the sweeper

Every `FT_SWEEP_INTERVAL`, each task marks up to 100 records past their
validity as `expired`, and aborts the open multipart uploads of incomplete
ones. Downloads do not depend on the mark: they compare the validity with the
clock. Records are removed by the table's TTL.

- **Bounded calls.** Each storage call of a sweep has its own
  `FT_STORAGE_TIMEOUT`, so a call that never answers fails the sweep
  (`sweep.failed`) instead of stopping the sweeper silently. Each sweep's
  length is reported as `sweep.duration`.
- **Cost.** The scan reads the whole table and is eventually consistent, which
  halves its cost. Every update the sweeper makes is conditional on the version
  it read. What is read is everything retained (validity plus 30 days), not just
  the expired records. At 100,000 uploads a day that is about 4 GB per scan.
  With two tasks sweeping hourly that comes to about $100 a month at on-demand
  prices (half the strongly consistent figure). At 10,000 a day it is about $10.
  A deployment of that size needs an index on expiry (follow-up).

## Metrics and logs

Counts are written as CloudWatch EMF. The only dimension is `Service`, and no
identifier ever appears in a metric name:

| Metric | Counts |
|---|---|
| `upload.precheck`, `upload.started`, `upload.restarted`, `upload.resumed`, `upload.completed` | Upload steps |
| `upload.bytes`, `upload.parts`, `upload.lease_renewed`, `upload.commit_retried` | Bytes completed, parts stored, lease renewals, retries of the update that completes an upload |
| `upload.failed.<reason>` | Failures, by reason (see below) |
| `download.served`, `download.partial`, `download.bytes`, `download.not_found`, `download.unsatisfiable` | Downloads |
| `download.failed.storage`, `download.failed.interrupted`, `download.failed.too_slow`, `download.failed.busy`, `download.failed.file_busy`, `download.failed.missing_object` | Failed downloads |
| `auth.challenged`, `auth.stale`, `auth.failed`, `auth.backend_error`, `auth.bad_credential_record`, `auth.lookup_busy`, `auth.uri_path_only` | Authentication |
| `sweep.expired`, `sweep.failed`, `sweep.duration` (ms) | Sweeper |

The reasons in `upload.failed.<reason>`:

- Limits: `too_large`, `too_slow`, `timeout`, `busy` (task slots), `user_busy`
  (per-user slots), `rate_limited`.
- Lease and record state: `leased` (another request holds the lease),
  `tid_used`, `conflict`, `not_found`, `not_resumable`.
- Resume ranges: `range_conflict`, `bad_content_range`.
- Content and storage: `length_mismatch`, `storage`, `interrupted`.
- Form problems: `not_multipart`, `bad_tid`, `file_missing`, `extra_part`,
  `malformed`, and others.

File content, file names, tids and file ids are never logged. A file id is a
download capability. The S3 adapter strips request URLs, which contain the
object key, from every error. Owners are logged only through `internal/pii`.

### Signals to alarm on

These signals are for the Phase 7 alarms and runbook. Each one should become
an alarm with a runbook section of the same name (handbook 06 §5):

| Signal | Meaning |
|---|---|
| `auth.backend_error` > 0 | The HSS lookup fails. Uploads get `503` |
| `auth.lookup_busy` sustained | Lookups pile up (slow HSS, or an unauthenticated flood). Check the WAF rule |
| `auth.bad_credential_record` > 0 | A subscriber's FT credential record in the HSS is unusable. That user cannot upload |
| `upload.failed.storage`, `download.failed.storage` > 0 | S3 or DynamoDB fails |
| `download.failed.missing_object` > 0 | A valid file's object is gone. The lifecycle rule is shorter than the validity |
| `upload.failed.busy`, `download.failed.busy` sustained | The tasks are full. Uploads are I/O bound, so scale on this, not on CPU |
| `sweep.failed` > 0, or no `sweep.duration` for two intervals | The sweeper is failing or stuck. Until the expiry index exists (follow-up), a table too large to scan within `FT_STORAGE_TIMEOUT` makes every sweep fail. Raise the timeout or build the index before alarming on this |

## Operations notes

- **WAF rate limiting is a deployment prerequisite.** Requests are limited per
  task: lookups, uploads per user, downloads. Only an AWS WAF rate-based rule in
  front of the ALB limits requests per client across tasks. That covers
  unauthenticated requests, which can cause credential lookups, and downloads,
  which need no authentication by default.
- **Shutdown.** On SIGTERM, running requests get `FT_DRAIN_TIMEOUT` to finish.
  Uploads still running then have their connections closed. Their handlers keep
  the durable parts, release their leases and return before the process exits,
  so the client can resume on another task at once.
  - For Phase 7, set the ft target group's deregistration delay to the length
    of the uploads you want to finish in place (for example 300 s).
  - Set the ECS `stopTimeout` longer than `RCS_SHUTDOWN_TIMEOUT`.
- **Rate limit.** The upload rate limit is per task, so a user spread over N
  tasks can start N times as many uploads. It stops a runaway client; the WAF
  rule stops a determined one.
- **Dead task.** A task that crashes while writing leaves the upload's lease
  until it lapses, which takes up to 3 minutes with the defaults. During that
  time the client gets `503` with `Retry-After` on resume.
- **Integration tests.** `make test-integration` runs the storage contract and
  an end-to-end upload, resume and download against S3Mock and DynamoDB Local
  containers pinned by digest. CI runs it as the `storage integration` job.
  S3Mock enforces the per-part checksum rule of a CRC32 multipart upload. It
  has not been run against AWS S3 itself, with or without SSE-KMS. The Phase 7
  smoke test should cover that:
  - a 12 MB upload, broken off and resumed;
  - a ranged download across a part boundary.

## Unverified against RCC.07

The wire format was implemented from publicly documented behaviour (the GSMA
`rcsjta` reference client) and not checked against a licensed copy of RCC.07.
These items remain to be confirmed:

- The namespace `urn:gsma:params:xml:ns:rcs:rcs:fthttp` on both documents. The
  `file-resume-info` document of the reference client carries none. That client
  finds elements by name, so it reads either form.
- The position of `branded-url` within `file-info`.
- The `204` answer to an authenticated empty `POST`.
- The `404` answer to `get_upload_info` when no byte is held. The reference
  client then posts again. An answer with `end="-1"` would be the other
  reading.
- `503` with `Retry-After` for rate, concurrency, lease and backend limits,
  rather than `429`.
- That the `PUT` answer may carry the file-info document. The reference client
  ignores it and calls `get_download_info`.
