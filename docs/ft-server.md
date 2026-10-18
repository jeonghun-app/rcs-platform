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

- The form is read in order and streamed. The `tid` (1 to 128 URI unreserved
  characters, not `.` or `..`) comes first. An optional `Thumbnail` follows. It
  is held in memory, up to `FT_MAX_THUMBNAIL_SIZE`, and stored before the file.
  Then comes the `File`, whose content goes to storage part by part. Field
  names match regardless of case.
- Refused with `400`: a missing or misplaced `tid`, a second `tid`, `File` or
  `Thumbnail`, any other part, a part after `File`, a
  `Content-Transfer-Encoding` other than binary, 7bit or 8bit, a `File` part
  without a file name, or a file name with control characters or over 512
  bytes. Also refused: a content type that is not one media type, and a
  `Content-Length` on the `File` part that the content does not match. Refused
  with `413`: a file over `FT_MAX_SIZE`, a thumbnail over the limit, or a part
  header over 16 KiB. A body that is not `multipart/form-data` gets `415`.
- The declared content type is stored and served as declared, after a syntax
  check. It is never sniffed. A part without one is stored as
  `application/octet-stream`.
- A `tid` still uploading may be posted again: the upload starts over from the
  first byte. That is what a client does when it cannot resume. A completed or
  expired `tid` gets `409`. Each owner has its own `tid` space.

### Resume rules

- Only whole parts are durable. When an upload breaks, whatever arrived after
  the last stored part is lost. `get_upload_info` reports the durable bytes.
  If there are none it answers `404`, and the client posts again.
- The resume URL is the upload URI plus `/<tid>`. It is a path with no query,
  because some clients compute the Digest `uri` from the path alone.
- A `PUT` must continue exactly where the held bytes end and must run to the
  last byte. Its total must match any size declared earlier. A range that starts
  elsewhere gets `409`, so the client asks for the upload info again. One that
  ends early gets `400`, because only the end of a file completes it.
- One upload has one writer at a time. A request that writes content first
  takes the record's lease with a conditional update. A second request for the
  same upload gets `409`. The lease lasts as long as the longest possible
  request: `FT_UPLOAD_TIMEOUT` plus `FT_STORAGE_TIMEOUT` plus one minute. It is
  released when its request ends. Only a task that dies holding the lease
  leaves it to lapse.
- The update that completes an upload depends on the version the writer holds.
  Two tasks therefore cannot both complete the same `tid`.

### Download rules

- Every answer except a live, complete file is `404`: an unknown or malformed
  id, an upload in progress, a file past its validity, or an expired record.
- Headers: the declared `Content-Type`, `Content-Disposition: attachment` with
  the file name (RFC 6266), `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: default-src 'none'; sandbox`,
  `Referrer-Policy: no-referrer`, `Cache-Control: private, no-store`,
  `Accept-Ranges: bytes`, a strong `ETag` (the SHA-256 of the content) and
  `Last-Modified`.
- Ranges (RFC 9110 §14): one `bytes` range is served with `206`. Several
  ranges, an invalid value, another unit, or a range on an empty file get the
  whole file with `200`, as §14.2 allows. An unsatisfiable range gets `416`
  with `Content-Range: bytes */<size>`. `If-Range` holds only for the exact
  `ETag`. A date never matches, so the whole file is sent.

### Authentication

Uploads, info requests and resumes require HTTP Digest (RFC 7616) through
`internal/sip/digest`. Each 401 offers SHA-256 first and MD5 second. Every
failure gets the same 401 with fresh challenges, whether the credentials are
missing, the user is unknown, the password is wrong, the nonce-count is
replayed, the `uri` is wrong or the credential lookup failed. A client cannot
learn which user names exist. The one exception is a correct response with an
expired nonce, which gets `stale=true`. A failed lookup is counted
(`auth.backend_error`) and logged without the user name.

Credentials come from a `CredentialSource`:

- `FT_CREDENTIALS=hss` (the default). The HSS provisioning API answers
  `GET /v1/subscriptions/{impi}/ft-credential?algorithm=SHA-256|MD5` with the
  HA1 for the FT realm and the IMPU that owns the uploads. The contract is
  [docs/api/hss.yaml](api/hss.yaml), and the HSS side is #12. The Digest user
  name is the IMPI. The FT password is what `acs` provisions as the FT HTTP
  credential.
- `FT_CREDENTIALS=static`. `FT_STATIC_USERS=user=password,...`, for dev and
  test stacks. It is refused in staging and prod.

Nonces are stateless and keyed by `FT_NONCE_KEY`, so every task must have the
same key. Nonce-counts live in the files table, so a replay is refused by
every task.

#### Downloads without authentication

`FT_DOWNLOAD_AUTH` is off by default. The download URL then works as a bearer
capability. Anyone holding the link can fetch the file until it expires, and
the 144-bit random id is the only protection. This is the common deployment:
recipients' clients fetch the bare URL from the file-info document, and many do
not answer a challenge on download. A link can be forwarded or leak through
logs that record full URLs, such as ALB access logs. With `FT_DOWNLOAD_AUTH=true`
a download also needs Digest credentials. Any provisioned subscriber is
accepted, because the server does not know who the recipient is. The file is
then out of reach of anyone without an account, but clients that cannot
authenticate downloads stop working.

## Settings

Shared `RCS_` settings are described in `internal/runtime`. The `FT_` settings:

| Variable | Default | Meaning |
|---|---|---|
| `FT_LISTEN_ADDR` | `:8081` | Public HTTP listener, behind the ALB, which terminates TLS |
| `FT_UPLOAD_URI` | required | Public `ftHTTPCSURI`, absolute, https in staging and prod, with a path |
| `FT_DOWNLOAD_URI` | required | Public `ftHTTPDLURI`. Its path must differ from the upload path and must not lie below it |
| `FT_BRANDED_URI` | none | Base of the optional `branded-url` |
| `FT_REALM` | required | Digest realm of the FT credentials |
| `FT_NONCE_KEY` | random per start | At least 32 bytes, shared by every task. Required in staging and prod |
| `FT_CREDENTIALS` | `hss` | `hss` or `static` (refused in staging and prod) |
| `FT_HSS_URL`, `FT_HSS_TOKEN` | required with `hss` | HSS provisioning API base and bearer token. `https` in staging and prod |
| `FT_HSS_TIMEOUT` | `2s` | Per lookup |
| `FT_STATIC_USERS` | required with `static` | `user=password,...` |
| `FT_STORE` | `aws` | `aws` or `memory` (refused in staging and prod) |
| `FT_S3_BUCKET` | required with `aws` | Content bucket |
| `FT_S3_PREFIX` | empty | Prepended to every object key |
| `FT_SSE` | `AES256` | `AES256` (SSE-S3) or `aws:kms` (SSE-KMS) on every object |
| `FT_SSE_KMS_KEY_ID` | account `aws/s3` key | KMS key with `aws:kms` |
| `FT_DYNAMODB_TABLE` | `files` | Metadata table |
| `FT_S3_ENDPOINT`, `FT_DYNAMODB_ENDPOINT` | AWS | Local containers only |
| `FT_MAX_SIZE` | `104857600` (100 MiB) | Largest file. Keep it equal to what `acs` publishes as `MaxSizeFileTr` |
| `FT_MAX_THUMBNAIL_SIZE` | `524288` (512 KiB) | Largest thumbnail |
| `FT_PART_SIZE` | `8388608` (8 MiB) | Stored part size and per-upload memory. At least 5 MiB with `aws` |
| `FT_VALIDITY` | `168h` | Download links are valid this long after completion. An incomplete upload can be resumed this long after it started |
| `FT_DOWNLOAD_AUTH` | `false` | Require Digest on downloads (see above) |
| `FT_UPLOADS_PER_MINUTE` | `20` | New uploads per user and task (token bucket). `0` turns the limit off |
| `FT_MAX_CONCURRENT_UPLOADS` | `32` | Uploads in progress per task. Beyond that, `503` with `Retry-After` |
| `FT_IDLE_TIMEOUT` | `30s` | A transfer that moves no byte for this long is cut off |
| `FT_UPLOAD_TIMEOUT` | `30m` | Longest upload request |
| `FT_STORAGE_TIMEOUT` | `1m` | Each S3 or DynamoDB call |
| `FT_SWEEP_INTERVAL` | `1h` | How often expired records are marked |

The rate limit and the upload limit answer `503` with `Retry-After`, because
RCS clients wait and retry on that. A task needs memory for at least
`FT_MAX_CONCURRENT_UPLOADS × FT_PART_SIZE` (256 MiB with the defaults) plus
thumbnails.

## Storage

### S3

The key of each object is `FT_S3_PREFIX` plus the file id. A thumbnail has the
same key with `.t` appended. An upload larger than one part uses an S3
multipart upload, one part per `FT_PART_SIZE`. A smaller file is stored with
one `PutObject`. Every object and multipart upload asks for `FT_SSE`
explicitly. The infrastructure (Phase 7) must add these to the bucket:

- **Lifecycle expiration** of current objects under the prefix after twice
  `FT_VALIDITY` plus one day, rounded up to whole days (15 days with the
  defaults). S3 dates an object from the start of its multipart upload, and an
  upload may complete up to `FT_VALIDITY` after it started, so one validity
  would delete files that are still valid. The server never deletes complete
  content itself. Downloads refuse expired files whatever is still in the
  bucket, and a valid file whose object is gone gets `404`.
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
| `f#<file id>` | The upload record: owner, tid, state, file name, content type, sizes, SHA-256, hash state, multipart id and parts, thumbnail, times, lease, version |
| `t#<len(owner)>#<owner><tid>` | The owner's tid, pointing at the file id. It is created in one transaction with the record |
| `n#<len(user)>#<user><nonce>` | Highest Digest nonce-count seen for (user, nonce) |

Every record write is conditional on the version read. Reads are strongly
consistent. Items expire 30 days after their validity ends (records and tid
items) or one hour after their nonce (nonce-counts).

### IAM

The task role needs these permissions:

- On the bucket: `s3:PutObject`, `s3:GetObject`, `s3:AbortMultipartUpload` and
  `s3:ListBucket`. `ListBucket` is what `HeadBucket` in `/readyz` needs. With
  SSE-KMS it also needs `kms:GenerateDataKey` and `kms:Decrypt` on the key.
- On the table: `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `Scan` and
  `DescribeTable`. `TransactWriteItems` is covered by `PutItem`.

## Expiry and the sweeper

Every `FT_SWEEP_INTERVAL` each task marks up to 100 records past their
validity as `expired` and aborts their open multipart uploads. Downloads do
not depend on the mark: they compare the validity with the clock. The sweep
scans the whole table, which is acceptable at an hourly interval for a first
release. A larger table needs an index on expiry (follow-up). Records are
removed by the table's TTL.

## Metrics and logs

Counts are written as CloudWatch EMF. The only dimension is `Service`, and no
identifier ever appears in a metric name:

| Metric | Counts |
|---|---|
| `upload.precheck`, `upload.started`, `upload.restarted`, `upload.resumed`, `upload.completed` | Upload steps |
| `upload.bytes`, `upload.parts` | Bytes completed and parts stored |
| `upload.failed.<reason>` | Failures, where `<reason>` is one of `too_large`, `length_mismatch`, `busy`, `tid_used`, `conflict`, `storage`, `timeout`, `interrupted`, `rate_limited`, `not_found`, `not_resumable`, `range_conflict`, `bad_content_range`, `not_multipart`, or a form problem (`bad_tid`, `file_missing`, `extra_part`, `malformed`, ...) |
| `download.served`, `download.partial`, `download.bytes`, `download.not_found`, `download.unsatisfiable`, `download.failed.storage`, `download.failed.interrupted` | Downloads |
| `auth.challenged`, `auth.stale`, `auth.failed`, `auth.backend_error` | Authentication |
| `sweep.expired`, `sweep.failed` | Sweeper |

File content, file names, tids and file ids are never logged. A file id is a
download capability. The S3 adapter strips request URLs, which contain the
object key, from every error. Owners are logged only through `internal/pii`.

## Operations notes

- **Shutdown.** Uploads still running at shutdown get until
  `RCS_SHUTDOWN_TIMEOUT`. An upload cut off there keeps its durable parts, and
  the client resumes on another task.
- **Rate limit.** The limit is per task, so a user spread over N tasks can
  start N times as many uploads. It stops a runaway client. AWS WAF rate-based
  rules in front of the ALB can stop a determined one.
- **Dead task.** A task that dies while writing leaves the upload's lease until
  it lapses, which takes about 32 minutes with the defaults. During that time
  the client gets `409` on resume.
- **Integration tests.** `make test-integration` runs the storage contract and
  an end-to-end upload, resume and download against S3Mock and DynamoDB Local
  containers pinned by digest. CI runs it as the `storage integration` job.

## Unverified against RCC.07

The wire format was implemented from publicly documented behaviour (the GSMA
`rcsjta` reference client) and not checked against a licensed copy of RCC.07.
These items remain to be confirmed:

- The namespace `urn:gsma:params:xml:ns:rcs:rcs:fthttp` on both documents. The
  `file-resume-info` document of the reference client carries none.
- The position of `branded-url` within `file-info`.
- The `204` answer to an authenticated empty `POST`.
- The `404` answer to `get_upload_info` when no byte is held. The reference
  client then posts again. An answer with `end="-1"` would be the other
  reading.
- `503` with `Retry-After` for rate and concurrency limits, rather than `429`.
- That the `PUT` answer may carry the file-info document. The reference client
  ignores it and calls `get_download_info`.
- The reference client signs only the path in the Digest `uri` of
  `get_upload_info`. `internal/sip/digest` requires the full request target
  (RFC 7616 §3.4.6), so that client's authenticated info request fails.
