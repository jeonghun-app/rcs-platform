// Package ftserver is the HTTP content server of RCS File Transfer via HTTP
// (GSMA RCC.07, FT via HTTP): the server acs provisions as ftHTTPCSURI and
// ftHTTPDLURI. A sending client uploads a file to it and forwards the
// returned file-info document to the recipient over chat or standalone
// messaging; the recipient downloads from the links in that document.
//
// It exists as its own service because file content must not pass through
// the SIP and MSRP path: files are large, are fetched later and by link, and
// belong in S3 rather than in a messaging application server.
//
// # Flows
//
//   - POST to the upload URI with an empty body: the client's authentication
//     pre-check; 401 with a Digest challenge, then 204.
//   - POST with multipart/form-data (tid, optional Thumbnail, File): the
//     upload, streamed to storage part by part; 200 with the file-info
//     document.
//   - GET ?tid=…&get_upload_info: what a broken upload has stored and its
//     resume URL; PUT with Content-Range to the resume URL completes it.
//     GET ?tid=…&get_download_info returns the file-info document again.
//   - GET or HEAD ?id=… on the download URI: the file or thumbnail, with
//     single byte ranges for resumed downloads.
//
// Uploads and info requests need HTTP Digest (SHA-256 preferred, MD5) against
// a CredentialSource; downloads only with Options.DownloadAuth, because a
// recipient's client commonly fetches the bare link. docs/ft-server.md has the
// settings, the table layout and what is unverified against RCC.07.
//
// # Consistency
//
// Any task may serve any request (ADR 0005). A request that writes content
// first takes the record's lease with a conditional update, so one upload has
// one writer at a time, and the update that marks it complete is conditional
// on the version that writer holds, so it completes once.
//
// # Privacy
//
// File content, file names, transaction ids and file ids are never logged;
// owners only through internal/pii. Metrics are counts with no identifier in
// the name.
package ftserver
