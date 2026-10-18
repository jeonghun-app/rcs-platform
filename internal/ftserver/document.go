package ftserver

import (
	"encoding/xml"
	"strconv"
	"time"
)

// ContentType is the media type of the file-info and upload-info documents
// (RCC.07 FT via HTTP, the HTTP content server's responses).
const ContentType = "application/vnd.gsma.rcs-ft-http+xml"

// namespace is the XML namespace of the FT via HTTP documents. Taken from
// the publicly documented wire format (RCC.07 FT via HTTP); see
// docs/ft-server.md for what is unverified against the licensed text.
const namespace = "urn:gsma:params:xml:ns:rcs:rcs:fthttp"

// The file-info types (RCC.07 FT via HTTP, file-info document).
const (
	infoTypeFile      = "file"
	infoTypeThumbnail = "thumbnail"
)

// fileDocument is the file-info document returned when an upload completes
// and for get_download_info: the sender forwards it to the recipient, who
// downloads from the data URLs.
type fileDocument struct {
	XMLName xml.Name   `xml:"urn:gsma:params:xml:ns:rcs:rcs:fthttp file"`
	Infos   []fileInfo `xml:"file-info"`
}

// fileInfo is one file-info element. The field order is the order of the
// elements in the document.
type fileInfo struct {
	Type        string   `xml:"type,attr"`
	Size        int64    `xml:"file-size"`
	Name        string   `xml:"file-name,omitempty"`
	ContentType string   `xml:"content-type"`
	Data        dataLink `xml:"data"`
	BrandedURL  string   `xml:"branded-url,omitempty"`
}

type dataLink struct {
	URL   string `xml:"url,attr"`
	Until string `xml:"until,attr,omitempty"`
}

// resumeDocument is the upload-info document (get_upload_info): which bytes
// the server holds and where to PUT the rest.
type resumeDocument struct {
	XMLName xml.Name `xml:"urn:gsma:params:xml:ns:rcs:rcs:fthttp file-resume-info"`
	Range   struct {
		Start string `xml:"start,attr"`
		End   string `xml:"end,attr"`
	} `xml:"file-range"`
	Data dataLink `xml:"data"`
}

// marshalDocument returns v with the XML declaration. encoding/xml escapes
// every value and replaces characters XML cannot carry, so a file name cannot
// change the document's structure.
func marshalDocument(v any) ([]byte, error) {
	out, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(out, '\n')...), nil
}

// formatUntil writes a validity as an xs:dateTime in UTC with second
// precision, the form RCS clients parse.
func formatUntil(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// newResumeDocument describes received bytes held for an upload whose rest
// goes to url. received is at least 1: with nothing stored there is nothing
// to resume and the client starts again (see handleInfo).
func newResumeDocument(received int64, url string) resumeDocument {
	var d resumeDocument
	d.Range.Start = "0"
	d.Range.End = strconv.FormatInt(received-1, 10)
	d.Data.URL = url
	return d
}
