package sh

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// Data is the subset of an Sh-Data document (TS 29.328 Annex D, tSh-Data)
// described in the package documentation.
type Data struct {
	// PublicIdentifiers is nil when the element is absent.
	PublicIdentifiers *PublicIdentifiers
	RepositoryData    []RepositoryData
}

// PublicIdentifiers is a tPublicIdentity: the public identities and MSISDNs
// of a user (TS 29.328 §7.6.2, §7.6.9).
type PublicIdentifiers struct {
	IMSPublicIdentities []string
	MSISDNs             []string
}

// RepositoryData is a tTransparentData: data an AS keeps in the HSS
// (TS 29.328 §7.6.1).
type RepositoryData struct {
	ServiceIndication string
	// SequenceNumber is 0 to 65535; an update must carry the stored number
	// plus one, wrapping from 65535 to 1 (TS 29.328 §6.1.2).
	SequenceNumber int
	// ServiceData is nil when the element is absent. An Sh-Update with
	// repository data but without ServiceData deletes the stored data
	// (TS 29.328 §6.1.2), while an empty element is present (§6), so the
	// two must not be confused.
	ServiceData *ServiceData
}

// ServiceData is the content of a ServiceData element: the AS's own XML,
// kept byte for byte.
type ServiceData struct {
	InnerXML []byte
}

// maxSequenceNumber is the top of tSequenceNumber.
const maxSequenceNumber = 65535

type wireData struct {
	XMLName           xml.Name             `xml:"Sh-Data"`
	PublicIdentifiers []wirePublicIdentity `xml:"PublicIdentifiers"`
	RepositoryData    []wireRepositoryData `xml:"RepositoryData"`
}

type wirePublicIdentity struct {
	IMSPublicIdentity []string `xml:"IMSPublicIdentity"`
	MSISDN            []string `xml:"MSISDN"`
}

type wireRepositoryData struct {
	ServiceIndication []string          `xml:"ServiceIndication"`
	SequenceNumber    []string          `xml:"SequenceNumber"`
	ServiceData       []wireServiceData `xml:"ServiceData"`
}

type wireServiceData struct {
	InnerXML []byte `xml:",innerxml"`
}

// ParseData parses an Sh-Data document, normally the User-Data of a UDA, SNA
// or PNR. It returns ErrTooLarge, ErrDTD or an error wrapping ErrMalformed.
func ParseData(data []byte) (*Data, error) {
	data = withoutBOM(data)
	if err := checkDocument(data); err != nil {
		return nil, err
	}
	var w wireData
	if err := xml.Unmarshal(data, &w); err != nil {
		return nil, decodeError(err)
	}
	d := &Data{}
	if len(w.PublicIdentifiers) > 1 {
		return nil, fmt.Errorf("%w: PublicIdentifiers occurs more than once", ErrMalformed)
	}
	if len(w.PublicIdentifiers) == 1 {
		p := w.PublicIdentifiers[0]
		d.PublicIdentifiers = &PublicIdentifiers{MSISDNs: p.MSISDN}
		for _, id := range p.IMSPublicIdentity {
			d.PublicIdentifiers.IMSPublicIdentities = append(d.PublicIdentifiers.IMSPublicIdentities, collapse(id))
		}
	}
	for i, r := range w.RepositoryData {
		rd, err := readRepositoryData(r)
		if err != nil {
			return nil, fmt.Errorf("%w: RepositoryData[%d]: %s", ErrMalformed, i+1, err)
		}
		d.RepositoryData = append(d.RepositoryData, rd)
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	return d, nil
}

func readRepositoryData(w wireRepositoryData) (RepositoryData, error) {
	var rd RepositoryData
	if len(w.ServiceIndication) != 1 || len(w.SequenceNumber) != 1 || len(w.ServiceData) > 1 {
		return rd, fmt.Errorf("needs one ServiceIndication, one SequenceNumber and at most one ServiceData")
	}
	rd.ServiceIndication = w.ServiceIndication[0]
	n, err := strconv.Atoi(collapse(w.SequenceNumber[0]))
	if err != nil || n < 0 || n > maxSequenceNumber {
		return rd, fmt.Errorf("SequenceNumber is not an integer from 0 to %d", maxSequenceNumber)
	}
	rd.SequenceNumber = n
	if len(w.ServiceData) == 1 {
		rd.ServiceData = &ServiceData{InnerXML: w.ServiceData[0].InnerXML}
		if rd.ServiceData.InnerXML == nil {
			rd.ServiceData.InnerXML = []byte{}
		}
	}
	return rd, nil
}

// validate checks a document built in code before it is written, and a
// parsed one, so that both directions accept the same documents.
func (d *Data) validate() error {
	if p := d.PublicIdentifiers; p != nil {
		for _, id := range p.IMSPublicIdentities {
			if id == "" || id != collapse(id) || !isXMLText(id) {
				return fmt.Errorf("%w: IMSPublicIdentity is empty, has white space around it or characters XML cannot carry", ErrMalformed)
			}
		}
		for _, n := range p.MSISDNs {
			if !isXMLText(n) {
				return fmt.Errorf("%w: MSISDN has characters XML cannot carry", ErrMalformed)
			}
		}
	}
	for i, rd := range d.RepositoryData {
		switch {
		case !isXMLText(rd.ServiceIndication):
			return fmt.Errorf("%w: RepositoryData[%d]: ServiceIndication has characters XML cannot carry", ErrMalformed, i+1)
		case rd.SequenceNumber < 0 || rd.SequenceNumber > maxSequenceNumber:
			return fmt.Errorf("%w: RepositoryData[%d]: SequenceNumber is out of range", ErrMalformed, i+1)
		}
	}
	return nil
}

// Marshal writes the data as an Sh-Data document. It refuses what ParseData
// would refuse, a document over MaxDataSize with ErrTooLarge; ServiceData
// must be well-formed XML content without a document type declaration, since
// it is written as it is.
func (d *Data) Marshal() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	var w wireData
	if p := d.PublicIdentifiers; p != nil {
		w.PublicIdentifiers = []wirePublicIdentity{{IMSPublicIdentity: p.IMSPublicIdentities, MSISDN: p.MSISDNs}}
	}
	for i, rd := range d.RepositoryData {
		wr := wireRepositoryData{
			ServiceIndication: []string{rd.ServiceIndication},
			SequenceNumber:    []string{strconv.Itoa(rd.SequenceNumber)},
		}
		if rd.ServiceData != nil {
			// The content goes out unescaped, so it must stand on its own
			// as XML; otherwise it could close ServiceData and add
			// elements of its own to the document. Size and depth are
			// checked on the whole document below.
			wrapped := append(append([]byte("<ServiceData>"), rd.ServiceData.InnerXML...), "</ServiceData>"...)
			if err := checkDocument(wrapped); err != nil {
				return nil, fmt.Errorf("RepositoryData[%d]: ServiceData: %w", i+1, err)
			}
			wr.ServiceData = []wireServiceData{{InnerXML: rd.ServiceData.InnerXML}}
		}
		w.RepositoryData = append(w.RepositoryData, wr)
	}
	body, err := xml.Marshal(&w)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(xml.Header)
	out.Write(body)
	// The whole document must pass the parser's checks too: the size
	// limit, and the depth limit at the depth ServiceData really sits at.
	// Otherwise the HSS, or this AS reading its data back, would refuse
	// what was written.
	if err := checkDocument(out.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
