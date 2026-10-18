package sdp

// Session is one session description. Fields are listed in the order their
// lines appear on the wire (RFC 8866 §5); the struct shape enforces the order,
// so Marshal never has to reorder anything. The protocol version is not stored:
// RFC 8866 §5.1 defines only v=0, and the parser rejects any other value.
//
// An empty string or a nil slice means the line is absent.
type Session struct {
	Origin      Origin      // o=
	Name        string      // s=, never empty (RFC 8866 §5.3); "-" when there is no name
	Information string      // i=
	URI         string      // u=
	Emails      []string    // e=
	Phones      []string    // p=
	Connection  *Connection // c=; may be nil when every media description has its own
	Bandwidths  []Bandwidth // b=
	Times       []Time      // t= with its r= lines; at least one
	TimeZones   string      // z=, kept as written
	Key         string      // k=, obsolete (RFC 8866 §5.12) but preserved
	Attributes  Attributes  // session-level a=, in wire order
	Media       []Media     // m= sections, in wire order
}

// Origin is the o= line. The session id and version are kept as the decimal
// strings the originator wrote: RFC 8866 §5.2 bounds neither, and a proxy has
// no reason to renumber them.
type Origin struct {
	Username       string // "-" when the originator has no user id
	SessionID      string
	SessionVersion string
	NetType        string // "IN"
	AddrType       string // "IP4" or "IP6"
	Address        string // unicast address or FQDN
}

// Connection is a c= line. Address keeps any multicast /ttl and /count suffix
// as written.
type Connection struct {
	NetType  string // "IN"
	AddrType string // "IP4" or "IP6"
	Address  string
}

// Bandwidth is a b= line, for example AS:64.
type Bandwidth struct {
	Type  string
	Value uint64
}

// Time is a t= line and the r= lines that follow it. Start and Stop are NTP
// seconds, 0 meaning unbounded (RFC 8866 §5.9). Repeat lines are kept as
// written once their syntax has been checked.
type Time struct {
	Start   uint64
	Stop    uint64
	Repeats []string
}

// Media is one media description: an m= line and the lines up to the next m=.
type Media struct {
	Type        string // "message", "audio", ...
	Port        int
	PortCount   int      // the "/<number of ports>" suffix; 0 when absent
	Proto       string   // "TCP/MSRP", "TCP/TLS/MSRP", "RTP/AVP", ...
	Formats     []string // at least one; "*" for MSRP (RFC 4975 §8.1)
	Information string   // i=
	// Connections holds the media-level c= lines. RFC 8866 §5.7 allows more
	// than one; when there are none the session-level line applies.
	Connections []Connection
	Bandwidths  []Bandwidth // b=
	Key         string      // k=, obsolete but preserved
	Attributes  Attributes  // media-level a=, in wire order
}

// Attribute is one a= line. Value is empty for a property attribute such as
// a=sendrecv; RFC 8866 §9 does not allow "a=name:" with an empty value, so the
// two forms cannot be confused.
type Attribute struct {
	Name  string
	Value string
}
