package sdp

import "strings"

// Sample descriptions shaped like what RCS clients and rcs-as exchange. They
// are written for these tests: addresses come from the RFC 5737 documentation
// ranges and host names from example.com.

// crlf turns a readable multi-line literal into wire form.
func crlf(lines ...string) string {
	return strings.Join(lines, "\r\n") + "\r\n"
}

// chatOffer is a 1-to-1 chat INVITE offer from a client over TLS: actpass, CPIM
// with IMDN and is-composing, and an attribute this package does not know.
var chatOffer = crlf(
	"v=0",
	"o=- 3913000001 3913000001 IN IP4 192.0.2.10",
	"s=-",
	"c=IN IP4 192.0.2.10",
	"t=0 0",
	"m=message 9 TCP/TLS/MSRP *",
	"a=accept-types:message/cpim application/im-iscomposing+xml",
	"a=accept-wrapped-types:text/plain message/imdn+xml application/vnd.gsma.rcs-ft-http+xml",
	"a=setup:actpass",
	"a=path:msrps://192.0.2.10:9/s7d2k8f;tcp",
	"a=sendrecv",
	"a=msrp-cema",
)

// chatAnswer is rcs-as answering a chat offer that reached it through
// msrp-relay: passive, so the relay connects to it.
var chatAnswer = crlf(
	"v=0",
	"o=rcs-as 3913000002 3913000002 IN IP4 10.0.1.20",
	"s=-",
	"c=IN IP4 10.0.1.20",
	"t=0 0",
	"m=message 2855 TCP/MSRP *",
	"a=accept-types:message/cpim application/im-iscomposing+xml",
	"a=accept-wrapped-types:text/plain message/imdn+xml",
	"a=path:msrp://10.0.1.20:2855/as9f2c1;tcp",
	"a=setup:passive",
	"a=sendrecv",
)

// fileOffer is an MSRP file transfer push (RFC 5547): sendonly with the file
// selector, transfer id, disposition, date, icon and a resume range.
var fileOffer = crlf(
	"v=0",
	"o=- 3913000100 3913000100 IN IP4 192.0.2.20",
	"s=-",
	"c=IN IP4 192.0.2.20",
	"t=0 0",
	"m=message 9 TCP/MSRP *",
	"i=holiday photo",
	"a=accept-types:message/cpim",
	"a=accept-wrapped-types:image/jpeg",
	`a=file-selector:name:"beach photo%22.jpg" type:image/jpeg size:48213 hash:sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E`,
	"a=file-transfer-id:vBnG916bdberum2fFEABR4f",
	"a=file-disposition:render",
	`a=file-date:creation:"Mon, 12 Oct 2026 09:30:00 +0000" modification:"Tue, 13 Oct 2026 10:00:00 +0000"`,
	"a=file-icon:cid:icon1@example.com",
	"a=file-range:1-48213",
	"a=sendonly",
	"a=path:msrp://192.0.2.20:9/kjhd37s2;tcp",
	"a=setup:active",
	"a=max-size:10485760",
)

// everyField uses every line type RFC 8866 defines, including the rarely seen
// ones, and an audio stream next to the MSRP one.
var everyField = crlf(
	"v=0",
	"o=alice 2890844526 2890842807 IN IP6 2001:db8::10",
	"s=RCS conference",
	"i=weekly sync",
	"u=https://example.com/conf/42",
	"e=alice@example.com (Alice)",
	"p=+15550100001",
	"c=IN IP6 2001:db8::10",
	"b=CT:384",
	"t=3913000000 3913003600",
	"r=7d 1h 0 25h",
	"t=0 0",
	"z=3913000000 -1h 3920000000 0",
	"k=prompt",
	"a=recvonly",
	"a=tool:example-client 1.0",
	"m=audio 49170/2 RTP/AVP 0 96",
	"i=voice",
	"c=IN IP6 2001:db8::11",
	"c=IN IP6 2001:db8::12",
	"b=AS:64",
	"k=uri:https://example.com/keys/1",
	"a=rtpmap:96 opus/48000/2",
	"m=message 7394 TCP/MSRP *",
	"a=accept-types:*",
	"a=path:msrp://example.com:7394/ab12;tcp",
)
