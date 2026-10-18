package sdp_test

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sdp"
)

func printSDP(b []byte) {
	fmt.Print(strings.ReplaceAll(string(b), "\r\n", "\n"))
}

// rcs-as answering a chat offer that msrp-relay forwards: every offered line
// gets an answer line, and the MSRP one is accepted.
func ExampleNegotiateMSRP() {
	offer, err := sdp.Parse([]byte("v=0\r\n" +
		"o=- 1 1 IN IP4 10.0.0.5\r\n" +
		"s=-\r\n" +
		"c=IN IP4 10.0.0.5\r\n" +
		"t=0 0\r\n" +
		"m=message 9 TCP/MSRP *\r\n" +
		"a=accept-types:message/cpim application/im-iscomposing+xml\r\n" +
		"a=accept-wrapped-types:*\r\n" +
		"a=path:msrp://10.0.0.5:9/rl7a1;tcp\r\n" +
		"a=setup:active\r\n"))
	if err != nil {
		fmt.Println(err)
		return
	}
	answer := sdp.NewAnswer(offer,
		sdp.Origin{Username: "rcs-as", SessionID: "2", SessionVersion: "2", NetType: "IN", AddrType: "IP4", Address: "10.0.1.20"},
		sdp.Connection{NetType: "IN", AddrType: "IP4", Address: "10.0.1.20"})
	for i := range offer.Media {
		m, err := sdp.NegotiateMSRP(offer, i, sdp.MSRPEndpoint{
			Port:               2855,
			Path:               []string{"msrp://10.0.1.20:2855/as9f2c1;tcp"},
			AcceptTypes:        []string{"message/cpim"},
			AcceptWrappedTypes: []string{"text/plain", "message/imdn+xml"},
		})
		if errors.Is(err, sdp.ErrNotMSRP) || errors.Is(err, sdp.ErrMediaDisabled) {
			continue // stays rejected
		}
		if err != nil {
			fmt.Println("488:", err)
			return
		}
		answer.Media[i] = m
	}
	b, err := answer.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	printSDP(b)
	// Output:
	// v=0
	// o=rcs-as 2 2 IN IP4 10.0.1.20
	// s=-
	// c=IN IP4 10.0.1.20
	// t=0 0
	// m=message 2855 TCP/MSRP *
	// a=accept-types:message/cpim
	// a=accept-wrapped-types:text/plain message/imdn+xml
	// a=path:msrp://10.0.1.20:2855/as9f2c1;tcp
	// a=setup:passive
	// a=sendrecv
}

// pcscf anchoring a client's chat offer on msrp-relay before forwarding it
// to the core (ADR 0004).
func ExampleSession_RewriteMSRP() {
	offer, err := sdp.Parse([]byte("v=0\n" +
		"o=- 1 1 IN IP4 192.0.2.10\n" +
		"s=-\n" +
		"c=IN IP4 192.0.2.10\n" +
		"t=0 0\n" +
		"m=message 9 TCP/TLS/MSRP *\n" +
		"a=accept-types:message/cpim\n" +
		"a=path:msrps://192.0.2.10:9/s7d2k8f;tcp\n" +
		"a=setup:actpass\n" +
		"a=x-vendor:kept\n"))
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := range offer.Media {
		err := offer.RewriteMSRP(i, sdp.MSRPRewrite{
			Connection: sdp.Connection{NetType: "IN", AddrType: "IP4", Address: "10.0.0.5"},
			Port:       9,
			Path:       []string{"msrp://10.0.0.5:9/rl7a1;tcp"},
			Setup:      sdp.SetupActive,
		})
		if err != nil && !errors.Is(err, sdp.ErrNotMSRP) && !errors.Is(err, sdp.ErrMediaDisabled) {
			fmt.Println(err)
			return
		}
	}
	b, err := offer.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	printSDP(b)
	// Output:
	// v=0
	// o=- 1 1 IN IP4 192.0.2.10
	// s=-
	// c=IN IP4 10.0.0.5
	// t=0 0
	// m=message 9 TCP/MSRP *
	// a=accept-types:message/cpim
	// a=path:msrp://10.0.0.5:9/rl7a1;tcp
	// a=setup:active
	// a=x-vendor:kept
}
