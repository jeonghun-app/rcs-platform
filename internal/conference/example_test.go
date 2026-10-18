package conference_test

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
)

func ExampleMerge() {
	full := []byte(`<conference-info xmlns="urn:ietf:params:xml:ns:conference-info"
    entity="sip:chat@example.com" state="full" version="1">
  <conference-description><subject>Plans</subject></conference-description>
  <users>
    <user entity="sip:alice@example.com"><endpoint entity="a1"><status>connected</status></endpoint></user>
    <user entity="sip:bob@example.com"><endpoint entity="b1"><status>connected</status></endpoint></user>
  </users>
</conference-info>`)
	update := []byte(`<conference-info xmlns="urn:ietf:params:xml:ns:conference-info"
    entity="sip:chat@example.com" state="partial" version="2">
  <users state="partial">
    <user entity="sip:bob@example.com" state="partial">
      <endpoint entity="b1" state="partial">
        <status>disconnected</status><disconnection-method>departed</disconnection-method>
      </endpoint>
    </user>
  </users>
</conference-info>`)

	var state *conference.Info
	for _, doc := range [][]byte{full, update} {
		c, err := conference.Parse(doc)
		if err != nil {
			panic(err)
		}
		if state, err = conference.Merge(state, c); err != nil {
			panic(err)
		}
	}
	for _, u := range state.Users.List {
		e := u.Endpoints[0]
		fmt.Printf("%s: %s", u.Entity, e.Status)
		if e.DisconnectionMethod != "" {
			fmt.Printf(" (%s)", e.DisconnectionMethod)
		}
		fmt.Println()
	}
	// Output:
	// sip:alice@example.com: connected
	// sip:bob@example.com: disconnected (departed)
}
