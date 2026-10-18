package sh_test

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/sh"
)

// rcs-as reads its repository data from the User-Data of a UDA, changes it
// and writes it back with the next sequence number, which the HSS checks
// (TS 29.328 §6.1.2).
func ExampleParseData() {
	uda := []byte(`<Sh-Data><RepositoryData>
		<ServiceIndication>rcs-chat</ServiceIndication>
		<SequenceNumber>7</SequenceNumber>
		<ServiceData><settings days="7"/></ServiceData>
	</RepositoryData></Sh-Data>`)
	data, err := sh.ParseData(uda)
	if err != nil {
		fmt.Println(err)
		return
	}
	rd := data.RepositoryData[0]
	rd.SequenceNumber = rd.SequenceNumber%65535 + 1
	rd.ServiceData = &sh.ServiceData{InnerXML: []byte(`<settings days="30"/>`)}
	out, err := (&sh.Data{RepositoryData: []sh.RepositoryData{rd}}).Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(out))
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <Sh-Data><RepositoryData><ServiceIndication>rcs-chat</ServiceIndication><SequenceNumber>8</SequenceNumber><ServiceData><settings days="30"/></ServiceData></RepositoryData></Sh-Data>
}
