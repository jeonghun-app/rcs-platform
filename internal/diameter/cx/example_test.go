package cx_test

import (
	"context"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// An HSS answers UARs. A malformed request is answered by the node itself
// from the parse error, with the AVPs every Cx answer needs.
func Example_hssHandler() {
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		fmt.Println(err)
		return
	}
	node, err := diameter.NewNode(diameter.Config{
		OriginHost:         "hss.ims.mnc001.mcc001.3gppnetwork.org",
		OriginRealm:        "ims.mnc001.mcc001.3gppnetwork.org",
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dict,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	node.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	node.HandleFunc(cx.ApplicationID, cx.CodeUserAuthorization,
		func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
			uar, err := cx.ParseUAR(req)
			if err != nil {
				return nil, err
			}
			_ = uar.PublicIdentity // look the user up here
			uaa := &cx.UAA{
				Answer:     cx.Answer{Result: cx.ExperimentalResult(cx.FirstRegistration)},
				ServerName: "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org",
			}
			return uaa.Message(node, req)
		})
	fmt.Println("serving Cx")
	// Output: serving Cx
}
