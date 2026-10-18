// Command rcs-version prints the release version stamped into the image.
//
// It is the image's default command, so running the image without choosing a
// service reports which build it is instead of starting one by accident. It
// also gives the image build a binary to compile before any service exists,
// which proves the -trimpath and buildinfo ldflag wiring end to end.
package main

import (
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/buildinfo"
)

func main() {
	fmt.Println(buildinfo.String("rcs-version"))
}
