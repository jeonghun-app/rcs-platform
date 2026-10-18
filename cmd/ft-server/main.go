// Command ft-server is the HTTP content server for RCS File Transfer via
// HTTP (GSMA RCC.07): clients upload files to it, with resume, and recipients
// download them from the links in the file-info document. Content is in S3
// and metadata in DynamoDB. All of the logic is in internal/ftserver; the
// settings are documented in docs/ft-server.md.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/ftserver"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(ftserver.Service())
}
