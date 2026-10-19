package simtest_test

import (
	"net/http"
	"testing"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

func TestTheServicesStartAndAnswer(t *testing.T) {
	f := simtest.StartFT(t, 64<<10)
	resp, err := f.Server.Client().Post(f.UploadURL.String(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ft-server pre-check = %d, want 401", resp.StatusCode)
	}
	r := simtest.StartRelay(t, simtest.FreePort(t))
	resp, err = http.Post(r.Control.JoinPath("/v1/bindings").String(), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("relay control without a token = %d, want 401", resp.StatusCode)
	}
}
