package buildinfo

import "testing"

func TestStringNamesTheServiceAndTheVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v1.2.3"
	if got := String("pcscf"); got != "pcscf v1.2.3" {
		t.Fatalf("String() = %q", got)
	}
}
