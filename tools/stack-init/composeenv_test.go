package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scripts/compose-env.sh writes the env file this tool and the stack read;
// its tests live here, with the rest of the local stack's tooling.

func composeEnv(t *testing.T, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join("..", "..", "scripts", "compose-env.sh")
	out, err := exec.Command("sh", append([]string{script}, args...)...).CombinedOutput()
	return string(out), err
}

func readEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(k, "#") {
			if _, dup := m[k]; dup {
				t.Fatalf("%s twice in the file", k)
			}
			m[k] = v
		}
	}
	return m
}

var secret = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestComposeEnvGeneratesEverySecretOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.env")
	if out, err := composeEnv(t, path); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	first := readEnv(t, path)
	for _, k := range []string{"HSS_ADMIN_TOKEN", "HSS_ACS_TOKEN", "HSS_FT_TOKEN", "RELAY_PCSCF_TOKEN", "ACS_ADMIN_TOKEN", "FT_NONCE_KEY", "RCS_PII_HMAC_KEY"} {
		if !secret.MatchString(first[k]) {
			t.Errorf("%s = %q, want 64 hex digits", k, first[k])
		}
	}
	if len(first["HSS_DATA_KEY"]) != 44 {
		t.Errorf("HSS_DATA_KEY is not base64 of 32 bytes")
	}
	if first["HSS_ADMIN_TOKEN"] == first["HSS_FT_TOKEN"] {
		t.Error("two secrets are equal")
	}
	// A second run keeps the file.
	if out, err := composeEnv(t, path); err != nil || !strings.Contains(out, "keeping it") {
		t.Fatalf("%v: %s", err, out)
	}
	if readEnv(t, path)["HSS_ADMIN_TOKEN"] != first["HSS_ADMIN_TOKEN"] {
		t.Fatal("a second run changed a secret")
	}
	// -f writes new ones.
	if out, err := composeEnv(t, "-f", path); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if readEnv(t, path)["HSS_ADMIN_TOKEN"] == first["HSS_ADMIN_TOKEN"] {
		t.Fatal("-f kept a secret")
	}
}

func TestComposeEnvAddsSettingsTheFileLacks(t *testing.T) {
	// A file written before a change added RELAY_PCSCF_TOKEN and a port.
	path := filepath.Join(t.TempDir(), "compose.env")
	if out, err := composeEnv(t, path); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	before := readEnv(t, path)
	b, _ := os.ReadFile(path)
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "RELAY_PCSCF_TOKEN=") && !strings.HasPrefix(line, "FT_HOST_PORT=") {
			kept = append(kept, line)
		}
	}
	// Edited by hand, without a newline at the end.
	if err := os.WriteFile(path, []byte(strings.TrimRight(strings.Join(kept, "\n"), "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := composeEnv(t, path)
	if err != nil || !strings.Contains(out, "added RELAY_PCSCF_TOKEN FT_HOST_PORT") {
		t.Fatalf("%v: %s", err, out)
	}
	after := readEnv(t, path)
	if !secret.MatchString(after["RELAY_PCSCF_TOKEN"]) || after["RELAY_PCSCF_TOKEN"] == before["RELAY_PCSCF_TOKEN"] ||
		after["FT_HOST_PORT"] != "18081" || after["HSS_ADMIN_TOKEN"] != before["HSS_ADMIN_TOKEN"] {
		t.Fatalf("after: %v", after)
	}
}

func TestComposeEnvRefusesAFileWithAnEmptySecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.env")
	if out, err := composeEnv(t, path); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	b, _ := os.ReadFile(path)
	cleared := regexp.MustCompile(`(?m)^ACS_ADMIN_TOKEN=.*$`).ReplaceAll(b, []byte("ACS_ADMIN_TOKEN="))
	if err := os.WriteFile(path, cleared, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := composeEnv(t, path)
	if err == nil || !strings.Contains(out, "ACS_ADMIN_TOKEN") || !strings.Contains(out, "-f") {
		t.Fatalf("%v: %s", err, out)
	}
}
