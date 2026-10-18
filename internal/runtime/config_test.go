package runtime

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

func TestSharedSettingsHaveSafeDefaults(t *testing.T) {
	e := NewEnv("RCS_", envMap{"RCS_ENV": "dev"}.lookup)
	s := loadShared(e)
	if err := e.Err(); err != nil {
		t.Fatal(err)
	}
	if s.environment != Dev || s.logLevel != slog.LevelInfo || s.shutdownTimeout != 20*time.Second ||
		s.metricsNamespace != "RCS" || s.admin.listen != ":8080" || s.admin.probeURL != "http://127.0.0.1:8080/healthz" {
		t.Fatalf("defaults = %+v", s)
	}
}

func TestSharedSettingsAreRead(t *testing.T) {
	e := NewEnv("RCS_", envMap{
		"RCS_ENV":               "prod",
		"RCS_LOG_LEVEL":         "debug",
		"RCS_ADMIN_ADDR":        "127.0.0.1:9090",
		"RCS_SHUTDOWN_TIMEOUT":  "110s",
		"RCS_METRICS_NAMESPACE": "RCS/staging-1",
		"RCS_PII_HMAC_KEY":      strings.Repeat("k", 32),
	}.lookup)
	s := loadShared(e)
	if err := e.Err(); err != nil {
		t.Fatal(err)
	}
	if s.environment != Prod || s.logLevel != slog.LevelDebug || s.shutdownTimeout != 110*time.Second ||
		s.metricsNamespace != "RCS/staging-1" || s.admin.probeURL != "http://127.0.0.1:9090/healthz" {
		t.Fatalf("settings = %+v", s)
	}
	want := pii.NewRedactor([]byte(strings.Repeat("k", 32))).Redact("tel:+15550100001")
	if got := s.redactor.Redact("tel:+15550100001"); got != want {
		t.Fatalf("redactor is not keyed with RCS_PII_HMAC_KEY: %q", got)
	}
}

func TestRCSEnvIsRequired(t *testing.T) {
	e := NewEnv("RCS_", envMap{}.lookup)
	loadShared(e)
	if err := e.Err(); err == nil || !strings.Contains(err.Error(), "RCS_ENV: required") {
		t.Fatalf("Err() = %v", err)
	}
}

func TestEnvironmentsOutsideTheFourStagesAreRefused(t *testing.T) {
	for _, v := range []string{"production", "PROD", "Dev", "local"} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": v}.lookup)
		s := loadShared(e)
		if err := e.Err(); err == nil || !strings.Contains(err.Error(), "RCS_ENV: not one of") {
			t.Errorf("RCS_ENV=%s: Err() = %v", v, err)
		}
		if s.environment != "" {
			t.Errorf("RCS_ENV=%s: environment = %q", v, s.environment)
		}
	}
}

func TestOnlyStagingAndProdAreProduction(t *testing.T) {
	for env, want := range map[Environment]bool{Dev: false, Test: false, Staging: true, Prod: true, "": false} {
		if got := env.Production(); got != want {
			t.Errorf("%q.Production() = %v", env, got)
		}
	}
}

func TestLogLevelsAreTheFourNames(t *testing.T) {
	for v, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_LOG_LEVEL": v}.lookup)
		if s := loadShared(e); s.logLevel != want || e.Err() != nil {
			t.Errorf("RCS_LOG_LEVEL=%s gave %v, %v", v, s.logLevel, e.Err())
		}
	}
	for _, v := range []string{"DEBUG", "warning", "info+2", "trace"} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_LOG_LEVEL": v}.lookup)
		loadShared(e)
		if e.Err() == nil {
			t.Errorf("RCS_LOG_LEVEL=%s accepted", v)
		}
	}
}

func TestAdminAddressDecidesWhereTheHealthcheckProbes(t *testing.T) {
	tests := []struct{ addr, probe string }{
		{":8080", "http://127.0.0.1:8080/healthz"},
		{"0.0.0.0:8081", "http://127.0.0.1:8081/healthz"},
		{"[::]:8082", "http://127.0.0.1:8082/healthz"},
		{"127.0.0.1:8083", "http://127.0.0.1:8083/healthz"},
		{"[::1]:8084", "http://[::1]:8084/healthz"},
		{"10.0.3.7:8085", "http://10.0.3.7:8085/healthz"},
	}
	for _, tt := range tests {
		a, ok := parseAdminAddr(tt.addr)
		if !ok || a.listen != tt.addr || a.probeURL != tt.probe {
			t.Errorf("parseAdminAddr(%q) = %+v, %v; want probe %s", tt.addr, a, ok, tt.probe)
		}
	}
}

func TestAdminAddressesTheHealthcheckCannotFindAreRefused(t *testing.T) {
	for _, v := range []string{"8080", ":0", ":65536", ":http", ":080", "localhost:8080", "admin.internal:8080", "[fe80::1%eth0]:8080", ":-1", ""} {
		if _, ok := parseAdminAddr(v); ok {
			t.Errorf("parseAdminAddr(%q) accepted", v)
		}
	}
	e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_ADMIN_ADDR": "localhost:8080"}.lookup)
	s := loadShared(e)
	if e.Err() == nil || s.admin.listen != DefaultAdminAddr {
		t.Fatalf("bad RCS_ADMIN_ADDR: err %v, listen %q", e.Err(), s.admin.listen)
	}
}

func TestZeroShutdownTimeoutIsRefused(t *testing.T) {
	e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_SHUTDOWN_TIMEOUT": "0s"}.lookup)
	loadShared(e)
	if err := e.Err(); err == nil || !strings.Contains(err.Error(), "RCS_SHUTDOWN_TIMEOUT: must be greater than zero") {
		t.Fatalf("Err() = %v", err)
	}
}

func TestMetricsNamespaceFollowsCloudWatchRules(t *testing.T) {
	for _, ok := range []string{"RCS", "rcs/prod", "My App:1 #2", strings.Repeat("n", 255)} {
		if !validNamespace(ok) {
			t.Errorf("validNamespace(%q) = false", ok)
		}
	}
	for _, bad := range []string{"AWS/ECS", "rcs\tprod", "rcs\n", "ünicode", strings.Repeat("n", 256)} {
		if validNamespace(bad) {
			t.Errorf("validNamespace(%q) = true", bad)
		}
	}
	e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_METRICS_NAMESPACE": "AWS/Lambda"}.lookup)
	if s := loadShared(e); e.Err() == nil || s.metricsNamespace != DefaultMetricsNamespace {
		t.Fatalf("AWS/ namespace: err %v, namespace %q", e.Err(), s.metricsNamespace)
	}
}

func TestShortPIIKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	const key = "too-short-key"
	e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_PII_HMAC_KEY": key}.lookup)
	loadShared(e)
	err := e.Err()
	if err == nil || !strings.Contains(err.Error(), "RCS_PII_HMAC_KEY: shorter than 32 bytes") {
		t.Fatalf("Err() = %v", err)
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("problem echoes the key: %v", err)
	}
}

func TestSharedProblemsAreAllListed(t *testing.T) {
	e := NewEnv("RCS_", envMap{
		"RCS_ENV":               "qa",
		"RCS_LOG_LEVEL":         "loud",
		"RCS_ADMIN_ADDR":        "nowhere",
		"RCS_SHUTDOWN_TIMEOUT":  "forever",
		"RCS_METRICS_NAMESPACE": "AWS/x",
		"RCS_PII_HMAC_KEY":      "short",
	}.lookup)
	loadShared(e)
	var ce *ConfigError
	if !errors.As(e.Err(), &ce) {
		t.Fatal(e.Err())
	}
	var names []string
	for _, p := range ce.Problems {
		names = append(names, p[:strings.Index(p, ":")])
	}
	want := []string{"RCS_ENV", "RCS_LOG_LEVEL", "RCS_ADMIN_ADDR", "RCS_SHUTDOWN_TIMEOUT", "RCS_METRICS_NAMESPACE", "RCS_PII_HMAC_KEY"}
	if !slices.Equal(names, want) {
		t.Fatalf("problems for %q, want %q", names, want)
	}
}
