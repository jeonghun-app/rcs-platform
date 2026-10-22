package ftserver

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// devEnv is a minimal valid dev configuration with the memory store and
// static users.
var devEnv = map[string]string{
	"RCS_ENV":           "dev",
	"FT_REALM":          realm,
	"FT_UPLOAD_URI":     "http://localhost:8081/ft",
	"FT_DOWNLOAD_URI":   "http://localhost:8081/dl",
	"FT_STORE":          "memory",
	"FT_CREDENTIALS":    "static",
	"FT_STATIC_USERS":   "alice=secret, bob=other",
	"FT_SWEEP_INTERVAL": "1m",
}

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

// configure runs Configure the way runtime.Run does and returns the
// configuration and every problem.
func configure(env map[string]string) (Config, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("FT_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

func TestDevConfigurationIsReadWithDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != DefaultListenAddr || c.MaxSize != 100<<20 || c.Validity != 7*24*time.Hour ||
		c.DownloadAuth || c.UploadsPerMinute != DefaultUploadsPerMinute || c.SweepInterval != time.Minute {
		t.Fatalf("config = %+v", c)
	}
	if c.UploadURI.String() != "http://localhost:8081/ft" || len(c.StaticUsers) != 2 || c.StaticUsers["bob"].value() != "other" {
		t.Fatalf("config = %+v", c)
	}
}

func TestAWSConfigurationIsRead(t *testing.T) {
	c, err := configure(with(devEnv, "FT_STORE", "aws", "FT_S3_BUCKET", "files-bucket", "FT_SSE", "aws:kms",
		"FT_SSE_KMS_KEY_ID", "alias/ft", "FT_S3_ENDPOINT", "http://s3:9090"))
	if err != nil {
		t.Fatal(err)
	}
	if c.AWS.Bucket != "files-bucket" || c.AWS.Table != DefaultTable || c.AWS.SSE != "aws:kms" || c.AWS.KMSKeyID != "alias/ft" {
		t.Fatalf("aws = %+v", c.AWS)
	}
}

func TestInvalidSettingsAreAllReported(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no realm":            {with(devEnv, "FT_REALM", ""), "FT_REALM: required"},
		"relative uri":        {with(devEnv, "FT_UPLOAD_URI", "/ft"), "FT_UPLOAD_URI"},
		"uri with query":      {with(devEnv, "FT_DOWNLOAD_URI", "https://ft/dl?x=1"), "FT_DOWNLOAD_URI"},
		"uri with user":       {with(devEnv, "FT_DOWNLOAD_URI", "https://u:p@ft/dl"), "FT_DOWNLOAD_URI"},
		"ftp uri":             {with(devEnv, "FT_BRANDED_URI", "ftp://ft/x"), "FT_BRANDED_URI"},
		"root upload":         {with(devEnv, "FT_UPLOAD_URI", "https://ft/"), "FT_UPLOAD_URI: needs a path"},
		"same paths":          {with(devEnv, "FT_DOWNLOAD_URI", "https://dl/ft"), "FT_DOWNLOAD_URI: path"},
		"upload slash":        {with(devEnv, "FT_UPLOAD_URI", "https://ft.example/ft/"), "FT_UPLOAD_URI: path must not end in '/'"},
		"download slash":      {with(devEnv, "FT_DOWNLOAD_URI", "https://ft.example/dl/"), "FT_DOWNLOAD_URI: path must not end in '/'"},
		"branded slash":       {with(devEnv, "FT_BRANDED_URI", "https://ft.example/view/"), "FT_BRANDED_URI: path must not end in '/'"},
		"no download path":    {with(devEnv, "FT_DOWNLOAD_URI", "https://ft.example"), "FT_DOWNLOAD_URI: needs a path"},
		"zero per user":       {with(devEnv, "FT_MAX_UPLOADS_PER_USER", "0"), "FT_MAX_UPLOADS_PER_USER"},
		"zero downloads":      {with(devEnv, "FT_MAX_CONCURRENT_DOWNLOADS", "0"), "FT_MAX_CONCURRENT_DOWNLOADS"},
		"zero lookups":        {with(devEnv, "FT_MAX_CONCURRENT_LOOKUPS", "0"), "FT_MAX_CONCURRENT_LOOKUPS"},
		"negative min rate":   {with(devEnv, "FT_MIN_UPLOAD_RATE", "-1"), "FT_MIN_UPLOAD_RATE"},
		"zero drain":          {with(devEnv, "FT_DRAIN_TIMEOUT", "0s"), "FT_DRAIN_TIMEOUT"},
		"zero per file":       {with(devEnv, "FT_MAX_DOWNLOADS_PER_FILE", "0"), "FT_MAX_DOWNLOADS_PER_FILE"},
		"negative dl rate":    {with(devEnv, "FT_MIN_DOWNLOAD_RATE", "-1"), "FT_MIN_DOWNLOAD_RATE"},
		"listen":              {with(devEnv, "FT_LISTEN_ADDR", "8081"), "FT_LISTEN_ADDR"},
		"short nonce key":     {with(devEnv, "FT_NONCE_KEY", "short"), "FT_NONCE_KEY"},
		"credentials":         {with(devEnv, "FT_CREDENTIALS", "ldap"), "FT_CREDENTIALS"},
		"no static users":     {with(devEnv, "FT_STATIC_USERS", ""), "FT_STATIC_USERS: required"},
		"bad static user":     {with(devEnv, "FT_STATIC_USERS", "alice"), "FT_STATIC_USERS: item 1"},
		"hss without url":     {with(devEnv, "FT_CREDENTIALS", "hss", "FT_HSS_TOKEN", "t"), "FT_HSS_URL: required"},
		"hss without token":   {with(devEnv, "FT_CREDENTIALS", "hss", "FT_HSS_URL", "https://hss"), "FT_HSS_TOKEN"},
		"store":               {with(devEnv, "FT_STORE", "disk"), "FT_STORE"},
		"aws without bucket":  {with(devEnv, "FT_STORE", "aws"), "FT_S3_BUCKET"},
		"sse":                 {with(devEnv, "FT_STORE", "aws", "FT_S3_BUCKET", "b", "FT_SSE", "none"), "FT_SSE"},
		"kms key with sse-s3": {with(devEnv, "FT_STORE", "aws", "FT_S3_BUCKET", "b", "FT_SSE_KMS_KEY_ID", "k"), "FT_SSE_KMS_KEY_ID"},
		"small s3 part":       {with(devEnv, "FT_STORE", "aws", "FT_S3_BUCKET", "b", "FT_PART_SIZE", "1024"), "FT_PART_SIZE: below"},
		"too many parts":      {with(devEnv, "FT_PART_SIZE", "1"), "FT_PART_SIZE: too small"},
		"zero size":           {with(devEnv, "FT_MAX_SIZE", "0"), "FT_MAX_SIZE"},
		"zero part":           {with(devEnv, "FT_PART_SIZE", "0"), "FT_PART_SIZE"},
		"zero thumbnail":      {with(devEnv, "FT_MAX_THUMBNAIL_SIZE", "0"), "FT_MAX_THUMBNAIL_SIZE"},
		"zero validity":       {with(devEnv, "FT_VALIDITY", "0s"), "FT_VALIDITY"},
		"negative rate":       {with(devEnv, "FT_UPLOADS_PER_MINUTE", "-1"), "FT_UPLOADS_PER_MINUTE"},
		"zero concurrency":    {with(devEnv, "FT_MAX_CONCURRENT_UPLOADS", "0"), "FT_MAX_CONCURRENT_UPLOADS"},
	} {
		_, err := configure(c.env)
		var ce *runtime.ConfigError
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a problem with %q", name, err, c.want)
		}
	}
}

// runService runs the ft-server service with env until it has started or
// failed, and returns the exit status and output.
func runService(t *testing.T, env map[string]string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // stop as soon as it has started
	status := runtime.Run(ctx, Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out,
		Listen:    listenLoopback,
	})
	return status, out.String()
}

func TestProductionRefusesEveryUnsafeSetting(t *testing.T) {
	status, out := runService(t, with(devEnv, "RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32)))
	if status != runtime.ExitFailure {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{"FT_STORE=memory", "FT_CREDENTIALS=static", "FT_NONCE_KEY is unset", "FT_UPLOAD_URI is not https", "FT_DOWNLOAD_URI is not https"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, out)
		}
	}
}

func TestProductionRefusesPlainHTTPToTheHSS(t *testing.T) {
	_, out := runService(t, with(devEnv, "RCS_ENV", "prod", "FT_CREDENTIALS", "hss", "FT_HSS_URL", "http://hss:8081", "FT_HSS_TOKEN", "t"))
	if !strings.Contains(out, "FT_HSS_URL is http to a host that is not private") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestProductionRefusesAShortHSSToken(t *testing.T) {
	prod := with(devEnv, "RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
		"FT_CREDENTIALS", "hss", "FT_HSS_URL", "https://hss.example.test", "FT_STATIC_USERS", "")
	if _, out := runService(t, with(prod, "FT_HSS_TOKEN", strings.Repeat("t", 42))); !strings.Contains(out, "FT_HSS_TOKEN is shorter than 43") {
		t.Fatalf("a 42-character token was accepted:\n%s", out)
	}
	if _, out := runService(t, with(prod, "FT_HSS_TOKEN", strings.Repeat("t", 43))); strings.Contains(out, "FT_HSS_TOKEN") {
		t.Fatalf("a 43-character token was refused:\n%s", out)
	}
}

func TestPlainHTTPToTheHSSIsAllowedOnlyForPrivateHosts(t *testing.T) {
	prod := with(devEnv, "RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32), "RCS_SERVICE_NAMESPACE", "rcs.local",
		"FT_CREDENTIALS", "hss", "FT_HSS_TOKEN", strings.Repeat("t", 43), "FT_STATIC_USERS", "")
	// The rule is runtime.IsPrivateInternalURL's (ADR 0007 §5); these show
	// ft-server applies it to FT_HSS_URL.
	for url, allowed := range map[string]bool{
		"http://hss.rcs.local:8081":     true,
		"http://10.0.3.7:8081":          true,
		"http://[fd00::7]:8081":         true,
		"https://hss.example.com":       true,
		"http://hss.example.com":        false,
		"http://169.254.169.254/":       false,
		"http://127.0.0.1:8081":         false,
		"http://hss.evilrcs.local:8081": false,
	} {
		_, out := runService(t, with(prod, "FT_HSS_URL", url))
		if refused := strings.Contains(out, "FT_HSS_URL"); refused == allowed {
			t.Errorf("FT_HSS_URL=%s: refused %t, want %t:\n%s", url, refused, !allowed, out)
		}
	}
}
