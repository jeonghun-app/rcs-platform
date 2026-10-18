package ftserver

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Defaults of the FT_ settings. docs/ft-server.md has the full table.
const (
	DefaultListenAddr           = ":8081"
	DefaultMaxSize              = 100 << 20 // at least what acs publishes as MaxSizeFileTr (KiB) × 1024
	DefaultMaxThumbnailSize     = 512 << 10
	DefaultPartSize             = 8 << 20
	DefaultValidity             = 7 * 24 * time.Hour
	DefaultUploadsPerMinute     = 20
	DefaultMaxConcurrentUploads = 32
	DefaultMaxUploadsPerUser    = 4
	DefaultMaxDownloads         = 256
	DefaultMaxLookups           = 16
	DefaultMinUploadRate        = 1024 // bytes per second
	// A group chat delivers one link to every member at once: 64 downloads
	// of a file per task keep them from 503-and-retry, and a 16 KiB/s floor
	// keeps 64 slow readers from sitting on the file (#50).
	DefaultMinDownloadRate         = 16 << 10 // bytes per second
	DefaultMaxDownloadsPerFile     = 64
	DefaultMaxDownloadsPerUploader = 128
	DefaultDrainTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 30 * time.Second
	DefaultUploadTimeout           = 30 * time.Minute
	DefaultStorageTimeout          = time.Minute
	DefaultSweepInterval           = time.Hour
	DefaultHSSTimeout              = 2 * time.Second
	DefaultTable                   = "files"
)

// The FT_STORE and FT_CREDENTIALS values.
const (
	StoreMemory       = "memory"
	StoreAWS          = "aws"
	CredentialsStatic = "static"
	CredentialsHSS    = "hss"
)

// Config is ft-server's configuration, read by Configure from FT_ variables.
// Secrets in it print as "[redacted]".
type Config struct {
	ListenAddr  string
	UploadURI   *url.URL
	DownloadURI *url.URL
	BrandedURI  *url.URL

	Realm    string
	NonceKey secret // empty: a random key per start (dev and test only)

	Credentials string
	StaticUsers map[string]secret
	HSSURL      *url.URL
	HSSToken    secret
	HSSTimeout  time.Duration

	Store string
	AWS   AWSConfig

	MaxSize                 int64
	MaxThumbnailSize        int64
	PartSize                int64
	Validity                time.Duration
	DownloadAuth            bool
	UploadsPerMinute        int
	MaxConcurrentUploads    int
	MaxUploadsPerUser       int
	MaxDownloads            int
	MaxLookups              int
	MinUploadRate           int64
	MinDownloadRate         int64
	MaxDownloadsPerFile     int
	MaxDownloadsPerUploader int
	IdleTimeout             time.Duration
	UploadTimeout           time.Duration
	StorageTimeout          time.Duration
	SweepInterval           time.Duration
	DrainTimeout            time.Duration
}

// AWSConfig is the S3 and DynamoDB part of Config, used with FT_STORE=aws.
// The region and credentials come from the SDK's usual sources (the ECS task
// role and AWS_REGION).
type AWSConfig struct {
	Bucket   string
	Prefix   string
	Table    string
	SSE      string // AES256 (SSE-S3) or aws:kms (SSE-KMS)
	KMSKeyID string
	// Endpoints override the AWS endpoints, for local containers.
	S3Endpoint       string
	DynamoDBEndpoint string
}

// Configure reads the FT_ settings (see docs/ft-server.md) and refuses the
// ones that are unsafe with more than one task or on the internet in staging
// and prod.
func Configure(s *runtime.Settings) Config {
	e := s.Env
	c := Config{
		ListenAddr:              e.String("LISTEN_ADDR", DefaultListenAddr),
		Realm:                   e.RequiredString("REALM"),
		NonceKey:                secret{e.String("NONCE_KEY", "")},
		Credentials:             e.String("CREDENTIALS", CredentialsHSS),
		HSSToken:                secret{e.String("HSS_TOKEN", "")},
		HSSTimeout:              e.Duration("HSS_TIMEOUT", DefaultHSSTimeout),
		Store:                   e.String("STORE", StoreAWS),
		MaxSize:                 int64(e.Int("MAX_SIZE", DefaultMaxSize)),
		MaxThumbnailSize:        int64(e.Int("MAX_THUMBNAIL_SIZE", DefaultMaxThumbnailSize)),
		PartSize:                int64(e.Int("PART_SIZE", DefaultPartSize)),
		Validity:                e.Duration("VALIDITY", DefaultValidity),
		DownloadAuth:            e.Bool("DOWNLOAD_AUTH", false),
		UploadsPerMinute:        e.Int("UPLOADS_PER_MINUTE", DefaultUploadsPerMinute),
		MaxConcurrentUploads:    e.Int("MAX_CONCURRENT_UPLOADS", DefaultMaxConcurrentUploads),
		MaxUploadsPerUser:       e.Int("MAX_UPLOADS_PER_USER", DefaultMaxUploadsPerUser),
		MaxDownloads:            e.Int("MAX_CONCURRENT_DOWNLOADS", DefaultMaxDownloads),
		MaxLookups:              e.Int("MAX_CONCURRENT_LOOKUPS", DefaultMaxLookups),
		MinUploadRate:           int64(e.Int("MIN_UPLOAD_RATE", DefaultMinUploadRate)),
		MinDownloadRate:         int64(e.Int("MIN_DOWNLOAD_RATE", DefaultMinDownloadRate)),
		MaxDownloadsPerFile:     e.Int("MAX_DOWNLOADS_PER_FILE", DefaultMaxDownloadsPerFile),
		MaxDownloadsPerUploader: e.Int("MAX_DOWNLOADS_PER_UPLOADER", DefaultMaxDownloadsPerUploader),
		IdleTimeout:             e.Duration("IDLE_TIMEOUT", DefaultIdleTimeout),
		UploadTimeout:           e.Duration("UPLOAD_TIMEOUT", DefaultUploadTimeout),
		StorageTimeout:          e.Duration("STORAGE_TIMEOUT", DefaultStorageTimeout),
		SweepInterval:           e.Duration("SWEEP_INTERVAL", DefaultSweepInterval),
		DrainTimeout:            e.Duration("DRAIN_TIMEOUT", DefaultDrainTimeout),
		AWS: AWSConfig{
			Bucket:           e.String("S3_BUCKET", ""),
			Prefix:           e.String("S3_PREFIX", ""),
			Table:            e.String("DYNAMODB_TABLE", DefaultTable),
			SSE:              e.String("SSE", "AES256"),
			KMSKeyID:         e.String("SSE_KMS_KEY_ID", ""),
			S3Endpoint:       e.String("S3_ENDPOINT", ""),
			DynamoDBEndpoint: e.String("DYNAMODB_ENDPOINT", ""),
		},
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		e.Invalid("LISTEN_ADDR", "not host:port")
	}
	c.UploadURI = publicURI(s, "UPLOAD_URI", true)
	c.DownloadURI = publicURI(s, "DOWNLOAD_URI", true)
	c.BrandedURI = publicURI(s, "BRANDED_URI", false)
	// Links are built from these URIs as given and requests are routed on
	// their exact paths, so a trailing '/' (which acs would provision as
	// is) would make the server's own links miss it.
	for _, u := range []struct {
		name string
		v    *url.URL
	}{{"UPLOAD_URI", c.UploadURI}, {"DOWNLOAD_URI", c.DownloadURI}, {"BRANDED_URI", c.BrandedURI}} {
		if u.v != nil && strings.HasSuffix(u.v.Path, "/") && u.v.Path != "/" {
			e.Invalid(u.name, "path must not end in '/'")
		}
	}
	if c.UploadURI != nil && c.DownloadURI != nil {
		up, down := c.UploadURI.Path, c.DownloadURI.Path
		switch {
		case up == "" || up == "/":
			e.Invalid("UPLOAD_URI", "needs a path, below which resume URLs live")
		case down == "" || down == "/":
			e.Invalid("DOWNLOAD_URI", "needs a path")
		case up == down || strings.HasPrefix(down, up+"/"):
			e.Invalid("DOWNLOAD_URI", "path must not be the upload path or below it")
		}
	}

	if k := c.NonceKey.v; k != "" && len(k) < digest.MinNonceKeySize {
		e.Invalid("NONCE_KEY", "shorter than "+strconv.Itoa(digest.MinNonceKeySize)+" bytes")
	}
	s.ForbidInProduction(c.NonceKey.v == "",
		"FT_NONCE_KEY is unset: every task would issue nonces the others reject")

	switch c.Credentials {
	case CredentialsStatic:
		c.StaticUsers = staticUsers(e)
		s.ForbidInProduction(true, "FT_CREDENTIALS=static authenticates against fixed test passwords")
	case CredentialsHSS:
		c.HSSURL = absoluteURL(e, "HSS_URL", true)
		if c.HSSToken.v == "" {
			e.Invalid("HSS_TOKEN", "required with FT_CREDENTIALS=hss")
		}
		// ADR 0007 §4: service tokens carry at least 256 bits. The length of
		// 32 random bytes in base64 (43 characters) is the shortest encoded
		// form; a shorter token cannot hold that much.
		s.ForbidInProduction(c.HSSToken.v != "" && len(c.HSSToken.v) < minTokenLength,
			"FT_HSS_TOKEN is shorter than "+strconv.Itoa(minTokenLength)+" characters (ADR 0007: at least 256 random bits, e.g. 32 bytes in base64)")
		// ADR 0007: plain http to an internal API only for a private host
		// (an RFC 1918 or ULA address, or a name in the Cloud Map
		// namespace), always with the service's own bearer token.
		namespace := s.Shared.String("SERVICE_NAMESPACE", "")
		s.ForbidInProduction(c.HSSURL != nil && c.HSSURL.Scheme != "https" && !privateHost(c.HSSURL.Hostname(), namespace),
			"FT_HSS_URL is http to a host that is not private (RFC 1918/ULA address or a name in RCS_SERVICE_NAMESPACE): the bearer token and HA1 would cross a network outside the VPC in the clear")
	default:
		e.Invalid("CREDENTIALS", "not one of static, hss")
	}

	switch c.Store {
	case StoreMemory:
		s.ForbidInProduction(true, "FT_STORE=memory keeps files in one task and loses them on restart")
	case StoreAWS:
		if c.AWS.Bucket == "" {
			e.Invalid("S3_BUCKET", "required with FT_STORE=aws")
		}
		switch c.AWS.SSE {
		case "AES256":
			if c.AWS.KMSKeyID != "" {
				e.Invalid("SSE_KMS_KEY_ID", "only with FT_SSE=aws:kms")
			}
		case "aws:kms":
		default:
			e.Invalid("SSE", "not one of AES256, aws:kms")
		}
		if c.PartSize < minPartSize {
			e.Invalid("PART_SIZE", "below the S3 minimum part size of 5 MiB")
		}
	default:
		e.Invalid("STORE", "not one of memory, aws")
	}

	switch {
	case c.MaxSize <= 0:
		e.Invalid("MAX_SIZE", "must be positive")
	case c.PartSize <= 0:
		e.Invalid("PART_SIZE", "must be positive")
	case (c.MaxSize+c.PartSize-1)/c.PartSize >= maxParts:
		e.Invalid("PART_SIZE", "too small for FT_MAX_SIZE: an upload may have at most "+strconv.Itoa(maxParts-1)+" parts")
	}
	if c.MaxThumbnailSize <= 0 {
		e.Invalid("MAX_THUMBNAIL_SIZE", "must be positive")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"VALIDITY", c.Validity}, {"IDLE_TIMEOUT", c.IdleTimeout}, {"UPLOAD_TIMEOUT", c.UploadTimeout},
		{"STORAGE_TIMEOUT", c.StorageTimeout}, {"SWEEP_INTERVAL", c.SweepInterval}, {"HSS_TIMEOUT", c.HSSTimeout},
		{"DRAIN_TIMEOUT", c.DrainTimeout},
	} {
		if d.v == 0 {
			e.Invalid(d.name, "must be greater than zero")
		}
	}
	if c.UploadsPerMinute < 0 {
		e.Invalid("UPLOADS_PER_MINUTE", "must not be negative")
	}
	for _, n := range []struct {
		name string
		v    int
	}{
		{"MAX_CONCURRENT_UPLOADS", c.MaxConcurrentUploads}, {"MAX_UPLOADS_PER_USER", c.MaxUploadsPerUser},
		{"MAX_CONCURRENT_DOWNLOADS", c.MaxDownloads}, {"MAX_CONCURRENT_LOOKUPS", c.MaxLookups},
		{"MAX_DOWNLOADS_PER_FILE", c.MaxDownloadsPerFile}, {"MAX_DOWNLOADS_PER_UPLOADER", c.MaxDownloadsPerUploader},
	} {
		if n.v <= 0 {
			e.Invalid(n.name, "must be positive")
		}
	}
	if c.MinUploadRate < 0 {
		e.Invalid("MIN_UPLOAD_RATE", "must not be negative")
	}
	if c.MinDownloadRate < 0 {
		e.Invalid("MIN_DOWNLOAD_RATE", "must not be negative")
	}
	return c
}

// publicURI reads an absolute http(s) URL without query or fragment. http is
// refused in staging and prod: the links carry credentials' challenges and
// capability ids.
func publicURI(s *runtime.Settings, name string, required bool) *url.URL {
	u := absoluteURL(s.Env, name, required)
	if u != nil {
		s.ForbidInProduction(u.Scheme != "https", "FT_"+name+" is not https")
	}
	return u
}

func absoluteURL(e *runtime.Env, name string, required bool) *url.URL {
	var v string
	if required {
		v = e.RequiredString(name)
	} else {
		v = e.String(name, "")
	}
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		e.Invalid(name, "not an absolute http or https URL without query, fragment or user")
		return nil
	}
	return u
}

// minTokenLength is the shortest FT_HSS_TOKEN accepted in staging and prod.
const minTokenLength = 43

// privateHost reports whether host is a private address (RFC 1918, or an
// IPv6 unique local address) or a name inside the Cloud Map namespace
// (ADR 0007).
func privateHost(host, namespace string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsPrivate()
	}
	namespace = strings.TrimSuffix(strings.ToLower(namespace), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return namespace != "" && strings.HasSuffix(host, "."+namespace)
}

// staticUsers reads FT_STATIC_USERS: comma-separated user=password pairs.
func staticUsers(e *runtime.Env) map[string]secret {
	users := map[string]secret{}
	for i, item := range e.List("STATIC_USERS", nil) {
		name, password, ok := strings.Cut(item, "=")
		if !ok || name == "" || password == "" {
			e.Invalid("STATIC_USERS", "item "+strconv.Itoa(i+1)+" is not user=password")
			continue
		}
		users[name] = secret{password}
	}
	if len(users) == 0 {
		e.Invalid("STATIC_USERS", "required with FT_CREDENTIALS=static")
	}
	return users
}
