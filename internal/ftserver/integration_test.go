//go:build integration

package ftserver

import (
	"crypto/sha256"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
)

// TestIntegrationUploadResumeAndDownloadOverS3 runs the whole flow on the
// S3 and DynamoDB containers of make test-integration, with S3's real 5 MiB
// part minimum: an upload broken off after more than one part, its resume,
// and a ranged download across a part boundary.
func TestIntegrationUploadResumeAndDownloadOverS3(t *testing.T) {
	s3Endpoint, ddbEndpoint := os.Getenv("FT_IT_S3_ENDPOINT"), os.Getenv("FT_IT_DYNAMODB_ENDPOINT")
	if s3Endpoint == "" || ddbEndpoint == "" {
		t.Fatal("FT_IT_S3_ENDPOINT and FT_IT_DYNAMODB_ENDPOINT must name the test containers")
	}
	ctx := t.Context()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	bucket, table := "ft-flow-"+suffix, "files-flow-"+suffix
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(s3Endpoint); o.UsePathStyle = true })
	if _, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ddbEndpoint) })
	if _, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(table),
		BillingMode:          dtypes.BillingModePayPerRequest,
		AttributeDefinitions: []dtypes.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: dtypes.ScalarAttributeTypeS}},
		KeySchema:            []dtypes.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: dtypes.KeyTypeHash}},
	}); err != nil {
		t.Fatal(err)
	}
	stores, err := awsstore.New(ctx, awsstore.Config{
		Bucket: bucket, Prefix: "files/", Table: table, SSE: "AES256",
		S3Endpoint: s3Endpoint, DynamoDBEndpoint: ddbEndpoint,
	})
	if err != nil {
		t.Fatal(err)
	}

	const part = minPartSize
	e := newEnv(t, func(o *Options) {
		o.Metadata, o.Blobs = stores.Metadata, stores.Blobs
		o.PartSize, o.MaxSize = part, 4*part
	})
	u := e.user(alice)
	data := pattern(2*part + 12345)
	breakUpload(t, e, u, "s3-flow", data, part+777)

	info := parseResumeDocument(t, u.get("/ft?tid=s3-flow&get_upload_info").Body.Bytes())
	if info.Range.End != strconv.Itoa(part-1) {
		t.Fatalf("file-range = %+v, want 0-%d", info.Range, part-1)
	}
	put := u.put("/ft/s3-flow", rangeHeader(part, len(data)), data[part:])
	if put.Code != http.StatusOK {
		t.Fatalf("resume = %d %s", put.Code, put.Body)
	}
	file := downloadTarget(t, fileOf(t, parseFileDocument(t, put.Body.Bytes())).Data.URL)

	whole := get(e, file)
	if whole.Code != http.StatusOK || sha256.Sum256(whole.Body.Bytes()) != sha256.Sum256([]byte(data)) {
		t.Fatalf("download = %d, %d bytes", whole.Code, whole.Body.Len())
	}
	from := part - 10
	partial := get(e, file, "Range", "bytes="+strconv.Itoa(from)+"-"+strconv.Itoa(from+19))
	if partial.Code != http.StatusPartialContent || partial.Body.String() != data[from:from+20] {
		t.Fatalf("range across the part boundary = %d %q", partial.Code, partial.Body)
	}
}
