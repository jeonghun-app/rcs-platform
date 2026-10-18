package awsstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
)

// S3API is the part of the S3 client the stores use; *s3.Client has it.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// Blobs is a store.Blobs in an S3 bucket. Every object and multipart upload
// is created with the configured server-side encryption, so nothing is
// stored unencrypted even if the bucket's default changes.
type Blobs struct {
	api      S3API
	bucket   string
	prefix   string
	sse      string
	kmsKeyID string
}

var _ store.Blobs = (*Blobs)(nil)

func (b *Blobs) key(k string) *string { return aws.String(b.prefix + k) }

func (b *Blobs) kms() *string {
	if b.sse == string(types.ServerSideEncryptionAwsKms) && b.kmsKeyID != "" {
		return aws.String(b.kmsKeyID)
	}
	return nil
}

// Put implements store.Blobs.
func (b *Blobs) Put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := b.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(b.bucket),
		Key:                  b.key(key),
		Body:                 bytes.NewReader(body),
		ContentLength:        aws.Int64(int64(len(body))),
		ContentType:          aws.String(contentType),
		ServerSideEncryption: types.ServerSideEncryption(b.sse),
		SSEKMSKeyId:          b.kms(),
	})
	if err != nil {
		return sanitize("put object", err)
	}
	return nil
}

// CreateMultipart implements store.Blobs.
func (b *Blobs) CreateMultipart(ctx context.Context, key, contentType string) (string, error) {
	out, err := b.api.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:               aws.String(b.bucket),
		Key:                  b.key(key),
		ContentType:          aws.String(contentType),
		ServerSideEncryption: types.ServerSideEncryption(b.sse),
		SSEKMSKeyId:          b.kms(),
	})
	if err != nil {
		return "", sanitize("create multipart upload", err)
	}
	if out.UploadId == nil || *out.UploadId == "" {
		return "", fmt.Errorf("awsstore: create multipart upload: no upload id")
	}
	return *out.UploadId, nil
}

// UploadPart implements store.Blobs.
func (b *Blobs) UploadPart(ctx context.Context, key, uploadID string, number int32, body []byte) (string, error) {
	out, err := b.api.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(b.bucket),
		Key:           b.key(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(number),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	if err != nil {
		return "", s3Err("upload part", err)
	}
	if out.ETag == nil {
		return "", fmt.Errorf("awsstore: upload part: no ETag")
	}
	return *out.ETag, nil
}

// CompleteMultipart implements store.Blobs.
func (b *Blobs) CompleteMultipart(ctx context.Context, key, uploadID string, parts []store.Part) error {
	completed := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		completed[i] = types.CompletedPart{PartNumber: aws.Int32(p.Number), ETag: aws.String(p.ETag)}
	}
	_, err := b.api.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(b.bucket),
		Key:             b.key(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		return s3Err("complete multipart upload", err)
	}
	return nil
}

// AbortMultipart implements store.Blobs.
func (b *Blobs) AbortMultipart(ctx context.Context, key, uploadID string) error {
	_, err := b.api.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(b.bucket),
		Key:      b.key(key),
		UploadId: aws.String(uploadID),
	})
	if err != nil {
		return s3Err("abort multipart upload", err)
	}
	return nil
}

// Open implements store.Blobs with a ranged GetObject. An empty range needs
// no request; S3 could not express it anyway.
//
// Response checksum validation is left to requests that ask for it: a
// checksum of the whole object cannot validate a range, and S3-compatible
// servers that send one anyway would fail every partial read.
func (b *Blobs) Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	if length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	out, err := b.api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    b.key(key),
		Range:  aws.String("bytes=" + strconv.FormatInt(offset, 10) + "-" + strconv.FormatInt(offset+length-1, 10)),
	}, func(o *s3.Options) { o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired })
	if err != nil {
		return nil, s3Err("get object", err)
	}
	return out.Body, nil
}

// s3Err maps the codes S3 uses for a missing object or multipart upload to
// store.ErrNotFound, and those for parts that cannot complete an upload to
// store.ErrInvalidParts.
func s3Err(op string, err error) error {
	switch errorCode(err) {
	case "NoSuchKey", "NoSuchUpload", "NotFound":
		return fmt.Errorf("awsstore: %s: %w", op, store.ErrNotFound)
	case "InvalidPart", "InvalidPartOrder", "EntityTooSmall":
		return fmt.Errorf("awsstore: %s: %w", op, store.ErrInvalidParts)
	}
	return sanitize(op, err)
}
