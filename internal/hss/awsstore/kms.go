package awsstore

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
)

// KMSAPI is the part of the KMS client the wrapper uses; *kms.Client has
// it.
type KMSAPI interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// encryptionContext binds every wrapped key to its use: KMS refuses to
// unwrap it for a request that does not present the same context, and the
// context appears in CloudTrail, so a key policy can allow the HSS role
// exactly this (kms:EncryptionContext:purpose).
var encryptionContext = map[string]string{"service": "hss", "purpose": "subscriber-secrets"}

// KMS is a keyring.Wrapper over an AWS KMS symmetric key. It needs
// kms:GenerateDataKey and kms:Decrypt on the key.
type KMS struct {
	api   KMSAPI
	keyID string
}

var _ keyring.Wrapper = (*KMS)(nil)

// NewKMS returns a wrapper using keyID (key ID, ARN or alias).
func NewKMS(api KMSAPI, keyID string) *KMS { return &KMS{api: api, keyID: keyID} }

// GenerateDataKey implements keyring.Wrapper.
func (k *KMS) GenerateDataKey(ctx context.Context) (plaintext, wrapped []byte, err error) {
	out, err := k.api.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(k.keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return nil, nil, sanitize("kms generate data key", err)
	}
	if len(out.Plaintext) != keyring.DataKeySize || len(out.CiphertextBlob) == 0 {
		return nil, nil, errors.New("awsstore: kms returned an unusable data key")
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

// Unwrap implements keyring.Wrapper. KeyId is given although a symmetric
// ciphertext names its key, so that a wrapped key planted by someone who can
// write the table but under a key they control is refused.
func (k *KMS) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	out, err := k.api.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    wrapped,
		KeyId:             aws.String(k.keyID),
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return nil, sanitize("kms decrypt", err)
	}
	return out.Plaintext, nil
}
