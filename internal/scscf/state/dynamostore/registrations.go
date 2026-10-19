package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// profilePrefix starts the key of a profile item in the registrations table.
// No IMPU starts with it: a canonical one starts with sip:, sips: or tel:.
const profilePrefix = "profile#"

// profileKey is profile#<IMPI>#<default IMPU>. No two profiles share one: the
// IMPI has a single '@' and after it a domain name, which has no '#', so the
// first '#' after the first '@' ends the IMPI.
func profileKey(k state.ProfileKey) map[string]types.AttributeValue {
	return key(profilePrefix + k.IMPI + "#" + k.IMPU)
}

// possibleProfile reports whether k could name a stored profile; one that
// could not is not looked up, it is simply not found.
func possibleProfile(k state.ProfileKey) bool {
	return state.KeyOK(k.IMPI, state.MaxKey) && state.KeyOK(k.IMPU, state.MaxKey)
}

func (d *Dynamo) registrationItem(r *state.Registration, version int64) (map[string]types.AttributeValue, error) {
	doc, err := encodeRegistration(r)
	if err != nil {
		return nil, err
	}
	var sweepAt int64
	if t := r.SweepAt(); !t.IsZero() {
		sweepAt = t.Unix()
	}
	item := map[string]types.AttributeValue{
		attrPK:      str(r.IMPU),
		attrVersion: num(version),
		attrDoc:     bin(doc),
		attrWriter:  str(d.token()),
		attrIMPI:    str(r.IMPI),
		attrShard:   str(shardOf(r.IMPU)),
		// 0 without contacts and lease lists the registration as expiring at
		// once, so a sweep deletes one that an instance left empty.
		attrExpires: num(sweepAt),
	}
	return item, checkSize(item, "registration")
}

func decodeRegistrationItem(item map[string]types.AttributeValue) (*state.Registration, error) {
	doc, err := docOf(item)
	if err != nil {
		return nil, err
	}
	version, err := nv(item, attrVersion)
	if err != nil {
		return nil, err
	}
	return decodeRegistration(doc, version)
}

// Registration implements state.Registrations.
func (d *Dynamo) Registration(ctx context.Context, impu string) (*state.Registration, error) {
	if !state.KeyOK(impu, state.MaxKey) {
		return nil, fmt.Errorf("dynamostore: get registration: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.registrations, key(impu), "get registration")
	if err != nil {
		return nil, err
	}
	return decodeRegistrationItem(item)
}

// RegistrationsOf implements state.Registrations.
func (d *Dynamo) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	if !state.KeyOK(impi, state.MaxKey) {
		return nil, nil
	}
	items, err := d.byIndex(ctx, d.registrations, IMPIIndex, attrIMPI, impi, "query registrations of an IMPI")
	if err != nil {
		return nil, err
	}
	out, err := decodeAll(items, decodeRegistrationItem)
	slices.SortFunc(out, func(a, b *state.Registration) int { return strings.Compare(a.IMPU, b.IMPU) })
	return out, err
}

// SaveRegistration implements state.Registrations.
func (d *Dynamo) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	version, err := d.nextVersion(r.Version)
	if err != nil {
		return nil, err
	}
	item, err := d.registrationItem(r, version)
	if err != nil {
		return nil, err
	}
	if err := d.putVersioned(ctx, d.registrations, r.IMPU, r.Version, item, "save registration"); err != nil {
		return nil, err
	}
	saved := r.Clone()
	saved.Version = version
	return saved, nil
}

// DeleteRegistration implements state.Registrations.
func (d *Dynamo) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	if !state.KeyOK(r.IMPU, state.MaxKey) {
		return fmt.Errorf("dynamostore: delete registration: %w", state.ErrNotFound)
	}
	return d.deleteVersioned(ctx, d.registrations, r.IMPU, r.Version, "delete registration")
}

// ExpiringRegistrations implements state.Registrations.
func (d *Dynamo) ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*state.Registration, error) {
	var out []*state.Registration
	var decodeErr error
	_, err := d.expiring(ctx, d.registrations, now, limit, func(item map[string]types.AttributeValue) bool {
		r, err := decodeRegistrationItem(item)
		if err != nil {
			decodeErr = errors.Join(decodeErr, err)
			return false
		}
		// The index holds whole seconds; the registration decides.
		if r.SweepAt().After(now) {
			return false
		}
		out = append(out, r)
		return true
	}, "query expiring registrations")
	if err != nil {
		return nil, err
	}
	return out, decodeErr
}

// Profile implements state.Profiles.
func (d *Dynamo) Profile(ctx context.Context, k state.ProfileKey) ([]byte, error) {
	if !possibleProfile(k) {
		return nil, fmt.Errorf("dynamostore: get profile: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.registrations, profileKey(k), "get profile")
	if err != nil {
		return nil, err
	}
	return docOf(item)
}

// SaveProfile implements state.Profiles with a PutItem conditional on no
// later profile of the set being stored. A resend carries the same time and
// passes.
func (d *Dynamo) SaveProfile(ctx context.Context, k state.ProfileKey, userData []byte, received time.Time) error {
	if err := state.ValidProfile(k, userData, received); err != nil {
		return err
	}
	item := profileKey(k)
	item[attrDoc] = bin(userData)
	item[attrReceived] = num(received.UnixNano())
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(d.registrations),
		Item:                      item,
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #rcv <= :rcv"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#rcv": attrReceived},
		ExpressionAttributeValues: map[string]types.AttributeValue{":rcv": num(received.UnixNano())},
	})
	switch {
	case ccf(err):
		return fmt.Errorf("dynamostore: save profile: %w", state.ErrConflict)
	case err != nil:
		return sanitize("save profile", err)
	}
	return nil
}

// DeleteProfile implements state.Profiles.
func (d *Dynamo) DeleteProfile(ctx context.Context, k state.ProfileKey) error {
	if !possibleProfile(k) {
		return nil
	}
	if _, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(d.registrations), Key: profileKey(k)}); err != nil {
		return sanitize("delete profile", err)
	}
	return nil
}

// decodeAll decodes every item, keeping those that decode and reporting the
// others together, so one corrupt item does not hide the rest.
func decodeAll[T any](items []map[string]types.AttributeValue, decode func(map[string]types.AttributeValue) (T, error)) ([]T, error) {
	var out []T
	var errs error
	for _, item := range items {
		v, err := decode(item)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		out = append(out, v)
	}
	return out, errs
}
