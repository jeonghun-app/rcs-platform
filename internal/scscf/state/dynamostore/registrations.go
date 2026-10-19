package dynamostore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

func (d *Dynamo) registrationItem(r *state.Registration, version int64) (map[string]types.AttributeValue, error) {
	doc, err := encodeRegistration(r)
	if err != nil {
		return nil, err
	}
	var expires int64
	if next := r.NextExpiry(); !next.IsZero() {
		expires = next.Unix()
	}
	return map[string]types.AttributeValue{
		attrPK:      str(r.IMPU),
		attrVersion: num(version),
		attrDoc:     bin(doc),
		attrWriter:  str(d.token()),
		attrIMPI:    str(r.IMPI),
		attrShard:   str(shardOf(r.IMPU)),
		// 0 without contacts lists the registration as expiring at once, so a
		// sweep deletes one that an instance left empty.
		attrExpires: num(expires),
	}, nil
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
	item, err := d.get(ctx, d.registrations, key(impu), "get registration")
	if err != nil {
		return nil, err
	}
	return decodeRegistrationItem(item)
}

// RegistrationsOf implements state.Registrations.
func (d *Dynamo) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
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
	item, err := d.registrationItem(r, r.Version+1)
	if err != nil {
		return nil, err
	}
	if err := d.putVersioned(ctx, d.registrations, r.IMPU, r.Version, item, "save registration"); err != nil {
		return nil, err
	}
	saved := r.Clone()
	saved.Version = r.Version + 1
	return saved, nil
}

// DeleteRegistration implements state.Registrations.
func (d *Dynamo) DeleteRegistration(ctx context.Context, r *state.Registration) error {
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
		// The index holds whole seconds; the contacts decide.
		if len(r.Contacts) > 0 && r.NextExpiry().After(now) {
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
