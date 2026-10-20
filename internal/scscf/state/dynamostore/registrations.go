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

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// profilePrefix starts the key of a profile item in the registrations table.
// No IMPU starts with it: a canonical one starts with sip:, sips: or tel:.
const profilePrefix = "profile#"

// setPrefix starts the key of a set's registration item; no IMPU starts with
// it either.
const setPrefix = "set#"

// profileKey is profile#<IMPI>#<default IMPU>, and setPK set#<IMPI>#<default
// IMPU>. No two sets share one: the IMPI has a single '@' and after it a
// domain name, which has no '#', so the first '#' after the first '@' ends
// the IMPI.
func profileKey(k state.SetKey) map[string]types.AttributeValue {
	return key(profilePrefix + k.IMPI + "#" + k.IMPU)
}

func setPK(k state.SetKey) string { return setPrefix + k.IMPI + "#" + k.IMPU }

// possibleSet reports whether k could name a stored set or profile; one that
// could not is not looked up, it is simply not found.
func possibleSet(k state.SetKey) bool {
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
	pk := setPK(r.Key)
	item := map[string]types.AttributeValue{
		attrPK:      str(pk),
		attrVersion: num(version),
		attrDoc:     bin(doc),
		attrWriter:  str(d.token()),
		attrIMPI:    str(r.Key.IMPI),
		attrShard:   str(shardOf(pk)),
		// 0 without contacts, lease or unregistered state lists the
		// registration as expiring at once, so a sweep deletes one that an
		// instance left empty.
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
func (d *Dynamo) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	if !possibleSet(k) {
		return nil, fmt.Errorf("dynamostore: get registration: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.registrations, key(setPK(k)), "get registration")
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
	slices.SortFunc(out, func(a, b *state.Registration) int { return strings.Compare(a.Key.IMPU, b.Key.IMPU) })
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
	if err := d.putVersioned(ctx, d.registrations, setPK(r.Key), r.Version, item, "save registration"); err != nil {
		return nil, err
	}
	saved := r.Clone()
	saved.Version = version
	return saved, nil
}

// DeleteRegistration implements state.Registrations.
func (d *Dynamo) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	if !possibleSet(r.Key) {
		return fmt.Errorf("dynamostore: delete registration: %w", state.ErrNotFound)
	}
	return d.deleteVersioned(ctx, d.registrations, setPK(r.Key), r.Version, "delete registration")
}

// possibleIdentity reports whether impu could name an identity item: a
// canonical IMPU, never another kind of item's key.
func possibleIdentity(impu string) bool {
	canon, ok := identity.CanonicalIMPU(impu)
	return ok && canon == impu && state.KeyOK(impu, state.MaxKey)
}

// Identity implements state.Registrations. It checks KeepUntil itself, as
// Profile does.
func (d *Dynamo) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	if !possibleIdentity(impu) {
		return nil, fmt.Errorf("dynamostore: get identity: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.registrations, key(impu), "get identity")
	if err != nil {
		return nil, err
	}
	doc, err := docOf(item)
	if err != nil {
		return nil, err
	}
	version, err := nv(item, attrVersion)
	if err != nil {
		return nil, err
	}
	ttl, err := nv(item, attrTTL)
	if err != nil {
		return nil, err
	}
	i, err := decodeIdentity(doc, impu, version, time.Unix(ttl, 0).UTC())
	if err != nil {
		return nil, err
	}
	if !i.KeepUntil.After(now) {
		return nil, fmt.Errorf("dynamostore: get identity: %w", state.ErrNotFound)
	}
	return i, nil
}

// SaveIdentity implements state.Registrations. An identity item has no index
// attribute, so no listing or sweep sees it, and its ttl is the table's TTL
// attribute, as a profile's is.
func (d *Dynamo) SaveIdentity(ctx context.Context, i *state.Identity) (*state.Identity, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	version, err := d.nextVersion(i.Version)
	if err != nil {
		return nil, err
	}
	doc, err := encodeIdentity(i)
	if err != nil {
		return nil, err
	}
	item := map[string]types.AttributeValue{
		attrPK: str(i.IMPU), attrVersion: num(version), attrDoc: bin(doc), attrWriter: str(d.token()),
		attrTTL: num(i.KeepUntil.Unix()),
	}
	if err := d.putVersioned(ctx, d.registrations, i.IMPU, i.Version, item, "save identity"); err != nil {
		return nil, err
	}
	saved := *i
	saved.Version = version
	saved.KeepUntil = time.Unix(i.KeepUntil.Unix(), 0).UTC()
	return &saved, nil
}

// KeepIdentity implements state.Registrations, as KeepProfile.
func (d *Dynamo) KeepIdentity(ctx context.Context, impu string, until, now time.Time) error {
	if !possibleIdentity(impu) {
		return fmt.Errorf("dynamostore: keep identity: %w", state.ErrNotFound)
	}
	return d.keep(ctx, key(impu), until, now, "keep identity", func() (time.Time, error) {
		i, err := d.Identity(ctx, impu, now)
		if err != nil {
			return time.Time{}, err
		}
		return i.KeepUntil, nil
	})
}

// DeleteIdentity implements state.Registrations.
func (d *Dynamo) DeleteIdentity(ctx context.Context, i *state.Identity) error {
	if !possibleIdentity(i.IMPU) {
		return fmt.Errorf("dynamostore: delete identity: %w", state.ErrNotFound)
	}
	return d.deleteVersioned(ctx, d.registrations, i.IMPU, i.Version, "delete identity")
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

// Profile implements state.Profiles. It checks KeepUntil itself, because TTL
// deletion can lag by days.
func (d *Dynamo) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	if !possibleSet(k) {
		return nil, fmt.Errorf("dynamostore: get profile: %w", state.ErrNotFound)
	}
	item, err := d.get(ctx, d.registrations, profileKey(k), "get profile")
	if err != nil {
		return nil, err
	}
	p, err := decodeProfile(k, item)
	if err != nil {
		return nil, err
	}
	if !p.KeepUntil.After(now) {
		return nil, fmt.Errorf("dynamostore: get profile: %w", state.ErrNotFound)
	}
	return p, nil
}

func decodeProfile(k state.SetKey, item map[string]types.AttributeValue) (*state.Profile, error) {
	doc, err := docOf(item)
	if err != nil {
		return nil, err
	}
	rcv, err := nv(item, attrReceived)
	if err != nil {
		return nil, err
	}
	ttl, err := nv(item, attrTTL)
	if err != nil {
		return nil, err
	}
	return &state.Profile{Key: k, UserData: doc, Received: time.Unix(0, rcv).UTC(), KeepUntil: time.Unix(ttl, 0).UTC()}, nil
}

// SaveProfile implements state.Profiles with a PutItem conditional on no
// later profile of the set being stored and on ttl not having moved past the
// one it writes, which is the later of p's KeepUntil and the stored one: a
// save never brings KeepUntil closer, which a registration on another
// instance may have just extended. The stored item is read first; one that
// changes between the read and the put is read again. A resend carries the
// same values and passes.
func (d *Dynamo) SaveProfile(ctx context.Context, p *state.Profile) error {
	if err := state.ValidProfile(p); err != nil {
		return err
	}
	for range saveProfileAttempts {
		ttl := p.KeepUntil.Unix()
		cur, err := d.get(ctx, d.registrations, profileKey(p.Key), "save profile")
		switch {
		case errors.Is(err, state.ErrNotFound):
		case err != nil:
			return err
		default:
			stored, err := decodeProfile(p.Key, cur)
			if err != nil {
				return err
			}
			if stored.Received.After(p.Received) {
				// The newer profile stays, kept as long as either needs.
				if err := d.KeepProfile(ctx, p.Key, p.KeepUntil, p.Received); err != nil && !errors.Is(err, state.ErrNotFound) {
					return err
				}
				return fmt.Errorf("dynamostore: save profile: %w", state.ErrConflict)
			}
			ttl = max(ttl, stored.KeepUntil.Unix())
		}
		item := profileKey(p.Key)
		item[attrDoc] = bin(p.UserData)
		item[attrReceived] = num(p.Received.UnixNano())
		item[attrTTL] = num(ttl)
		_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:                 aws.String(d.registrations),
			Item:                      item,
			ConditionExpression:       aws.String("attribute_not_exists(#pk) OR (#rcv <= :rcv AND #ttl <= :ttl)"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#rcv": attrReceived, "#ttl": attrTTL},
			ExpressionAttributeValues: map[string]types.AttributeValue{":rcv": num(p.Received.UnixNano()), ":ttl": num(ttl)},
		})
		switch {
		case ccf(err):
			// A later profile, or a later ttl, was stored meanwhile.
			continue
		case err != nil:
			return sanitize("save profile", err)
		}
		return nil
	}
	return fmt.Errorf("dynamostore: save profile: %w", state.ErrContended)
}

// saveProfileAttempts bounds how often SaveProfile reads again a profile that
// changed under it.
const saveProfileAttempts = 3

// KeepProfile implements state.Profiles with keep.
func (d *Dynamo) KeepProfile(ctx context.Context, k state.SetKey, until, now time.Time) error {
	if !possibleSet(k) {
		return fmt.Errorf("dynamostore: keep profile: %w", state.ErrNotFound)
	}
	return d.keep(ctx, profileKey(k), until, now, "keep profile", func() (time.Time, error) {
		p, err := d.Profile(ctx, k, now)
		if err != nil {
			return time.Time{}, err
		}
		return p.KeepUntil, nil
	})
}

// keep moves an item's ttl to until with an UpdateItem of ttl alone,
// conditional on the item being there, alive at now, and ttl moving later. A
// resend, or an item already kept as long, fails the condition and is read
// back (current); one that a save replaced with an earlier ttl meanwhile gets
// a second attempt, and if that is overtaken too, the save stands.
func (d *Dynamo) keep(ctx context.Context, k map[string]types.AttributeValue, until, now time.Time, op string, current func() (time.Time, error)) error {
	for range 2 {
		_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 aws.String(d.registrations),
			Key:                       k,
			UpdateExpression:          aws.String("SET #ttl = :until"),
			ConditionExpression:       aws.String("attribute_exists(#pk) AND #ttl > :now AND #ttl < :until"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#ttl": attrTTL},
			ExpressionAttributeValues: map[string]types.AttributeValue{":until": num(until.Unix()), ":now": num(now.Unix())},
		})
		switch {
		case err == nil:
			return nil
		case !ccf(err):
			return sanitize(op, err)
		}
		kept, err := current()
		if err != nil {
			return err
		}
		if kept.Unix() >= until.Unix() {
			return nil
		}
	}
	return nil
}

// DeleteProfileIf implements state.Profiles with a DeleteItem conditional on
// received. A resend finds nothing and succeeds.
func (d *Dynamo) DeleteProfileIf(ctx context.Context, k state.SetKey, received time.Time) error {
	if !possibleSet(k) {
		return nil
	}
	_, err := d.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(d.registrations),
		Key:                       profileKey(k),
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #rcv = :rcv"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#rcv": attrReceived},
		ExpressionAttributeValues: map[string]types.AttributeValue{":rcv": num(received.UnixNano())},
	})
	switch {
	case ccf(err):
		return fmt.Errorf("dynamostore: delete profile: %w", state.ErrConflict)
	case err != nil:
		return sanitize("delete profile", err)
	}
	return nil
}

// DeleteProfile implements state.Profiles.
func (d *Dynamo) DeleteProfile(ctx context.Context, k state.SetKey) error {
	if !possibleSet(k) {
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
