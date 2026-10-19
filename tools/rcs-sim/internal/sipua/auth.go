package sipua

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// The environment variables the credentials come from (#135). They are read
// nowhere else, and their values reach no result line, log or error.
const (
	EnvAKAK        = "RCS_SIM_AKA_K"
	EnvAKAOPc      = "RCS_SIM_AKA_OPC"
	EnvSIPPassword = "RCS_SIM_SIP_PASSWORD"
)

// Authentication errors.
var (
	// ErrNoUsableChallenge means a 401 or 407 offered no challenge these
	// credentials can answer: AKAv1-MD5 for AKA keys, MD5 or SHA-256 for a
	// password.
	ErrNoUsableChallenge = errors.New("sipua: no challenge these credentials can answer")
	// ErrNetworkNotAuthenticated means AUTN did not verify with the card's
	// keys (TS 33.102 §6.3.3): the challenge was not made with them. The UA
	// stops there rather than registering again; for a simulator it means
	// the test was set up with keys the HSS does not hold.
	ErrNetworkNotAuthenticated = errors.New("sipua: AUTN did not verify: the challenge is not from the home network")
)

// Credentials authenticate a registration: a Digest password, or the K and
// OPc of an AKA card. Only made-up keys or the published test sets of TS
// 35.208 belong here, never a real SIM's. Every fmt, slog and JSON form is a
// placeholder, and the values sit behind a pointer, so a Credentials inside
// another value prints as an address at most. The zero value means none:
// the UA then answers no challenge.
type Credentials struct {
	p *credentials
}

type credentials struct {
	// impi is the private user identity, the Digest username (TS 24.229
	// §5.1.1.2.1).
	impi     string
	password []byte
	card     *card
}

// card is the part of a USIM that AKA needs: the keys and the highest SQN
// it has accepted (TS 33.102 §6.3.3, Annex C).
type card struct {
	m       milenage.Milenage
	mu      sync.Mutex
	highest milenage.SQN
}

// DigestCredentials returns credentials that answer MD5 and SHA-256
// challenges with password. The bytes are copied.
func DigestCredentials(impi string, password []byte) (Credentials, error) {
	if impi == "" || len(password) == 0 {
		return Credentials{}, errors.New("sipua: Digest credentials need an IMPI and a password")
	}
	return Credentials{&credentials{impi: impi, password: append([]byte(nil), password...)}}, nil
}

// AKACredentials returns credentials that answer AKAv1-MD5 challenges as a
// card with keys k and opc that has accepted no SQN yet.
func AKACredentials(impi string, k, opc [milenage.KeySize]byte) (Credentials, error) {
	if impi == "" {
		return Credentials{}, errors.New("sipua: AKA credentials need an IMPI")
	}
	return Credentials{&credentials{impi: impi, card: &card{m: milenage.New(k, opc)}}}, nil
}

// DigestCredentialsFromEnv is DigestCredentials with the password from
// RCS_SIM_SIP_PASSWORD. getenv is os.Getenv outside tests.
func DigestCredentialsFromEnv(impi string, getenv func(string) string) (Credentials, error) {
	p := getenv(EnvSIPPassword)
	if p == "" {
		return Credentials{}, errors.New("sipua: " + EnvSIPPassword + " is not set")
	}
	return DigestCredentials(impi, []byte(p))
}

// AKACredentialsFromEnv is AKACredentials with K and OPc from RCS_SIM_AKA_K
// and RCS_SIM_AKA_OPC, 32 hex digits each. getenv is os.Getenv outside tests.
func AKACredentialsFromEnv(impi string, getenv func(string) string) (Credentials, error) {
	k, err := hexKey(getenv, EnvAKAK)
	if err != nil {
		return Credentials{}, err
	}
	opc, err := hexKey(getenv, EnvAKAOPc)
	if err != nil {
		return Credentials{}, err
	}
	return AKACredentials(impi, k, opc)
}

// hexKey reads a 128-bit key. The error names the variable, never its value.
func hexKey(getenv func(string) string, name string) ([milenage.KeySize]byte, error) {
	var key [milenage.KeySize]byte
	v := getenv(name)
	if v == "" {
		return key, errors.New("sipua: " + name + " is not set")
	}
	if len(v) != 2*milenage.KeySize {
		return key, fmt.Errorf("sipua: %s is not %d hex digits", name, 2*milenage.KeySize)
	}
	if _, err := hex.Decode(key[:], []byte(v)); err != nil {
		return key, fmt.Errorf("sipua: %s is not %d hex digits", name, 2*milenage.KeySize)
	}
	return key, nil
}

func (c Credentials) set() bool { return c.p != nil }

const redactedCredentials = "sipua.Credentials{redacted}"

// String returns a fixed placeholder.
func (c Credentials) String() string { return redactedCredentials }

// GoString returns the same placeholder as String.
func (c Credentials) GoString() string { return redactedCredentials }

// Format makes every fmt verb produce the placeholder.
func (c Credentials) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedCredentials) }

// LogValue keeps log/slog handlers from serialising the fields.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(redactedCredentials) }

// MarshalJSON emits the placeholder.
func (c Credentials) MarshalJSON() ([]byte, error) { return json.Marshal(redactedCredentials) }

// initialAuthorization is the Authorization of an unchallenged REGISTER:
// the IMPI and the home domain with an empty nonce and response, from
// which the S-CSCF learns which private identity registers (TS 24.229
// §5.1.1.2.1).
func (ua *UA) initialAuthorization(uri string) string {
	return digest.Credentials{Username: ua.cfg.Credentials.p.impi, Realm: ua.cfg.Domain, URI: uri}.Header()
}

// authorize answers the first usable challenge of a 401 or 407 to a
// REGISTER for uri. It returns the header field to send, its value, and
// whether the answer is a resynchronisation (AUTS) rather than RES, after
// which the network challenges again.
func (ua *UA) authorize(res *sip.Response, uri string) (field, value string, resync bool, err error) {
	asked, field := "WWW-Authenticate", "Authorization"
	if res.StatusCode == 407 {
		asked, field = "Proxy-Authenticate", "Proxy-Authorization"
	}
	c := ua.cfg.Credentials.p
	ch, ok := firstUsable(res.Header.Values(asked), c.card != nil)
	if !ok {
		return "", "", false, ErrNoUsableChallenge
	}
	cnonce, err := digest.NewCNonce(ua.cfg.Rand)
	if err != nil {
		return "", "", false, err
	}
	p := digest.ClientParams{Username: c.impi, Method: "REGISTER", URI: uri, CNonce: cnonce, NC: 1}
	if c.card == nil {
		p.Password = c.password
	} else if p.Password, p.AUTS, err = c.card.answer(ch.Nonce); err != nil {
		return "", "", false, err
	}
	creds, err := digest.Respond(ch, p)
	if err != nil {
		// Respond's errors name parameters, not values.
		return "", "", false, fmt.Errorf("sipua: answering the challenge: %w", err)
	}
	return field, creds.Header(), len(p.AUTS) > 0, nil
}

// firstUsable returns the first challenge, in the server's order of
// preference (RFC 8760 §2.4), that the credentials can answer.
func firstUsable(values []string, aka bool) (digest.Challenge, bool) {
	for _, v := range values {
		ch, err := digest.ParseChallenge(v)
		if err != nil {
			continue
		}
		switch ch.Algorithm {
		case digest.AKAv1MD5:
			if aka {
				return ch, true
			}
		case digest.MD5, digest.SHA256:
			if !aka {
				return ch, true
			}
		}
	}
	return digest.Challenge{}, false
}

// answer does what the card does with an AKA nonce (TS 33.102 §6.3.3): it
// verifies AUTN, and then answers RES for a fresh SQN, which it now holds
// as its highest, or AUTS carrying its highest for a SQN it will not
// accept, so that the network resynchronises.
func (c *card) answer(nonce string) (res, auts []byte, err error) {
	rand, autn, err := digest.ParseAKANonce(nonce)
	if err != nil {
		return nil, nil, errors.New("sipua: the AKA nonce does not hold RAND and AUTN")
	}
	sqn, err := c.m.CheckAUTN(rand, autn)
	if err != nil {
		return nil, nil, ErrNetworkNotAuthenticated
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !milenage.Fresh(sqn, c.highest) {
		a := c.m.AUTS(rand, c.highest)
		return nil, a[:], nil
	}
	c.highest = sqn
	// RES depends on RAND alone (f2); SQN and AMF only shape AUTN.
	amf := [milenage.AMFSize]byte(autn[milenage.SQNSize : milenage.SQNSize+milenage.AMFSize])
	xres := c.m.Vector(rand, sqn, amf).XRES()
	return xres[:], nil, nil
}
