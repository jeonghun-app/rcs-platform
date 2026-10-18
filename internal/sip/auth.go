package sip

import "strings"

// Challenge is the value of a WWW-Authenticate or Proxy-Authenticate header field
// (RFC 3261 §20.44, §20.27).
type Challenge struct {
	Scheme string
	// Params are the auth-params in order, values without quotes. Names are
	// matched case-insensitively.
	Params Params
}

// Credentials is the value of an Authorization or Proxy-Authorization header field
// (RFC 3261 §20.7, §20.28).
type Credentials struct {
	Scheme string
	// Params are the auth-params in order, values without quotes. Names are
	// matched case-insensitively.
	Params Params
}

// Which digest parameters are quoted-strings and which are tokens differs between
// a challenge and the credentials answering it: qop is a quoted list in one and a
// bare token in the other (RFC 3261 §25.1; RFC 7616 §3.3, §3.4; RFC 3310 for auts). A parameter in neither list is quoted only when it is not a token.
var (
	challengeQuoted = map[string]bool{
		"realm": true, "domain": true, "nonce": true, "opaque": true, "qop": true,
	}
	credentialsQuoted = map[string]bool{
		"username": true, "realm": true, "nonce": true, "uri": true, "response": true,
		"cnonce": true, "opaque": true, "auts": true,
	}
)

// Param returns the value of an auth-param and whether it is present.
func (c Challenge) Param(name string) (string, bool) { return c.Params.Get(name) }

// SetParam sets an auth-param, quoting it as a challenge requires.
func (c *Challenge) SetParam(name, value string) {
	c.Params.put(Param{Name: name, Value: value, Quoted: authQuoted(challengeQuoted, name, value)})
}

// String writes the challenge.
func (c Challenge) String() string { return authString(c.Scheme, c.Params) }

// Param returns the value of an auth-param and whether it is present.
func (c Credentials) Param(name string) (string, bool) { return c.Params.Get(name) }

// SetParam sets an auth-param, quoting it as credentials require.
func (c *Credentials) SetParam(name, value string) {
	c.Params.put(Param{Name: name, Value: value, Quoted: authQuoted(credentialsQuoted, name, value)})
}

// String writes the credentials.
func (c Credentials) String() string { return authString(c.Scheme, c.Params) }

func authQuoted(quoted map[string]bool, name, value string) bool {
	return quoted[strings.ToLower(name)] || !isAll(value, classToken)
}

func authString(scheme string, ps Params) string {
	b := append(make([]byte, 0, 128), scheme...)
	for i, p := range ps {
		if i == 0 {
			b = append(b, ' ')
		} else {
			b = append(b, ", "...)
		}
		b = append(b, p.Name...)
		b = append(b, '=')
		if p.Quoted || !isAll(p.Value, classToken) {
			b = appendQuoted(b, p.Value)
		} else {
			b = append(b, p.Value...)
		}
	}
	return string(b)
}

// parseAuth parses `scheme LWS auth-param *(COMMA auth-param)`, the shared shape of
// challenges and credentials (RFC 3261 §25.1). Each field line holds one
// challenge or one set of credentials: §7.3.1 excludes these fields from comma
// combination. A repeated parameter is refused, since a verifier and a proxy
// picking different realms or responses is how authentication gets bypassed.
func parseAuth(s string) (string, Params, error) {
	i := skipWS(s, 0)
	j := scanClass(s, i, classToken)
	if j == i || j == len(s) || !isWS(s[j]) {
		return "", nil, syntaxError("invalid authentication scheme")
	}
	scheme := s[i:j]
	i = skipWS(s, j)
	var ps Params
	for {
		k := scanClass(s, i, classToken)
		if k == i {
			return "", nil, syntaxError("invalid auth-param name")
		}
		p := Param{Name: s[i:k]}
		k = skipWS(s, k)
		if k >= len(s) || s[k] != '=' {
			return "", nil, syntaxError("auth-param without value")
		}
		k = skipWS(s, k+1)
		if k < len(s) && s[k] == '"' {
			v, next, ok := parseQuoted(s, k)
			if !ok {
				return "", nil, syntaxError("invalid quoted auth-param value")
			}
			p.Value, p.Quoted, k = v, true, next
		} else {
			e := scanClass(s, k, classToken)
			if e == k {
				return "", nil, syntaxError("invalid auth-param value")
			}
			p.Value, k = s[k:e], e
		}
		if ps.Has(p.Name) {
			return "", nil, syntaxError("repeated auth-param")
		}
		if len(ps) == maxParams {
			return "", nil, errTooManyParams
		}
		ps = append(ps, p)
		i = skipWS(s, k)
		if i == len(s) {
			return scheme, ps, nil
		}
		if s[i] != ',' {
			return "", nil, syntaxError("auth-params must be separated by commas")
		}
		i = skipWS(s, i+1)
	}
}
