package jwt

import (
	"encoding/json"
	"reflect"
	"strings"
)

// StandardClaims are the OpenID Connect Core 1.0 §5.1 standard claims,
// common across virtually every OIDC provider.
type StandardClaims struct {
	Name                string       `json:"name,omitempty"`
	GivenName           string       `json:"given_name,omitempty"`
	FamilyName          string       `json:"family_name,omitempty"`
	MiddleName          string       `json:"middle_name,omitempty"`
	Nickname            string       `json:"nickname,omitempty"`
	PreferredUsername   string       `json:"preferred_username,omitempty"`
	Profile             string       `json:"profile,omitempty"`
	Picture             string       `json:"picture,omitempty"`
	Website             string       `json:"website,omitempty"`
	Email               string       `json:"email,omitempty"`
	EmailVerified       *bool        `json:"email_verified,omitempty"`
	Gender              string       `json:"gender,omitempty"`
	Birthdate           string       `json:"birthdate,omitempty"`
	ZoneInfo            string       `json:"zoneinfo,omitempty"`
	Locale              string       `json:"locale,omitempty"`
	PhoneNumber         string       `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool        `json:"phone_number_verified,omitempty"`
	Address             *Address     `json:"address,omitempty"`
	UpdatedAt           *NumericDate `json:"updated_at,omitempty"`
	Nonce               string       `json:"nonce,omitempty"` // OIDC Core §2, replay protection
}

// Address is the OIDC Core 1.0 §5.1.1 address claim.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// GoogleClaims adds Google-specific ID token claims.
// https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
type GoogleClaims struct {
	HostedDomain    string `json:"hd,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
}

// OktaClaims adds Okta-specific ID token claims.
// https://developer.okta.com/docs/reference/api/oidc/#id-token
type OktaClaims struct {
	Version  string       `json:"ver,omitempty"`
	AuthTime *NumericDate `json:"auth_time,omitempty"`
	AMR      []string     `json:"amr,omitempty"`
	IDP      string       `json:"idp,omitempty"`
	Groups   []string     `json:"groups,omitempty"`
}

// EntraClaims adds Microsoft Entra ID (Azure AD) specific claims.
// https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
type EntraClaims struct {
	TenantID   string   `json:"tid,omitempty"`
	ObjectID   string   `json:"oid,omitempty"`
	UPN        string   `json:"upn,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	AppID      string   `json:"appid,omitempty"`
	Version    string   `json:"ver,omitempty"`
	UniqueName string   `json:"unique_name,omitempty"`
}

// IDToken composes RegisteredClaims + StandardClaims + a provider-specific
// extension via generics (Provider = GoogleClaims, OktaClaims, EntraClaims,
// or a caller-defined struct), plus a catch-all Extra map for anything not
// otherwise modeled. All four contribute to one flat JSON object.
type IDToken[Provider any] struct {
	RegisteredClaims
	StandardClaims
	Provider Provider
	Extra    map[string]any `json:"-"`
}

// MarshalJSON flattens every part into a single JSON object. Modeled claims
// take precedence over same-named Extra entries.
func (t IDToken[Provider]) MarshalJSON() ([]byte, error) {
	merged := map[string]json.RawMessage{}
	for k, v := range t.Extra {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		merged[k] = raw
	}
	for _, part := range []any{t.RegisteredClaims, t.StandardClaims, t.Provider} {
		raw, err := json.Marshal(part)
		if err != nil {
			return nil, err
		}
		if err := mergeObject(merged, raw); err != nil {
			return nil, err
		}
	}
	return json.Marshal(merged)
}

// UnmarshalJSON fills every modeled part and routes all remaining members
// into Extra.
func (t *IDToken[Provider]) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &t.RegisteredClaims); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &t.StandardClaims); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &t.Provider); err != nil {
		return err
	}
	rest := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &rest); err != nil {
		return err
	}
	for _, name := range jsonFieldNames(t.RegisteredClaims) {
		delete(rest, name)
	}
	for _, name := range jsonFieldNames(t.StandardClaims) {
		delete(rest, name)
	}
	for _, name := range jsonFieldNames(t.Provider) {
		delete(rest, name)
	}
	if len(rest) == 0 {
		return nil
	}
	t.Extra = make(map[string]any, len(rest))
	for k, raw := range rest {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		t.Extra[k] = v
	}
	return nil
}

// jsonFieldNames returns the JSON member names a struct value would read or
// write, recursing into anonymous (embedded) struct fields.
func jsonFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	if rt == nil {
		return nil
	}
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for f := range rt.Fields() {
		f := f
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		// encoding/json promotes the fields of an anonymous struct even when
		// the embedded type itself is unexported, so recurse before the
		// exported-field check.
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				out = append(out, jsonFieldNames(reflect.New(ft).Elem().Interface())...)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	return out
}
