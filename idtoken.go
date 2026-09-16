package jwt

import (
	"bytes"
	"fmt"
)

// StandardClaims are the OpenID Connect Core 1.0 §5.1 standard claims,
// common across virtually every OIDC provider. Embed it (alongside
// RegisteredClaims and a provider claim set) in your own ID-token struct.
//
// None of these claims is validated by Parse. In particular, "sub" (not
// "email" or "preferred_username") is the stable identifier (OIDC Core §5.7),
// and "nonce" must be compared with the value sent in the authentication
// request by the relying party (OIDC Core §3.1.3.7 step 11).
type StandardClaims struct {
	Name              string `json:"name,omitempty"`               // full name
	GivenName         string `json:"given_name,omitempty"`         // first name(s)
	FamilyName        string `json:"family_name,omitempty"`        // surname(s)
	MiddleName        string `json:"middle_name,omitempty"`        // middle name(s)
	Nickname          string `json:"nickname,omitempty"`           // casual name
	PreferredUsername string `json:"preferred_username,omitempty"` // mutable; not an identifier (§5.7)
	Profile           string `json:"profile,omitempty"`            // profile page URL
	Picture           string `json:"picture,omitempty"`            // profile picture URL
	Website           string `json:"website,omitempty"`            // web page or blog URL
	Email             string `json:"email,omitempty"`              // mutable; not an identifier (§5.7)
	// EmailVerified is "email_verified"; string forms are accepted (see Bool).
	EmailVerified *Bool  `json:"email_verified,omitempty"`
	Gender        string `json:"gender,omitempty"`       // "female", "male" or other values
	Birthdate     string `json:"birthdate,omitempty"`    // ISO 8601 YYYY-MM-DD, or YYYY / 0000-MM-DD
	ZoneInfo      string `json:"zoneinfo,omitempty"`     // IANA time zone, e.g. "Europe/Paris"
	Locale        string `json:"locale,omitempty"`       // BCP 47 language tag, e.g. "fr-FR"
	PhoneNumber   string `json:"phone_number,omitempty"` // E.164 recommended, e.g. "+1 (425) 555-1212"
	// PhoneNumberVerified is "phone_number_verified"; string forms are
	// accepted (see Bool).
	PhoneNumberVerified *Bool        `json:"phone_number_verified,omitempty"`
	Address             *Address     `json:"address,omitempty"`    // §5.1.1 structured address
	UpdatedAt           *NumericDate `json:"updated_at,omitempty"` // last profile update
	Nonce               string       `json:"nonce,omitempty"`      // OIDC Core §2, replay protection
}

// Bool is an OIDC boolean claim such as "email_verified". OpenID Connect
// Core 1.0 §5.1 defines these as JSON booleans, but some providers emit the
// strings "true" / "false" instead (Google's documented example, Amazon
// Cognito). Bool accepts exactly those four forms and always marshals as a
// JSON boolean. Its underlying type is bool, so it can be used directly in
// conditions: if claims.EmailVerified != nil && *claims.EmailVerified { ... }.
type Bool bool

// UnmarshalJSON accepts true, false, "true" or "false".
func (b *Bool) UnmarshalJSON(data []byte) error {
	switch string(bytes.TrimSpace(data)) {
	case `true`, `"true"`:
		*b = true
	case `false`, `"false"`:
		*b = false
	default:
		return fmt.Errorf("jwt: %s is not an OIDC boolean", data)
	}

	return nil
}

// Address is the OIDC Core 1.0 §5.1.1 address claim.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`      // full mailing address, may contain newlines
	StreetAddress string `json:"street_address,omitempty"` // street, house number, apartment, ...
	Locality      string `json:"locality,omitempty"`       // city
	Region        string `json:"region,omitempty"`         // state, province, prefecture or region
	PostalCode    string `json:"postal_code,omitempty"`    // zip or postal code
	Country       string `json:"country,omitempty"`        // country name
}

// GoogleClaims adds Google-specific ID token claims.
// https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
type GoogleClaims struct {
	HostedDomain    string `json:"hd,omitempty"`      // Google Workspace domain of the user
	AuthorizedParty string `json:"azp,omitempty"`     // OIDC Core §2: client the token was issued to
	AccessTokenHash string `json:"at_hash,omitempty"` // OIDC Core §3.2.2.9; not verified by Parse
}

// OktaClaims adds Okta-specific ID token claims.
// https://developer.okta.com/docs/reference/api/oidc/#id-token
type OktaClaims struct {
	Version  int          `json:"ver,omitempty"`       // a JSON number (e.g. 1) in Okta ID tokens
	AuthTime *NumericDate `json:"auth_time,omitempty"` // OIDC Core §2: time of the end-user authentication
	AMR      []string     `json:"amr,omitempty"`       // authentication methods, RFC 8176 values
	IDP      string       `json:"idp,omitempty"`       // Okta org or external IdP that authenticated the user
	Groups   []string     `json:"groups,omitempty"`    // present when a groups claim is configured
}

// EntraClaims adds Microsoft Entra ID (Azure AD) specific claims.
// https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
type EntraClaims struct {
	TenantID   string   `json:"tid,omitempty"`         // tenant GUID; restrict accepted tenants with it
	ObjectID   string   `json:"oid,omitempty"`         // immutable user object GUID within the tenant
	UPN        string   `json:"upn,omitempty"`         // user principal name; mutable, not an identifier
	Roles      []string `json:"roles,omitempty"`       // app roles assigned to the user
	Groups     []string `json:"groups,omitempty"`      // group object IDs, when the groups claim is configured
	AppID      string   `json:"appid,omitempty"`       // v1.0 tokens: application ID of the client
	Version    string   `json:"ver,omitempty"`         // "1.0" or "2.0"
	UniqueName string   `json:"unique_name,omitempty"` // v1.0 tokens: display-only name

	IdentityProvider string `json:"idp,omitempty"` // authenticating IdP when it differs from iss (e.g. guests)
	SessionID        string `json:"sid,omitempty"` // session GUID
	TokenID          string `json:"uti,omitempty"` // Entra's per-token identifier, equivalent to jti
}

// GoogleIDToken is a ready-made ID-token claims struct for Google:
// registered + OIDC standard + Google claims, all flattened into one JSON
// object by struct embedding. Pass it straight to Parse:
//
//	var claims jwt.GoogleIDToken
//	err := jwt.Parse(ctx, raw, &claims, keys, opts...)
//	claims.Subject       // registered
//	claims.Email         // standard
//	claims.HostedDomain  // Google
//
// For a provider this library does not model, declare the same shape with
// your own claim set in place of GoogleClaims.
type GoogleIDToken struct {
	RegisteredClaims
	StandardClaims
	GoogleClaims
}

// OktaIDToken is the Okta equivalent of GoogleIDToken.
type OktaIDToken struct {
	RegisteredClaims
	StandardClaims
	OktaClaims
}

// EntraIDToken is the Microsoft Entra ID equivalent of GoogleIDToken.
type EntraIDToken struct {
	RegisteredClaims
	StandardClaims
	EntraClaims
}
