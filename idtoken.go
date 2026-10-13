package jwt

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// IDTokenClaims is the provider-neutral OpenID Connect Core 1.0 ID Token
// Claims Set. Embed it in an application-specific ID-token type when the
// provider-specific ready-made types below are not appropriate.
//
// AccessTokenHash and CodeHash carry the OIDC half-hash values. This package
// validates their base64url representation but cannot recompute them without
// the access token or authorization code; the relying party remains
// responsible for that flow-specific comparison. Nonce is available through
// StandardClaims and likewise requires comparison with the authentication
// request by the relying party.
type IDTokenClaims struct {
	RegisteredClaims
	StandardClaims

	// AuthorizedParty is "azp": the client to which the ID Token was issued.
	AuthorizedParty string `json:"azp,omitempty"`
	// AccessTokenHash is "at_hash" (OIDC Core §3.1.3.6/§3.2.2.9).
	AccessTokenHash string `json:"at_hash,omitempty"`
	// CodeHash is "c_hash" (OIDC Core §3.3.2.11).
	CodeHash string `json:"c_hash,omitempty"`
	// AuthTime is "auth_time": time of end-user authentication.
	AuthTime *NumericDate `json:"auth_time,omitempty"`
	// ACR is "acr": authentication context class reference.
	ACR string `json:"acr,omitempty"`
	// AMR is "amr": authentication method references (RFC 8176 values).
	AMR []string `json:"amr,omitempty"`
}

// ValidateIDTokenClaims validates the provider-neutral OIDC Core §2 ID-token
// profile. iss, sub, aud, exp and iat are required. iss, sub, aud, and azp use
// RFC 7519 StringOrURI syntax without normalization. azp is required for a
// multi-audience token and, whenever present, must identify one audience.
// at_hash and c_hash, when present, must be canonical unpadded base64url; their
// flow-specific digest comparison remains the caller's responsibility.
func ValidateIDTokenClaims(claims IDTokenClaims) error {
	var missing []string
	if claims.Issuer == "" {
		missing = append(missing, "iss")
	}

	if claims.Subject == "" {
		missing = append(missing, "sub")
	}

	if len(claims.Audience) == 0 {
		missing = append(missing, "aud")
	}

	if claims.ExpiresAt == nil {
		missing = append(missing, "exp")
	}

	if claims.IssuedAt == nil {
		missing = append(missing, "iat")
	}

	if len(claims.Audience) > 1 && claims.AuthorizedParty == "" {
		missing = append(missing, "azp")
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingClaim, strings.Join(missing, ", "))
	}

	if err := ValidateStringOrURI(claims.Issuer); err != nil {
		return fmt.Errorf("iss: %w", err)
	}

	if err := ValidateStringOrURI(claims.Subject); err != nil {
		return fmt.Errorf("sub: %w", err)
	}

	for i, audience := range claims.Audience {
		if audience == "" {
			return fmt.Errorf("%w: aud[%d] is empty", ErrInvalidClaim, i)
		}

		if err := ValidateStringOrURI(audience); err != nil {
			return fmt.Errorf("aud[%d]: %w", i, err)
		}
	}

	if claims.AuthorizedParty != "" {
		if err := ValidateStringOrURI(claims.AuthorizedParty); err != nil {
			return fmt.Errorf("azp: %w", err)
		}

		if !claims.Audience.Has(claims.AuthorizedParty) {
			return fmt.Errorf("%w: azp %q is not in aud", ErrInvalidClaim, claims.AuthorizedParty)
		}
	}

	for name, value := range map[string]string{"at_hash": claims.AccessTokenHash, "c_hash": claims.CodeHash} {
		if value == "" {
			continue
		}

		decoded, err := b64.Decode(value)
		if err != nil || len(decoded) == 0 {
			return fmt.Errorf("%w: %s is not canonical base64url", ErrInvalidClaim, name)
		}
	}

	for i, method := range claims.AMR {
		if method == "" {
			return fmt.Errorf("%w: amr[%d] is empty", ErrInvalidClaim, i)
		}
	}

	return nil
}

// IDTokenValidationContext supplies the relying-party state needed for the
// flow-dependent checks in OIDC Core §3.1.3.7. ClientID is required. Additional
// trusted audiences, expected nonce, access token, and authorization code are
// optional and checked when configured or when the corresponding hash claim is
// present.
type IDTokenValidationContext struct {
	ClientID          string
	TrustedAudiences  []string
	ExpectedNonce     string
	RequireNonce      bool
	AccessToken       string
	AuthorizationCode string
	SigningAlgorithm  Algorithm
}

// ValidateIDTokenForContext applies ValidateIDTokenClaims and the OIDC checks
// that depend on relying-party state: client audience, additional trusted
// audiences, azp, nonce, at_hash, and c_hash. It performs exact comparisons and
// never normalizes identifiers.
func ValidateIDTokenForContext(claims IDTokenClaims, validation IDTokenValidationContext) error {
	if err := ValidateIDTokenClaims(claims); err != nil {
		return err
	}

	if validation.ClientID == "" {
		return fmt.Errorf("%w: client_id validation context is required", ErrInvalidClaim)
	}

	if !claims.Audience.Has(validation.ClientID) {
		return ErrAudienceMismatch
	}

	trusted := make(map[string]bool, len(validation.TrustedAudiences)+1)

	trusted[validation.ClientID] = true
	for _, audience := range validation.TrustedAudiences {
		trusted[audience] = true
	}

	for _, audience := range claims.Audience {
		if !trusted[audience] {
			return fmt.Errorf("%w: untrusted additional audience %q", ErrAudienceMismatch, audience)
		}
	}

	if claims.AuthorizedParty != "" && claims.AuthorizedParty != validation.ClientID {
		return fmt.Errorf("%w: azp %q does not match client_id %q", ErrInvalidClaim, claims.AuthorizedParty, validation.ClientID)
	}

	if len(claims.Audience) > 1 && claims.AuthorizedParty != validation.ClientID {
		return fmt.Errorf("%w: multi-audience ID Token requires azp equal to client_id", ErrInvalidClaim)
	}

	if validation.RequireNonce || validation.ExpectedNonce != "" {
		if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(validation.ExpectedNonce)) != 1 {
			return fmt.Errorf("%w: nonce mismatch", ErrInvalidClaim)
		}
	}

	if err := validateOIDCHash("at_hash", claims.AccessTokenHash, validation.AccessToken, validation.SigningAlgorithm); err != nil {
		return err
	}

	if err := validateOIDCHash("c_hash", claims.CodeHash, validation.AuthorizationCode, validation.SigningAlgorithm); err != nil {
		return err
	}

	return nil
}

func validateOIDCHash(name, claim, value string, alg Algorithm) error {
	if claim == "" {
		return nil
	}

	if value == "" {
		return fmt.Errorf("%w: %s is present but its source value was not provided", ErrInvalidClaim, name)
	}

	hash, ok := oidcHashAlgorithm(alg)
	if !ok || !hash.Available() {
		return fmt.Errorf("%w: cannot validate %s for signing algorithm %q", ErrUnsupportedAlgorithm, name, alg)
	}

	h := hash.New()
	_, _ = h.Write([]byte(value))
	digest := h.Sum(nil)

	want := b64.Encode(digest[:len(digest)/2])
	if subtle.ConstantTimeCompare([]byte(claim), []byte(want)) != 1 {
		return fmt.Errorf("%w: %s mismatch", ErrInvalidClaim, name)
	}

	return nil
}

func oidcHashAlgorithm(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case HS256, RS256, PS256, ES256:
		return crypto.SHA256, true
	case HS384, RS384, PS384, ES384:
		return crypto.SHA384, true
	case HS512, RS512, PS512, ES512, Ed25519, EdDSA:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

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
