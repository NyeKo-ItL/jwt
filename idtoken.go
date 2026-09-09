package jwt

// StandardClaims are the OpenID Connect Core 1.0 §5.1 standard claims,
// common across virtually every OIDC provider. Embed it (alongside
// RegisteredClaims and a provider claim set) in your own ID-token struct.
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
