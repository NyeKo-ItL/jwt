package jwt

import (
	"fmt"
	"strings"
)

// AccessTokenClaims models the RFC 9068 JWT profile for OAuth 2.0 access
// tokens. The RFC 7519 registered claims are embedded and flattened into the
// same JSON object by encoding/json's normal anonymous-field promotion.
type AccessTokenClaims struct {
	RegisteredClaims
	ClientID     string       `json:"client_id"`
	Scope        string       `json:"scope,omitempty"`
	AuthTime     *NumericDate `json:"auth_time,omitempty"`
	ACR          string       `json:"acr,omitempty"`
	AMR          []string     `json:"amr,omitempty"`
	Groups       []string     `json:"groups,omitempty"`
	Roles        []string     `json:"roles,omitempty"`
	Entitlements []string     `json:"entitlements,omitempty"`
}

// AccessTokenType is the mandatory "typ" header value per RFC 9068 §2.1,
// intended for use with WithRequiredType.
const AccessTokenType = "at+jwt"

// ValidateAccessTokenClaims checks the RFC 9068 §2.2 required-claims profile
// beyond what Parse already validates: iss, exp, aud, sub, client_id and iat
// MUST be present. (jti only SHOULD be present, so it is not enforced.)
func ValidateAccessTokenClaims(claims AccessTokenClaims) error {
	var missing []string
	if claims.Issuer == "" {
		missing = append(missing, "iss")
	}
	if claims.ExpiresAt == nil {
		missing = append(missing, "exp")
	}
	if len(claims.Audience) == 0 {
		missing = append(missing, "aud")
	}
	if claims.Subject == "" {
		missing = append(missing, "sub")
	}
	if claims.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if claims.IssuedAt == nil {
		missing = append(missing, "iat")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingClaim, strings.Join(missing, ", "))
	}
	return nil
}
