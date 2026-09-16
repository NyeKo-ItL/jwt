package jwt

// Header is the JOSE header (RFC 7515 §4.1), modeling every registered
// parameter. jku/x5u/jwk/x5c are parsed and readable but are NEVER
// automatically dereferenced or trusted to select a verification key
// (spec §4.8, RFC 8725 §3.9-3.10).
type Header struct {
	// Algorithm is "alg" (RFC 7515 §4.1.1): checked against the mandatory
	// allowlist before anything else.
	Algorithm Algorithm `json:"alg"`
	// Type is "typ" (§4.1.9), compared by WithRequiredType (RFC 8725 §3.11).
	Type string `json:"typ,omitempty"`
	// ContentType is "cty" (§4.1.10); "JWT" marks a nested JWT, which is not
	// unwrapped automatically.
	ContentType string `json:"cty,omitempty"`
	// KeyID is "kid" (§4.1.4), passed to KeyProvider.Lookup.
	KeyID string `json:"kid,omitempty"`
	// JWKSetURL is "jku" (§4.1.2). Never fetched (RFC 8725 §3.10).
	JWKSetURL string `json:"jku,omitempty"`
	// JWK is "jwk" (§4.1.3). Never trusted to verify the token.
	JWK *Key `json:"jwk,omitempty"`
	// X509URL is "x5u" (§4.1.5). Never fetched.
	X509URL string `json:"x5u,omitempty"`
	// X509CertChain is "x5c" (§4.1.6), base64 (not base64url) DER
	// certificates. Not validated or trusted.
	X509CertChain []string `json:"x5c,omitempty"`
	// X509CertSHA1 is "x5t" (§4.1.7). Informational only.
	X509CertSHA1 string `json:"x5t,omitempty"`
	// X509CertSHA256 is "x5t#S256" (§4.1.8). Informational only.
	X509CertSHA256 string `json:"x5t#S256,omitempty"`
	// Critical is "crit" (§4.1.11). No extension is implemented, so Parse
	// rejects any token carrying it (ErrUnsupportedCritical).
	Critical []string `json:"crit,omitempty"`
}
