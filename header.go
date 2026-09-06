package jwt

// Header is the JOSE header (RFC 7515 §4.1), modeling every registered
// parameter. jku/x5u/jwk/x5c are parsed and readable but are NEVER
// automatically dereferenced or trusted to select a verification key
// (spec §4.8, RFC 8725 §3.9-3.10).
type Header struct {
	Algorithm      Algorithm `json:"alg"`
	Type           string    `json:"typ,omitempty"`
	ContentType    string    `json:"cty,omitempty"`
	KeyID          string    `json:"kid,omitempty"`
	JWKSetURL      string    `json:"jku,omitempty"`
	JWK            *Key      `json:"jwk,omitempty"`
	X509URL        string    `json:"x5u,omitempty"`
	X509CertChain  []string  `json:"x5c,omitempty"`
	X509CertSHA1   string    `json:"x5t,omitempty"`
	X509CertSHA256 string    `json:"x5t#S256,omitempty"`
	Critical       []string  `json:"crit,omitempty"`
}
