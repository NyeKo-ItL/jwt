package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"regexp"
	"strings"
	"time"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/NyeKo-ItL/jwt/internal/b64"
)

// CMWClaimName is the "cmw" JWT claim registered by RFC 9999 §9.2: a RATS
// Conceptual Message Wrapper carried in a JWT Claims Set.
const CMWClaimName = "cmw"

// CMWContentType is the "cty" of a JWS whose payload is a JSON CMW
// (RFC 9999 §4.2, §9.5.2).
const CMWContentType = "application/cmw+json"

// cmwCollectionTypeKey is the reserved collection member "__cmwc_t"
// (RFC 9999 §3.3) that carries the collection type.
const cmwCollectionTypeKey = "__cmwc_t"

// maxCMWDepth bounds collection nesting so a hostile claim cannot exhaust
// the stack. RFC 9999 sets no limit; real collections nest two or three levels.
const maxCMWDepth = 16

// CMWIndicator is the "ind" bitmap of a CMW record (RFC 9999 §3.1): bit n is
// set when the record carries the RATS conceptual message with indicator
// value n in the IANA "RATS Conceptual Message Wrapper (CMW) Indicators"
// registry. Bits 5–31 are unassigned and are preserved, not rejected.
type CMWIndicator uint32

// The initial indicator bits (RFC 9999 §9.4).
const (
	CMWReferenceValues    CMWIndicator = 1 << 0
	CMWEndorsements       CMWIndicator = 1 << 1
	CMWEvidence           CMWIndicator = 1 << 2
	CMWAttestationResults CMWIndicator = 1 << 3
	CMWAppraisalPolicy    CMWIndicator = 1 << 4
)

const cmwMediaNamePartPattern = `[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}`

var (
	cmwMediaName  = regexp.MustCompile(`^` + cmwMediaNamePartPattern + `/` + cmwMediaNamePartPattern + `$`)
	cmwBase64URL  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	cmwOIDPattern = regexp.MustCompile(`^[0-2](\.0|\.[1-9][0-9]*)*$`)
)

// CMWRecord is a JSON-encoded record CMW (RFC 9999 §3.1):
// [type, value, ind?]. The wire form of Value is unpadded base64url.
type CMWRecord struct {
	// Type is the media type of the wrapped conceptual message.
	Type string
	// Value is the decoded conceptual message.
	Value []byte
	// Indicator is the optional "ind" bitmap; nil when absent.
	Indicator *CMWIndicator
}

// CMWCollection is a JSON-encoded collection CMW (RFC 9999 §3.3): an object
// of labelled CMWs with an optional "__cmwc_t" collection type.
type CMWCollection struct {
	// Type is "__cmwc_t": an absolute URI or an OID in dotted form; empty
	// when absent.
	Type string
	// Members are the labelled CMWs; at least one is required.
	Members map[string]CMW
}

// CMW is a JSON CMW: exactly one of Record and Collection is set.
type CMW struct {
	Record     *CMWRecord
	Collection *CMWCollection
}

// CMWClaims is a JWT Claims Set carrying the RFC 9999 "cmw" claim next to the
// RFC 7519 registered claims.
type CMWClaims struct {
	RegisteredClaims

	// CMW is "cmw" (RFC 9999 §4.3): a record or a collection.
	CMW *CMW `json:"cmw,omitempty"`
}

// ParseCMW decodes and validates a JSON CMW per the RFC 9999 §6 CDDL.
// Duplicate member names and malformed members are rejected; errors wrap
// ErrInvalidClaim.
func ParseCMW(data []byte) (CMW, error) {
	return parseCMW(data, 0)
}

// UnmarshalJSON implements json.Unmarshaler with the rules of ParseCMW.
func (c *CMW) UnmarshalJSON(data []byte) error {
	parsed, err := ParseCMW(data)
	if err != nil {
		return err
	}

	*c = parsed

	return nil
}

// MarshalJSON implements json.Marshaler. The CMW is validated first, so an
// invalid value never reaches a token.
func (c CMW) MarshalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c.marshal()
}

// Validate reports whether c is a well-formed CMW (RFC 9999 §6).
func (c CMW) Validate() error {
	return c.validate(0)
}

func (c CMW) validate(depth int) error {
	if depth > maxCMWDepth {
		return cmwErr("collections nested deeper than %d", maxCMWDepth)
	}

	switch {
	case c.Record != nil && c.Collection != nil:
		return cmwErr("both record and collection set")
	case c.Record != nil:
		return validateCMWMediaType(c.Record.Type)
	case c.Collection != nil:
		return c.Collection.validate(depth)
	default:
		return cmwErr("empty CMW")
	}
}

func (col *CMWCollection) validate(depth int) error {
	if col.Type != "" {
		if err := validateCMWCollectionType(col.Type); err != nil {
			return err
		}
	}

	if len(col.Members) == 0 {
		return cmwErr("collection has no members")
	}

	for label, member := range col.Members {
		if label == cmwCollectionTypeKey {
			return cmwErr("member label %q is reserved", cmwCollectionTypeKey)
		}

		if err := member.validate(depth + 1); err != nil {
			return fmt.Errorf("%q: %w", label, err)
		}
	}

	return nil
}

func (c CMW) marshal() ([]byte, error) {
	if c.Record != nil {
		fields := []any{c.Record.Type, base64.RawURLEncoding.EncodeToString(c.Record.Value)}
		if c.Record.Indicator != nil {
			fields = append(fields, uint32(*c.Record.Indicator))
		}

		return json.Marshal(fields)
	}

	members := make(map[string]any, len(c.Collection.Members)+1)
	if c.Collection.Type != "" {
		members[cmwCollectionTypeKey] = c.Collection.Type
	}

	for label, member := range c.Collection.Members {
		members[label] = member
	}

	return json.Marshal(members)
}

func parseCMW(data []byte, depth int) (CMW, error) {
	if depth > maxCMWDepth {
		return CMW{}, cmwErr("collections nested deeper than %d", maxCMWDepth)
	}

	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	if trimmed == "" {
		return CMW{}, cmwErr("empty value")
	}

	switch trimmed[0] {
	case '[':
		record, err := parseCMWRecord(data)
		if err != nil {
			return CMW{}, err
		}

		return CMW{Record: record}, nil
	case '{':
		collection, err := parseCMWCollection(data, depth)
		if err != nil {
			return CMW{}, err
		}

		return CMW{Collection: collection}, nil
	default:
		return CMW{}, cmwErr("must be a JSON array (record) or object (collection)")
	}
}

func parseCMWRecord(data []byte) (*CMWRecord, error) {
	var fields []jsontext.Value
	if err := jsonv2.Unmarshal(data, &fields); err != nil {
		return nil, cmwErr("record: %v", err)
	}

	if len(fields) < 2 || len(fields) > 3 {
		return nil, cmwErr("record has %d elements, want 2 or 3", len(fields))
	}

	var mediaType, encoded string
	if err := jsonv2.Unmarshal(fields[0], &mediaType); err != nil {
		return nil, cmwErr("record type must be a string")
	}

	if err := validateCMWMediaType(mediaType); err != nil {
		return nil, err
	}

	if err := jsonv2.Unmarshal(fields[1], &encoded); err != nil {
		return nil, cmwErr("record value must be a string")
	}

	if !cmwBase64URL.MatchString(encoded) {
		return nil, cmwErr("record value is not unpadded base64url")
	}

	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, cmwErr("record value: %v", err)
	}

	record := &CMWRecord{Type: mediaType, Value: value}

	if len(fields) == 3 {
		var bits uint32
		if err := jsonv2.Unmarshal(fields[2], &bits); err != nil {
			return nil, cmwErr("record indicator must be an unsigned 32-bit integer")
		}

		indicator := CMWIndicator(bits)
		record.Indicator = &indicator
	}

	return record, nil
}

func parseCMWCollection(data []byte, depth int) (*CMWCollection, error) {
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(data, &members); err != nil {
		return nil, cmwErr("collection: %v", err)
	}

	collection := &CMWCollection{Members: make(map[string]CMW, len(members))}

	for label, raw := range members {
		if label == cmwCollectionTypeKey {
			if err := jsonv2.Unmarshal(raw, &collection.Type); err != nil {
				return nil, cmwErr("%s must be a string", cmwCollectionTypeKey)
			}

			if err := validateCMWCollectionType(collection.Type); err != nil {
				return nil, err
			}

			continue
		}

		member, err := parseCMW(raw, depth+1)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", label, err)
		}

		collection.Members[label] = member
	}

	if len(collection.Members) == 0 {
		return nil, cmwErr("collection has no members")
	}

	return collection, nil
}

// validateCMWMediaType checks the RFC 9999 §6 media-type rule: a
// restricted-name "type/subtype" followed by optional ";" parameters.
func validateCMWMediaType(mediaType string) error {
	name, _, hasParams := strings.Cut(mediaType, ";")
	if !cmwMediaName.MatchString(strings.TrimRight(name, " ")) {
		return cmwErr("%q is not a media type", mediaType)
	}

	if hasParams {
		if _, _, err := mime.ParseMediaType(mediaType); err != nil {
			return cmwErr("%q is not a media type: %v", mediaType, err)
		}
	}

	return nil
}

// validateCMWCollectionType checks "__cmwc_t": an absolute URI or an OID.
func validateCMWCollectionType(value string) error {
	if cmwOIDPattern.MatchString(value) {
		return nil
	}

	if strings.Contains(value, ":") && ValidateStringOrURI(value) == nil {
		return nil
	}

	return cmwErr("%s %q is neither an absolute URI nor an OID", cmwCollectionTypeKey, value)
}

func cmwErr(format string, args ...any) error {
	return fmt.Errorf("%w: cmw: %s", ErrInvalidClaim, fmt.Sprintf(format, args...))
}

// SignCMW signs a JSON CMW as a compact JWS (RFC 9999 §4.2): the payload is
// the CMW itself, not a JWT Claims Set, and the protected header carries "alg"
// and "cty": "application/cmw+json". "typ" is omitted unless WithType sets it;
// "cty" cannot be overridden. The CMW is validated first.
func SignCMW(cmw CMW, signer Signer, opts ...SignOption) (string, error) {
	if err := cmw.Validate(); err != nil {
		return "", err
	}

	if isNilValue(signer) {
		return "", fmt.Errorf("%w: nil signer", ErrUnsupportedAlgorithm)
	}

	alg := signer.Algorithm()
	if alg == "" || strings.EqualFold(string(alg), "none") {
		return "", fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, alg)
	}

	cfg := signConfig{}

	for _, o := range opts {
		if isNilValue(o) {
			continue
		}

		o.applySign(&cfg)
	}

	headerJSON, err := json.Marshal(Header{
		Algorithm:   alg,
		Type:        cfg.typ,
		ContentType: CMWContentType,
		KeyID:       signer.KeyID(),
	})
	if err != nil {
		return "", err
	}

	payload, err := cmw.marshal()
	if err != nil {
		return "", err
	}

	signingInput := b64.Encode(headerJSON) + "." + b64.Encode(payload)

	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jwt: signer callback: %w", err)
	}

	return signingInput + "." + b64.Encode(sig), nil
}

// ParseSignedCMW verifies a compact JWS produced by SignCMW and returns the
// validated CMW. It applies the same defences as Parse (mandatory
// WithAllowedAlgorithms, key lookup by "kid" only, no "none"), requires
// "cty": "application/cmw+json" (RFC 9999 §4.2), and skips the JWT claims
// checks (exp, iss, aud), which do not apply to a CMW; ParseOptions about
// claims are ignored. A JWT is rejected: its payload is not a CMW.
func ParseSignedCMW(ctx context.Context, token string, keys KeyProvider, opts ...ParseOption) (CMW, error) {
	cfg := parseConfig{now: time.Now}

	for _, o := range opts {
		if isNilValue(o) {
			continue
		}

		o.applyParse(&cfg)
	}

	var header Header

	cfg.rawPayload = true
	cfg.headerOut = &header

	payload, err := parseVerified(ctx, token, keys, cfg)
	if err != nil {
		return CMW{}, err
	}

	if !typeMatches(header.ContentType, CMWContentType) || !strings.Contains(header.ContentType, "/") {
		return CMW{}, fmt.Errorf("%w: cty %q, want %q", ErrTypeMismatch, header.ContentType, CMWContentType)
	}

	return ParseCMW(payload)
}
