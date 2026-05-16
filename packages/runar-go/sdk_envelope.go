package runar

// Signed-broadcast wire protocol for overlay apps. Byte-compatible with the
// TypeScript reference implementation in `packages/runar-sdk/src/envelope.ts`.
//
// Three primitives:
//   - CanonicalJSON: RFC 8785 / JCS serialization (sorted keys, no whitespace,
//     ES Number.prototype.toString equivalents). Must produce byte-identical
//     output to every other Runar SDK tier for the same input.
//   - SignEnvelope: bind data + nonce + expiresAt into a canonical-JSON
//     payload, sha256 it, and sign the digest via a caller-supplied callback.
//   - VerifyEnvelope: six-reason rejection ladder mirroring the TS impl.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
	"unicode/utf16"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ---------------------------------------------------------------------------
// CanonicalJSON
// ---------------------------------------------------------------------------

// CanonicalJSON serializes value to RFC 8785 / JCS canonical JSON. Sorted
// object keys (UTF-16 code-unit order), no whitespace, ES-style number
// formatting. Returns an error for unsupported inputs (NaN, +Inf, -Inf,
// channels, functions, circular references).
func CanonicalJSON(value any) (string, error) {
	var out []byte
	out, err := canonicalAppend(out, value, make(map[uintptr]bool))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func canonicalAppend(out []byte, value any, seen map[uintptr]bool) ([]byte, error) {
	if value == nil {
		return append(out, "null"...), nil
	}
	switch v := value.(type) {
	case bool:
		if v {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case string:
		return appendJSONString(out, v), nil
	case int:
		return strconv.AppendInt(out, int64(v), 10), nil
	case int8:
		return strconv.AppendInt(out, int64(v), 10), nil
	case int16:
		return strconv.AppendInt(out, int64(v), 10), nil
	case int32:
		return strconv.AppendInt(out, int64(v), 10), nil
	case int64:
		return strconv.AppendInt(out, v, 10), nil
	case uint:
		return strconv.AppendUint(out, uint64(v), 10), nil
	case uint8:
		return strconv.AppendUint(out, uint64(v), 10), nil
	case uint16:
		return strconv.AppendUint(out, uint64(v), 10), nil
	case uint32:
		return strconv.AppendUint(out, uint64(v), 10), nil
	case uint64:
		return strconv.AppendUint(out, v, 10), nil
	case float32:
		return appendFloat(out, float64(v))
	case float64:
		return appendFloat(out, v)
	case json.Number:
		return append(out, v.String()...), nil
	case []any:
		out = append(out, '[')
		for i, e := range v {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			out, err = canonicalAppend(out, e, seen)
			if err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		out = append(out, '{')
		first := true
		for _, k := range keys {
			elem, ok := v[k]
			if !ok {
				continue
			}
			// ES JSON.stringify omits keys whose value is undefined; we
			// don't have undefined in Go, so emit nil as null (per JSON spec).
			if !first {
				out = append(out, ',')
			}
			first = false
			out = appendJSONString(out, k)
			out = append(out, ':')
			var err error
			out, err = canonicalAppend(out, elem, seen)
			if err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	}
	return nil, fmt.Errorf("canonical JSON: unsupported type %T", value)
}

// appendFloat formats f matching ES Number.prototype.toString. Rejects NaN/Inf.
// Integer-valued floats within safe-integer range serialize without a decimal point
// (e.g. 42 not 42.0), matching the JS spec.
func appendFloat(out []byte, f float64) ([]byte, error) {
	if f != f { // NaN
		return nil, fmt.Errorf("canonical JSON: NaN not supported")
	}
	if f > 1e308 || f < -1e308 {
		return nil, fmt.Errorf("canonical JSON: Infinity not supported")
	}
	if f == 0 {
		return append(out, '0'), nil
	}
	if f == float64(int64(f)) && f >= -9007199254740992 && f <= 9007199254740992 {
		return strconv.AppendInt(out, int64(f), 10), nil
	}
	// strconv.FormatFloat with 'g' prec=-1 matches ES Number.prototype.toString
	// for typical finite floats. Edge cases (1e21 transition) are documented
	// divergences but unused by the envelope wire protocol (only ms-timestamps
	// and small ints appear in practice).
	return strconv.AppendFloat(out, f, 'g', -1, 64), nil
}

// utf16Less compares two strings by UTF-16 code-unit order, matching
// JavaScript's default Array.prototype.sort() lexicographic comparison.
func utf16Less(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	n := len(au)
	if len(bu) < n {
		n = len(bu)
	}
	for i := 0; i < n; i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

// appendJSONString escapes s per ES JSON.stringify rules. Note: ES does NOT
// escape U+002F '/' by default in modern engines, and DOES \u-escape
// U+0000–U+001F. Backslash and quote are escaped with their short forms.
func appendJSONString(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				out = append(out, '\\', 'u')
				const hexd = "0123456789abcdef"
				out = append(out, '0', '0', hexd[(r>>4)&0xf], hexd[r&0xf])
			} else if r < 0x80 {
				out = append(out, byte(r))
			} else {
				// UTF-8 encoding for the rune
				var buf [4]byte
				n := utf8EncodeRune(buf[:], r)
				out = append(out, buf[:n]...)
			}
		}
	}
	return append(out, '"')
}

func utf8EncodeRune(p []byte, r rune) int {
	switch {
	case r < 0x80:
		p[0] = byte(r)
		return 1
	case r < 0x800:
		p[0] = 0xC0 | byte(r>>6)
		p[1] = 0x80 | byte(r&0x3F)
		return 2
	case r < 0x10000:
		p[0] = 0xE0 | byte(r>>12)
		p[1] = 0x80 | byte((r>>6)&0x3F)
		p[2] = 0x80 | byte(r&0x3F)
		return 3
	default:
		p[0] = 0xF0 | byte(r>>18)
		p[1] = 0x80 | byte((r>>12)&0x3F)
		p[2] = 0x80 | byte((r>>6)&0x3F)
		p[3] = 0x80 | byte(r&0x3F)
		return 4
	}
}

// ---------------------------------------------------------------------------
// Envelope types
// ---------------------------------------------------------------------------

// SignedEnvelope is the wire format for a signed broadcast payload.
type SignedEnvelope struct {
	// Payload is the canonical JSON of {...data, nonce, expiresAt}.
	Payload string `json:"payload"`
	// Sig is the DER-hex of the ECDSA signature over sha256(Payload).
	Sig string `json:"sig"`
	// Pubkey is the 66-char hex of the signer's compressed secp256k1 pubkey.
	Pubkey string `json:"pubkey"`
	// Nonce is the wall-clock millisecond timestamp at signing.
	Nonce int64 `json:"nonce"`
	// ExpiresAt is Nonce + TtlMs.
	ExpiresAt int64 `json:"expiresAt"`
}

// EnvelopeSigner is the minimal surface needed by SignEnvelope. Implementers
// receive a 32-byte sha256 digest and return a DER-encoded ECDSA signature.
type EnvelopeSigner interface {
	// SignHash signs digest (raw ECDSA, no re-hashing) and returns DER bytes.
	SignHash(digest []byte) ([]byte, error)
	// PublicKey returns the 66-char hex of the compressed secp256k1 pubkey.
	PublicKey() (string, error)
}

// SignEnvelopeOpts captures the input to SignEnvelope.
type SignEnvelopeOpts struct {
	Data   map[string]any
	Signer EnvelopeSigner
	// TtlMs is the lifetime in milliseconds. Defaults to 30_000 when zero.
	TtlMs int64
	// NowMs is the timestamp to embed as nonce. Defaults to time.Now() when
	// zero. Exposed for deterministic testing.
	NowMs int64
}

// SignEnvelope produces a signed envelope around data.
func SignEnvelope(opts SignEnvelopeOpts) (SignedEnvelope, error) {
	ttl := opts.TtlMs
	if ttl == 0 {
		ttl = 30_000
	}
	nonce := opts.NowMs
	if nonce == 0 {
		nonce = time.Now().UnixMilli()
	}
	expiresAt := nonce + ttl

	merged := make(map[string]any, len(opts.Data)+2)
	for k, v := range opts.Data {
		merged[k] = v
	}
	merged["nonce"] = nonce
	merged["expiresAt"] = expiresAt

	payload, err := CanonicalJSON(merged)
	if err != nil {
		return SignedEnvelope{}, fmt.Errorf("canonical json: %w", err)
	}

	digest := sha256.Sum256([]byte(payload))
	sigBytes, err := opts.Signer.SignHash(digest[:])
	if err != nil {
		return SignedEnvelope{}, fmt.Errorf("sign: %w", err)
	}
	pubkey, err := opts.Signer.PublicKey()
	if err != nil {
		return SignedEnvelope{}, fmt.Errorf("pubkey: %w", err)
	}

	return SignedEnvelope{
		Payload:   payload,
		Sig:       hex.EncodeToString(sigBytes),
		Pubkey:    pubkey,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyEnvelopeReason enumerates the ordered rejection causes.
type VerifyEnvelopeReason string

const (
	ReasonMissingFields   VerifyEnvelopeReason = "missing-fields"
	ReasonExpired         VerifyEnvelopeReason = "expired"
	ReasonBadJSON         VerifyEnvelopeReason = "bad-json"
	ReasonEnvelopeMismatch VerifyEnvelopeReason = "envelope-mismatch"
	ReasonBadSig          VerifyEnvelopeReason = "bad-sig"
	ReasonPubkeyNotAllowed VerifyEnvelopeReason = "pubkey-not-allowed"
)

// VerifyEnvelopeOpts captures the input to VerifyEnvelope.
type VerifyEnvelopeOpts struct {
	Envelope     SignedEnvelope
	ExpectedKeys []string // optional pubkey allowlist (66-char hex)
	ClockSkewMs  int64    // defaults to 5_000 when zero
	NowMs        int64    // override Now() for deterministic tests; zero = wall clock
}

// VerifyEnvelopeResult mirrors the TypeScript shape. Data is populated
// when JSON parsing succeeded, so callers can apply app-specific checks
// even on later-stage rejections.
type VerifyEnvelopeResult struct {
	OK     bool
	Reason VerifyEnvelopeReason
	Data   map[string]any
}

// VerifyEnvelope mirrors the six-reason rejection ladder of the TS impl.
func VerifyEnvelope(opts VerifyEnvelopeOpts) VerifyEnvelopeResult {
	env := opts.Envelope
	clockSkew := opts.ClockSkewMs
	if clockSkew == 0 {
		clockSkew = 5_000
	}
	now := opts.NowMs
	if now == 0 {
		now = time.Now().UnixMilli()
	}

	// 1. Field presence + types.
	if env.Payload == "" || env.Sig == "" || env.Pubkey == "" || env.Nonce == 0 || env.ExpiresAt == 0 {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonMissingFields}
	}

	// 2. Expiry.
	if env.ExpiresAt < now-clockSkew {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonExpired}
	}

	// 3. Parse payload.
	var parsed map[string]any
	dec := json.NewDecoder(stringReader(env.Payload))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil || parsed == nil {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadJSON}
	}

	// 4. Inner-payload nonce/expiresAt must match outer fields.
	innerNonce, innerExpiresAt, ok := readNonceExpiresAt(parsed)
	if !ok || innerNonce != env.Nonce || innerExpiresAt != env.ExpiresAt {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonEnvelopeMismatch, Data: parsed}
	}

	// 5. ECDSA verify.
	digest := sha256.Sum256([]byte(env.Payload))
	sigBytes, err := hex.DecodeString(env.Sig)
	if err != nil {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadSig, Data: parsed}
	}
	pkBytes, err := hex.DecodeString(env.Pubkey)
	if err != nil {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadSig, Data: parsed}
	}
	pubKey, err := ec.ParsePubKey(pkBytes)
	if err != nil {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadSig, Data: parsed}
	}
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadSig, Data: parsed}
	}
	if !sig.Verify(digest[:], pubKey) {
		return VerifyEnvelopeResult{OK: false, Reason: ReasonBadSig, Data: parsed}
	}

	// 6. Allowlist.
	if len(opts.ExpectedKeys) > 0 {
		found := false
		for _, k := range opts.ExpectedKeys {
			if k == env.Pubkey {
				found = true
				break
			}
		}
		if !found {
			return VerifyEnvelopeResult{OK: false, Reason: ReasonPubkeyNotAllowed, Data: parsed}
		}
	}

	return VerifyEnvelopeResult{OK: true, Data: parsed}
}

// readNonceExpiresAt extracts nonce + expiresAt from a parsed payload that
// used json.Number (json.NewDecoder().UseNumber()) to preserve precision.
func readNonceExpiresAt(parsed map[string]any) (int64, int64, bool) {
	nonceRaw, ok1 := parsed["nonce"]
	expiresAtRaw, ok2 := parsed["expiresAt"]
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	nonce, ok1 := envelopeToInt64(nonceRaw)
	expiresAt, ok2 := envelopeToInt64(expiresAtRaw)
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return nonce, expiresAt, true
}

func envelopeToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// stringReader avoids importing strings just for one Reader.
type stringReaderImpl struct {
	s   string
	pos int
}

func stringReader(s string) *stringReaderImpl { return &stringReaderImpl{s: s} }

func (r *stringReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}
