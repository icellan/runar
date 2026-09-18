package runar

// Unpaired-surrogate detection on an envelope payload (R-115 / CL-BUG-066).
//
// VerifyEnvelope hashes the payload string RAW — it never routes it through
// CanonicalJSON — so the lone-surrogate rejection in appendJSONString (audit
// D6, fixture vector v22) never sees the envelope path. What each tier did
// instead was whatever its JSON parser happened to do, and the parsers
// disagree. Measured on one envelope whose payload holds `"x\ud800y"`:
//
//	ts / go / python / java   accepted it, fell through to bad-sig
//	rust / ruby / zig         rejected it at the parse step, bad-json
//
// Four tiers against three, returning a different VerifyEnvelopeReason for
// identical wire bytes — the exact thing the seven SDKs are required not to do.
//
// This tier has the sharpest version of the problem: `encoding/json.Unmarshal`
// SUCCEEDS on `\ud800` and silently rewrites it to U+FFFD, so appendJSONString's
// byte-pattern check can never fire on a string that arrived through it — a
// defence that is present, tested, and unreachable. The check therefore runs on
// the payload TEXT, before the parser gets to destroy the evidence.
//
// Two shapes count as unpaired:
//   - a \uD800–\uDBFF escape not immediately followed by a \uDC00–\uDFFF escape,
//     or a \uDC00–\uDFFF escape with no high surrogate before it;
//   - raw WTF-8 bytes (0xED, 0xA0..0xBF, 0x80..0xBF) encoding a surrogate.

// payloadHasLoneSurrogate reports whether s contains a surrogate code point —
// escaped or raw — that has no partner.
func payloadHasLoneSurrogate(s string) bool {
	// Raw WTF-8 first: the same 3-byte pattern appendJSONString looks for.
	for i := 0; i+2 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
			return true
		}
	}

	hexVal := func(b byte) int {
		switch {
		case b >= '0' && b <= '9':
			return int(b - '0')
		case b >= 'a' && b <= 'f':
			return int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			return int(b-'A') + 10
		}
		return -1
	}
	escapeAt := func(i int) (int, bool) {
		// s[i] is the backslash of a \uXXXX escape; return the code point.
		if i+5 >= len(s) || s[i+1] != 'u' {
			return 0, false
		}
		code := 0
		for k := 0; k < 4; k++ {
			v := hexVal(s[i+2+k])
			if v < 0 {
				return 0, false
			}
			code = code*16 + v
		}
		return code, true
	}

	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		// A run of backslashes of even length escapes itself; only an odd run
		// leaves a live escape at its end.
		run := 0
		for i+run < len(s) && s[i+run] == '\\' {
			run++
		}
		esc := i + run - 1
		i = esc
		if run%2 == 0 {
			continue
		}
		code, ok := escapeAt(esc)
		if !ok {
			continue
		}
		switch {
		case code >= 0xD800 && code <= 0xDBFF:
			low, lowOK := escapeAt(esc + 6)
			if !lowOK || low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i = esc + 11
		case code >= 0xDC00 && code <= 0xDFFF:
			return true
		default:
			i = esc + 5
		}
	}
	return false
}
