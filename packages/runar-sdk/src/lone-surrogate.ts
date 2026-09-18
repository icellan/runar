/**
 * Unpaired-surrogate detection on an envelope payload (R-115 / CL-BUG-066).
 *
 * `verifyEnvelope` hashes the payload string RAW — it never routes it through
 * `canonicalJson` — so canonicalJson's lone-surrogate rejection (audit D6,
 * fixture vector v22) never sees the envelope path. What each tier did instead
 * was whatever its JSON parser happened to do, and the parsers disagree.
 * Measured on one envelope whose payload holds `"x\ud800y"`:
 *
 *   ts / go / python / java   accepted it, fell through to `bad-sig`
 *   rust / ruby / zig         rejected it at the parse step, `bad-json`
 *
 * Four tiers against three, returning a different `VerifyEnvelopeReason` for
 * identical wire bytes — the exact thing the seven SDKs are required not to do.
 *
 * The check runs on the payload TEXT rather than on the parsed value, because
 * that is the only form every tier still has: Go's `encoding/json` silently
 * rewrites `\ud800` to U+FFFD while parsing, destroying the evidence before any
 * post-parse check could look for it.
 *
 * Two shapes count as unpaired:
 *   - a `\uD800`–`\uDBFF` escape not immediately followed by a `\uDC00`–`\uDFFF`
 *     escape, or a `\uDC00`–`\uDFFF` escape with no high surrogate before it;
 *   - a raw unpaired surrogate code unit in the text itself (a JS string can
 *     hold one; WTF-8 bytes decode to one).
 */

/** True when `text` contains a surrogate code unit — escaped or raw — that has no partner. */
export function hasLoneSurrogate(text: string): boolean {
  // Raw code units first: cheap, and covers payloads that arrived as WTF-8.
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }

  // Then `\uXXXX` escapes. A backslash run of odd length means the `u` that
  // follows is really an escape; an even run means the backslashes escaped
  // each other and the `u` is a literal.
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '\\') continue;
    let backslashes = 0;
    while (i + backslashes < text.length && text[i + backslashes] === '\\') backslashes++;
    const esc = i + backslashes - 1;
    i = esc;
    if (backslashes % 2 === 0) continue;
    if (text[esc + 1] !== 'u') continue;
    const hex = text.slice(esc + 2, esc + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) continue;
    const code = parseInt(hex, 16);
    if (code >= 0xd800 && code <= 0xdbff) {
      // Must be followed immediately by a low-surrogate escape.
      if (text[esc + 6] !== '\\' || text[esc + 7] !== 'u') return true;
      const lowHex = text.slice(esc + 8, esc + 12);
      if (!/^[0-9a-fA-F]{4}$/.test(lowHex)) return true;
      const low = parseInt(lowHex, 16);
      if (low < 0xdc00 || low > 0xdfff) return true;
      i = esc + 11;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    } else {
      i = esc + 5;
    }
  }
  return false;
}
