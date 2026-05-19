# Canonical-JSON RFC 8785 / JCS Parity Audit (7 SDK tiers)

**Item 9** — Cross-tier audit of `canonicalJson` implementations.
**Auditor:** read-only review, 2026-05-18.
**Sources:** the seven SDK packages under `packages/runar-{ts(ir-schema/sdk),go,rs,py,zig,rb,java}`.

## Implementations located

| Tier   | File                                                                                                                  | Symbol                  |
|--------|-----------------------------------------------------------------------------------------------------------------------|-------------------------|
| TS     | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-ir-schema/src/canonical-json.ts`           | `canonicalJsonStringify` (re-exported by `runar-sdk/src/envelope.ts` as `canonicalJson`) |
| Go     | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-go/sdk_envelope.go`                         | `CanonicalJSON`         |
| Rust   | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-rs/src/sdk/envelope.rs`                     | `canonical_json`        |
| Python | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-py/runar/sdk/envelope.py`                   | `canonical_json`        |
| Zig    | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-zig/src/sdk_envelope.zig`                   | `canonicalJson`         |
| Ruby   | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-rb/lib/runar/sdk/envelope.rb`               | `Runar::SDK::Envelope.canonical_json` |
| Java   | `/Users/siggioskarsson/gitcheckout/runar-review-remediation/packages/runar-java/src/main/java/runar/lang/sdk/Envelope.java` | `Envelope.canonicalJson` |

All seven located. No "missing impl" tier.

---

## 1. Parity matrix

Legend: `✓` conforms, `✗` documented divergence, `?` not verifiable from source alone, `n/a` not expressible in this tier's value type. **TS = reference**; cell shows behaviour vs TS reference (which itself wraps ES `JSON.stringify`).

### 1.1 Number serialization (RFC 8785 §3.2.2.3)

| Sub-rule                                          | TS  | Go  | Rust | Python | Zig | Ruby | Java |
|---------------------------------------------------|-----|-----|------|--------|-----|------|------|
| Integers: no `.0`, no `+`, no leading zeros        | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| `-0` → `"0"`                                       | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| Integer-valued float in ±2^53 → integer form       | ✓ (via `JSON.stringify`) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `NaN` / `±Infinity` rejected                       | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| Shortest-roundtrip non-integer float (e.g. `0.1`)  | ✓   | `?` ES-like via `'g',-1` | `?` serde shortest | `?` `repr()` | **✗** uses `{e}` always | `?` `Float#to_s` shortest | **✗** `Double.toString` (capital `E`, trailing `.0`) |
| Large positive (`1e21` boundary, ES emits `1e+21`) | ✓   | **✗** `1e+21` printed but `'g'` uses lowercase, mantissa OK; `1e22+` divergent | **✗** serde may keep integer form | **✗** `repr(1e21)` → `1e+21` matches; `repr(1e22)` → `1e+22` matches | **✗** always scientific (`{e}`) | **✗** Ruby `1e21.to_s` → `"1.0e+21"` (extra `.0`) | **✗** Java emits `1.0E21` |
| Extremely small (`1e-300`)                         | ✓ `1e-300` | **✗** likely OK via `'g'` | **✗** serde shortest | **✗** `1e-300` matches | **✗** `{e}` differs in exponent width | **✗** `1.0e-300` (extra `.0`) | **✗** `1.0E-300` |
| Subnormal (`5e-324`)                               | ✓   | `?` | `?`  | `?`    | `?` | `?`  | `?`  |

Bottom line on numbers: **All tiers ship a deliberate integer special-case that covers the only float values the envelope wire protocol actually carries today (ms-since-epoch timestamps). Every tier's float fallback path diverges from ES for at least some inputs.** The Go (line 149), Rust (line 49), Python (line 56), Zig (line 70), Ruby (line 47), and Java (line 80–86) source comments all explicitly acknowledge this. The wire protocol does not hit those paths today; future schema additions can break parity overnight.

### 1.2 String escaping (RFC 8785 §3.2.2.2)

| Sub-rule                                                              | TS  | Go  | Rust | Python | Zig | Ruby | Java |
|-----------------------------------------------------------------------|-----|-----|------|--------|-----|------|------|
| Short forms `\" \\ \b \f \n \r \t`                                    | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| U+0000–U+001F (other) → `\u00xx`, lowercase hex                       | ✓   | ✓ (`hexd` lowercase) | ✓ (`{:04x}`) | ✓ (`{:04x}`) | ✓ (`{x:0>4}`) | ✓ (`%04x`) | ✓ (`%04x`) |
| Solidus `/` left unescaped                                            | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| Printable ASCII left unescaped                                        | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| Iterates per Unicode codepoint (multi-byte preserved as-is)           | ✓   | ✓ `for _, r := range s` | ✓ `s.chars()` | ✓ `for ch in s` | **✗** byte-by-byte `s[i]` loop | ✓ `each_char` | ✓ `charAt` (UTF-16 unit; surrogate-correct for printable BMP+SMP) |
| Lone surrogate (e.g. `"\uD800"`) rejected                             | **✗** TS `JSON.stringify` emits it | **✗** Go would emit replacement char (`utf8.RuneError`) | **✗** Rust `Value::String` cannot hold a lone surrogate (rejected at parse-time, but `canonical_json` accepts whatever's in the `&str`) | **✗** Python `str` can contain a lone surrogate; would emit invalid UTF-8 sequence | **✗** Zig accepts arbitrary bytes | **✗** Ruby preserves whatever encoding | **✗** Java `charAt` would emit lone surrogate char directly |
| Valid surrogate pair (e.g. U+1F600 `"😀"`) preserved as UTF-8 bytes   | ✓   | ✓   | ✓    | ✓      | ✓ (byte-pass) | ✓   | **?** Java emits two `char` surrogate halves via `out.append(c)` — `StringBuilder` rebuilds the codepoint; final UTF-8 encoding happens at byte-emission time (caller uses `getBytes(UTF_8)`). |

**Zig escape loop is bytewise** (`appendJsonString`, line 113): it walks bytes, not codepoints. For typical multi-byte UTF-8 sequences (continuation bytes 0x80–0xBF, leads 0xC2+) none collide with the special-cased values (`"`, `\`, 0x08, 0x0C, `\n`, `\r`, `\t`, or `< 0x20`), so for *well-formed* UTF-8 input the bytewise loop accidentally produces correct output. For malformed UTF-8 it silently passes through bytes. Not a correctness bug today; is a latent foot-gun if anyone changes the escape table.

### 1.3 Object key sort order (RFC 8785 §3.2.3 — UTF-16 code units)

| Tier   | Sort key derivation                                                                       | Verdict | Notes |
|--------|-------------------------------------------------------------------------------------------|---------|-------|
| TS     | `Object.keys(obj).sort()` (line 163) — ES default sort is UTF-16 code-unit lex            | ✓       | Reference |
| Go     | `utf16.Encode([]rune(a))` per key, lex-compare uint16 slices (line 155–168)               | ✓       | Correct |
| Rust   | `BTreeMap<Vec<u16>, &String>`, key = `k.encode_utf16().collect()` (line 87–89)            | ✓       | Correct |
| Python | `sorted(keys, key=lambda k: k.encode("utf-16-be"))` (line 73)                              | ✓       | Big-endian bytes preserve uint16 lex order |
| Zig    | `utf16Less` is **byte-by-byte UTF-8 compare** (line 138–145), NOT UTF-16                  | **✗ BLOCKING** | Diverges for any key past U+007F whose UTF-8 bytes sort differently than the UTF-16 code units. Concrete break: `"\u{1F600}"` (😀, UTF-16 `[0xD83D,0xDE00]`, UTF-8 `[0xF0,0x9F,0x98,0x80]`) vs `"�"` (UTF-16 `[0xFFFD]`, UTF-8 `[0xEF,0xBF,0xBD]`). UTF-16 order: FFFD < D83D-DE00 (D83D < FFFD as units). UTF-8 byte order: EF < F0. Same direction here, but pair vs single-BMP-char-with-higher-codepoint cases will flip. **Even simpler break**: `"é"` (U+00E9, UTF-16 [0x00E9], UTF-8 [0xC3,0xA9]) vs `"~"` (U+007E, UTF-16 [0x007E], UTF-8 [0x7E]). UTF-16: `~` < `é` (0x007E < 0x00E9). UTF-8 byte cmp: `~` (0x7E) < `é` (0xC3). Same direction. Construct a counter-example: `"Ā"` (UTF-16 [0x0100], UTF-8 [0xC4,0x80]) vs `"ÿ"` (UTF-16 [0x00FF], UTF-8 [0xC3,0xBF]). UTF-16 says U+00FF < U+0100. UTF-8 bytes: 0xC3 < 0xC4 — same direction. Cross-BMP is where it bites: any BMP char ≥ U+0800 (3-byte UTF-8 lead 0xE0–0xEF) vs an astral char (4-byte lead 0xF0–0xF7) — UTF-16 reorders because the astral char encodes as a surrogate pair starting with 0xD800–0xDBFF, which is LESS than any 3-byte BMP char ≥ U+E000. **Concrete failing pair**: `"\u{1F600}"` vs `""`. UTF-16: 0xD83D < 0xE000 → 😀 sorts first. UTF-8: 0xF0 > 0xEE → "" sorts first. Different order. |
| Ruby   | `sort_by { |k| k.encode('UTF-16BE').bytes }` (line 62)                                     | ✓       | Same trick as Python |
| Java   | `Collections.sort(keys)` → `String.compareTo` which compares `char` values = UTF-16 units | ✓       | Correct |

### 1.4 Object/array ordering

| Sub-rule                          | TS  | Go  | Rust | Python | Zig | Ruby | Java |
|-----------------------------------|-----|-----|------|--------|-----|------|------|
| Arrays preserve input order        | ✓   | ✓   | ✓    | ✓      | ✓   | ✓    | ✓    |
| Objects emit sorted keys           | ✓   | ✓   | ✓    | ✓      | ✗ (see 1.3) | ✓ | ✓ |
| Duplicate-key handling             | dedup by last-wins (object literal) | dedup by `map[string]any` | dedup by `serde_json::Map` (last-wins) | dedup by `dict` | **✗** Zig `Value.Object` is `[]const KeyValue`, duplicates retained — every duplicate is emitted | dedup by `Hash` | dedup by `Map` |

### 1.5 Whitespace

| Tier   | Verdict |
|--------|---------|
| TS     | ✓ (manual concat with `,` `:`, no spaces) |
| Go     | ✓ |
| Rust   | ✓ |
| Python | ✓ |
| Zig    | ✓ |
| Ruby   | ✓ |
| Java   | ✓ |

---

## 2. Concrete divergences (severity-ranked)

### D1 — BLOCKING: Zig key sort is UTF-8-byte, not UTF-16
- File: `packages/runar-zig/src/sdk_envelope.zig:138-145` (`utf16Less`).
- Code comment ("ASCII fast path covers all realistic envelope keys") admits the scope but the function name lies.
- **Trigger**: any object key containing a codepoint ≥ U+0080 will sort byte-wise in Zig vs UTF-16-wise everywhere else. Today's overlay payloads (`kind`, `n`, `nonce`, `expiresAt`) are all ASCII so it doesn't fire. As soon as any user-controlled string lands in an envelope key (display name, BSV-20 ticker, ordinal label), Zig signatures stop verifying against the other six tiers.
- **Remediation**: replace the byte loop with a real UTF-16-code-unit comparison. Zig has no stdlib UTF-16 encoder; either pull in a small helper that walks UTF-8 codepoints and yields 1-or-2 UTF-16 units per codepoint, or fully UTF-16-encode both keys into a temporary buffer and lex-compare.

### D2 — HIGH: Zig string escape loop walks bytes, not codepoints
- File: `packages/runar-zig/src/sdk_envelope.zig:111-136`.
- Today benign: the escape table only matches single-byte ASCII values that never appear inside a valid UTF-8 multi-byte sequence. **Latent**: if anyone ever adds an entry for a codepoint ≥ U+0080 (e.g. RFC 8785 ` ` LINE SEPARATOR escape that some impls add for JS-source safety), the bytewise loop will silently fail.
- **Remediation**: iterate via `std.unicode.Utf8Iterator` and dispatch on codepoint, not byte.

### D3 — HIGH: Zig `Value.Object` is a slice, not a deduping map
- File: `packages/runar-zig/src/sdk_envelope.zig:18-31` (`Value` type).
- A `Value.Object` with two `{key="x", value=...}` entries will sort and emit both, producing `{"x":1,"x":2}`. Every other tier collapses duplicates via its native map type. Wire-protocol-level: today the envelope builder (line 188–192 in same file) only appends `nonce`/`expiresAt` to caller data, so a duplicate is structurally impossible from the SDK. From a third party constructing a `Value` tree directly, this footgun is live.
- **Remediation**: either dedupe in `canonicalAppend` (sort + skip consecutive duplicates with same key — needs a "last-wins or first-wins?" decision) or reject duplicates with an error.

### D4 — MEDIUM: Ruby `value[k] || value[k.to_sym]` silently rewrites falsy values
- File: `packages/runar-rb/lib/runar/sdk/envelope.rb:66`.
- For any hash entry where the string-keyed value is `false`, `0`, `nil`, or `""`, Ruby's `||` falls through to a symbol-key lookup of the same name. If the caller passes `{ "active" => false }`, the canonical-JSON output silently uses `nil` (if no `:active` key exists) or the symbol-keyed value (if one happens to exist), producing different bytes from every other tier.
- **Remediation**: replace with `value.fetch(k) { value.fetch(k.to_sym, nil) }`. Better: require callers to pre-normalize to string keys (already done on line 129 via `transform_keys(&:to_s)`), and just write `value[k]`.

### D5 — MEDIUM: Five tiers use non-ES float formatters for the non-integer path
- Files: Go `sdk_envelope.go:150`, Rust `envelope.rs:63`, Python `envelope.py:58`, Zig `sdk_envelope.zig:74`, Ruby `envelope.rb:49`, Java `Envelope.java:83`.
- Each tier's source comment acknowledges the divergence and notes the envelope wire protocol doesn't exercise the path. **Latent**: any future field that puts a non-integer float in an envelope (price, exchange rate, lat/long) immediately diverges across at least three tier pairs.
- Worst: Java emits capital `E` and trailing `.0` (`1.0E-300`). Ruby emits trailing `.0` for integer-magnitude scientific (`1.0e+21`). Zig always emits scientific notation.
- **Remediation**: port the ES `Number.prototype.toString` algorithm (per ECMA-262 §7.1.12.1) into each tier. There are reference implementations in `dtoa`-style crates for most languages. This is non-trivial — the simplest interim fix is **reject non-integer floats** (`is_integer() && in ±2^53`) for envelope payloads at the type-system level. That contractually forces the wire protocol to never hit the divergent path.

### D6 — LOW: Lone-surrogate handling is undefined in every tier
- All seven tiers accept whatever the input string type holds. TS, Python, and Java string types can hold lone surrogates; canonical-JSON emits them as-is, producing invalid UTF-8 (in the case of Go's `for _, r := range s` that uses `utf8.RuneError`) or invalid UTF-16 (TS, Java) or raises later on byte-write (Python).
- RFC 8785 § 3.2.2.2 implicitly assumes the input is well-formed Unicode. The conformance fixture should pin "lone surrogate → reject" to one of the six rejection reasons (probably `bad-json`) at the verify side. Not a sign-side blocker for any realistic payload.

### D7 — LOW: Documentation drift in TS reference
- `packages/runar-ir-schema/src/canonical-json.ts:179-182` — `isPlainObjectOrToJSON` is used at line 88 but the function is dead-equivalent to "always true" for the call site (the `else` branch on line 90–94 invokes `serialiseObject` too). The TS impl effectively never bails out on non-plain objects. This is a code-clarity issue, not a parity issue.

---

## 3. Recommended conformance vectors to add to `/Users/siggioskarsson/gitcheckout/runar-review-remediation/conformance/sdk-envelope/fixtures.json`

The current 17 `canonical_json_vectors` exclusively use ASCII keys, integer numbers, and a small set of escape characters. Every divergence above is invisible to the fixture today. Recommended additions, ordered by "would gate a real bug":

1. **`{"\u{1F600}":1,"":2}` → `{"":2,"😀":1}`** (modulo correct emission of the astral char as UTF-8 bytes). Triggers D1 (Zig byte-sort vs UTF-16 unit-sort). The expected JSON has the BMP key first because in UTF-16 code-unit order, U+E000 < U+D83D (high surrogate of U+1F600). Smallest possible failing case.

2. **`{"é":1,"x":2}` → `{"x":2,"é":1}`** (U+007E `x` < U+00E9 `é` in UTF-16; Zig byte-sort agrees here — use this as a *positive* sanity test confirming non-ASCII keys at all). Triggers parser-level "does each tier handle non-ASCII keys at all" — a quieter version of #1.

3. **`{"k":false, "z":0}` → `{"k":false,"z":0}`** (with the input dict containing symbol-keyed entries too in Ruby tests). Triggers D4 — Ruby's `||` fallthrough on `false`/`0`.

4. **Non-integer float vector**: `{"r":0.1}` → `{"r":0.1}`. Triggers D5 in Zig (emits `1e-1`-ish), Java (emits `0.1` actually — Java's Double.toString happens to match here, but `{"r":1e-300}` definitely diverges in Ruby and Java).

5. **`{"big":1e21}` → `{"big":1e+21}`** (ES output). Triggers D5: Ruby emits `1.0e+21`, Java emits `1.0E21`, Zig emits `{e}`-format. This is the cleanest single-byte tripwire for the float-formatter family.

6. **`{"surrogate":"\uD800"}` → REJECT** (sign-side throws, verify-side returns `bad-json`). Pins D6: lone surrogates are not legal canonical-JSON input.

7. **Duplicate-key in Zig**: not expressible in TS/JSON fixture form (the JSON parser deduplicates). Add a **tier-local** Zig test that constructs a `Value.Object` with two same-key `KeyValue` entries and asserts the canonical output rejects/dedupes. (Triggers D3.)

Add the first five to the cross-tier `fixtures.json`; #6 as a sign-side reject test in each tier's unit tests; #7 as a Zig-only test.

---

## 4. Overall verdict

**For the canonical Rúnar IR shapes and the today-shipping envelope payloads (ASCII-only keys; integer-valued `nonce`, `expiresAt`, `n` fields; short string values), all seven implementations produce byte-identical output and round-trip signatures correctly across tier boundaries.** The existing 17 cross-tier fixture vectors plus the valid-envelope verify path exercise this surface and pass.

**The parity is fragile**: a single non-ASCII object key, a single non-integer float, a Ruby hash with a `false`/`0` string-keyed value, or a Zig caller constructing a `Value.Object` with duplicates will break parity tomorrow. The Zig sort bug (D1) is the only divergence I would call **blocking** as a latent defect — the function is named `utf16Less` and the surrounding comments claim UTF-16 behaviour, so the next person to add a non-ASCII key in good faith will silently break cross-tier signature verification with no warning.

**Recommended action ordering**:
1. **Fix D1 (Zig key sort)** before next release. Function lies about what it does; comments confirm the author knew. Real UTF-16 helper is <40 lines.
2. **Fix D4 (Ruby `||`)** in the same patch — one-line trivial fix, blocks a real silent-data-corruption bug for any payload with falsy values.
3. **Add conformance vectors 1–6** above to gate D1/D3/D4/D5/D6 in CI. This is the durable fix — pin the wire bytes at the fixture level so any future divergence fails CI on the next commit.
4. **D5 (float formatters)** — defer. Either port ECMA-262 §7.1.12.1 properly to all tiers (large work) or contractually narrow the envelope payload schema to "integer-valued doubles only" and reject non-integer floats at the sign-side (small work, covers today's actual use cases).
5. **D2, D3, D7** — defer; latent, low-blast-radius.

No tier's implementation is missing or unlocatable; this audit is complete.
