import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { IR_TIER_IDS, REPO, Tier, buildIrTiers, compileHex, verdict } from './tier-harness.js';

/**
 * ---------------------------------------------------------------------------
 * N-132 — a string `ANFProperty.initialValue` on the `--ir` boundary
 * ---------------------------------------------------------------------------
 *
 * `anf-ir.schema.json` types `initialValue` as `string | integer | boolean`
 * and does NOT discriminate the string arm by the property's declared type.
 * It cannot: the arm carries two different things, and which one a given
 * string is has to be read off the string itself.
 *
 * Measured, fold-off, on `fixed-array-index`'s own golden IR with exactly one
 * property's `initialValue` edited, classified by exit code:
 *
 *   "42n"     go     exit 1  stack lowering: invalid hex string: ... U+006E 'n'
 *             python exit 1  stack lowering: non-hexadecimal number ... position 2
 *             rust   exit 0  ...012a...   (42)
 *             zig    exit 0  ...012a...   (42)
 *             java   exit 0  ...012a...   (42)
 *             ruby   exit 0  ...024270... (the ASCII digits, mangled)
 *
 *   "-3n"     go/python reject · rust/zig/java 0x83 (-3) · ruby 0x02d370
 *   "…N…n"    go/python reject · rust/zig/java the 33-byte secp256k1 order
 *                              · ruby the 40 ASCII digits
 *   "zz"      go/python/zig/java reject · RUST pushes 0x00 · ruby pushes 0x33
 *   "5"       go/python/rust/zig/java reject · ruby pushes 0x50
 *   "1.5n"    go/python/zig/java reject · rust pushes 0x0000 · ruby 0x1e57
 *
 * Six tiers, four answers, and the disagreement is in emitted script BYTES.
 *
 * ---------------------------------------------------------------------------
 * The direction: `"42n"` MEANS 42. It is not a hex ByteString.
 * ---------------------------------------------------------------------------
 *
 * Go's and Python's hex-decode failure is suggestive — it looks like evidence
 * that a string here was only ever meant to be hex. It is not, and the
 * PRODUCER side settles it. Compiled with `--emit-ir` (fold-off) from one
 * contract carrying a `bigint` initializer, a `ByteString` initializer and an
 * over-int64 `bigint` initializer, the seven tiers emit:
 *
 *                   count: bigint = 42n   tag: ByteString = "deadbeef"   big: bigint = <2^256-ish>
 *   ts (reference)  "42n"                 "deadbeef"                     "…n"
 *   rust            42                    "deadbeef"                     "…n"
 *   zig             42                    "deadbeef"                     "…n"
 *   java            42                    "deadbeef"                     "…n"
 *   go              42                    "deadbeef"                     <bare number>
 *   python          42                    "deadbeef"                     <bare number>
 *   ruby            42                    "deadbeef"                     <bare number>
 *
 * The REFERENCE tier writes `"42n"` for every bigint initializer it emits,
 * whatever the magnitude — so "Go and Python reject `"42n"`" is not an edge
 * case, it is "Go and Python cannot consume TypeScript-produced IR for any
 * contract with a bigint property initializer". Four more tiers write the
 * same shape once the value passes int64. And every tier writes a bare hex
 * string for a ByteString initializer.
 *
 * So both readings are real, and the discriminator already exists and is
 * already documented. `compilers/go/ir/types.go#isDecimalBigIntLiteral` is
 * the canonical rule for `load_const.value` — optional `-`, ASCII digits, a
 * REQUIRED trailing `n` — and every tier has a copy of it
 * (`_is_decimal_bigint_literal`, `is_decimal_bigint_literal`, …). The TS
 * loader applies `/^-?\d+n$/` in its JSON reviver, i.e. to EVERY string in the
 * document, `initialValue` included. runner.ts says why in as many words:
 * "keep the canonical JS BigInt `n` suffix so downstream IR consumers can
 * distinguish a decimal-encoded big integer from a hex-encoded ByteString
 * literal (which never carries the suffix)".
 *
 * `initialValue` was simply the one place three tiers never applied the rule.
 *
 * ---------------------------------------------------------------------------
 * The rule, in full
 * ---------------------------------------------------------------------------
 *
 *   1. A string matching `-?\d+n` is a decimal bigint. It must lower to the
 *      SAME BYTES as the integer it denotes.
 *   2. Any other string is a hex-encoded ByteString, decoded STRICTLY: even
 *      length, hex digits only. `""` is the empty ByteString.
 *   3. A string that is neither is REFUSED. It is not decoded leniently into
 *      whatever bytes fall out.
 *
 * Rule 3 is where Rust and Ruby were putting numbers into locking scripts
 * that the IR did not contain: Rust's `u8::from_str_radix(..).unwrap_or(0)`
 * turned `"zz"` into `0x00`, and Ruby's `[s].pack("H*")` turned `"42n"` into
 * `0x4270` because `pack` maps a non-hex character to `(c & 15) + (c >> 6)*9`
 * instead of failing. Both are the fail-open half of the same defect the
 * float boundary (N-131) was about — the difference is only that a bad hex
 * string is obviously bad, so nobody checked that the tiers agreed it was.
 *
 * Rule 1 is what Go and Python were missing; nothing else changes for them,
 * because they already refuse a bad hex string. Zig and Java already
 * implement all three rules and are untouched.
 *
 * ---------------------------------------------------------------------------
 * What this file adds over the corpus next door
 * ---------------------------------------------------------------------------
 *
 * `I24`–`I27` live in `./ir/` so `ir-rejection-parity.test.ts` grades them
 * under its `verdict()` — exited under its own control, non-zero, real
 * diagnostic. This file states the half that a rejection corpus cannot:
 *
 *   - `"42n"` is not merely ACCEPTED, it is accepted AS 42 — byte-identical
 *     to the integer form. A loader that read it as something else would pass
 *     any "does it load" test and still emit the wrong script.
 *   - `"1000"` is 0x10 0x00, NOT one thousand. That control is the teeth
 *     against an over-broad fix: a tier that reads any digit string as
 *     decimal passes every other claim here and fails this one.
 */

const IR_DIR = join(__dirname, 'ir');
const CONTROL_DIR = join(IR_DIR, 'controls');

/** The string shapes no tier may accept, by what each one probes. */
const REFUSED: ReadonlyArray<readonly [string, string]> = [
  ['a non-hex, non-bigint string', 'I24-initial-value-non-hex-string.ir.json'],
  ['an odd-length hex string', 'I25-initial-value-odd-hex-string.ir.json'],
  ['a double `n` suffix', 'I26-initial-value-double-n-suffix.ir.json'],
  ['float syntax reached through the string arm', 'I27-initial-value-float-string.ir.json'],
];

/** `"42n"` / `"-3n"` on two properties, `"1000"` / `"deadbeef"` on the other two. */
const BIGINT_STRINGS = join(CONTROL_DIR, 'C07-initial-value-bigint-string.ir.json');
/** The same file with the two bigint strings written as JSON integers. */
const INTEGER_FORMS = join(CONTROL_DIR, 'C08-initial-value-integer-form.ir.json');
/** `C08` with the hex string `"1000"` replaced by the INTEGER 1000. */
const HEX_NOT_DECIMAL = join(CONTROL_DIR, 'C09-initial-value-hex-not-decimal.ir.json');
/** One property set to the secp256k1 group order as a `"…n"` string. */
const OVERSIZE = join(CONTROL_DIR, 'C10-initial-value-oversize-bigint-string.ir.json');

const ALL_CONTROLS: ReadonlyArray<readonly [string, string]> = [
  ['bigint strings', BIGINT_STRINGS],
  ['integer forms', INTEGER_FORMS],
  ['hex-not-decimal', HEX_NOT_DECIMAL],
  ['oversize bigint string', OVERSIZE],
];

/**
 * The golden every fixture in this file is one edited field away from.
 * `fixed-array-index` carries four properties that each have an
 * `initialValue` AND are each pushed into the locking script, which is why it
 * and not `property-initializers` — that one's only bigint initializer is a
 * mutable state field the locking script never pushes, so editing it moves no
 * bytes and a probe built on it proves nothing.
 */
const DERIVED_FROM = join(REPO, 'conformance/tests/fixed-array-index/expected-ir.json');

/**
 * secp256k1's group order, minimally encoded as Bitcoin Script push data:
 * PUSH33 then the 33-byte little-endian sign-magnitude body (the extra byte
 * carries the sign, since bit 7 of the top magnitude byte is set).
 *
 * Hard-coded rather than derived, so "all six tiers agree" cannot be
 * satisfied by all six agreeing on the WRONG number — which is exactly what
 * a shared fallback-to-zero would look like.
 */
const SECP256K1_N_PUSH =
  '21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00';

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** Read the four `initialValue`s out of a fixture, in declaration order. */
function initialValues(path: string): unknown[] {
  const doc = JSON.parse(readFileSync(path, 'utf-8')) as {
    properties: { initialValue?: unknown }[];
  };
  return doc.properties.map((p) => p.initialValue);
}

describe('N-132: a string ANFProperty.initialValue on the --ir boundary', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all six IR-capable tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every fixture and control referenced here exists on disk', () => {
    const negatives = new Set(readdirSync(IR_DIR));
    for (const [, f] of REFUSED) expect(negatives.has(f), f).toBe(true);
    const controls = new Set(readdirSync(CONTROL_DIR));
    for (const [, p] of ALL_CONTROLS) {
      expect(controls.has(p.split('/').pop()!), p).toBe(true);
    }
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') {
      expect(missing, `no toolchain for: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- the fixtures are what they claim to be -------------------------------
  //
  // A control that does not differ from its pair in the way the claim assumes
  // turns a byte-equality assertion into a tautology.

  it('C07 and C08 differ ONLY in the bigint arm (string vs integer)', () => {
    const strings = initialValues(BIGINT_STRINGS);
    const integers = initialValues(INTEGER_FORMS);
    expect(strings).toEqual(['42n', '-3n', '1000', 'deadbeef']);
    expect(integers).toEqual([42, -3, '1000', 'deadbeef']);
  });

  it('C09 differs from C08 ONLY in reading "1000" as a number', () => {
    expect(initialValues(HEX_NOT_DECIMAL)).toEqual([42, -3, 1000, 'deadbeef']);
  });

  it('C10 carries an over-int64 "…n" string', () => {
    const [first] = initialValues(OVERSIZE);
    expect(typeof first).toBe('string');
    expect(first as string).toMatch(/^\d{70,}n$/);
  });

  it('every refused fixture really does carry a string initialValue', () => {
    for (const [shape, f] of REFUSED) {
      const [first] = initialValues(join(IR_DIR, f));
      expect(typeof first, `${f} (${shape})`).toBe('string');
      expect(/^-?\d+n$/.test(first as string), `${f} is the sanctioned form`).toBe(false);
    }
  });

  // -- positive control -----------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the golden these fixtures are derived from`, () => {
      expect(
        verdict(tier, DERIVED_FROM),
        `${tier.id} did not accept fixed-array-index's own checked-in IR, so ` +
          `every row below for this tier is vacuous.`,
      ).toBe('accepted');
    });
  }

  // -- claim 1: every tier REFUSES every unreadable string ------------------

  for (const [shape, fixture] of REFUSED) {
    for (const tier of available) {
      it(`${tier.id} rejects ${shape} (${fixture})`, () => {
        expect(
          verdict(tier, join(IR_DIR, fixture)),
          `${tier.id} ACCEPTED a string initialValue that is neither the ` +
            `sanctioned "<decimal>n" bigint form nor valid even-length hex. ` +
            `A tier that decodes it anyway invents bytes, and its peers ` +
            `invent different ones — see the header.`,
        ).toBe('rejected');
      });
    }
  }

  // -- claim 2: the tiers agree on each control -----------------------------

  for (const [name, path] of ALL_CONTROLS) {
    it(`all tiers compile the ${name} control to identical bytes`, () => {
      const byTier = available.map((t) => [t.id, compileHex(t, path)] as const);
      const distinct = new Map<string, string[]>();
      for (const [id, hex] of byTier) {
        const ids = distinct.get(hex) ?? [];
        ids.push(id);
        distinct.set(hex, ids);
      }
      expect(
        distinct.size,
        `tiers disagree on the bytes for legal IR:\n` +
          [...distinct.entries()]
            .map(([hex, ids]) => `  ${ids.join(', ')}: ${hex.slice(0, 120)}`)
            .join('\n'),
      ).toBe(1);
    });
  }

  // -- claim 3: "42n" MEANS 42, in every tier -------------------------------
  //
  // The claim a rejection corpus cannot make, and the one that matters: not
  // "it loads" but "it loads as the number it spells". Both a positive and a
  // negative value, because 0 is what every fallback path also produces.

  for (const tier of available) {
    it(`${tier.id} reads "42n" / "-3n" as the integers they denote`, () => {
      expect(
        compileHex(tier, BIGINT_STRINGS),
        `${tier.id} accepted the "<decimal>n" form but did not lower it to ` +
          `the same bytes as the integer it spells.`,
      ).toBe(compileHex(tier, INTEGER_FORMS));
    });
  }

  // -- claim 4: a bare digit string is HEX, not decimal ---------------------
  //
  // The teeth. `"1000"` is two bytes, 0x10 0x00; one thousand is 0xe8 0x03.
  // A fix that reads any all-digit string as decimal satisfies every claim
  // above and fails here.

  for (const tier of available) {
    it(`${tier.id} reads "1000" as the ByteString 0x1000, not as one thousand`, () => {
      const asHex = compileHex(tier, INTEGER_FORMS);
      const asDecimal = compileHex(tier, HEX_NOT_DECIMAL);
      expect(
        asHex,
        `${tier.id} emitted the same bytes for the hex string "1000" and for ` +
          `the integer 1000, so its "<decimal>n" discriminator is not ` +
          `discriminating — the required trailing 'n' is what separates a ` +
          `decimal-encoded bigint from a hex ByteString.`,
      ).not.toBe(asDecimal);
      expect(asHex).toContain('021000');
      expect(asDecimal).toContain('02e803');
    });
  }

  // -- claim 5: an over-int64 "…n" is the number, not a saturated stand-in --

  for (const tier of available) {
    it(`${tier.id} pushes the full 256-bit value for an oversize "…n"`, () => {
      expect(
        compileHex(tier, OVERSIZE),
        `${tier.id} accepted an over-int64 "<decimal>n" initialValue but did ` +
          `not push secp256k1's order; a truncated, saturated or zeroed ` +
          `stand-in is a locking script the IR does not describe.`,
      ).toContain(SECP256K1_N_PUSH);
    });
  }

  // -- claim 6: the corpus does not depend on lenient decoding --------------
  //
  // The empirical half, re-run every time: if a golden ever acquires a string
  // initialValue outside the two sanctioned forms, strictness stops being
  // free and it says so here rather than as a mystery failure in a tier suite.

  it('ir_corpus_initial_values_are_well_formed', () => {
    const dirs = readdirSync(join(REPO, 'conformance/tests'), { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => join(REPO, 'conformance/tests', d.name, 'expected-ir.json'));
    const offenders: string[] = [];
    let checked = 0;
    for (const g of dirs) {
      let text: string;
      try {
        text = readFileSync(g, 'utf-8');
      } catch {
        continue; // fixture without a golden IR
      }
      checked += 1;
      const doc = JSON.parse(text) as { properties?: { initialValue?: unknown }[] };
      for (const p of doc.properties ?? []) {
        const v = p.initialValue;
        if (typeof v !== 'string') continue;
        const bigint = /^-?\d+n$/.test(v);
        const hex = /^(?:[0-9a-fA-F]{2})*$/.test(v);
        if (!bigint && !hex) offenders.push(`${g}: ${JSON.stringify(v)}`);
      }
    }
    expect(checked).toBeGreaterThan(50);
    expect(offenders).toEqual([]);
  });
});
