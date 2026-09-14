import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { IR_TIER_IDS, REPO, Tier, buildIrTiers, compileHex, verdict } from './tier-harness.js';

/**
 * ---------------------------------------------------------------------------
 * N-131 — a JSON float is not a legal value on the `--ir` boundary
 * ---------------------------------------------------------------------------
 *
 * `ir-rejection-parity.test.ts` asks "do all six tiers refuse this?". That is
 * the right question for IR that is obviously broken. It is the WRONG question
 * for a float, because a float is not obviously broken to a JSON parser — it
 * is a perfectly well-formed number that four of the six tiers happily read
 * and then guessed at. The guesses did not agree, and the disagreement is in
 * emitted script BYTES, not in diagnostics.
 *
 * Measured before this change, fold-off, on `bounded-loop`'s own golden IR
 * with exactly one field edited:
 *
 *   {"kind":"loop","start":1e30}
 *      go, zig, java   reject
 *      rust, python    accept, start = 1e30
 *      ruby            accept, start = 0            <- third answer, other bytes
 *
 *   {"kind":"loop","count":3.5}            (3.5 is INSIDE the 10000 cap)
 *      go, rust, python, ruby, java  reject
 *      zig                           accept, truncated to 3 -> 3 unrolled bodies
 *
 *   {"kind":"loop","step":1.5}
 *      go, rust, java      reject
 *      python, zig         accept, step = 1  -> i = 0,1,2,3,4
 *      ruby                accept, step 1.5  -> i = 0,1,3,4,6   <- other bytes
 *
 *   {"kind":"load_const","value":1e50}
 *      go, zig, java       reject
 *      rust                accept, SATURATED to i128::MAX (pushes 10ffff..7f)
 *      python, ruby        accept, 100000000000000007629769841091887003294964970946560
 *
 *   {"kind":"raw_script","out_arity":1.0}
 *      go, rust, python, ruby, java  reject
 *      zig                           accept
 *
 * Rust saturating an attacker-supplied constant to `i128::MAX` and Ruby
 * turning `1e30` into `0` are each their own defect: both put a number into a
 * locking script that the IR did not contain. But they are symptoms. The
 * defect is that the boundary admitted a float at all.
 *
 * ---------------------------------------------------------------------------
 * Why REJECT, and why this is not really a behaviour change
 * ---------------------------------------------------------------------------
 *
 * The repo's own normative schema already says so.
 * `packages/runar-ir-schema/src/schemas/anf-ir.schema.json`:
 *
 *   Loop.count      {"type": "integer", "minimum": 0}
 *   Loop.step       {"type": "integer", "enum": [1, -1]}
 *   Loop.start      integer | string
 *   LoadConst.value string | integer | boolean
 *   RawScript.in_arity / out_arity  {"type": "integer", "minimum": 0}
 *
 * There is no float-typed field anywhere in the ANF IR wire format. The four
 * accepting tiers were not implementing a documented alternative semantics;
 * they were each inventing one where the schema had already spoken. So the
 * four tiers are moving from UNDEFINED behaviour to the defined one, which is
 * a narrower claim than "a behaviour change".
 *
 * The three facts that make rejection safe rather than merely defensible:
 *
 *   1. NO PRODUCER WRITES ONE. Every conformance fixture (78) was compiled
 *      through every tier's `--emit-ir` (468 documents) and scanned, both as
 *      parsed JSON and as raw text so that `5.0` and `1e3` could not hide
 *      behind a parser that normalises them. Zero floats.
 *   2. NO FIXTURE CONTAINS ONE. Every `.json` in the repo was scanned: the
 *      only float in anything IR-shaped is `I17`, a deliberate negative. (The
 *      two in `conformance/sdk-envelope/fixtures.json` are RFC 8785
 *      canonical-JSON vectors, a different wire format.) `ir_corpus_is_float_free`
 *      below re-checks the IR half of that on every run.
 *   3. THE LARGE-VALUE ESCAPE HATCH ALREADY EXISTS AND IS NOT A FLOAT. A value
 *      too big for the tier's native integer is written as a decimal string
 *      with an `n` suffix, and all six tiers agree on it byte-for-byte. The
 *      `C04` control pins that, so a guard that over-reaches and swallows the
 *      sanctioned form fails here rather than in production.
 *
 * ---------------------------------------------------------------------------
 * The rule is LEXICAL: float SYNTAX, not fractional VALUE
 * ---------------------------------------------------------------------------
 *
 * `1.0` and `1e2` name integers. A value-based rule would accept them and
 * reject only `3.5`. This gate takes the syntactic rule — any JSON number
 * written with a `.` or an exponent is refused — for three reasons:
 *
 *   - Go and Java, the two tiers already correct here, ALREADY do it this way.
 *     Measured: both refuse `1.0`, `1e2`, `5.0` and `0e0`. Converging on the
 *     tiers that were right means adopting the rule they implement.
 *   - Every tier's JSON parser already draws the line lexically — serde_json,
 *     `encoding/json`, `json.loads`, Ruby's `JSON.parse` and `std.json` all
 *     decide integer-vs-float from the token, not from the value. So the rule
 *     is the one each tier can enforce without a value comparison, which is
 *     what makes six independent implementations agree by construction.
 *   - A value-based rule is the rule Zig already had, and `1.0` on `out_arity`
 *     is precisely what it let through while its five peers refused.
 *
 * `I19` (`load_const.value: 1.0`) is the fixture that distinguishes the two
 * rules. Without it a value-based guard would pass this file.
 *
 * ---------------------------------------------------------------------------
 * What this file adds over the corpus next door
 * ---------------------------------------------------------------------------
 *
 * The float fixtures live in `./ir/` so `ir-rejection-parity.test.ts` grades
 * them too, and its `verdict()` — own-control exit, non-zero, real diagnostic,
 * not a usage or launcher error — is the one they are graded by. This file
 * exists for the half that corpus cannot state:
 *
 *   - "all six agree" is only half a parity claim. The other half is the
 *     POSITIVE side: the integer forms the floats were derived from must still
 *     compile, and must compile to the SAME BYTES in all six tiers. A guard
 *     that rejects the float by rejecting every loop would pass a
 *     rejection-only gate perfectly.
 *   - the controls are integer values at the edges (`count: 0`, a negative
 *     start, `step: -1`, a negative const) plus the `"...n"` string form, so
 *     an over-broad guard has somewhere to fail.
 */

const IR_DIR = join(__dirname, 'ir');
const CONTROL_DIR = join(IR_DIR, 'controls');

/** The float negatives, by the IR shape each one probes. */
const FLOAT_FIXTURES: ReadonlyArray<readonly [string, string]> = [
  ['load_const.value, non-integral magnitude', 'I18-load-const-float.ir.json'],
  ['load_const.value, float syntax naming an integer', 'I19-load-const-float-integral.ir.json'],
  ['loop.start', 'I20-loop-start-float.ir.json'],
  ['loop.count, inside the 10000 cap', 'I21-loop-count-float.ir.json'],
  ['loop.step', 'I22-loop-step-float.ir.json'],
  ['raw_script.out_arity', 'I23-raw-script-arity-float.ir.json'],
];

/**
 * The integer forms that must keep working, byte-identically.
 *
 * Each is the same golden the matching negative was derived from, with the
 * same field set to a legal integer — `C04` to the sanctioned `"...n"` decimal
 * string. They are the falsification target for an over-broad guard: a tier
 * that refuses floats by refusing numbers, or by refusing the string form,
 * reddens here and not in the rejection corpus.
 */
const CONTROLS: ReadonlyArray<readonly [string, string]> = [
  ['loop.count = 0 (lower bound)', 'C01-loop-count-zero.ir.json'],
  ['loop.start = -5', 'C02-loop-start-negative.ir.json'],
  ['loop.step = -1, start = 9', 'C03-loop-step-down.ir.json'],
  ['load_const.value = "...n" decimal string', 'C04-load-const-bigint-string.ir.json'],
  ['load_const.value = -1', 'C05-load-const-negative.ir.json'],
  ['raw_script arities, integer', 'C06-raw-script-arity-int.ir.json'],
];

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** Raw text, not `JSON.parse`: `5.0` parses to the number 5 in JS, so a
 *  structural walk over the parsed document cannot see the float syntax this
 *  gate is about. Only the bytes on disk can. */
const FLOAT_TOKEN = /:\s*-?\d+(?:\.\d|[eE][-+]?\d)/;

describe('N-131: JSON floats on the --ir boundary', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all six IR-capable tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every fixture and control referenced here exists on disk', () => {
    const negatives = new Set(readdirSync(IR_DIR));
    for (const [, f] of FLOAT_FIXTURES) expect(negatives.has(f), f).toBe(true);
    const controls = new Set(readdirSync(CONTROL_DIR));
    for (const [, f] of CONTROLS) expect(controls.has(f), f).toBe(true);
  });

  it('every float fixture really does contain a float (else it probes nothing)', () => {
    for (const [shape, f] of FLOAT_FIXTURES) {
      const text = readFileSync(join(IR_DIR, f), 'utf-8');
      expect(FLOAT_TOKEN.test(text), `${f} (${shape}) has no float token`).toBe(true);
    }
  });

  it('no control contains a float (else it is a second negative, not a control)', () => {
    for (const [, f] of CONTROLS) {
      const text = readFileSync(join(CONTROL_DIR, f), 'utf-8');
      expect(FLOAT_TOKEN.test(text), `${f} contains a float`).toBe(false);
    }
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') {
      expect(missing, `no toolchain for: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- claim 1: no checked-in IR needs a float ------------------------------
  //
  // The empirical half of the decision, re-run every time. If a fixture ever
  // acquires a float in a numeric field, rejection stops being free and this
  // says so here rather than as a mystery failure in the tier suites.

  it('ir_corpus_is_float_free: no golden ANF IR contains a float', () => {
    const goldens = readdirSync(join(REPO, 'conformance/tests'), { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => join(REPO, 'conformance/tests', d.name, 'expected-ir.json'));
    const offenders: string[] = [];
    for (const g of goldens) {
      let text: string;
      try {
        text = readFileSync(g, 'utf-8');
      } catch {
        continue; // fixture without a golden IR
      }
      if (FLOAT_TOKEN.test(text)) offenders.push(g);
    }
    expect(goldens.length).toBeGreaterThan(50);
    expect(offenders).toEqual([]);
  });

  // -- claim 2: every tier REFUSES every float shape ------------------------

  for (const [shape, fixture] of FLOAT_FIXTURES) {
    for (const tier of available) {
      it(`${tier.id} rejects a float in ${shape} (${fixture})`, () => {
        expect(
          verdict(tier, join(IR_DIR, fixture)),
          `${tier.id} ACCEPTED a JSON float on the --ir boundary. The ANF IR ` +
            `schema declares this field an integer; a tier that reads a float ` +
            `here is inventing a value, and its five peers invent different ` +
            `ones. See the header for the measured divergence.`,
        ).toBe('rejected');
      });
    }
  }

  // -- claim 3: the integer forms still compile, to the SAME BYTES ----------
  //
  // Rejection parity alone is satisfiable by a tier that rejects everything.
  // This is the half that makes the fix a fix rather than a mute button.

  for (const [shape, fixture] of CONTROLS) {
    it(`all tiers compile ${shape} to identical bytes (${fixture})`, () => {
      const path = join(CONTROL_DIR, fixture);
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
            .map(([hex, ids]) => `  ${ids.join(', ')}: ${hex.slice(0, 96)}`)
            .join('\n'),
      ).toBe(1);
    });
  }
});
