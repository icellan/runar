import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  BrokenTier,
  IR_TIER_IDS,
  REPO,
  Tier,
  buildIrTiers,
  compileHex,
  verdict,
} from './tier-harness.js';

/**
 * ---------------------------------------------------------------------------
 * N-133 — an unreadable `loop.start` became 0 instead of an error
 * ---------------------------------------------------------------------------
 *
 * `anf-ir.schema.json` types `Loop.start` as `integer | string`, and N-131's
 * follow-up settled what the string arm means: the sanctioned `"<decimal>n"`
 * form, suffix REQUIRED, which is the same encoding `load_const.value` and
 * `ANFProperty.initialValue` use. Java implements exactly that rule.
 *
 * Four tiers implement something looser, and all four fail the same way — by
 * substituting 0. Measured fold-off on `bounded-loop`'s own golden IR with
 * only `start` edited, classified by exit code (`4aa9d9` is the sha of the
 * golden's OWN start-0 script, so a tier reporting it invented a start):
 *
 *   "5"      go 5 · python 5 · zig 5 · ruby 5 · RUST 0        · java reject
 *   "abc"    go reject · python reject · rust/zig/ruby 0      · java reject
 *   ""       go reject · python reject · rust/zig/ruby 0      · java reject
 *   "5nn"    go reject · python reject · rust/zig/ruby 0      · java reject
 *   true     go reject · python 1 (!) · rust/zig/ruby 0       · java reject
 *   null     go reject · python/rust/zig/ruby 0                 · java reject
 *   "999999999999999999999999999999n"
 *            go/rust/python/ruby/java the value · ZIG 0
 *
 * An explicit `null` is a different thing from an ABSENT `start`, which still
 * means a zero-start counting-up loop and must keep meaning that — the two
 * were conflated by every tier that read `start` through a "missing or
 * nullish" default.
 *
 * 0 is what makes this class of defect invisible. It is a perfectly plausible
 * loop start — it is the commonest one, and it is what `bounded-loop` itself
 * carries — so the wrong program compiles, emits a well-formed locking
 * script, and nothing anywhere looks wrong. Compare N-131, where Ruby turning
 * `1e30` into 0 was a symptom of the same thing.
 *
 * ---------------------------------------------------------------------------
 * The rule: refuse what you cannot represent; never substitute
 * ---------------------------------------------------------------------------
 *
 * One sentence covers every row: a `loop.start` must be a JSON integer or the
 * `"<decimal>n"` string, and a value the tier cannot represent is REFUSED
 * rather than replaced.
 *
 * Converging on refusal for the unreadable strings means converging on Java,
 * the tier that already implements the decided rule, and it is safe on the
 * producer side: no tier emits an unsuffixed decimal string for `loop.start`.
 * Compiled with `--emit-ir`, an over-int64 start comes out as
 * `"999999999999999999999999999999n"` from ts / go / rust and as a bare JSON
 * number from python / ruby / java. `loop_start_corpus_is_well_formed` below
 * re-checks the checked-in half of that on every run.
 *
 * `"5"` looks like it has a majority (four tiers read it as 5) and it does
 * not have a defensible one: the schema's string arm is the `n`-suffixed
 * form, no producer writes the bare one, and the fifth tier reading it as 0
 * is the whole problem. A rule with an exception is a rule two tiers will
 * implement differently.
 *
 * ---------------------------------------------------------------------------
 * The over-int64 case is a REAL SPLIT and is not papered over
 * ---------------------------------------------------------------------------
 *
 * This one is not a bug in the five tiers that accept it. Go, Rust, Python,
 * Ruby and Java carry `start` as an arbitrary-precision integer and emit the
 * right script. Zig's `ANFLoop.start` is an `i64`, so 10^30 is a value it
 * genuinely cannot represent — and the tiers therefore disagree about what
 * "too wide" even means.
 *
 * That is reported, not resolved. What this change does is make Zig REFUSE
 * it instead of compiling a start-0 loop, which is the part that was a defect
 * under every reading. Widening Zig's start to a bigint is a separate piece
 * of work: `start` is an `i64` through its whole codegen path, not just at
 * the loader.
 *
 * The consequence is that the over-int64 fixture CANNOT live in
 * `./ir/` — `ir-rejection-parity.test.ts` requires all six tiers to refuse
 * everything it globs, and five of them are right to accept this. It sits in
 * `./ir/controls/` and is graded here, per tier, so the split is a written-
 * down measurement rather than a gap.
 */

const IR_DIR = join(__dirname, 'ir');
const CONTROL_DIR = join(IR_DIR, 'controls');

/** Shapes no tier may accept, by what each one probes. */
const REFUSED: ReadonlyArray<readonly [string, string]> = [
  ['an unsuffixed decimal string', 'I28-loop-start-unsuffixed-decimal.ir.json'],
  ['a non-numeric string', 'I29-loop-start-non-numeric-string.ir.json'],
  ['an empty string', 'I30-loop-start-empty-string.ir.json'],
  ['a double `n` suffix', 'I31-loop-start-double-n-suffix.ir.json'],
  ['a boolean', 'I32-loop-start-boolean.ir.json'],
  ['an explicit null', 'I33-loop-start-null.ir.json'],
];

/**
 * Pairs: the sanctioned string form and the integer it denotes. Both of them
 * NON-ZERO, deliberately — `"0n"` would be satisfied by every fallback path
 * in this file's header, since 0 is exactly what they all produce.
 */
const EQUIVALENT_PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  ['5', 'C11-loop-start-bigint-string.ir.json', 'C12-loop-start-integer.ir.json'],
  ['-3', 'C13-loop-start-negative-bigint-string.ir.json', 'C14-loop-start-negative-integer.ir.json'],
];

/** The documented split: an `n`-suffixed start wider than i64. */
const OVER_INT64 = join(CONTROL_DIR, 'C15-loop-start-over-int64.ir.json');

/**
 * The golden every fixture here is one edited field away from, and the script
 * a fallback-to-zero produces. Comparing against it is what turns "the tier
 * accepted it" into "the tier accepted it and did NOT invent a start".
 */
const BOUNDED_LOOP = join(REPO, 'conformance/tests/bounded-loop/expected-ir.json');

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** The single `loop` node's `start` in a fixture. */
function loopStart(path: string): unknown {
  const doc = JSON.parse(readFileSync(path, 'utf-8')) as { methods: unknown[] };
  const found: unknown[] = [];
  const walk = (bindings: unknown[]): void => {
    for (const b of bindings as { value: Record<string, unknown> }[]) {
      const v = b.value;
      if (v.kind === 'loop') found.push(v.start);
      for (const k of ['body', 'then', 'else']) {
        if (Array.isArray(v[k])) walk(v[k] as unknown[]);
      }
    }
  };
  for (const m of doc.methods as { body?: unknown[] }[]) walk(m.body ?? []);
  expect(found.length, `${path} must carry exactly one loop`).toBe(1);
  return found[0];
}

describe('N-133: loop.start on the --ir boundary', () => {
  // -- vacuity guards -------------------------------------------------------

  it('the matrix names all six IR-capable tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every fixture referenced here exists on disk', () => {
    const negatives = new Set(readdirSync(IR_DIR));
    for (const [, f] of REFUSED) expect(negatives.has(f), f).toBe(true);
    const controls = new Set(readdirSync(CONTROL_DIR));
    for (const [, s, i] of EQUIVALENT_PAIRS) {
      expect(controls.has(s), s).toBe(true);
      expect(controls.has(i), i).toBe(true);
    }
    expect(controls.has('C15-loop-start-over-int64.ir.json')).toBe(true);
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') {
      expect(missing, `no toolchain for: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('each fixture carries the start it claims (else it probes nothing)', () => {
    expect(loopStart(join(IR_DIR, REFUSED[0]![1]))).toBe('5');
    expect(loopStart(join(IR_DIR, REFUSED[1]![1]))).toBe('abc');
    expect(loopStart(join(IR_DIR, REFUSED[2]![1]))).toBe('');
    expect(loopStart(join(IR_DIR, REFUSED[3]![1]))).toBe('5nn');
    expect(loopStart(join(IR_DIR, REFUSED[4]![1]))).toBe(true);
    // An explicit `null` is NOT the same as an absent `start`: absent
    // still means a zero-start counting-up loop, which is why the
    // fixture has the key with a null value rather than no key.
    expect(loopStart(join(IR_DIR, REFUSED[5]![1]))).toBe(null);
    expect(loopStart(join(CONTROL_DIR, EQUIVALENT_PAIRS[0]![1]))).toBe('5n');
    expect(loopStart(join(CONTROL_DIR, EQUIVALENT_PAIRS[0]![2]))).toBe(5);
    expect(loopStart(join(CONTROL_DIR, EQUIVALENT_PAIRS[1]![1]))).toBe('-3n');
    expect(loopStart(join(CONTROL_DIR, EQUIVALENT_PAIRS[1]![2]))).toBe(-3);
    expect(loopStart(OVER_INT64)).toBe('999999999999999999999999999999n');
    // The base golden's own start, and the value every fallback path lands on.
    expect(loopStart(BOUNDED_LOOP)).toBe(0);
  });

  // -- positive control -----------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the bounded-loop golden these are derived from`, () => {
      expect(verdict(tier, BOUNDED_LOOP)).toBe('accepted');
    });
  }

  // -- claim 1: every tier REFUSES every unreadable start -------------------

  for (const [shape, fixture] of REFUSED) {
    for (const tier of available) {
      it(`${tier.id} rejects ${shape} (${fixture})`, () => {
        expect(
          verdict(tier, join(IR_DIR, fixture)),
          `${tier.id} ACCEPTED a loop.start it cannot read. Every tier that ` +
            `does substitutes 0 — a perfectly plausible loop start, and the ` +
            `one this very golden carries, so the wrong program compiles and ` +
            `nothing looks wrong.`,
        ).toBe('rejected');
      });
    }
  }

  // -- claim 2: the sanctioned form still works, and MEANS the integer ------
  //
  // The teeth against an over-broad guard: a tier that refuses the bad
  // strings by refusing strings reddens here and nowhere else.

  for (const [denotes, stringForm, integerForm] of EQUIVALENT_PAIRS) {
    for (const tier of available) {
      it(`${tier.id} reads the "${denotes}n" start as ${denotes}`, () => {
        const asString = compileHex(tier, join(CONTROL_DIR, stringForm));
        const asInteger = compileHex(tier, join(CONTROL_DIR, integerForm));
        expect(
          asString,
          `${tier.id} accepted the "<decimal>n" start but did not lower it ` +
            `to the same bytes as the integer it spells.`,
        ).toBe(asInteger);
        // Non-zero, so a fallback-to-zero cannot satisfy this row.
        expect(asString).not.toBe(compileHex(tier, BOUNDED_LOOP));
      });
    }
  }

  // -- claim 3: an over-int64 start is never silently zeroed ----------------
  //
  // The invariant that holds on both sides of the split. A tier may refuse a
  // start it cannot represent; what it may not do is compile a DIFFERENT
  // loop and exit 0.

  const startZeroHex = (): string => compileHex(available[0]!, BOUNDED_LOOP);

  for (const tier of available) {
    it(`${tier.id} never compiles an over-int64 start into the start-0 loop`, () => {
      let hex: string;
      try {
        hex = compileHex(tier, OVER_INT64);
      } catch (e) {
        if (e instanceof BrokenTier) return; // refused — the safe side
        throw e;
      }
      expect(
        hex,
        `${tier.id} exited 0 for a loop start wider than its native integer ` +
          `and emitted the script for start = 0. Refusing it is fine; ` +
          `substituting a different loop is not.`,
      ).not.toBe(startZeroHex());
    });
  }

  it('the tiers that accept an over-int64 start all agree', () => {
    const accepted: [string, string][] = [];
    for (const tier of available) {
      try {
        accepted.push([tier.id, compileHex(tier, OVER_INT64)]);
      } catch (e) {
        if (e instanceof BrokenTier) continue;
        throw e;
      }
    }
    expect(accepted.length).toBeGreaterThanOrEqual(2);
    const distinct = new Set(accepted.map(([, hex]) => hex));
    expect(
      distinct.size,
      `tiers that accept an over-int64 start disagree on the bytes:\n` +
        accepted.map(([id, hex]) => `  ${id}: ${hex.slice(0, 96)}`).join('\n'),
    ).toBe(1);
  });

  /**
   * The split, written down. Zig's `ANFLoop.start` is an `i64`, so 10^30 is a
   * value it cannot carry; its five peers hold `start` as an arbitrary-
   * precision integer and emit the right script.
   *
   * This row is a MEASUREMENT, not a requirement. Widening Zig's start to a
   * bigint is legitimate work and would redden exactly this test — which is
   * the point: the split should not be able to change without someone saying
   * so out loud.
   */
  it('zig refuses an over-int64 start (i64 ceiling) while its five peers accept', () => {
    const zig = available.find((t) => t.id === 'zig');
    if (!zig) return; // not built locally; the CI build guard above covers it
    expect(
      verdict(zig, OVER_INT64),
      `zig now accepts an over-int64 loop.start. If its start was widened ` +
        `past i64, update this row and the header's split note — the ` +
        `divergence is documented here deliberately.`,
    ).toBe('rejected');

    const peers = available.filter((t) => t.id !== 'zig');
    for (const tier of peers) {
      expect(verdict(tier, OVER_INT64), `${tier.id} should accept`).toBe('accepted');
    }
  });

  // -- claim 4: no checked-in IR depends on the loose readings --------------

  it('loop_start_corpus_is_well_formed', () => {
    const goldens = readdirSync(join(REPO, 'conformance/tests'), { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => join(REPO, 'conformance/tests', d.name, 'expected-ir.json'));
    const offenders: string[] = [];
    let checked = 0;
    for (const g of goldens) {
      let doc: { methods?: unknown[] };
      try {
        doc = JSON.parse(readFileSync(g, 'utf-8')) as { methods?: unknown[] };
      } catch {
        continue; // fixture without a golden IR
      }
      checked += 1;
      const walk = (bindings: unknown[]): void => {
        for (const b of bindings as { value: Record<string, unknown> }[]) {
          const v = b.value;
          if (v.kind === 'loop' && 'start' in v) {
            const s = v.start;
            const ok =
              typeof s === 'number' ||
              (typeof s === 'string' && /^-?\d+n$/.test(s));
            if (!ok) offenders.push(`${g}: ${JSON.stringify(s)}`);
          }
          for (const k of ['body', 'then', 'else']) {
            if (Array.isArray(v[k])) walk(v[k] as unknown[]);
          }
        }
      };
      for (const m of (doc.methods ?? []) as { body?: unknown[] }[]) walk(m.body ?? []);
    }
    expect(checked).toBeGreaterThan(50);
    expect(offenders).toEqual([]);
  });
});
