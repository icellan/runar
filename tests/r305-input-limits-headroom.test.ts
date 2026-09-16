/**
 * The justifications on `InputLimits` must be recomputed from the corpus they
 * cite, not asserted against it.
 *
 * Those comments are the only record of WHY each DoS bound has the value it
 * has, and the round-three audit found two of them false in the direction that
 * matters most — they overstated the margin:
 *
 *   - `MAX_STRING_BYTES = 4 MiB` claimed "~3× headroom" against "the largest
 *     checked-in hex pushdata (witness-assisted Groth16 VK)". The named
 *     artifact, `examples/go/SP1Verifier.groth16.vk.json`, is 3,287 bytes in
 *     total. The real binding case is a compiled script carried as hex:
 *     `conformance/tests/p384-wallet/expected-script.hex` is 3,926,724 hex
 *     characters — 93.6% of the bound, 1.07× headroom. Someone reading "~3×"
 *     would have concluded there was room for a script three times the largest
 *     one in the tree; there is room for 7%.
 *   - `MAX_IR_BYTES = 16 MiB` claimed the largest compiled-IR JSON "observed
 *     during conformance is ~2 MiB". The largest is 88,311 B.
 *
 * Both numbers move the moment a fixture grows, and nothing was watching them.
 * This guard reads the comment block, pulls out every figure it states about
 * the tree, and recomputes each one. It also pins the hex-doubling consequence
 * — MAX_SCRIPT_BYTES admits 4 MiB of script, hex doubles it, so the effective
 * ceiling for a script travelling through canonicalJson is half the advertised
 * one — because that is arithmetic between two constants and a reader should
 * not have to rederive it.
 *
 * Nothing here changes a constant. If a row goes red because a fixture grew,
 * the fix is to restate the measured margin, and then to decide on the merits
 * whether 1.07× is still enough.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InputLimits } from '../packages/runar-ir-schema/src/input-limits.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LIMITS_FILE = 'packages/runar-ir-schema/src/input-limits.ts';
const conformanceTests = join(repoRoot, 'conformance', 'tests');

const comment = readFileSync(join(repoRoot, LIMITS_FILE), 'utf8')
  .split('\n')
  .map((l) => l.replace(/^\s*\*\s?/, ''))
  .join(' ')
  .replace(/\s+/g, ' ');

/** The largest file matching `name` under conformance/tests, by byte size. */
function largestFixtureFile(name: string): { fixture: string; bytes: number } {
  let best = { fixture: '', bytes: -1 };
  for (const d of readdirSync(conformanceTests)) {
    const p = join(conformanceTests, d, name);
    if (!existsSync(p)) continue;
    const bytes = statSync(p).size;
    if (bytes > best.bytes) best = { fixture: d, bytes };
  }
  return best;
}

/** Hex characters in a `.hex` golden, ignoring trailing whitespace. */
function hexChars(fixture: string): number {
  return readFileSync(join(conformanceTests, fixture, 'expected-script.hex'), 'utf8').trim()
    .length;
}

function num(s: string): number {
  return Number(s.replace(/,/g, ''));
}

describe('R-305: the MAX_STRING_BYTES justification is measured, not asserted', () => {
  const claim = comment.match(
    /largest checked-in script is `conformance\/tests\/([a-z0-9-]+)\/expected-script\.hex`: ([\d,]+) script bytes = ([\d,]+) hex characters, which is ([\d.]+)% of this bound\. Real headroom is ([\d.]+)×/,
  );

  it('the justification sentence is present and parseable', () => {
    expect(
      claim,
      `${LIMITS_FILE} no longer states the largest-script measurement in the ` +
        'shape this guard reads — re-point the regex rather than deleting the row',
    ).not.toBeNull();
  });

  it('names the actually-largest checked-in script', () => {
    const largest = largestFixtureFile('expected-script.hex');
    expect(
      claim![1],
      `comment names ${claim![1]}; the largest expected-script.hex is ${largest.fixture}`,
    ).toBe(largest.fixture);
  });

  it('states that script’s real byte and hex-character sizes', () => {
    const chars = hexChars(claim![1]!);
    expect(num(claim![3]!), 'hex-character count').toBe(chars);
    expect(num(claim![2]!), 'script-byte count').toBe(chars / 2);
  });

  it('states the real utilisation and headroom against MAX_STRING_BYTES', () => {
    const chars = hexChars(claim![1]!);
    const pct = (chars / InputLimits.MAX_STRING_BYTES) * 100;
    const headroom = InputLimits.MAX_STRING_BYTES / chars;
    // One decimal place is the precision the comment states; require it to
    // round to the same figure rather than to match a float exactly.
    expect(Number(claim![4]), `utilisation: comment ${claim![4]}%, measured ${pct.toFixed(1)}%`)
      .toBeCloseTo(pct, 1);
    expect(
      Number(claim![5]),
      `headroom: comment ${claim![5]}×, measured ${headroom.toFixed(2)}×`,
    ).toBeCloseTo(headroom, 2);
  });

  it('the hex-doubling consequence it states matches the two constants', () => {
    // "capped at 2 MiB of script — HALF the advertised script bound"
    const stated = comment.match(/capped at (\d+) MiB of script/);
    expect(stated, 'the hex-doubling sentence has moved or changed shape').not.toBeNull();
    const effectiveScriptMiB = InputLimits.MAX_STRING_BYTES / 2 / (1024 * 1024);
    expect(Number(stated![1])).toBe(effectiveScriptMiB);
    // ...and it really is half of MAX_SCRIPT_BYTES, which is the point.
    expect(effectiveScriptMiB * 2 * 1024 * 1024).toBe(InputLimits.MAX_SCRIPT_BYTES);
  });

  it('the artifact it names as NOT the worst case is still small', () => {
    // The old justification pointed at the Groth16 VK. Keeping the counter-
    // example honest matters: if that file ever did become the binding case,
    // the paragraph would be telling the reader the opposite of the truth.
    const vk = join(repoRoot, 'examples', 'go', 'SP1Verifier.groth16.vk.json');
    const stated = comment.match(/`examples\/go\/SP1Verifier\.groth16\.vk\.json`, is ([\d,]+) bytes/);
    expect(stated, 'the Groth16-VK counter-example sentence has moved').not.toBeNull();
    expect(existsSync(vk), 'the named VK artifact no longer exists').toBe(true);
    expect(num(stated![1]!)).toBe(statSync(vk).size);
    expect(statSync(vk).size).toBeLessThan(hexChars(largestFixtureFile('expected-script.hex').fixture));
  });
});

describe('R-305: the MAX_IR_BYTES justification is measured, not asserted', () => {
  const claim = comment.match(
    /largest compiled-IR JSON in the corpus is `conformance\/tests\/([a-z0-9-]+)\/expected-ir\.json` at ([\d,]+) B \(([\d.]+) MiB\), so 16 MiB is ~(\d+)× headroom/,
  );

  it('the justification sentence is present and parseable', () => {
    expect(claim, `${LIMITS_FILE} no longer states the largest-IR measurement`).not.toBeNull();
  });

  it('names the actually-largest expected-ir.json and its real size', () => {
    const largest = largestFixtureFile('expected-ir.json');
    expect(claim![1], `comment names ${claim![1]}; largest is ${largest.fixture}`).toBe(
      largest.fixture,
    );
    expect(num(claim![2]!)).toBe(largest.bytes);
    expect(Number(claim![3])).toBeCloseTo(largest.bytes / (1024 * 1024), 3);
  });

  it('states headroom that matches the constant', () => {
    const largest = largestFixtureFile('expected-ir.json');
    const headroom = InputLimits.MAX_IR_BYTES / largest.bytes;
    // The comment rounds to a whole multiple; allow ±5 on a ~190× figure so a
    // one-byte golden churn does not redden it, but not the 24× the old
    // "~2 MiB / 8×" claim was out by.
    expect(
      Math.abs(Number(claim![4]) - headroom),
      `headroom: comment ~${claim![4]}×, measured ${headroom.toFixed(1)}×`,
    ).toBeLessThan(5);
  });
});

describe('R-305: anti-vacuity', () => {
  it('the corpus the guard measures against is real', () => {
    const script = largestFixtureFile('expected-script.hex');
    const ir = largestFixtureFile('expected-ir.json');
    expect(script.bytes).toBeGreaterThan(1_000_000);
    expect(ir.bytes).toBeGreaterThan(10_000);
    expect(script.fixture).not.toBe('');
    expect(ir.fixture).not.toBe('');
    // The two worst cases are different fixtures — a measurement bug that
    // returned one file for both would otherwise go unnoticed.
    expect(script.fixture).not.toBe(ir.fixture);
  });

  it('the constants themselves are unchanged (this guard must never move one)', () => {
    expect(InputLimits.MAX_STRING_BYTES).toBe(4 * 1024 * 1024);
    expect(InputLimits.MAX_SCRIPT_BYTES).toBe(4 * 1024 * 1024);
    expect(InputLimits.MAX_IR_BYTES).toBe(16 * 1024 * 1024);
    expect(InputLimits.MAX_WIRE_NESTING).toBe(100);
    expect(InputLimits.MAX_NESTING).toBe(512);
    expect(InputLimits.MAX_SOURCE_BYTES).toBe(4 * 1024 * 1024);
  });
});
