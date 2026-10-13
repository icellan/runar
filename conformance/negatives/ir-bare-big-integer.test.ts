import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  IR_TIER_IDS,
  REPO,
  TS_TIMEOUT,
  Tier,
  buildIrTiers,
  compileHex,
  resolveTsxLoader,
} from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * ---------------------------------------------------------------------------
 * N-212 — a bare JSON integer wider than 2^53 on the `--ir` boundary
 * ---------------------------------------------------------------------------
 *
 * `anf-ir.schema.json` types `load_const.value` and `initialValue` as
 * `string | integer | boolean`, and JSON puts no width limit on an integer.
 * Go, Python and Ruby `--emit-ir` write an oversize property initializer as a
 * bare number. Measured before the fix, fold-off, with the secp256k1 order N
 * written bare:
 *
 *   load_const    ts REFUSE · go/python/zig/ruby/java exact
 *                 · RUST i128::MAX (10ffff…7f)
 *   initialValue  ts REFUSE · python/zig/ruby/java exact
 *                 · GO i64::MAX (08ffff…7f) · RUST i128::MAX
 *   initialValue 9007199254740993 (2^53+1): GO pushed 2^53
 *
 * Decision R82 is to parse exactly everywhere. Go reads `initialValue` through
 * json.Number, Rust keeps the raw token of a wide constant, and TS reads it
 * from the JSON.parse reviver's `context.source` (Node >= 21; on Node 20 TS
 * still refuses, and this gate then reports TS as BrokenTier and fails).
 *
 * The fixtures are CONTROLS, not `I*` negatives: `ir-rejection-parity` requires
 * every tier to refuse everything in `./ir/`, and these must compile.
 *
 * Proves: all seven tiers, driven through their real `--ir` / `--from-ir` CLI,
 * emit byte-identical scripts carrying the EXACT push of N in both positions,
 * and still agree on the bare 2^53-1 control.
 * Does not prove: anything about float syntax (ir-float-boundary.test.ts) or
 * about `loop.start` (ir-loop-start-boundary.test.ts).
 */

const CONTROL_DIR = join(__dirname, 'ir', 'controls');

/** Minimal little-endian Script-number push of N: 0x21, 32 bytes, 0x00 sign pad. */
const N_PUSH = '21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00';
/** 2^53-1 = 0x1fffffffffffff, 7 bytes. */
const MAX_SAFE_PUSH = '07ffffffffffff1f';

/** The TS reference tier's IR consumer: `runar-cli compile --from-ir <f> --hex`. */
function tsIrTier(): Tier {
  const loader = resolveTsxLoader();
  const cli = join(REPO, 'packages/runar-cli/src/bin.ts');
  return {
    id: 'ts',
    cmd: loader && existsSync(cli) ? process.execPath : null,
    prefix: loader ? ['--import', loader, cli, 'compile'] : [],
    argsFor: (p) => ['--from-ir', p, '--hex'],
    cwd: REPO,
    timeoutMs: TS_TIMEOUT,
  };
}

const TIERS: Tier[] = [tsIrTier(), ...buildIrTiers()];
const available = TIERS.filter((t) => t.cmd !== null);

const CASES: ReadonlyArray<readonly [string, string, string, number]> = [
  ['load_const = bare secp256k1 order', 'C16-load-const-bare-secp256k1-order.ir.json', N_PUSH, 1],
  ['initialValue = bare secp256k1 order', 'C17-initial-value-bare-secp256k1-order.ir.json', N_PUSH, 1],
  ['bare 2^53-1 in both positions (control)', 'C18-bare-max-safe-integer.ir.json', MAX_SAFE_PUSH, 2],
];

describe('N-212: bare JSON integers beyond 2^53 on --ir are parsed exactly', () => {
  it('the matrix names all seven tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual(['ts', ...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) {
      expect(missing, `no toolchain for: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const [shape, fixture, push, times] of CASES) {
    it(`all tiers push the exact value: ${shape} (${fixture})`, () => {
      const path = join(CONTROL_DIR, fixture);
      const byTier = available.map((t) => [t.id, compileHex(t, path)] as const);
      for (const [id, hex] of byTier) {
        expect(hex.split(push).length - 1, `${id} emitted ${hex}`).toBe(times);
      }
      const distinct = new Set(byTier.map(([, hex]) => hex));
      expect(
        distinct.size,
        `tiers disagree:\n${byTier.map(([id, hex]) => `  ${id}: ${hex}`).join('\n')}`,
      ).toBe(1);
    });
  }
});
