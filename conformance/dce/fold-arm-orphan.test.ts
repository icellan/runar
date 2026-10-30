import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ScriptVM } from 'runar-testing';
import {
  ALL_TIER_IDS,
  REPO,
  Tier,
  buildSourceTiers,
  compileHex,
  missingTierIds,
} from '../negatives/tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-446 — under constant folding (the default) an operand binding the folder
 * orphaned INSIDE an `if` arm survived, and the arms came out unbalanced.
 *
 * `-5n` lowers to `t0 = 5; t1 = -t0`. The folder rewrites `t1` to `-5`, and
 * the N-138 prune (`foldConstantsAndPrune` and its six ports) removes the
 * orphaned `t0` — but only among the method's TOP-LEVEL bindings. In an arm
 * `t0` stayed, stack lowering pushed it, and the else arm ended one slot
 * deeper than the then arm. Go refused the contract with "conditional needs 1
 * placeholder push(es) to balance a NON-EMPTY then arm"; TS, Rust, Python,
 * Zig, Ruby and Java padded the then arm with OP_0 and emitted
 * `…69 00 67 76 55 01 85 7b 7c a0 69 68 7c …` (push 5, push -5, swap the dead 5
 * away later). Fold-OFF, all seven accepted it.
 *
 * What this proves: every tier ACCEPTS both fixtures under the default fold-ON
 * compile, the bytes are identical across tiers and carry no orphan push and
 * no pad (pinned below), and the script executes with the source's semantics
 * for accepting and rejecting `p` on both arms.
 *
 * What it does not prove: that no other folded shape leaves a nested orphan
 * (the fold-ON fuzz campaign, `conformance/fuzzer --ir --hex --fold-on`, is
 * the broad check), nor anything about fold-OFF bytes — the prune runs only
 * when folding is on.
 */

const FIXTURES = [
  {
    file: 'FoldArmOrphan.runar.ts',
    // Pre-fix TS: 7600a0637657a0690067765501857b7ca069687c599c9177 (pad + orphan).
    hex: '7600a0637657a06967760185a06968599c91',
  },
  {
    file: 'FoldArmOrphanInLoop.runar.ts',
    hex: '007800a0637857a06967780185a0696875517800a0637857a06967780185a0696875599c91',
  },
];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** Minimal script-number push of `n`, as an unlocking script. */
function pushInt(n: number): Uint8Array {
  if (n === 0) return new Uint8Array([0x00]);
  if (n === -1) return new Uint8Array([0x4f]);
  if (n >= 1 && n <= 16) return new Uint8Array([0x50 + n]);
  const neg = n < 0;
  let a = Math.abs(n);
  const bytes: number[] = [];
  while (a > 0) {
    bytes.push(a & 0xff);
    a >>= 8;
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1]! |= 0x80;
  return new Uint8Array([bytes.length, ...bytes]);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Source semantics: (p > 0 ? p > 7 : p > -5) && p !== 9. */
const SPENDS = [
  { p: 8, ok: true },
  { p: 10, ok: true },
  { p: 0, ok: true },
  { p: -1, ok: true },
  { p: -4, ok: true },
  { p: 1, ok: false },
  { p: 7, ok: false },
  { p: 9, ok: false },
  { p: -5, ok: false },
  { p: -6, ok: false },
];

describe('N-446 fold-ON: an operand orphaned inside an if arm is pruned', () => {
  it('the matrix names all seven tiers (a silently dropped tier fails here)', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = missingTierIds(TIERS);
    if (isCiEnv(process.env) || process.env.RUNAR_CONFORMANCE_STRICT) {
      expect(missing, `these tiers have no toolchain: ${missing.join(', ')}`).toEqual([]);
    }
    expect(available.length, `REPO=${REPO}`).toBeGreaterThanOrEqual(2);
  });

  for (const { file, hex: expected } of FIXTURES) {
    const source = join(__dirname, file);
    for (const tier of available) {
      it(`${tier.id}: ${file} compiles fold-ON to the balanced, orphan-free script`, () => {
        expect(compileHex(tier, source)).toBe(expected);
      });

      it(`${tier.id}: ${file} executes with the source's semantics`, () => {
        const lock = hexToBytes(compileHex(tier, source));
        for (const { p, ok } of SPENDS) {
          const res = new ScriptVM().execute(pushInt(p), lock);
          expect(res.success, `${tier.id} ${file} p=${p} error=${res.error ?? '(none)'}`).toBe(ok);
        }
      });
    }
  }
});
