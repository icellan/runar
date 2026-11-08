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
 * Execution-fuzzer finding (nightly seed 1351961626, FuzzContract94.method2):
 * the fold-ON compile accepted a spend the source rejects.
 *
 * Dead-binding elimination treated every `bin_op` as pure and therefore
 * removable. Purity is not totality (spec/semantics.md §3.7): `& | ^` abort on
 * operands of unequal byte length, `<< >>` abort on a negative count, and
 * `/ %` abort on a zero divisor. When folding orphaned such a binding — here a
 * `let` whose only reader is a comparison the folder decides — the N-138
 * prune deleted it, and with it the abort. The fold-ON script (the shipped
 * default) then accepted every input; fold-OFF and the interpreter reject the
 * inputs the partial operation fails on. All seven tiers share the DCE
 * definition, so cross-tier byte parity held throughout.
 *
 * What this proves: in every built tier, the fold-ON and fold-OFF scripts for
 * each fixture accept exactly the spends the source semantics accept (run on
 * the @bsv/sdk-backed ScriptVM), and both modes are byte-identical across
 * tiers and match the pins. `EcArmedDeadDiv` covers the second route to the
 * same predicate: `optimizeEC`'s unrestricted DCE sweep, which an EC call
 * anywhere in the program arms in both fold modes, so a partial binding that
 * is simply never read was deleted even with folding off.
 *
 * What it does not prove: that no other ANF kind marked pure can abort
 * (builtins that can abort are `call` nodes, already retained), nor anything
 * about operand-dependent totality — every `/ % & | ^ << >>` is kept, even
 * where its operands make it total.
 */

const FIXTURES = [
  {
    file: 'FoldOrphanPartialAnd.runar.ts',
    foldOff: '01297c8455559c77',
    // Pre-fix fold-ON: 5177 (OP_1 OP_NIP — accepts every p).
    foldOn: '01297c845177',
    spends: [
      { p: 1, ok: true },
      { p: -1, ok: true },
      { p: 127, ok: true },
      { p: 0, ok: false },
      { p: 300, ok: false },
      { p: -49253, ok: false },
    ],
  },
  {
    file: 'FoldOrphanPartialDiv.runar.ts',
    foldOff: '01647c9651519c77',
    // Pre-fix fold-ON: 5177.
    foldOn: '01647c965177',
    spends: [
      { p: 1, ok: true },
      { p: -7, ok: true },
      { p: 1000, ok: true },
      { p: 0, ok: false },
    ],
  },
  {
    file: 'FoldOrphanPartialShift.runar.ts',
    foldOff: '517c9851519c77',
    // Pre-fix fold-ON: 5177.
    foldOn: '517c985177',
    spends: [
      { p: 0, ok: true },
      { p: 3, ok: true },
      { p: -1, ok: false },
      { p: -5, ok: false },
    ],
  },
  {
    // The EC optimizer's DCE sweep is unrestricted and runs in BOTH fold
    // modes, so here fold-OFF moved too and no folding is needed: `q` is
    // simply never read.
    file: 'EcArmedDeadDiv.runar.ts',
    // Pre-fix fold-OFF and fold-ON: <G> 00 87 91 77 (no OP_DIV — p = 0 spends).
    // Post-fix both modes: 01 64 7c 96 (100 / p) <G> 00 87 91 77.
    foldOff: '01647c964079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b800879177',
    foldOn: '01647c964079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b800879177',
    spends: [
      { p: 1, ok: true },
      { p: -3, ok: true },
      { p: 0, ok: false },
    ],
  },
];

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function foldOff(tier: Tier): Tier {
  return { ...tier, argsFor: (s) => [...tier.argsFor(s), '--disable-constant-folding'] };
}

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

describe('fold-ON DCE keeps partial bin_ops whose result the fold orphaned', () => {
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

  for (const { file, foldOff: offHex, foldOn: onHex, spends } of FIXTURES) {
    const source = join(__dirname, file);
    for (const tier of available) {
      for (const [mode, t] of [
        ['fold-ON', tier],
        ['fold-OFF', foldOff(tier)],
      ] as const) {
        it(`${tier.id}: ${file} ${mode} executes with the source's semantics`, () => {
          const lock = hexToBytes(compileHex(t, source));
          for (const { p, ok } of spends) {
            const res = new ScriptVM().execute(pushInt(p), lock);
            expect(res.success, `${tier.id} ${mode} ${file} p=${p} error=${res.error ?? '(none)'}`).toBe(ok);
          }
        });
      }

      it(`${tier.id}: ${file} compiles fold-ON to the pinned script`, () => {
        expect(compileHex(tier, source)).toBe(onHex);
      });

      it(`${tier.id}: ${file} compiles fold-OFF to the pinned script`, () => {
        expect(compileHex(foldOff(tier), source)).toBe(offHex);
      });
    }
  }
});
