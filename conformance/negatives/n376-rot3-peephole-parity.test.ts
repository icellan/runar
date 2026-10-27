import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { optimizeStackIR } from '../../packages/runar-compiler/src/optimizer/peephole.js';
import type { StackOp } from '../../packages/runar-compiler/src/ir/index.js';
import { REPO, Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-376 — stack lowering marshals a 3-argument consumer whose arguments are
 * already the top three slots in order by rolling each from depth 2: three
 * OP_ROTs, the identity permutation on [a b c]. `load_param` does the same for
 * three consecutive parameters, so `within(x, lo, hi)` on the method's own
 * parameters lowers to ROT x6 + OP_WITHIN, and the merkle-proof prologue carries
 * ROT x6 per method. Every tier emits the same dead bytes (28 conformance
 * goldens carry them). The fix is a `ROT ROT ROT -> []` peephole rule in all
 * seven tiers.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules via `newConsensusSpend`, and an
 * opcode walk (push data cannot fake or hide a match) — never the ANF
 * interpreter or TestContract.
 *
 * What this proves:
 *   - every available tier, fold OFF and ON, compiles `assert(within(x, lo, hi))`
 *     on its own three parameters to the single opcode OP_WITHIN, with no
 *     ROT ROT ROT window left, and that script accepts an in-range spend and
 *     rejects an out-of-range one on @bsv/sdk;
 *   - the merkle-proof fixture compiles (fold OFF) to the current golden with
 *     every ROT run reduced to its length mod 3 and nothing else changed:
 *     195 -> 183 bytes, no `7b 7b 7b` opcode window;
 *   - the TS rule itself: ROT^3 -> [], ROT ROT is kept, ROT^4 -> one ROT
 *     (not dropped), ROT^6 -> [].
 * What it does NOT prove: anything about the longer `n ROLL`^(n+1) identity
 * cycles (oracle-price, price-bet, babybear-ext4, bn254-pairing), which this
 * rule deliberately leaves alone; nor that ROT^3 is never emitted across an
 * if-arm boundary (the peephole never spans one).
 */

const ROT = '7b';
const WITHIN = 'a5';

/** Split a script into whole opcodes (opcode byte plus any push payload). */
function walk(hex: string): string[] {
  const b = Buffer.from(hex, 'hex');
  const ops: string[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i]!;
    const start = i++;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) i += 1 + b[i]!;
    else if (op === 0x4d) i += 2 + b.readUInt16LE(i);
    else if (op === 0x4e) i += 4 + b.readUInt32LE(i);
    if (i > b.length) throw new Error(`truncated push at byte ${start}`);
    ops.push(b.subarray(start, i).toString('hex'));
  }
  return ops;
}

function rot3Windows(hex: string): number {
  const ops = walk(hex);
  let n = 0;
  for (let k = 0; k + 3 <= ops.length; k++) {
    if (ops[k] === ROT && ops[k + 1] === ROT && ops[k + 2] === ROT) n++;
  }
  return n;
}

/** Every maximal OP_ROT run of length n reduced to n mod 3; all else verbatim. */
function stripRot3(hex: string): string {
  const out: string[] = [];
  let run = 0;
  const flush = () => {
    for (let k = 0; k < run % 3; k++) out.push(ROT);
    run = 0;
  };
  for (const op of walk(hex)) {
    if (op === ROT) {
      run++;
      continue;
    }
    flush();
    out.push(op);
  }
  flush();
  return out.join('');
}

function pushNum(n: number): string {
  if (n === 0) return '00';
  if (n >= 1 && n <= 16) return (0x50 + n).toString(16);
  if (n > 16 && n < 0x80) return '01' + n.toString(16).padStart(2, '0');
  throw new Error('pushNum only handles 0..127');
}

function accepts(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

const WITHIN_SRC = `import { SmartContract, assert, within } from 'runar-lang';
class N376W extends SmartContract {
  constructor() { super(); }
  public check(x: bigint, lo: bigint, hi: bigint) {
    assert(within(x, lo, hi));
  }
}
`;

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n376-rot3-'));
});

describe('N-376 ROT ROT ROT is an identity and no tier emits it', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TIERS.some((t) => t.id === 'ts')).toBe(true);
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  describe('TS peephole rule', () => {
    const rots = (n: number): StackOp[] => Array.from({ length: n }, () => ({ op: 'rot' }) as StackOp);
    const shape = (ops: StackOp[]) => ops.map((o) => o.op);
    it('ROT^3 -> [] and ROT^6 -> []', () => {
      expect(shape(optimizeStackIR(rots(3)))).toEqual([]);
      expect(shape(optimizeStackIR(rots(6)))).toEqual([]);
    });
    it('control: ROT ROT is kept, ROT^4 is one ROT (not dropped)', () => {
      expect(shape(optimizeStackIR(rots(2)))).toEqual(['rot', 'rot']);
      expect(shape(optimizeStackIR(rots(4)))).toEqual(['rot']);
    });
  });

  for (const mode of MODES) {
    describe(`assert(within(x, lo, hi)) on the method's own parameters (${mode.label})`, () => {
      for (const tier of TIERS) {
        it(`${tier.id}: OP_WITHIN only, no ROT^3, accepts in range / rejects out of range`, () => {
          const p = join(dir, `W-${tier.id}.runar.ts`);
          writeFileSync(p, WITHIN_SRC);
          const hex = compileHex(mode.tier(tier), p);
          expect(rot3Windows(hex), `${tier.id} still emits ROT ROT ROT`).toBe(0);
          expect(hex).toBe(WITHIN);
          expect(accepts(hex, pushNum(5) + pushNum(1) + pushNum(10)), 'in-range rejected').toBe(true);
          expect(accepts(hex, pushNum(10) + pushNum(1) + pushNum(10)), 'hi bound accepted').toBe(false);
          expect(accepts(hex, pushNum(0) + pushNum(1) + pushNum(10)), 'below lo accepted').toBe(false);
        }, 240_000);
      }
    });
  }

  describe('merkle-proof fixture (fold OFF): every ROT run reduced mod 3, nothing else', () => {
    const fixtureSrc = join(REPO, 'examples/ts/merkle-proof/MerkleProofDemo.runar.ts');
    /** The merkle-proof golden before N-376 (after F-249), 195 bytes. */
    const PRE_N376 =
      '76009c63757b7b7b7b7b7b760060a5697c01207f6b7c7652977c6b637c687ea86c6c01207f6b7c768e52977c6b637c687ea86c6c01207f6b7c7652b752977c6b637c687ea86c6c01207f6b7c7653b752977c6b637c687ea86c6c7c7582009d75008767519d7b7b7b7b7b7b760060a5697c01207f6b7c7652977c6b637c687eaa6c6c01207f6b7c768e52977c6b637c687eaa6c6c01207f6b7c7652b752977c6b637c687eaa6c6c01207f6b7c7653b752977c6b637c687eaa6c6c7c7582009d75008768';
    it('the pre-N-376 constant is the 195-byte golden with 12 dead ROTs', () => {
      expect(PRE_N376.length / 2).toBe(195);
      expect(rot3Windows(PRE_N376)).toBeGreaterThan(0);
      expect(stripRot3(PRE_N376).length / 2).toBe(183);
    });
    // merkle-proof is a Go-only fixture; TS ports the Merkle codegen too.
    for (const tier of TIERS.filter((t) => t.id === 'ts' || t.id === 'go')) {
      it(`${tier.id} compiles it to the pre-N-376 golden minus the ROT^3 runs (183 bytes)`, () => {
        const hex = compileHex(foldOff(tier), fixtureSrc);
        expect(rot3Windows(hex)).toBe(0);
        expect(hex).toBe(stripRot3(PRE_N376));
        expect(hex.length / 2).toBe(183);
      }, 240_000);
    }
    it('the checked-in golden matches the compiler output', () => {
      const golden = readFileSync(join(REPO, 'conformance/tests/merkle-proof/expected-script.hex'), 'utf-8').trim();
      expect(golden).toBe(stripRot3(PRE_N376));
    });
  });
});
