import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { REPO, Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * F-249 — the Merkle-root codegen emitted three consecutive OP_ROTs per tree
 * level, on the 3-element window [current, sibling, direction_bit]. Three
 * rotations of a 3-cycle are the identity, so each level carried 3 dead bytes
 * (3 x depth per merkleRootSha256 / merkleRootHash256 call), and every tier
 * that ports the codegen (TS, Go, Rust, Python, Zig, Ruby) emitted them
 * identically. Java's Merkle.java is a refusing stub with no rot ops, so it is
 * not a tier under test here.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (version-1, strict), via
 * `newConsensusSpend` — never the ANF interpreter or TestContract.
 *
 * What this proves:
 *   - for every tier that has Merkle codegen, fold OFF and ON, each level of
 *     the unrolled walk is `OP_TOALTSTACK OP_IF OP_SWAP OP_ENDIF OP_CAT <hash>`
 *     (exactly `depth` of them) and the old `OP_TOALTSTACK OP_ROT OP_ROT OP_ROT
 *     OP_IF` window appears nowhere — checked by walking the script opcode by
 *     opcode, so push data cannot fake or hide a match;
 *   - every tier emits the TS reference bytes, and those bytes ACCEPT an
 *     honest proof against a root computed outside the compiler, and REJECT a
 *     proof with any one sibling byte tampered and an in-domain index with any
 *     one direction bit flipped — so the deleted rots were dead, not
 *     load-bearing, and all six tiers agreeing on a wrong script still fails;
 *   - the merkle-proof fixture compiles (fold OFF, every Merkle tier) to the
 *     checked-in golden, which is the pre-fix golden with exactly its eight
 *     per-level ROT ROT ROT runs removed (219 -> 195 bytes, 2 calls x depth 4
 *     x 3 bytes) and, since N-376, its two prologue ROT x6 runs too (-> 183),
 *     nothing else changed.
 * What it does NOT prove: anything about the OTHER identity-rot run in these
 * scripts — the six (merkle-proof) / three (state-covenant) OP_ROTs emitted
 * by generic stack lowering BEFORE the Merkle prologue, when load_param and
 * lowerMerkleRoot's bringToTop each roll leaf/proof/index from depth 2. That
 * is stack-lowering argument marshalling, a separate finding (N-376, removed
 * by the ROT ROT ROT -> [] peephole rule and proved in
 * n376-rot3-peephole-parity.test.ts); here it only enters the expected
 * golden. Nor Poseidon2 Merkle (a different codegen family).
 */

/** The merkle-proof fixture golden BEFORE F-249 (fold OFF, 219 bytes). */
const PRE_FIX_MERKLE_PROOF_GOLDEN =
  '76009c63757b7b7b7b7b7b760060a5697c01207f6b7c7652977c6b7b7b7b637c687ea86c6c01207f6b7c768e52977c6b7b7b7b637c687ea86c6c01207f6b7c7652b752977c6b7b7b7b637c687ea86c6c01207f6b7c7653b752977c6b7b7b7b637c687ea86c6c7c7582009d75008767519d7b7b7b7b7b7b760060a5697c01207f6b7c7652977c6b7b7b7b637c687eaa6c6c01207f6b7c768e52977c6b7b7b7b637c687eaa6c6c01207f6b7c7652b752977c6b7b7b7b637c687eaa6c6c01207f6b7c7653b752977c6b7b7b7b637c687eaa6c6c7c7582009d75008768';
const PRE_FIX_MERKLE_PROOF_BYTES = 219;
/** N-376: ROT x6 before each of the two Merkle prologues, removed by the ROT^3 rule. */
const N376_PROLOGUE_ROTS = 2 * 6;
/** Two Merkle calls (verifySha256 + verifyHash256), each depth 4. */
const MERKLE_PROOF_LEVELS = 2 * 4;

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

/** Number of positions where `ops` starts the opcode window `win`. */
function countWindow(ops: string[], win: string[]): number {
  let n = 0;
  for (let k = 0; k + win.length <= ops.length; k++) {
    if (win.every((w, j) => ops[k + j] === w)) n++;
  }
  return n;
}

const TOALT = '6b';
const ROT = '7b';
const IF = '63';
const SWAP = '7c';
const ENDIF = '68';
const CAT = '7e';
const SHA256 = 'a8';
const HASH256 = 'aa';
const OLD_LEVEL = [TOALT, ROT, ROT, ROT, IF];
const levelWindow = (h: string) => [TOALT, IF, SWAP, ENDIF, CAT, h];

const sha = (b: Buffer) => createHash('sha256').update(b).digest();
function refRoot(leaf: Buffer, proof: Buffer, index: number, depth: number, dbl: boolean): Buffer {
  let cur = leaf;
  for (let i = 0; i < depth; i++) {
    const sib = proof.subarray(i * 32, (i + 1) * 32);
    const buf = (index >> i) & 1 ? Buffer.concat([sib, cur]) : Buffer.concat([cur, sib]);
    cur = dbl ? sha(sha(buf)) : sha(buf);
  }
  return cur;
}

function pushBytes(b: Buffer): string {
  if (b.length <= 75) return b.length.toString(16).padStart(2, '0') + b.toString('hex');
  if (b.length <= 255) return '4c' + b.length.toString(16).padStart(2, '0') + b.toString('hex');
  throw new Error('pushBytes only handles <= 255 bytes');
}
/** Minimal push of a small non-negative script number. */
function pushNum(n: number): string {
  if (n === 0) return '00';
  if (n <= 16) return (0x50 + n).toString(16);
  if (n < 0x80) return '01' + n.toString(16).padStart(2, '0');
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

interface Shape {
  name: string;
  fn: 'merkleRootSha256' | 'merkleRootHash256';
  depth: number;
  index: number;
}
const SHAPES: Shape[] = [
  { name: 'merkleRootSha256 depth 2', fn: 'merkleRootSha256', depth: 2, index: 2 },
  { name: 'merkleRootHash256 depth 3', fn: 'merkleRootHash256', depth: 3, index: 5 },
  { name: 'merkleRootSha256 depth 4', fn: 'merkleRootSha256', depth: 4, index: 11 },
];

function inputs(depth: number): { leaf: Buffer; proof: Buffer } {
  const leaf = Buffer.alloc(32, 0);
  leaf[31] = 0xaa;
  const proof = Buffer.alloc(32 * depth, 0);
  for (let i = 0; i < depth; i++) proof[i * 32 + 31] = i + 1;
  return { leaf, proof };
}

function shapeSource(s: Shape, root: Buffer): string {
  return `import { SmartContract, assert, toByteString, ${s.fn} } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class F249M extends SmartContract {
  constructor() { super(); }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    assert(${s.fn}(leaf, proof, index, ${s.depth}n) === toByteString('${root.toString('hex')}'));
  }
}
`;
}

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
// Java's Merkle.java is a refusing stub (no Merkle codegen), so it is not a tier
// that can carry this defect; every other tier ports merkle-codegen.ts.
const MERKLE_TIER_IDS = ['ts', 'go', 'rust', 'python', 'zig', 'ruby'];
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null && MERKLE_TIER_IDS.includes(t.id));
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f249-merkle-rot-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

function assertLevelShape(hex: string, depth: number, hashOp: string): void {
  const ops = walk(hex);
  expect(countWindow(ops, OLD_LEVEL), 'a Merkle level still carries ROT ROT ROT before OP_IF').toBe(0);
  expect(countWindow(ops, levelWindow(hashOp)), 'per-level TOALTSTACK IF SWAP ENDIF CAT <hash> count').toBe(depth);
}

describe('F-249 Merkle levels carry no identity ROT ROT ROT — six tiers, executed on @bsv/sdk', () => {
  it('the TS reference and at least one other Merkle tier are available (all six in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(MERKLE_TIER_IDS.length);
  });

  for (const [i, s] of SHAPES.entries()) {
    const dbl = s.fn === 'merkleRootHash256';
    const hashOp = dbl ? HASH256 : SHA256;
    const { leaf, proof } = inputs(s.depth);
    const root = refRoot(leaf, proof, s.index, s.depth, dbl);
    const src = shapeSource(s, root);
    const unlock = (p: Buffer, idx: number) => pushBytes(leaf) + pushBytes(p) + pushNum(idx);

    for (const mode of MODES) {
      describe(`${s.name} (${mode.label})`, () => {
        let tsHex = '';
        beforeAll(() => {
          tsHex = compileHex(mode.tier(TS_TIER!), write(`S${i}.runar.ts`, src));
        }, 240_000);

        for (const tier of TIERS) {
          it(`${tier.id}: per-level shape, TS bytes, honest accept, tampered sibling / flipped bit reject`, () => {
            const hex = tier.id === 'ts' ? tsHex : compileHex(mode.tier(tier), write(`S${i}.runar.ts`, src));
            assertLevelShape(hex, s.depth, hashOp);
            expect(accepts(hex, unlock(proof, s.index)), 'honest proof rejected').toBe(true);
            for (let lvl = 0; lvl < s.depth; lvl++) {
              const bad = Buffer.from(proof);
              bad[lvl * 32 + 7] = bad[lvl * 32 + 7]! ^ 0x01;
              expect(accepts(hex, unlock(bad, s.index)), `tampered sibling at level ${lvl} accepted`).toBe(false);
              const flipped = s.index ^ (1 << lvl); // still in [0, 2^depth)
              expect(accepts(hex, unlock(proof, flipped)), `direction bit ${lvl} flipped accepted`).toBe(false);
            }
            expect(hex).toBe(tsHex);
          }, 240_000);
        }
      });
    }
  }

  describe('merkle-proof fixture (fold OFF) vs the pre-fix golden', () => {
    const fixtureSrc = join(REPO, 'examples/ts/merkle-proof/MerkleProofDemo.runar.ts');
    const golden = () =>
      readFileSync(join(REPO, 'conformance/tests/merkle-proof/expected-script.hex'), 'utf-8').trim();

    it('the pre-fix constant is what it claims to be', () => {
      expect(PRE_FIX_MERKLE_PROOF_GOLDEN.length / 2).toBe(PRE_FIX_MERKLE_PROOF_BYTES);
      expect(countWindow(walk(PRE_FIX_MERKLE_PROOF_GOLDEN), OLD_LEVEL)).toBe(MERKLE_PROOF_LEVELS);
    });

    it('the golden is the pre-fix golden with exactly the per-level ROT ROT ROT runs (and, N-376, the prologue ROT x6 runs) removed', () => {
      const expected: string[] = [];
      const old = walk(PRE_FIX_MERKLE_PROOF_GOLDEN);
      for (let k = 0; k < old.length; k++) {
        if (OLD_LEVEL.every((w, j) => old[k + j] === w)) {
          expected.push(TOALT);
          k += 3; // skip the three ROTs; OP_IF is pushed on the next iteration
          continue;
        }
        expected.push(old[k]!);
      }
      // N-376: the remaining ROT runs (the two prologue ROT x6) go to length mod 3.
      const afterN376: string[] = [];
      let run = 0;
      const flush = () => {
        for (let r = 0; r < run % 3; r++) afterN376.push(ROT);
        run = 0;
      };
      for (const op of expected) {
        if (op === ROT) {
          run++;
          continue;
        }
        flush();
        afterN376.push(op);
      }
      flush();
      expect(walk(golden())).toEqual(afterN376);
      expect(golden().length / 2).toBe(
        PRE_FIX_MERKLE_PROOF_BYTES - 3 * MERKLE_PROOF_LEVELS - N376_PROLOGUE_ROTS,
      );
    });

    for (const tier of TIERS) {
      it(`${tier.id} compiles the fixture to the golden`, () => {
        expect(compileHex(foldOff(tier), fixtureSrc)).toBe(golden());
      }, 240_000);
    }
  });
});
