import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { emitMethod, emitMerkleRootSha256, emitMerkleRootHash256 } from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * R-120 — the Merkle index was an unbounded witness, and the proof remainder
 * was dropped without ever being looked at.
 *
 * `emitMerkleRoot` unrolls `depth` levels and consults bit i of the index at
 * level i. Nothing above bit `depth - 1` is ever read; the index is then
 * simply dropped. So `index`, `index + 2**depth`, `index + 2**40` and any
 * NEGATIVE index walk the identical path and return the identical root.
 * Measured on this file's engine — @bsv/sdk's `Spend`, the same one
 * `runar-cli debug` and the differential oracle use — at depth 2, before the
 * gate landed:
 *
 *     merkleRoot(idx=1)    -> 5306f72f…6ee0f336
 *     merkleRoot(idx=5)    -> 5306f72f…6ee0f336
 *     merkleRoot(idx=1025) -> 5306f72f…6ee0f336
 *     merkleRoot(idx=-1)   -> 5306f72f…6ee0f336
 *
 * A contract asserting "leaf L sits at position i of the tree rooted at R"
 * therefore constrained nothing about i beyond its low `depth` bits: one
 * accepted proof was simultaneously a proof for every index in the same
 * residue class mod 2**depth. Where the index IS the commitment — a UTXO-set
 * slot, a nullifier position, a FRI query index — that is the whole property.
 *
 * The proof blob had the same shape of hole: each level OP_SPLITs 32 bytes off
 * the front, and the leftover was dropped unexamined, so a blob of
 * 32*depth + k bytes verified for every k >= 0 and produced the same root.
 * Depth 2, measured: 64, 65, 96 and 128 bytes all returned 5306f72f…6ee0f336.
 *
 * THE FIX ABORTS rather than reducing. These are VALUE builtins, and
 * CL-BUG-095 set the policy that predicates clamp and flag while value
 * producers OP_VERIFY. Reducing the index mod 2**depth would keep exactly
 * today's aliasing under a politer name.
 *
 *     prologue:  OP_DUP <0> <2**depth> OP_WITHIN OP_VERIFY
 *     epilogue:  OP_SIZE <0> OP_NUMEQUALVERIFY
 *
 * A SHORT proof already aborted inside OP_SPLIT, so only the over-long
 * direction needed closing.
 *
 * Everything below is EXECUTED on @bsv/sdk's `Spend`.
 */

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function run(pushes: StackOp[], emitFn: (e: (op: StackOp) => void) => void) {
  const ops: StackOp[] = [...pushes];
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return {
    rejected: r.error !== undefined,
    top: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '',
  };
}

const bytes = (b: Uint8Array) => ({ op: 'push', value: b }) as StackOp;
const num = (n: bigint) => ({ op: 'push', value: n }) as StackOp;

/** The off-chain reference walk, so an ACCEPT is proved to be the right root. */
function refRoot(leaf: Uint8Array, proof: Uint8Array, index: bigint, depth: number, double: boolean) {
  let cur = leaf;
  for (let i = 0; i < depth; i++) {
    const sib = proof.subarray(i * 32, (i + 1) * 32);
    const buf = new Uint8Array(64);
    if ((index >> BigInt(i)) & 1n) { buf.set(sib, 0); buf.set(cur, 32); }
    else { buf.set(cur, 0); buf.set(sib, 32); }
    const h1 = createHash('sha256').update(buf).digest();
    cur = double ? new Uint8Array(createHash('sha256').update(h1).digest()) : new Uint8Array(h1);
  }
  return cur;
}

const VARIANTS = [
  { name: 'merkleRootSha256', emit: emitMerkleRootSha256, double: false },
  { name: 'merkleRootHash256', emit: emitMerkleRootHash256, double: true },
] as const;

describe.each(VARIANTS)('R-120 index domain + proof length — $name', (V) => {
  const DEPTH = 3;
  const leaf = new Uint8Array(32); leaf[31] = 0xaa;
  const proof = new Uint8Array(32 * DEPTH);
  for (let i = 0; i < DEPTH; i++) proof[i * 32 + 31] = i + 1;
  const go = (index: bigint, pf: Uint8Array = proof) =>
    run([bytes(leaf), bytes(pf), num(index)], (e) => V.emit(e, DEPTH));

  it('ASSERTION — an index carrying a bit at or above `depth` is REJECTED', () => {
    for (const idx of [1n, 3n, 5n, 7n]) {
      for (const add of [8n, 16n, 1024n, 1n << 40n]) {
        expect(go(idx + add).rejected, `index ${idx + add}`).toBe(true);
      }
    }
  });

  it('ASSERTION — a NEGATIVE index is REJECTED (OP_WITHIN\'s lower bound)', () => {
    for (const neg of [-1n, -8n, -1024n]) {
      expect(go(neg).rejected, `index ${neg}`).toBe(true);
    }
  });

  it('ASSERTION — a proof longer than 32*depth is REJECTED', () => {
    for (const extra of [1, 2, 31, 32, 64]) {
      const long = new Uint8Array(proof.length + extra);
      long.set(proof, 0);
      expect(go(5n, long).rejected, `${long.length} bytes`).toBe(true);
    }
  });

  it('ASSERTION — a SHORT proof stays rejected (it always aborted in OP_SPLIT)', () => {
    for (const missing of [1, 32]) {
      expect(go(5n, proof.subarray(0, proof.length - missing)).rejected).toBe(true);
    }
  });

  // ---------------------------------------------------------------------
  // Controls. Each must STAY green; an over-strict gate reddens them.
  // ---------------------------------------------------------------------

  it('CONTROL — every in-domain index still computes the RIGHT root', () => {
    for (let idx = 0n; idx < 1n << BigInt(DEPTH); idx++) {
      const r = go(idx);
      expect(r.rejected, `index ${idx}`).toBe(false);
      expect(r.top).toBe(hex(refRoot(leaf, proof, idx, DEPTH, V.double)));
    }
  });

  it('BOUNDARY — 2**depth - 1 is accepted and 2**depth is not', () => {
    expect(go((1n << BigInt(DEPTH)) - 1n).rejected).toBe(false);
    expect(go(1n << BigInt(DEPTH)).rejected).toBe(true);
  });

  it('BOUNDARY — an exactly-32*depth proof is accepted, one byte more is not', () => {
    expect(go(0n, proof).rejected).toBe(false);
    const plusOne = new Uint8Array(proof.length + 1);
    plusOne.set(proof, 0);
    expect(go(0n, plusOne).rejected).toBe(true);
  });
});

/**
 * The reference interpreter must refuse on the SAME bound as the script — the
 * three-places rule `pow` (R-169) established. Without this, the source-vs-
 * script differential oracle disagrees on every out-of-domain witness and
 * `TestContract` keeps telling an author a spend works that the chain rejects.
 * (There is no third place here: the constant folder does not fold these
 * builtins, so guard + interpreter is the whole set.)
 */
describe('R-120 the interpreter refuses what the script refuses', () => {
  const SRC = `
class MerkleDomain extends SmartContract {
  readonly root: ByteString;
  constructor(root: ByteString) { super(root); this.root = root; }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    assert(merkleRootSha256(leaf, proof, index, 2n) === this.root);
  }
}
`;
  const leaf = new Uint8Array(32); leaf[31] = 0xaa;
  const proof = new Uint8Array(64); proof[31] = 1; proof[63] = 2;
  const root = refRoot(leaf, proof, 1n, 2, false);
  // TestContract's arg coercion reads a plain hex STRING (no `0x` prefix —
  // `toRunarValue` parses two characters at a time, so a prefix becomes a
  // leading 0x00 byte).
  const hx = (b: Uint8Array) => hex(b);

  it('accepts the in-domain index and refuses index + 2**depth', async () => {
    const { TestContract } = await import('../index.js');
    const c = TestContract.fromSource(SRC, { root: hx(root) }, 'MerkleDomain.runar.ts');
    const spend = (index: bigint, pf: Uint8Array = proof) =>
      c.call('verify', { leaf: hx(leaf), proof: hx(pf), index });
    expect(spend(1n).success).toBe(true);
    for (const bad of [5n, 9n, -1n]) {
      const r = spend(bad);
      expect(r.success, `index ${bad}`).toBe(false);
      // The message must name the DOMAIN, not just "assert failed" — the
      // builtin refuses before the comparison, which is what distinguishes
      // a domain refusal from an ordinary near-miss.
      expect(r.error).toMatch(/outside \[0, 2\^2\)/);
    }
  });

  it('refuses an over-long proof', async () => {
    const { TestContract } = await import('../index.js');
    const c = TestContract.fromSource(SRC, { root: hx(root) }, 'MerkleDomain.runar.ts');
    const long = new Uint8Array(96); long.set(proof, 0);
    const r = c.call('verify', { leaf: hx(leaf), proof: hx(long), index: 1n });
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/expected exactly 64/);
  });
});
