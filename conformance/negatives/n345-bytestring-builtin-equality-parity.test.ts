import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-345: seven-tier parity for `===` / `!==` / `+` on the RESULT of a
 * ByteString-returning builtin.
 *
 * Pass 4 decides OP_EQUAL vs OP_NUMEQUAL (and OP_CAT vs OP_ADD) from a
 * per-tier list of builtins that return bytes. The seven lists disagreed:
 * TS and Rust lacked `toByteString` and `pack`, so `toByteString(a) ===
 * toByteString(b)` compiled to OP_NUMEQUAL there and OP_EQUAL in the other
 * five; TS, Python, Zig, Ruby and Java lacked `sha256Compress` and
 * `sha256Finalize` (OP_NUMEQUAL there, OP_EQUAL in Go and Rust); and no tier
 * listed `split` or `buildChangeOutput`, so all seven compared those results
 * numerically. Numeric equality on bytes is under-strict: `0100` and `01`
 * are both the number 1, so a covenant comparing them accepts bytes it should
 * refuse.
 *
 * What this proves: every available tier's CLI, in both fold modes, compiles
 * each shape below to the same pinned bytes, and those bytes use OP_EQUAL
 * (87) / OP_EQUAL OP_NOT (87 91) for ByteString equality and OP_CAT (7e) for
 * ByteString `+`. The controls (a ByteString parameter on one side, `cat`,
 * `sha256`) were already right and stay unchanged. The @bsv/sdk execution of the fixed and the pre-fix TS bytes is
 * in packages/runar-compiler/src/__tests__/04-anf-lower.test.ts (N-345).
 * What it does NOT prove: execution of each peer tier's bytes (pinned
 * byte-identical to the TS bytes that are executed), the non-TS source
 * surfaces (every parser lowers to the same AST these lists are consulted
 * on), or byte-returning builtins outside the shapes listed here.
 */

const contract = (name: string, body: string) => `import { SmartContract, assert, ByteString, toByteString, pack, sha256Compress, sha256Finalize, buildChangeOutput, split, cat, sha256, len } from 'runar-lang';

class ${name} extends SmartContract {
  constructor() {
    super();
  }

  public unlock(a: ByteString, b: ByteString, x: bigint, y: bigint) {
    ${body}
  }
}
`;

const CHANGE = '537a5279041976a9147b7e0288ac7e7c58807c7e537a537a041976a9147b7e0288ac7e7c58807c7e';

interface Case {
  name: string;
  body: string;
  /** Expected hex (both fold modes unless `foldOn` is given). */
  hex?: string;
  foldOn?: string;
  /** For the large SHA-256 scripts: sha256 of the hex string, plus its tail. */
  sha?: string;
  tail?: string;
}

const CASES: Case[] = [
  { name: 'TbsParams', body: 'assert(toByteString(a) === toByteString(b));', hex: '537a537a877777' },
  { name: 'TbsParamsNe', body: 'assert(toByteString(a) !== toByteString(b));', hex: '537a537a87917777' },
  { name: 'TbsLocal', body: 'const c = toByteString(a); const d = toByteString(b); assert(c === d);', hex: '537a537a877777' },
  { name: 'TbsPlus', body: 'assert(len(toByteString(a) + toByteString(b)) === x);', hex: '537a537a7e82777b9c77' },
  { name: 'PackEq', body: 'assert(pack(x) === pack(y));', hex: '877777' },
  { name: 'PackPlus', body: 'assert(len(pack(x) + pack(y)) === x);', hex: '787c7e82777c9c7777' },
  { name: 'SplitEq', body: 'assert(split(a, x) === split(b, x));', hex: '537a52797f77537a537a7f778777' },
  { name: 'ChangeEq', body: 'assert(buildChangeOutput(a, x) === buildChangeOutput(b, x));', hex: `${CHANGE}8777` },
  { name: 'ChangeNe', body: 'assert(buildChangeOutput(a, x) !== buildChangeOutput(b, x));', hex: `${CHANGE}879177` },
  {
    name: 'Sha256CompressEq', body: 'assert(sha256Compress(a, b) === sha256Compress(b, a));',
    sha: '619b6056c05a3935d1ebeec7d60bdb3c77e23499541e245711d244d0779a2bc1', tail: '757c75877777',
  },
  {
    name: 'Sha256FinalizeEq', body: 'assert(sha256Finalize(a, b, x) === sha256Finalize(b, a, x));',
    // N-376 re-stamp: the ROT ROT ROT -> [] peephole rule deletes 6 identity
    // OP_ROTs (opcode-walk checked); was b0eced81d5cb1cc9….
    sha: '593f2b477176d0755ef9f0d64c459dd3366741339848bf4aaaf54f085194f45e', tail: '757c75688777',
  },
  // Fold-ON already folds this to false in every tier; fold-OFF TS and Rust
  // compiled OP_NUMEQUAL, which is TRUE on-chain for 0100 vs 01.
  {
    name: 'TbsLit', body: "assert(toByteString('0100') === toByteString('01'));",
    hex: '020100518777777777', foldOn: '0201005100777777777777',
  },
  // Controls: already OP_EQUAL in every tier.
  { name: 'TbsVsParam', body: 'assert(toByteString(a) === b);', hex: '537a537a877777' },
  { name: 'CatEq', body: 'assert(cat(a, b) === cat(b, a));', hex: '537953797e537a547a7e877777' },
  { name: 'ShaEq', body: 'assert(sha256(a) === sha256(b));', hex: '537aa8537aa8877777' },
];

const DIR = mkdtempSync(join(tmpdir(), 'n345-bytestring-builtin-eq-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const foldOff = (t: Tier): Tier => ({
  ...t,
  argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'],
});
const sha256Hex = (s: string) => createHash('sha256').update(s).digest('hex');

describe('N-345: ByteString-returning builtins compare with OP_EQUAL in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const c of CASES) {
    const file = join(DIR, `${c.name}.runar.ts`);
    writeFileSync(file, contract(c.name, c.body));
    for (const tier of tiers) {
      for (const mode of ['fold-ON', 'fold-OFF'] as const) {
        it(`${tier.id} ${mode} compiles \`${c.body}\``, () => {
          const hex = compileHex(mode === 'fold-ON' ? tier : foldOff(tier), file);
          if (c.sha !== undefined) {
            expect(hex.slice(-c.tail!.length)).toBe(c.tail);
            expect(sha256Hex(hex)).toBe(c.sha);
          } else {
            expect(hex).toBe(mode === 'fold-ON' && c.foldOn !== undefined ? c.foldOn : c.hex);
          }
        }, tier.timeoutMs);
      }
    }
  }
});
