import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, Spend, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { ALL_TIER_IDS, BrokenTier, Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';
import { spawnSync } from 'node:child_process';

/**
 * D12 FE-F1 / FE-F4 / BM-F3 — seven tiers, every verdict executed on @bsv/sdk
 * `Spend` against the hex each tier's own CLI emits.
 *
 * FE-F1: `+` on byte strings lowered to OP_ADD and `===` / `!==` to
 * OP_NUMEQUAL whenever an ANF heuristic could not see a byte type (a ternary,
 * a private-method result, `this.arr[i]`, a bitwise result, or a local built
 * from one of those, even with an explicit `: ByteString` annotation). The
 * operator family now comes from the type checker; an operand whose type it
 * cannot resolve is a compile error.
 *
 * FE-F4: a private method's declared return type was ignored; it is now
 * enforced, and a call sees the declared type (Ruby, which has no return-type
 * syntax, gets the type inferred from the body with the full environment).
 *
 * BM-F3: reverseBytes reversed only the first 520 bytes and dropped the rest;
 * the script now aborts when the input is longer than 520 bytes.
 *
 * For each shape, every tier:
 *   - emits the TS reference bytes;
 *   - ACCEPTS the honest spend under the strict v1 rules (for `===`, with
 *     equal NON-MINIMAL operands, which OP_NUMEQUAL refuses outright);
 *   - REFUSES the wrong spend under the strict v1 rules AND under the relaxed
 *     (tx version 2) rules, where OP_NUMEQUAL / OP_ADD accepted it.
 * And the refusal corpus (d12-typed-operand-cases.json) is refused by every
 * tier with the shared diagnostic.
 *
 * Does not prove: anything about stateful continuations, the SDK / ANF
 * interpreters (which still reverse > 520 bytes in full; the script now
 * aborts, so the disagreement fails closed), or fold-OFF compilation (the
 * conformance runner's --disable-constant-folding lane covers the fixtures).
 */

const sha = (h: string): string => createHash('sha256').update(Buffer.from(h, 'hex')).digest('hex');

/** Minimal push (consensus MINIMALDATA). */
function push(h: string): string {
  const n = h.length / 2;
  if (n === 0) return '00';
  if (n === 1) {
    const b = parseInt(h, 16);
    if (b >= 1 && b <= 16) return (0x50 + b).toString(16);
    if (b === 0x81) return '4f';
  }
  if (n <= 75) return n.toString(16).padStart(2, '0') + h;
  if (n <= 255) return '4c' + n.toString(16).padStart(2, '0') + h;
  return '4d' + (n & 255).toString(16).padStart(2, '0') + (n >> 8).toString(16).padStart(2, '0') + h;
}

function strict(lock: string, pushes: string[]): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lock),
      unlockingScript: UnlockingScript.fromHex(pushes.map(push).join('')),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false;
  }
}

/** Chronicle relaxed rules: any spender may pick tx version 2. */
function relaxed(lock: string, pushes: string[]): boolean {
  try {
    return new Spend({
      ...CONSENSUS_SPEND_CONTEXT,
      transactionVersion: 2,
      lockingScript: LockingScript.fromHex(lock),
      unlockingScript: UnlockingScript.fromHex(pushes.map(push).join('')),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false;
  }
}

const HDR =
  "import { SmartContract, assert, ByteString, sha256, Sha256, FixedArray, toByteString, reverseBytes } from 'runar-lang';\n";
const ts = (cls: string, members: string): string =>
  `${HDR}class ${cls} extends SmartContract {\n  constructor() { super(); }\n${members}\n}\n`;

interface Shape {
  name: string;
  file: string;
  src: string;
  honest: string[][];
  wrong: string[][];
}

const T = '01'; // boolean true
const SHAPES: Shape[] = [
  {
    name: 'plus over ternary locals',
    file: 'PlusTernary.runar.ts',
    src: ts('PlusTernary', `  public unlock(c: boolean, a: ByteString, b: ByteString, h: Sha256) {
    const x = c ? a : b; const y = c ? b : a; assert(sha256(x + y) === h);
  }`),
    honest: [[T, 'aa01', 'bb02', sha('aa01bb02')]],
    wrong: [[T, '01', '02', sha('03')]],
  },
  {
    name: 'equality over ternary locals',
    file: 'EqTernary.runar.ts',
    src: ts('EqTernary', `  public unlock(c: boolean, a: ByteString, b: ByteString) {
    const x = c ? a : b; const y = c ? b : a; assert(x === y);
  }`),
    honest: [[T, '1200', '1200']],
    wrong: [[T, '01', '0100']],
  },
  {
    name: 'inequality over ternary locals',
    file: 'NeTernary.runar.ts',
    src: ts('NeTernary', `  public unlock(c: boolean, a: ByteString, b: ByteString) {
    const x = c ? a : b; const y = c ? b : a; assert(x !== y);
  }`),
    honest: [[T, '01', '0100']],
    wrong: [[T, '1200', '1200']],
  },
  {
    name: 'plus over private-helper results (annotated locals)',
    file: 'PlusHelper.runar.ts',
    src: ts('PlusHelper', `  private id(v: ByteString): ByteString { return v; }
  public unlock(a: ByteString, b: ByteString, h: Sha256) {
    const x: ByteString = this.id(a); const y: ByteString = this.id(b); assert(sha256(x + y) === h);
  }`),
    honest: [['aa01', 'bb02', sha('aa01bb02')]],
    wrong: [['01', '02', sha('03')]],
  },
  {
    name: 'equality over private-helper results',
    file: 'EqHelper.runar.ts',
    src: ts('EqHelper', `  private id(v: ByteString): ByteString { return v; }
  public unlock(a: ByteString, b: ByteString) { assert(this.id(a) === this.id(b)); }`),
    honest: [['1200', '1200']],
    wrong: [['01', '0100']],
  },
  {
    name: 'equality over hash-returning helper results',
    file: 'EqHashHelper.runar.ts',
    src: ts('EqHashHelper', `  private hh(x: ByteString): Sha256 { return sha256(x); }
  public unlock(a: ByteString, b: ByteString) { const p = this.hh(a); const q = this.hh(b); assert(p === q); }`),
    // sha256(fb01) ends in 0x0800: a non-minimal script number.
    honest: [['fb01', 'fb01']],
    wrong: [['aa', 'bb']],
  },
  {
    name: 'plus over FixedArray elements',
    file: 'PlusIndex.runar.ts',
    src: ts('PlusIndex', `  readonly ks: FixedArray<ByteString, 2> = [toByteString('aa01'), toByteString('bb02')];
  public unlock(i: bigint, j: bigint, h: Sha256) { assert(sha256(this.ks[i] + this.ks[j]) === h); }`),
    honest: [['', '01', sha('aa01bb02')]],
    // 0x01aa + 0x02bb = 0x0465, little-endian 6504
    wrong: [['', '01', sha('6504')]],
  },
  {
    name: 'equality over FixedArray elements',
    file: 'EqIndex.runar.ts',
    src: ts('EqIndex', `  readonly ks: FixedArray<ByteString, 4> = [toByteString('1200'), toByteString('1200'), toByteString('01'), toByteString('0100')];
  public unlock(i: bigint, j: bigint) { assert(this.ks[i] === this.ks[j]); }`),
    honest: [['', '01']],
    wrong: [['02', '03']],
  },
  {
    name: 'plus over bitwise results',
    file: 'PlusBitwise.runar.ts',
    src: ts('PlusBitwise', `  public unlock(a: ByteString, b: ByteString, d: ByteString, e: ByteString, h: Sha256) {
    const m = a & b; const n = d | e; assert(sha256(m + n) === h);
  }`),
    honest: [['ff01', '0f03', '1000', '0102', sha('0f011102')]],
    wrong: [['01', '01', '02', '02', sha('03')]],
  },
  {
    name: 'equality over bitwise results',
    file: 'EqBitwise.runar.ts',
    src: ts('EqBitwise', `  public unlock(a: ByteString, b: ByteString, d: ByteString, e: ByteString) {
    assert((a & b) === (d | e));
  }`),
    honest: [['1200', '1200', '1200', '0000']],
    wrong: [['01', '01', '0100', '0000']],
  },
  {
    name: 'equality over an inverted operand',
    file: 'EqInvert.runar.ts',
    src: ts('EqInvert', `  public unlock(a: ByteString, b: ByteString) { assert(~a === ~b); }`),
    honest: [['edff', 'edff']],
    wrong: [['fe', 'feff']],
  },
  {
    name: 'plus over annotated concatenation locals',
    file: 'PlusAnnotated.runar.ts',
    src: ts('PlusAnnotated', `  public unlock(a: ByteString, b: ByteString, d: ByteString, e: ByteString, h: Sha256) {
    const m: ByteString = a + b; const n: ByteString = d + e; assert(sha256(m + n) === h);
  }`),
    honest: [['aa', 'bb', 'cc', 'dd', sha('aabbccdd')]],
    // 0x0201 + 0x0403 = 0x0604, little-endian 0406
    wrong: [['01', '02', '03', '04', sha('0406')]],
  },
  {
    name: 'equality over annotated concatenation locals',
    file: 'EqAnnotated.runar.ts',
    src: ts('EqAnnotated', `  public unlock(a: ByteString, b: ByteString, d: ByteString, e: ByteString) {
    const m: ByteString = a + b; const n: ByteString = d + e; assert(m === n);
  }`),
    honest: [['12', '00', '12', '00']],
    wrong: [['01', '00', '01', '']],
  },
  {
    name: 'Ruby helper with an inferred (undeclarable) return type',
    file: 'RbHelperEq.runar.rb',
    src: `require 'runar'

class RbHelperEq < Runar::SmartContract
  def initialize
    super()
  end

  runar_public a: ByteString, b: ByteString
  def unlock(a, b)
    assert _same(a) == _same(b)
  end

  private

  params v: ByteString
  def _same(v)
    v
  end
end
`,
    honest: [['1200', '1200']],
    wrong: [['01', '0100']],
  },
];

const mk = (n: number): string =>
  Array.from({ length: n }, (_, i) => ((i * 7 + 3) & 0xff).toString(16).padStart(2, '0')).join('');
const rev = (h: string): string => Buffer.from(h, 'hex').reverse().toString('hex');
const revFirst520 = (h: string): string => Buffer.from(h, 'hex').subarray(0, 520).reverse().toString('hex');

const REVERSE_SRC = ts(
  'RevBytes',
  `  public unlock(a: ByteString, b: ByteString) { assert(reverseBytes(a) === b); }`,
);

const TIERS: Tier[] = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');

const ROOT = mkdtempSync(join(tmpdir(), 'd12-typed-ops-'));
let seq = 0;
function write(fileName: string, content: string): string {
  const d = join(ROOT, String(seq++));
  mkdirSync(d);
  const p = join(d, fileName);
  writeFileSync(p, content);
  return p;
}

function run(tier: Tier, input: string): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

describe('D12 typed operand lowering + reverseBytes guard (all 7 tiers, executed on @bsv/sdk)', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS]);
  });

  describe('FE-F1 / FE-F4: byte-string operators follow the type checker', () => {
    for (const s of SHAPES) {
      describe(s.name, () => {
        let ref = '';
        beforeAll(() => {
          ref = compileHex(TS_TIER!, write(s.file, s.src));
        }, 240_000);
        for (const tier of TIERS) {
          it(`${tier.id}: TS bytes, honest spend accepted, wrong spend refused (strict and relaxed)`, () => {
            const hex = tier.id === 'ts' ? ref : compileHex(tier, write(s.file, s.src));
            for (const p of s.honest) expect(strict(hex, p), `honest ${p.join(',')} refused`).toBe(true);
            for (const p of s.wrong) {
              expect(strict(hex, p), `wrong ${p.join(',')} accepted (strict)`).toBe(false);
              expect(relaxed(hex, p), `wrong ${p.join(',')} accepted (relaxed v2)`).toBe(false);
            }
            expect(hex).toBe(ref);
          }, 240_000);
        }
      });
    }
  });

  describe('BM-F3: reverseBytes aborts on inputs longer than 520 bytes', () => {
    let ref = '';
    beforeAll(() => {
      ref = compileHex(TS_TIER!, write('RevBytes.runar.ts', REVERSE_SRC));
    }, 240_000);
    for (const tier of TIERS) {
      it(`${tier.id}: 520 bytes reverse in full; 521 / 600 bytes refused for every claim`, () => {
        const hex = tier.id === 'ts' ? ref : compileHex(tier, write('RevBytes.runar.ts', REVERSE_SRC));
        const a520 = mk(520);
        expect(strict(hex, [a520, rev(a520)]), '520-byte honest reverse refused').toBe(true);
        expect(strict(hex, [a520, a520]), '520-byte non-reverse accepted').toBe(false);
        for (const n of [521, 600]) {
          const a = mk(n);
          expect(strict(hex, [a, rev(a)]), `${n}: full reverse accepted`).toBe(false);
          expect(strict(hex, [a, revFirst520(a)]), `${n}: reverse of the first 520 bytes accepted`).toBe(false);
          expect(relaxed(hex, [a, revFirst520(a)]), `${n}: reverse of the first 520 bytes accepted (relaxed)`).toBe(false);
        }
        expect(hex).toBe(ref);
      }, 240_000);
    }
  });

  describe('refusals: one shared diagnostic in every tier', () => {
    const { cases } = JSON.parse(readFileSync(join(__dirname, 'd12-typed-operand-cases.json'), 'utf8')) as {
      cases: Array<{ name: string; file: string; src: string; error: string }>;
    };
    it('the corpus covers both new diagnostics', () => {
      expect(cases.some((c) => c.error.startsWith('Cannot resolve the operand types of'))).toBe(true);
      expect(cases.some((c) => c.error.includes('declared return type'))).toBe(true);
    });
    for (const c of cases) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${c.name}`, () => {
          const { status, out, diag } = run(tier, write(c.file, c.src));
          expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(c.error);
        }, 240_000);
      }
    }
  });
});
