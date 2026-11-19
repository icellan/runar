/**
 * D12 NIST-F1 / BM-F8 / reverseBytes / BM-F9: TestContract (the AST
 * interpreter) must reach the same verdict as the compiled script, and the
 * oracle's witness builder must encode every push length correctly.
 *
 * Each row runs `assert((EXPR) === e)` both through TestContract and through
 * the compiled locking script on @bsv/sdk Spend (ScriptExecutionContract, the
 * oracle), and asserts the verdicts agree.
 *
 * - NIST-F1: p256Add / p384Add with the identity O (all-zero blob) as one
 *   operand return the other operand on chain; TestContract ran the chord
 *   formula from (0,0) instead.
 * - BM-F8: OP_NUM2BIN does not require its VALUE operand to be minimally
 *   encoded, so `num2bin(1n >> 1n, 2n)` is `0000` on chain; TestContract
 *   refused it.
 * - reverseBytes: the script reverses at most 520 bytes, so TestContract must
 *   refuse a longer input rather than report the full reverse as accepted.
 * - BM-F9: buildWitness must use PUSHDATA4 above 65535 bytes.
 *
 * Does not prove: SDK tiers (their own tests), other builtins.
 */
import { describe, it, expect } from 'vitest';
import { createECDH } from 'node:crypto';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { buildWitness } from '../oracle/witness.js';

function src(params: string, expr: string): string {
  return `import { SmartContract, assert, ByteString, P256Point, P384Point, p256Add, p384Add, num2bin, reverseBytes } from 'runar-lang';

export class P extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) { super(k); this.k = k; }
  public f(${params}) { assert((${expr}) === e); }
}
`;
}

function verdicts(params: string, expr: string, names: string[], args: unknown[]) {
  const s = src(params, expr);
  const script = ScriptExecutionContract.fromSource(s, { k: 0n }, 'P.runar.ts').execute('f', args).success;
  const tc = TestContract.fromSource(s, { k: 0n }, 'P.runar.ts');
  const r = tc.call('f', Object.fromEntries(names.map((n, i) => [n, args[i]])));
  return { script, tc: r.success, err: r.error };
}

function gen(curve: 'prime256v1' | 'secp384r1', bytes: number): string {
  const e = createECDH(curve);
  e.setPrivateKey(Buffer.from('01'.padStart(bytes * 2, '0'), 'hex'));
  return e.getPublicKey('hex').slice(2); // drop the 04 prefix: x || y
}

describe('D12: TestContract agrees with the compiled script', () => {
  for (const [name, curve, bytes, type] of [
    ['p256Add', 'prime256v1', 32, 'P256Point'],
    ['p384Add', 'secp384r1', 48, 'P384Point'],
  ] as const) {
    const G = gen(curve, bytes);
    const O = '00'.repeat(bytes * 2);
    it(`NIST-F1 ${name}(O, G) === G`, () => {
      const v = verdicts(`a: ${type}, b: ${type}, e: ${type}`, `${name}(a, b)`, ['a', 'b', 'e'], [O, G, G]);
      expect(v.script).toBe(true);
      expect(v.tc).toBe(true);
    });
    it(`NIST-F1 ${name}(G, O) === G`, () => {
      const v = verdicts(`a: ${type}, b: ${type}, e: ${type}`, `${name}(a, b)`, ['a', 'b', 'e'], [G, O, G]);
      expect(v.script).toBe(true);
      expect(v.tc).toBe(true);
    });
    it(`NIST-F1 control: ${name}(O, O) === O`, () => {
      const v = verdicts(`a: ${type}, b: ${type}, e: ${type}`, `${name}(a, b)`, ['a', 'b', 'e'], [O, O, O]);
      expect(v.script).toBe(true);
      expect(v.tc).toBe(true);
    });
  }

  it('BM-F8 num2bin(1 >> 1, 2) === 0000 (non-minimal VALUE operand is fine)', () => {
    const v = verdicts('a: bigint, b: bigint, e: ByteString', 'num2bin(a >> b, 2n)', ['a', 'b', 'e'], [1n, 1n, '0000']);
    expect(v.script).toBe(true);
    expect({ tc: v.tc, err: v.err }).toMatchObject({ tc: true });
  });

  it('BM-F8 control: a non-minimal SIZE operand still aborts in both', () => {
    // 1 >> 1 leaves [0x00]: a non-minimal size, consumed as a number.
    const v = verdicts('a: bigint, b: bigint, e: ByteString', 'num2bin(0n, a >> b)', ['a', 'b', 'e'], [1n, 1n, '']);
    expect(v.script).toBe(false);
    expect(v.tc).toBe(false);
  });

  const bytesOf = (n: number) => Array.from({ length: n }, (_, i) => (i % 251 + 1).toString(16).padStart(2, '0')).join('');
  const rev = (h: string) => h.match(/../g)!.reverse().join('');
  for (const n of [520, 521, 600]) {
    it(`reverseBytes(${n} B) full reverse: TestContract agrees with the script`, () => {
      const x = bytesOf(n);
      const v = verdicts('a: ByteString, e: ByteString', 'reverseBytes(a)', ['a', 'e'], [x, rev(x)]);
      expect(v.script).toBe(n <= 520);
      expect(v.tc).toBe(v.script);
      if (n > 520) expect(v.err).toMatch(/520/);
    });
  }
});

describe('D12 BM-F9: buildWitness push encodings', () => {
  const hex = (u: Uint8Array, n: number) => Buffer.from(u.slice(0, n)).toString('hex');
  it('65535 bytes -> PUSHDATA2', () => {
    const w = buildWitness([new Uint8Array(65535)]);
    expect(hex(w, 3)).toBe('4dffff');
    expect(w.length).toBe(3 + 65535);
  });
  it('65536 bytes -> PUSHDATA4', () => {
    const w = buildWitness([new Uint8Array(65536)]);
    expect(hex(w, 5)).toBe('4e00000100');
    expect(w.length).toBe(5 + 65536);
  });
  it('70000 bytes -> PUSHDATA4 with the full length', () => {
    const w = buildWitness([new Uint8Array(70000)]);
    expect(hex(w, 5)).toBe('4e70110100');
    expect(w.length).toBe(5 + 70000);
  });
});
