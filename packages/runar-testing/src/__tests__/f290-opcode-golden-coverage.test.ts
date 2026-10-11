/**
 * F-290 (CL-GAP-109) — every opcode the emitter can produce is either in a
 * checked-in conformance golden or executed here on `@bsv/sdk` Spend.
 *
 * The gate parses the emitter's opcode table (`OPCODES` in
 * `packages/runar-compiler/src/passes/06-emit.ts`), byte-walks every
 * `conformance/tests/<fixture>/expected-script.hex` (push payloads skipped, so a
 * data byte is never counted as an opcode), and fails while any table opcode
 * appears in no golden AND has no execution case in `CASES`.
 *
 * Every table opcode is reachable from source: the array form of `asm()`
 * (`asm({ body: [OP_X, ...] })`, `encodeAsmArrayBody` in 01-parse.ts) resolves
 * names through the same table. Each case records `via`:
 *   - 'language': an ordinary Rúnar construct makes the compiler emit it;
 *   - 'asm': only `asm()` reaches it. That includes the Chronicle byte-ops
 *     OP_SUBSTR / OP_LEFT / OP_RIGHT, because the `substr` / `left` / `right`
 *     builtins lower to OP_SPLIT, and OP_LSHIFTNUM, whose only codegen site
 *     (kbFieldMulConst's diag = 4 step in Poseidon2-KoalaBear) sits behind a
 *     builtin the TS typechecker does not expose (Poseidon2 is
 *     conformance-scoped to Go, R-130).
 *
 * Oracle: `@bsv/sdk` Spend via ScriptExecutionContract — never TestContract or
 * the ANF interpreter. Expected values come from hand-written JS semantics
 * (node:crypto for SHA-1, slice for the byte-ops, BigInt for shifts, the
 * opcode's stack picture for the shuffles). Every case has at least one
 * witness that must verify and one that must not, and asserts its compiled
 * script carries the target opcode byte at an opcode position.
 *
 * What this proves: each of the 19 opcodes in no golden is emitted with the
 * byte the interpreter executes, and executes with the stated semantics on a
 * consensus-shaped Spend, for at least one accepting and one rejecting input.
 * What it does not prove: that the other six compiler tiers emit these
 * opcodes identically (no golden pins them); that the semantics hold at every
 * edge (only the listed vectors run); or OP_RIGHT for 0 < n < len — see the
 * OP_RIGHT canary below, @bsv/sdk 2.0.7 computes that case wrongly.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { ScriptExecutionContract } from '../script-execution.js';
import type { ScriptExecResult } from '../script-execution.js';
import { encodeScriptNumber, decodeScriptNumber, bytesToHex, hexToBytes } from '../vm/utils.js';

const REPO = resolve(__dirname, '../../../..');

/** The emitter's opcode table, name -> byte, read from the source text. */
function emitterOpcodeTable(): Map<string, number> {
  const src = readFileSync(resolve(REPO, 'packages/runar-compiler/src/passes/06-emit.ts'), 'utf8');
  const start = src.indexOf('export const OPCODES');
  const body = src.slice(start, src.indexOf('};', start));
  const table = new Map<string, number>();
  for (const m of body.matchAll(/'(OP_[A-Z0-9_]+)':\s*0x([0-9a-fA-F]{2})/g)) {
    table.set(m[1]!, parseInt(m[2]!, 16));
  }
  return table;
}

/** Opcode bytes at opcode positions of a script (push payloads skipped). */
function opcodeBytes(hex: string): Set<number> {
  const b = Buffer.from(hex, 'hex');
  const seen = new Set<number>();
  let i = 0;
  while (i < b.length) {
    const op = b[i++]!;
    seen.add(op);
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) i += 1 + b[i]!;
    else if (op === 0x4d) i += 2 + b.readUInt16LE(i);
    else if (op === 0x4e) i += 4 + b.readUInt32LE(i);
  }
  return seen;
}

function goldenOpcodeBytes(): { fixtures: number; seen: Set<number> } {
  const dir = resolve(REPO, 'conformance/tests');
  const seen = new Set<number>();
  let fixtures = 0;
  for (const name of readdirSync(dir)) {
    const p = resolve(dir, name, 'expected-script.hex');
    if (!existsSync(p)) continue;
    fixtures++;
    for (const op of opcodeBytes(readFileSync(p, 'utf8').trim())) seen.add(op);
  }
  return { fixtures, seen };
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

interface Vector {
  label: string;
  accept: boolean;
  run: (c: ScriptExecutionContract) => ScriptExecResult;
}

interface OpcodeCase {
  opcode: string;
  via: 'language' | 'asm';
  title: string;
  source: string;
  constructorArgs?: Record<string, bigint | boolean | string>;
  vectors: Vector[];
}

/** Minimal script-number encoding, as hex (0 is the empty string). */
const num = (n: bigint): string => bytesToHex(encodeScriptNumber(n));
const dec = (hex: string): bigint => decodeScriptNumber(hexToBytes(hex));
const sha1 = (hex: string): string => createHash('sha1').update(Buffer.from(hex, 'hex')).digest('hex');

/** A wrong value for a byte string: flip the last byte, or make empty non-empty. */
function perturb(hex: string): string {
  if (hex === '') return '01';
  const last = (parseInt(hex.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');
  return hex.slice(0, -2) + last;
}

/** The oracle's output stack with one detectable error in it. */
function wrongOutputs(out: string[]): string[] {
  for (let i = 0; i < out.length; i++) {
    for (let j = i + 1; j < out.length; j++) {
      if (out[i] !== out[j]) {
        const w = [...out];
        [w[i], w[j]] = [w[j]!, w[i]!];
        return w;
      }
    }
  }
  const w = [...out];
  w[w.length - 1] = perturb(w[w.length - 1]!);
  return w;
}

/**
 * An asm()-only case. The method takes the opcode's inputs and then the
 * expected output stack (reversed), all as ByteString. The body parks the
 * expected values on the alt stack, runs `ops`, then compares every produced
 * item, top first, against the expected value with OP_EQUAL(VERIFY). So the
 * script verifies iff `ops` turns `inputs` into exactly `oracle(inputs)`.
 */
function asmCase(
  opcode: string,
  title: string,
  ops: string[],
  inputVectors: string[][],
  oracle: (inputs: string[]) => string[],
): OpcodeCase {
  const k = inputVectors[0]!.length;
  const m = oracle(inputVectors[0]!).length;
  for (const v of inputVectors) {
    if (v.length !== k || oracle(v).length !== m) throw new Error(`${opcode}: vectors must share one stack shape`);
  }
  const params = [
    ...Array.from({ length: k }, (_, i) => `i${i}: ByteString`),
    ...Array.from({ length: m }, (_, i) => `p${i}: ByteString`),
  ].join(', ');
  const body = [
    ...Array<string>(m).fill('OP_TOALTSTACK'),
    ...ops,
    ...Array.from({ length: m - 1 }, () => ['OP_FROMALTSTACK', 'OP_EQUALVERIFY']).flat(),
    'OP_FROMALTSTACK',
    'OP_EQUAL',
  ].join(', ');
  const source = [
    `import { UnsafeSmartContract, asm } from 'runar-lang';`,
    `class F290${opcode.slice(3)} extends UnsafeSmartContract {`,
    `  constructor() { super(); }`,
    `  public m(${params}) { asm({ body: [${body}], in_arity: ${k + m}, out_arity: 1 }); }`,
    `}`,
  ].join('\n');
  const vectors: Vector[] = [];
  for (const inputs of inputVectors) {
    const out = oracle(inputs);
    const tag = `[${inputs.map((x) => JSON.stringify(x)).join(', ')}]`;
    vectors.push({
      label: `${tag} -> [${out.map((x) => JSON.stringify(x)).join(', ')}]`,
      accept: true,
      run: (c) => c.execute('m', [...inputs, ...[...out].reverse()]),
    });
    const wrong = wrongOutputs(out);
    vectors.push({
      label: `${tag} -/-> [${wrong.map((x) => JSON.stringify(x)).join(', ')}]`,
      accept: false,
      run: (c) => c.execute('m', [...inputs, ...[...wrong].reverse()]),
    });
  }
  return { opcode, via: 'asm', title, source, vectors };
}

const KEY = PrivateKey.fromHex('11'.repeat(32));
const OTHER_KEY = PrivateKey.fromHex('22'.repeat(32));
const LIT_PUSHDATA2 = Array.from({ length: 300 }, (_, i) => (i & 0xff).toString(16).padStart(2, '0')).join('');
const LIT_PUSHDATA4 = Array.from({ length: 70_000 }, (_, i) => ((i * 7) & 0xff).toString(16).padStart(2, '0')).join('');

function literalCase(opcode: string, lit: string): OpcodeCase {
  return {
    opcode,
    via: 'language',
    title: `a ${lit.length / 2}-byte ByteString literal`,
    source: [
      `import { SmartContract, assert, toByteString } from 'runar-lang';`,
      `class F290${opcode.slice(3)} extends SmartContract {`,
      `  constructor() { super(); }`,
      `  public m(x: ByteString) { assert(x === toByteString('${lit}')); }`,
      `}`,
    ].join('\n'),
    vectors: [
      { label: 'the literal', accept: true, run: (c) => c.execute('m', [lit]) },
      { label: 'the literal, last byte flipped', accept: false, run: (c) => c.execute('m', [perturb(lit)]) },
      { label: 'the literal minus its last byte', accept: false, run: (c) => c.execute('m', [lit.slice(0, -2)]) },
    ],
  };
}

const CASES: OpcodeCase[] = [
  // ---- reached by ordinary Rúnar constructs -------------------------------
  literalCase('OP_PUSHDATA2', LIT_PUSHDATA2),
  literalCase('OP_PUSHDATA4', LIT_PUSHDATA4),
  {
    opcode: 'OP_1NEGATE',
    via: 'language',
    title: 'a bigint constructor arg baked as -1',
    source: [
      `import { SmartContract, assert } from 'runar-lang';`,
      `class F2901Negate extends SmartContract {`,
      `  readonly k: bigint;`,
      `  constructor(k: bigint) { super(k); this.k = k; }`,
      `  public m(x: bigint) { assert(x + this.k === 4n); }`,
      `}`,
    ].join('\n'),
    constructorArgs: { k: -1n },
    vectors: [
      { label: 'x = 5 (5 + -1 = 4)', accept: true, run: (c) => c.execute('m', [5n]) },
      { label: 'x = 3 (k read as +1)', accept: false, run: (c) => c.execute('m', [3n]) },
      { label: 'x = 4 (k read as 0)', accept: false, run: (c) => c.execute('m', [4n]) },
    ],
  },
  {
    opcode: 'OP_NEGATE',
    via: 'language',
    title: 'unary minus on a bigint',
    source: [
      `import { SmartContract, assert } from 'runar-lang';`,
      `class F290Negate extends SmartContract {`,
      `  constructor() { super(); }`,
      `  public m(x: bigint, y: bigint) { assert(-x === y); }`,
      `}`,
    ].join('\n'),
    vectors: [
      { label: '-(7) === -7', accept: true, run: (c) => c.execute('m', [7n, -7n]) },
      { label: '-(-300) === 300', accept: true, run: (c) => c.execute('m', [-300n, 300n]) },
      { label: '-(7) !== 7', accept: false, run: (c) => c.execute('m', [7n, 7n]) },
    ],
  },
  {
    opcode: 'OP_CHECKMULTISIGVERIFY',
    via: 'language',
    title: 'checkMultiSig in a non-terminal assert',
    source: [
      `import { SmartContract, assert, checkMultiSig } from 'runar-lang';`,
      `class F290CheckMultiSigVerify extends SmartContract {`,
      `  constructor() { super(); }`,
      `  public m(s: Sig, p: PubKey, x: bigint) { assert(checkMultiSig([s], [p])); assert(x === 1n); }`,
      `}`,
    ].join('\n'),
    vectors: [
      {
        label: 'valid 1-of-1 signature, x = 1',
        accept: true,
        run: (c) => c.executeSigned('m', ['', ScriptExecutionContract.pubKeyHex(KEY), 1n], 0, KEY),
      },
      {
        label: 'valid signature, x = 2 (the assert after the VERIFY still runs)',
        accept: false,
        run: (c) => c.executeSigned('m', ['', ScriptExecutionContract.pubKeyHex(KEY), 2n], 0, KEY),
      },
      {
        label: 'signature by another key, x = 1',
        accept: false,
        run: (c) => c.executeSigned('m', ['', ScriptExecutionContract.pubKeyHex(KEY), 1n], 0, OTHER_KEY),
      },
    ],
  },

  // ---- reached only through asm() -----------------------------------------
  asmCase('OP_SUBSTR', 'x begin len -> x[begin, begin+len)', ['OP_SUBSTR'],
    [['aabbccddee', num(1n), num(3n)], ['aabbccddee', num(0n), num(5n)], ['aabbccddee', num(4n), num(0n)]],
    ([x, b, l]) => {
      const begin = Number(dec(b!));
      return [x!.slice(begin * 2, (begin + Number(dec(l!))) * 2)];
    }),
  asmCase('OP_LEFT', 'x n -> first n bytes', ['OP_LEFT'],
    [['aabbccddee', num(2n)], ['aabbccddee', num(0n)], ['aabbccddee', num(5n)]],
    ([x, n]) => [x!.slice(0, Number(dec(n!)) * 2)]),
  // n = 0 and n = len only: @bsv/sdk 2.0.7 is wrong for 0 < n < len (canary below).
  asmCase('OP_RIGHT', 'x n -> last n bytes', ['OP_RIGHT'],
    [['aabbccddee', num(0n)], ['aabbccddee', num(5n)]],
    ([x, n]) => [x!.slice(x!.length - Number(dec(n!)) * 2)]),
  asmCase('OP_LSHIFTNUM', 'a n -> a << n (numeric)', ['OP_LSHIFTNUM'],
    [[num(5n), num(3n)], [num(1n), num(40n)], [num(-3n), num(2n)], [num(0x7fn), num(1n)]],
    ([a, n]) => [num(dec(a!) << dec(n!))]),
  asmCase('OP_NUMNOTEQUAL', 'a b -> a != b', ['OP_NUMNOTEQUAL'],
    [[num(3n), num(4n)], [num(3n), num(3n)], [num(-1n), num(1n)]],
    ([a, b]) => [a !== b ? '01' : '']),
  asmCase('OP_SHA1', 'x -> SHA-1(x)', ['OP_SHA1'],
    [[''], ['616263'], ['00'.repeat(100)]],
    ([x]) => [sha1(x!)]),
  asmCase('OP_NOTIF', 'b -> b ? 0 : 1, through NOTIF/ELSE/ENDIF',
    ['OP_NOTIF', 'OP_1', 'OP_ELSE', 'OP_0', 'OP_ENDIF'],
    [[''], ['01']],
    ([b]) => [b === '' ? '01' : '']),
  asmCase('OP_3DUP', 'a b c -> a b c a b c', ['OP_3DUP'],
    [['a1', 'a2', 'a3']],
    ([a, b, c]) => [a!, b!, c!, a!, b!, c!]),
  asmCase('OP_2OVER', 'a b c d -> a b c d a b', ['OP_2OVER'],
    [['a1', 'a2', 'a3', 'a4']],
    ([a, b, c, d]) => [a!, b!, c!, d!, a!, b!]),
  asmCase('OP_2ROT', 'a b c d e f -> c d e f a b', ['OP_2ROT'],
    [['a1', 'a2', 'a3', 'a4', 'a5', 'a6']],
    ([a, b, c, d, e, f]) => [c!, d!, e!, f!, a!, b!]),
  asmCase('OP_2SWAP', 'a b c d -> c d a b', ['OP_2SWAP'],
    [['a1', 'a2', 'a3', 'a4']],
    ([a, b, c, d]) => [c!, d!, a!, b!]),
  asmCase('OP_IFDUP', 'truthy a -> a a', ['OP_IFDUP'],
    [['a1'], ['0001']],
    ([a]) => [a!, a!]),
  asmCase('OP_IFDUP', 'falsy a -> a', ['OP_IFDUP'],
    [[''], ['0080']],
    ([a]) => [a!]),
  // The expected outputs sit on the alt stack while DEPTH runs, so the main
  // stack holds exactly the two inputs.
  asmCase('OP_DEPTH', 'a b -> a b 2', ['OP_DEPTH'],
    [['a1', 'a2']],
    ([a, b]) => [a!, b!, num(2n)]),
  {
    opcode: 'OP_RETURN',
    via: 'asm',
    title: 'OP_RETURN ends evaluation; the bytes after it never run',
    // Single method: no dispatch OP_IF encloses the OP_RETURN.
    source: [
      `import { UnsafeSmartContract, asm } from 'runar-lang';`,
      `class F290Return extends UnsafeSmartContract {`,
      `  constructor() { super(); }`,
      `  public m(x: bigint) { asm({ body: [OP_RETURN, OP_0, OP_VERIFY], in_arity: 1, out_arity: 1 }); }`,
      `}`,
    ].join('\n'),
    vectors: [
      { label: 'x = 1 (OP_0 OP_VERIFY after it would fail if run)', accept: true, run: (c) => c.execute('m', [1n]) },
      { label: 'x = 0 (the result is the top of stack at OP_RETURN)', accept: false, run: (c) => c.execute('m', [0n]) },
    ],
  },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('F-290: emittable opcodes absent from every golden are executed on Spend', () => {
  const table = emitterOpcodeTable();

  it('every emittable opcode is in a golden or has an execution case here', () => {
    expect(table.size).toBeGreaterThan(90);
    const { fixtures, seen } = goldenOpcodeBytes();
    expect(fixtures).toBeGreaterThan(70);
    const covered = new Set(CASES.map((c) => table.get(c.opcode)));
    const uncovered: string[] = [];
    const byteDone = new Set<number>();
    for (const [name, byte] of table) {
      if (byteDone.has(byte)) continue; // OP_0/OP_FALSE, OP_1/OP_TRUE alias one byte
      byteDone.add(byte);
      if (!seen.has(byte) && !covered.has(byte)) uncovered.push(name);
    }
    expect(uncovered, 'opcodes in no golden and with no execution case').toEqual([]);
  });

  for (const c of CASES) {
    describe(`${c.opcode} via ${c.via}: ${c.title}`, () => {
      const byte = table.get(c.opcode);

      it('the compiled script carries the opcode at an opcode position', () => {
        expect(byte, `${c.opcode} is not in the emitter table`).toBeDefined();
        const exec = ScriptExecutionContract.fromSource(c.source, c.constructorArgs ?? {}, 'F290.runar.ts');
        expect(opcodeBytes(exec.scriptHex).has(byte!)).toBe(true);
        expect(c.vectors.some((v) => v.accept)).toBe(true);
        expect(c.vectors.some((v) => !v.accept)).toBe(true);
      });

      const exec = ScriptExecutionContract.fromSource(c.source, c.constructorArgs ?? {}, 'F290.runar.ts');
      for (const v of c.vectors) {
        it(`${v.accept ? 'verifies' : 'rejects'}: ${v.label.length > 120 ? v.label.slice(0, 117) + '...' : v.label}`, () => {
          const r = v.run(exec);
          expect(r.success, r.error).toBe(v.accept);
        });
      }
    });
  }

  // Upstream divergence, not a Rúnar defect: @bsv/sdk 2.0.7 Spend computes
  // OP_RIGHT as `buf.slice(size - len, len)` instead of `buf.slice(size - len)`,
  // so for 0 < n < len it returns the wrong bytes (usually empty). go-sdk
  // (`opcodeSliceBytes`, `data[size-len:]`) and the Chronicle spec return the
  // last n bytes. Nothing the compiler emits for `right()` uses OP_RIGHT (it
  // lowers to OP_SPLIT), but the TS ScriptVM / `runar debug` wrap this Spend.
  // When @bsv/sdk fixes it this test fails: move n = 2 into the OP_RIGHT case
  // above and delete this one.
  it('canary: @bsv/sdk Spend still computes OP_RIGHT wrongly for 0 < n < len', () => {
    const c = CASES.find((x) => x.opcode === 'OP_RIGHT')!;
    const exec = ScriptExecutionContract.fromSource(c.source, {}, 'F290.runar.ts');
    // m(i0 = x, i1 = n, p0 = expected): right(aabbccddee, 2) is ddee.
    expect(exec.execute('m', ['aabbccddee', num(2n), 'ddee']).success).toBe(false);
    expect(exec.execute('m', ['aabbccddee', num(2n), '']).success).toBe(true);
  });
});
