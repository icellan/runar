import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
// @ts-expect-error vitest resolves these via the root alias
import { ScriptExecutionContract } from 'runar-testing';

// ---------------------------------------------------------------------------
// F-351: the ASM-presence tests below ("generates ASM containing BLAKE3
// operations") only ever checked that certain opcode NAMES appear in the
// emitted ASM string. They would pass unchanged even if the BLAKE3
// compression round were wired up wrong (wrong IV word, wrong message
// permutation, ...) as long as the same opcode kinds were still used
// somewhere in the body. The tests below close that gap: they actually
// EXECUTE the compiled script through `ScriptExecutionContract` (which runs
// the real Bitcoin Script hex through @bsv/sdk's `Spend`, not the compiler's
// own interpreter) and compare the result to digests from an INDEPENDENT
// source — the official BLAKE3 test vectors, vendored verbatim from the
// BLAKE3 team's own repo, never derived from this compiler.
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));

interface BlakeKatVector {
  input_len: number;
  input: string;
  expected: string;
}

const officialKat = JSON.parse(
  readFileSync(
    resolve(__dirname, '../../../../conformance/runtime-vectors/blake3-official-kat.json'),
    'utf8',
  ),
) as { blake3_hash_official: BlakeKatVector[] };

interface Blake3CompressVector {
  name: string;
  state: string;
  block: string;
  expected: string;
}

const runtimeVectors = JSON.parse(
  readFileSync(
    resolve(__dirname, '../../../../conformance/runtime-vectors/hashes.json'),
    'utf8',
  ),
) as { blake3_compress: Blake3CompressVector[] };

const BLAKE3_COMPRESS_SOURCE = `
class Blake3CompressTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }
}
`;

const BLAKE3_HASH_SOURCE = `
class Blake3HashTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(message: ByteString) {
    const result = blake3Hash(message);
    assert(result === this.expected);
  }
}
`;

function expectNoErrors(result: ReturnType<typeof compile>): void {
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  expect(errors).toEqual([]);
  expect(result.success).toBe(true);
}

describe('blake3Compress — compilation', () => {
  it('compiles a contract using blake3Compress', () => {
    const result = compile(BLAKE3_COMPRESS_SOURCE);
    expectNoErrors(result);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(100);
  });

  it('rejects blake3Compress with wrong argument types', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    const r = blake3Compress(x, x);
    assert(r === r);
  }
}
`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });

  it('generates ASM containing BLAKE3 operations', () => {
    const result = compile(BLAKE3_COMPRESS_SOURCE);
    expectNoErrors(result);
    const asm = result.artifact!.asm;
    expect(asm).toContain('OP_LSHIFT');
    expect(asm).toContain('OP_RSHIFT');
    expect(asm).toContain('OP_XOR');
    expect(asm).toContain('OP_BIN2NUM');
    expect(asm).toContain('OP_NUM2BIN');
  });

  // F-351: value + execution check (see header comment). `blake3_compress` in
  // hashes.json pins `state`/`block` as the little-endian bytes blake3Compress
  // actually consumes, and documents (`_blake3_doc`) that `expected` was
  // verified against the official BLAKE3 KATs — independent of this compiler.
  it('executed script output matches an independently-verified BLAKE3 compress vector', () => {
    const vector = runtimeVectors.blake3_compress.find(v => v.name === 'iv-abc-padded');
    if (!vector) throw new Error('fixture vector missing from hashes.json');

    const contract = ScriptExecutionContract.fromSource(
      BLAKE3_COMPRESS_SOURCE,
      { expected: vector.expected },
      'Blake3CompressTest.runar.ts',
    );
    const result = contract.execute('verify', [vector.state, vector.block]);
    expect(result.success, `Spend rejected the honest call: ${result.error}`).toBe(true);
  });

  it('rejects when the compiled script does not produce the independently-verified digest', () => {
    const vector = runtimeVectors.blake3_compress.find(v => v.name === 'iv-abc-padded');
    if (!vector) throw new Error('fixture vector missing from hashes.json');

    const wrongExpected = '00'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(
      BLAKE3_COMPRESS_SOURCE,
      { expected: wrongExpected },
      'Blake3CompressTest.runar.ts',
    );
    const result = contract.execute('verify', [vector.state, vector.block]);
    expect(result.success).toBe(false);
  });
});

describe('blake3Hash — compilation', () => {
  it('compiles a contract using blake3Hash', () => {
    const result = compile(BLAKE3_HASH_SOURCE);
    expectNoErrors(result);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(100);
  });

  it('rejects blake3Hash with wrong argument types', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    const r = blake3Hash(x);
    assert(r === r);
  }
}
`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });

  // F-351: blake3Hash had no ASM-presence test at all, and no execution test
  // either — this closes both by running the compiled script against every
  // length in the official BLAKE3 KAT (0..64 bytes, the function's whole
  // supported domain).
  describe('executed script output matches the official BLAKE3 KAT', () => {
    for (const vector of officialKat.blake3_hash_official) {
      it(`input_len=${vector.input_len}`, () => {
        const contract = ScriptExecutionContract.fromSource(
          BLAKE3_HASH_SOURCE,
          { expected: vector.expected },
          'Blake3HashTest.runar.ts',
        );
        const result = contract.execute('verify', [vector.input]);
        expect(result.success, `Spend rejected the honest call: ${result.error}`).toBe(true);
      });
    }
  });

  it('rejects when the compiled script does not produce the official KAT digest', () => {
    const vector = officialKat.blake3_hash_official.find(v => v.input_len === 3);
    if (!vector) throw new Error('fixture vector missing from blake3-official-kat.json');

    const wrongExpected = '00'.repeat(32);
    const contract = ScriptExecutionContract.fromSource(
      BLAKE3_HASH_SOURCE,
      { expected: wrongExpected },
      'Blake3HashTest.runar.ts',
    );
    const result = contract.execute('verify', [vector.input]);
    expect(result.success).toBe(false);
  });
});
