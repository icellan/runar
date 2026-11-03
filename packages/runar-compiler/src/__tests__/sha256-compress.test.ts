import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { createHash } from 'node:crypto';
// @ts-expect-error vitest resolves these via the root alias
import { ScriptExecutionContract } from 'runar-testing';

// ---------------------------------------------------------------------------
// F-351: "generates ASM containing SHA-256 operations" below only asserts
// that certain opcode NAMES appear somewhere in the emitted ASM string — it
// would still pass if sha256Compress computed the wrong value (e.g. a wrong
// round constant), as long as the same opcode kinds were used. This block
// closes that gap: it EXECUTES the compiled script through
// `ScriptExecutionContract` (the real Bitcoin Script hex via @bsv/sdk's
// `Spend`, not this compiler's own interpreter) and compares the result to
// a digest from node:crypto — an independent SHA-256 implementation, never
// derived from this compiler's output.
// ---------------------------------------------------------------------------

/** The standard FIPS 180-4 SHA-256 initial hash value. */
const SHA256_IV = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

/** FIPS 180-4 §5.1.1 padding: append 0x80, zero-pad to 56 mod 64, append the 8-byte BE bit length. */
function padToOneBlock(msgHex: string): string {
  const bitLen = (msgHex.length / 2) * 8;
  let padded = msgHex + '80';
  while ((padded.length / 2) % 64 !== 56) padded += '00';
  padded += bitLen.toString(16).padStart(16, '0');
  return padded;
}

// ---------------------------------------------------------------------------
// Test source — a contract that uses sha256Compress
// ---------------------------------------------------------------------------

const SHA256_COMPRESS_SOURCE = `
class Sha256CompressTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, block: ByteString) {
    const result = sha256Compress(state, block);
    assert(result === this.expected);
  }
}
`;

// ---------------------------------------------------------------------------
// Compilation tests
// ---------------------------------------------------------------------------

function expectNoErrors(result: ReturnType<typeof compile>): void {
  const errors = result.diagnostics.filter(d => d.severity === 'error');
  expect(errors).toEqual([]);
  expect(result.success).toBe(true);
}

describe('sha256Compress — compilation', () => {
  it('compiles a contract using sha256Compress', () => {
    const result = compile(SHA256_COMPRESS_SOURCE);
    expectNoErrors(result);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(100);
  });

  it('rejects sha256Compress with wrong argument types', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: bigint) {
    const r = sha256Compress(x, x);
    assert(r === r);
  }
}
`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });

  it('generates ASM containing SHA-256 operations', () => {
    const result = compile(SHA256_COMPRESS_SOURCE);
    expectNoErrors(result);
    const asm = result.artifact!.asm;
    // Should contain OP_LSHIFT/OP_RSHIFT (for ROTR via native BE shifts),
    // OP_AND/OP_OR/OP_XOR (bitwise), OP_BIN2NUM/OP_NUM2BIN (conversions)
    expect(asm).toContain('OP_LSHIFT');
    expect(asm).toContain('OP_RSHIFT');
    expect(asm).toContain('OP_AND');
    expect(asm).toContain('OP_XOR');
    expect(asm).toContain('OP_BIN2NUM');
    expect(asm).toContain('OP_NUM2BIN');
  });

  // F-351: value + execution check (see header comment). Padding "abc" to one
  // block and compressing from the standard IV is, by definition, SHA-256("abc")
  // — so node:crypto's own digest of "abc" is a valid independent oracle here.
  it('executed script output matches node:crypto sha256("abc")', () => {
    const msgHex = '616263'; // "abc"
    const expected = createHash('sha256').update(Buffer.from(msgHex, 'hex')).digest('hex');

    const contract = ScriptExecutionContract.fromSource(
      SHA256_COMPRESS_SOURCE,
      { expected },
      'Sha256CompressTest.runar.ts',
    );
    const result = contract.execute('verify', [SHA256_IV, padToOneBlock(msgHex)]);
    expect(result.success, `Spend rejected the honest call: ${result.error}`).toBe(true);
  });

  it('rejects when the compiled script does not produce the node:crypto digest', () => {
    const msgHex = '616263';
    const wrongExpected = '00'.repeat(32);

    const contract = ScriptExecutionContract.fromSource(
      SHA256_COMPRESS_SOURCE,
      { expected: wrongExpected },
      'Sha256CompressTest.runar.ts',
    );
    const result = contract.execute('verify', [SHA256_IV, padToOneBlock(msgHex)]);
    expect(result.success).toBe(false);
  });
});
