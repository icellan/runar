import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

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
});
