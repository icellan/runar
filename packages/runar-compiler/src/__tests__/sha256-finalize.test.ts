import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Test source — a contract that uses sha256Finalize
// ---------------------------------------------------------------------------

const SHA256_FINALIZE_SOURCE = `
class Sha256FinalizeTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const result = sha256Finalize(state, remaining, msgBitLen);
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

describe('sha256Finalize — compilation', () => {
  it('compiles a contract using sha256Finalize', () => {
    const result = compile(SHA256_FINALIZE_SOURCE);
    expectNoErrors(result);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(100);
  });

  it('rejects sha256Finalize with wrong argument types', () => {
    const src = `
class Bad extends SmartContract {
  constructor() { super(); }
  public test(x: ByteString) {
    const r = sha256Finalize(x, x, x);
    assert(r === r);
  }
}
`;
    const result = compile(src);
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.length).toBeGreaterThan(0);
  });

  it('generates ASM containing SHA-256 finalize operations', () => {
    const result = compile(SHA256_FINALIZE_SOURCE);
    expectNoErrors(result);
    const asm = result.artifact!.asm;
    // Standard SHA-256 operations (same as compress)
    expect(asm).toContain('OP_LSHIFT');
    expect(asm).toContain('OP_RSHIFT');
    expect(asm).toContain('OP_AND');
    expect(asm).toContain('OP_XOR');
    expect(asm).toContain('OP_BIN2NUM');
    expect(asm).toContain('OP_NUM2BIN');
    // Finalize-specific: branching between 1-block and 2-block padding paths
    expect(asm).toContain('OP_IF');
    expect(asm).toContain('OP_ELSE');
    expect(asm).toContain('OP_ENDIF');
  });
});
