import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { createHash } from 'node:crypto';
// @ts-expect-error vitest resolves these via the root alias
import { ScriptExecutionContract } from 'runar-testing';

// ---------------------------------------------------------------------------
// F-351: "generates ASM containing SHA-256 finalize operations" below only
// asserts that certain opcode NAMES (including OP_IF/OP_ELSE/OP_ENDIF for the
// 1-block/2-block branch) appear somewhere in the emitted ASM string — it
// would still pass even if either branch computed the wrong value. This
// block closes that gap: it EXECUTES the compiled script through
// `ScriptExecutionContract` (the real Bitcoin Script hex via @bsv/sdk's
// `Spend`) for one message on each branch and compares the result to
// node:crypto's own SHA-256 of the same message — an independent reference,
// never derived from this compiler's output.
// ---------------------------------------------------------------------------

/** The standard FIPS 180-4 SHA-256 initial hash value. */
const SHA256_IV = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

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

  // F-351: value + execution check (see header comment). Two messages, one
  // per branch of the OP_IF: a 3-byte message takes the 1-block path
  // (remaining <= 55 bytes after the 0x80 pad byte), a 56-byte message takes
  // the 2-block path (remaining in 56..119 bytes).
  describe('executed script output matches node:crypto sha256(...)', () => {
    const cases = [
      { name: '"abc" (1-block path)', msgHex: '616263' },
      { name: '56-byte message (2-block path)', msgHex: 'bb'.repeat(56) },
    ];

    for (const { name, msgHex } of cases) {
      it(name, () => {
        const bitLen = BigInt((msgHex.length / 2) * 8);
        const expected = createHash('sha256').update(Buffer.from(msgHex, 'hex')).digest('hex');

        const contract = ScriptExecutionContract.fromSource(
          SHA256_FINALIZE_SOURCE,
          { expected },
          'Sha256FinalizeTest.runar.ts',
        );
        const result = contract.execute('verify', [SHA256_IV, msgHex, bitLen]);
        expect(result.success, `Spend rejected the honest call: ${result.error}`).toBe(true);
      });
    }
  });

  it('rejects when the compiled script does not produce the node:crypto digest', () => {
    const msgHex = '616263';
    const wrongExpected = '00'.repeat(32);

    const contract = ScriptExecutionContract.fromSource(
      SHA256_FINALIZE_SOURCE,
      { expected: wrongExpected },
      'Sha256FinalizeTest.runar.ts',
    );
    const result = contract.execute('verify', [SHA256_IV, msgHex, 24n]);
    expect(result.success).toBe(false);
  });
});
