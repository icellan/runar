import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit, emitMethod, OPCODES } from '../passes/06-emit.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import type { StackMethod, StackOp } from '../ir/index.js';
import type { EmitResult } from '../passes/06-emit.js';
import type { ContractNode } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function compileToEmit(source: string): EmitResult {
  const contract = parseContract(source);
  const anf = lowerToANF(contract);
  const stack = lowerToStack(anf);
  // Match the real pipeline: apply standalone peephole optimizer before emit
  for (const method of stack.methods) {
    method.ops = optimizeStackIR(method.ops);
  }
  return emit(stack);
}

function emitMethodFromSource(source: string, methodName: string): EmitResult {
  const contract = parseContract(source);
  const anf = lowerToANF(contract);
  const stack = lowerToStack(anf);
  const method = stack.methods.find(m => m.name === methodName);
  if (!method) {
    throw new Error(`Method '${methodName}' not found`);
  }
  return emitMethod(method);
}

function isValidHex(s: string): boolean {
  return /^[0-9a-f]*$/i.test(s) && s.length % 2 === 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Pass 6: Emit', () => {
  // ---------------------------------------------------------------------------
  // Valid hex output
  // ---------------------------------------------------------------------------

  describe('determinism', () => {
    it('produces identical output for two compilations of the same contract (deterministic)', () => {
      const source = `
        class P2PKH extends SmartContract {
          readonly pubKeyHash: Sha256;
          constructor(pubKeyHash: Sha256) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
          public unlock(sig: Sig, pubKey: PubKey) {
            assert(hash160(pubKey) === this.pubKeyHash);
            assert(checkSig(sig, pubKey));
          }
        }
      `;
      const result1 = compileToEmit(source);
      const result2 = compileToEmit(source);
      expect(result1.scriptHex).toBe(result2.scriptHex);
      expect(result1.scriptAsm).toBe(result2.scriptAsm);
    });
  });

  describe('hex output', () => {
    it('emits valid hex string for a simple contract', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      expect(typeof result.scriptHex).toBe('string');
      expect(isValidHex(result.scriptHex)).toBe(true);
    });

    it('hex output has even length (full bytes)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      expect(result.scriptHex.length % 2).toBe(0);
    });

    it('emits non-empty hex for a contract with logic', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      expect(result.scriptHex.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // ASM output
  // ---------------------------------------------------------------------------

  describe('ASM output', () => {
    it('produces ASM string with opcode names', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      expect(typeof result.scriptAsm).toBe('string');
      expect(result.scriptAsm.length).toBeGreaterThan(0);
    });

    it('ASM contains OP_CHECKSIG for checkSig-based contract', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      expect(result.scriptAsm).toContain('OP_CHECKSIG');
    });

    it('terminal assert leaves value on stack (no OP_VERIFY for last assert)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const result = compileToEmit(source);
      // Terminal assert: OP_CHECKSIG is the last opcode, no OP_VERIFY
      expect(result.scriptAsm).toContain('OP_CHECKSIG');
      expect(result.scriptAsm).not.toContain('OP_VERIFY');
    });

    it('ASM contains OP_ADD for addition operation', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = a + 1n;
            assert(b > 0n);
          }
        }
      `;
      const result = emitMethodFromSource(source, 'm');
      expect(result.scriptAsm).toContain('OP_ADD');
    });

    it('ASM contains OP_SHA256 for sha256 calls', () => {
      const source = `
        class C extends SmartContract {
          readonly h: Sha256;
          constructor(h: Sha256) { super(h); this.h = h; }
          public m(data: ByteString) {
            assert(sha256(data) === this.h);
          }
        }
      `;
      const result = emitMethodFromSource(source, 'm');
      expect(result.scriptAsm).toContain('OP_SHA256');
    });
  });

  // ---------------------------------------------------------------------------
  // Push data encoding
  // ---------------------------------------------------------------------------

  describe('push data encoding', () => {
    it('encodes OP_0 for zero', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: 0n }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('00');
      expect(result.scriptAsm).toBe('OP_0');
    });

    it('encodes OP_1 through OP_16 for small integers', () => {
      for (let i = 1; i <= 16; i++) {
        const method: StackMethod = {
          name: 'test',
          ops: [{ op: 'push', value: BigInt(i) }],
          maxStackDepth: 1,
        };
        const result = emitMethod(method);
        const expectedOpcode = (0x50 + i).toString(16);
        expect(result.scriptHex).toBe(expectedOpcode);
        expect(result.scriptAsm).toBe(`OP_${i}`);
      }
    });

    it('encodes OP_1NEGATE for -1', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: -1n }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('4f');
      expect(result.scriptAsm).toBe('OP_1NEGATE');
    });

    it('encodes OP_TRUE for true', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: true }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('51');
      expect(result.scriptAsm).toBe('OP_TRUE');
    });

    it('encodes OP_FALSE for false', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: false }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('00');
      expect(result.scriptAsm).toBe('OP_FALSE');
    });

    it('encodes larger integers with push data', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: 42n }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      // 42 = 0x2a, encoded as single-byte push: length prefix (01) + data (2a)
      expect(result.scriptHex).toBe('012a');
      expect(result.scriptAsm).toContain('2a');
    });

    it('encodes byte arrays with appropriate push data prefix', () => {
      // Small byte array: 5 bytes
      const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: data }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      // Length prefix 05, then the 5 bytes
      expect(result.scriptHex).toBe('050102030405');
    });

    it('encodes empty byte array as OP_0', () => {
      const data = new Uint8Array(0);
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: data }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('00');
      expect(result.scriptAsm).toBe('OP_0');
    });

    it('encodes 75-byte data with direct length prefix (no OP_PUSHDATA1)', () => {
      // 75 bytes (0x4b) is the threshold: 0x01..0x4b use a 1-byte direct length prefix.
      // Only 76+ bytes trigger OP_PUSHDATA1 (0x4c).
      const data = new Uint8Array(75).fill(0xaa);
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: data }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      // Should start with 4b (75 decimal), NOT 4c (OP_PUSHDATA1)
      expect(result.scriptHex.startsWith('4b')).toBe(true);
      expect(result.scriptHex.startsWith('4c')).toBe(false);
      // Total length: 1 (prefix) + 75 (data) = 76 bytes = 152 hex chars
      expect(result.scriptHex).toHaveLength(152);
    });

    it('encodes data between 76-255 bytes with OP_PUSHDATA1', () => {
      const data = new Uint8Array(80).fill(0xab);
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: data }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      // Should start with 4c (OP_PUSHDATA1) followed by length byte 50 (80 decimal)
      expect(result.scriptHex.startsWith('4c50')).toBe(true);
    });

    it('encodes data of 256+ bytes with OP_PUSHDATA2 prefix', () => {
      // 256 bytes — requires PUSHDATA2 (0x4d), length as 2-byte little-endian
      const data = new Uint8Array(256).fill(0xcc);
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'push', value: data }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      // Should start with 4d (OP_PUSHDATA2) followed by length 256 as LE 2 bytes: 00 01
      expect(result.scriptHex.startsWith('4d0001')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Individual opcode emission
  // ---------------------------------------------------------------------------

  describe('opcode emission', () => {
    it('emits OP_DUP correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'dup' }],
        maxStackDepth: 2,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('76');
      expect(result.scriptAsm).toBe('OP_DUP');
    });

    it('emits OP_SWAP correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'swap' }],
        maxStackDepth: 2,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('7c');
      expect(result.scriptAsm).toBe('OP_SWAP');
    });

    it('emits OP_DROP correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'drop' }],
        maxStackDepth: 1,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('75');
      expect(result.scriptAsm).toBe('OP_DROP');
    });

    it('emits OP_ROLL correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'roll', depth: 3 }],
        maxStackDepth: 4,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('7a');
      expect(result.scriptAsm).toBe('OP_ROLL');
    });

    it('emits OP_PICK correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'pick', depth: 2 }],
        maxStackDepth: 3,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('79');
      expect(result.scriptAsm).toBe('OP_PICK');
    });

    it('emits OP_NIP correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'nip' }],
        maxStackDepth: 2,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('77');
      expect(result.scriptAsm).toBe('OP_NIP');
    });

    it('emits OP_OVER correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'over' }],
        maxStackDepth: 3,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('78');
      expect(result.scriptAsm).toBe('OP_OVER');
    });

    it('emits OP_ROT correctly', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [{ op: 'rot' }],
        maxStackDepth: 3,
      };
      const result = emitMethod(method);
      expect(result.scriptHex).toBe('7b');
      expect(result.scriptAsm).toBe('OP_ROT');
    });
  });

  // ---------------------------------------------------------------------------
  // If/else emission
  // ---------------------------------------------------------------------------

  describe('if/else emission', () => {
    it('emits OP_IF ... OP_ELSE ... OP_ENDIF structure', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [
          {
            op: 'if',
            then: [{ op: 'push', value: true }],
            else: [{ op: 'push', value: false }],
          },
        ],
        maxStackDepth: 2,
      };
      const result = emitMethod(method);
      expect(result.scriptAsm).toContain('OP_IF');
      expect(result.scriptAsm).toContain('OP_ELSE');
      expect(result.scriptAsm).toContain('OP_ENDIF');
    });

    it('emits OP_IF ... OP_ENDIF (no else) when else is empty', () => {
      const method: StackMethod = {
        name: 'test',
        ops: [
          {
            op: 'if',
            then: [{ op: 'push', value: true }],
          },
        ],
        maxStackDepth: 2,
      };
      const result = emitMethod(method);
      expect(result.scriptAsm).toContain('OP_IF');
      expect(result.scriptAsm).toContain('OP_ENDIF');
      // Should NOT contain OP_ELSE since else is undefined
      expect(result.scriptAsm).not.toContain('OP_ELSE');
    });
  });

  // ---------------------------------------------------------------------------
  // Method dispatch for multiple public methods
  // ---------------------------------------------------------------------------

  describe('method dispatch', () => {
    it('emits dispatch preamble for contracts with multiple public methods', () => {
      const source = `
        class Multi extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;
          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }
          public spend1(sig: Sig) { assert(checkSig(sig, this.pk1)); }
          public spend2(sig: Sig) { assert(checkSig(sig, this.pk2)); }
        }
      `;
      const result = compileToEmit(source);
      // With 2 public methods, the emitter generates a dispatch table
      // using OP_DUP, number push, OP_NUMEQUAL, OP_IF, OP_ELSE, OP_ENDIF
      expect(result.scriptAsm).toContain('OP_DUP');
      expect(result.scriptAsm).toContain('OP_NUMEQUAL');
      expect(result.scriptAsm).toContain('OP_IF');
      expect(result.scriptAsm).toContain('OP_ENDIF');
    });

    it('emits fail-closed dispatch for last method', () => {
      const source = `
        class Multi extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;
          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }
          public spend1(sig: Sig) { assert(checkSig(sig, this.pk1)); }
          public spend2(sig: Sig) { assert(checkSig(sig, this.pk2)); }
        }
      `;
      const result = compileToEmit(source);
      // Last method should use NUMEQUALVERIFY (fail-closed) instead of DROP
      expect(result.scriptAsm).toContain('OP_NUMEQUALVERIFY');
    });

    it('emits no dispatch for single public method', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) { assert(checkSig(sig, this.pk)); }
        }
      `;
      const result = compileToEmit(source);
      // Single method: no dispatch, no extra DUP/NUMEQUAL preamble
      // The script should not start with the dispatch pattern
      const asm = result.scriptAsm;
      // Should not have the dispatch-specific OP_DUP + OP_0 + OP_NUMEQUAL at the start
      // First token should NOT be OP_DUP for single-method contracts
      // (It could be OP_DUP if the method itself needs it, but not for dispatch)
      // We just verify there's no OP_NUMEQUAL since that's dispatch-specific
      expect(asm.includes('OP_NUMEQUAL')).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Source map
  // ---------------------------------------------------------------------------

  describe('source map', () => {
    it('returns an array of source mappings (possibly empty)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) { assert(checkSig(sig, this.pk)); }
        }
      `;
      const result = compileToEmit(source);
      expect(Array.isArray(result.sourceMap)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Standalone peephole handles verify-combinations (no emit-phase duplicate)
  // ---------------------------------------------------------------------------

  describe('verify-combination via standalone peephole optimizer', () => {
    it('emits OP_EQUALVERIFY when standalone optimizer runs before emit', () => {
      // OP_EQUAL + OP_VERIFY should be combined by the standalone peephole optimizer
      const ops: StackOp[] = [
        { op: 'push', value: 1n },
        { op: 'push', value: 1n },
        { op: 'opcode', code: 'OP_EQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      // Run standalone peephole optimizer (as the real pipeline does)
      const optimized = optimizeStackIR(ops);
      // Should combine OP_EQUAL + OP_VERIFY into OP_EQUALVERIFY
      expect(optimized).toEqual([
        { op: 'push', value: 1n },
        { op: 'push', value: 1n },
        { op: 'opcode', code: 'OP_EQUALVERIFY' },
      ]);
      // Emit the optimized ops
      const method: StackMethod = { name: 'test', ops: optimized, maxStackDepth: 2 };
      const result = emitMethod(method);
      expect(result.scriptAsm).toContain('OP_EQUALVERIFY');
      expect(result.scriptAsm).not.toContain('OP_VERIFY');
    });

    it('emits OP_CHECKSIGVERIFY when standalone optimizer runs before emit', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_CHECKSIG' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const optimized = optimizeStackIR(ops);
      expect(optimized).toEqual([
        { op: 'opcode', code: 'OP_CHECKSIGVERIFY' },
      ]);
      const method: StackMethod = { name: 'test', ops: optimized, maxStackDepth: 2 };
      const result = emitMethod(method);
      expect(result.scriptAsm).toBe('OP_CHECKSIGVERIFY');
    });

    it('emits OP_NUMEQUALVERIFY when standalone optimizer runs before emit', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_NUMEQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const optimized = optimizeStackIR(ops);
      expect(optimized).toEqual([
        { op: 'opcode', code: 'OP_NUMEQUALVERIFY' },
      ]);
      const method: StackMethod = { name: 'test', ops: optimized, maxStackDepth: 2 };
      const result = emitMethod(method);
      expect(result.scriptAsm).toBe('OP_NUMEQUALVERIFY');
    });

    it('emit produces correct hex without its own peephole pass', () => {
      // Verify that after standalone peephole runs, emit correctly encodes
      // the already-optimized ops without needing its own peephole
      const ops: StackOp[] = [
        { op: 'push', value: 42n },
        { op: 'push', value: 42n },
        { op: 'opcode', code: 'OP_EQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const optimized = optimizeStackIR(ops);
      const method: StackMethod = { name: 'test', ops: optimized, maxStackDepth: 2 };
      const result = emitMethod(method);
      // OP_EQUALVERIFY is 0x88
      expect(result.scriptHex).toContain('88');
      // Should NOT contain separate OP_EQUAL (0x87) followed by OP_VERIFY (0x69)
      expect(result.scriptHex).not.toContain('8769');
    });
  });

  // ---------------------------------------------------------------------------
  // OPCODES constant table
  // ---------------------------------------------------------------------------

  describe('OPCODES constant table', () => {
    it('has the standard Bitcoin Script opcodes', () => {
      expect(OPCODES['OP_DUP']).toBe(0x76);
      expect(OPCODES['OP_CHECKSIG']).toBe(0xac);
      expect(OPCODES['OP_VERIFY']).toBe(0x69);
      expect(OPCODES['OP_ADD']).toBe(0x93);
      expect(OPCODES['OP_SUB']).toBe(0x94);
      expect(OPCODES['OP_IF']).toBe(0x63);
      expect(OPCODES['OP_ELSE']).toBe(0x67);
      expect(OPCODES['OP_ENDIF']).toBe(0x68);
      expect(OPCODES['OP_SHA256']).toBe(0xa8);
      expect(OPCODES['OP_HASH160']).toBe(0xa9);
      expect(OPCODES['OP_EQUAL']).toBe(0x87);
      expect(OPCODES['OP_DROP']).toBe(0x75);
      expect(OPCODES['OP_SWAP']).toBe(0x7c);
      expect(OPCODES['OP_ROLL']).toBe(0x7a);
      expect(OPCODES['OP_PICK']).toBe(0x79);
    });
  });
});
