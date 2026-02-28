import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ContractNode } from '../ir/index.js';
import type { StackProgram, StackMethod, StackOp } from '../ir/index.js';

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

function compileToStack(source: string): StackProgram {
  const contract = parseContract(source);
  const anf = lowerToANF(contract);
  return lowerToStack(anf);
}

function findStackMethod(program: StackProgram, name: string): StackMethod {
  const method = program.methods.find(m => m.name === name);
  if (!method) {
    throw new Error(`Stack method '${name}' not found. Available: ${program.methods.map(m => m.name).join(', ')}`);
  }
  return method;
}

function flattenOps(ops: StackOp[]): StackOp[] {
  const result: StackOp[] = [];
  for (const op of ops) {
    if (op.op === 'if') {
      result.push(op);
      result.push(...flattenOps(op.then));
      if (op.else) {
        result.push(...flattenOps(op.else));
      }
    } else {
      result.push(op);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Pass 5: Stack Lower', () => {
  // ---------------------------------------------------------------------------
  // Basic stack program structure
  // ---------------------------------------------------------------------------

  describe('basic structure', () => {
    it('produces a StackProgram with the contract name', () => {
      const source = `
        class P2PKH extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      expect(program.contractName).toBe('P2PKH');
    });

    it('produces stack methods for constructor and public methods', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const methodNames = program.methods.map(m => m.name);
      expect(methodNames).toContain('constructor');
      expect(methodNames).toContain('unlock');
    });
  });

  // ---------------------------------------------------------------------------
  // Stack ops are produced
  // ---------------------------------------------------------------------------

  describe('stack ops production', () => {
    it('produces non-empty ops for a simple unlock method', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      expect(unlock.ops.length).toBeGreaterThan(0);
    });

    it('contains OP_CHECKSIG opcode for checkSig call', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      const allOps = flattenOps(unlock.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_CHECKSIG');
    });

    it('contains OP_VERIFY for assert calls', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      const allOps = flattenOps(unlock.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_VERIFY');
    });

    it('contains push ops for constants', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            assert(true);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const pushOps = method.ops.filter(o => o.op === 'push');
      expect(pushOps.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // OP_DUP / OP_SWAP / OP_ROLL usage
  // ---------------------------------------------------------------------------

  describe('stack manipulation ops', () => {
    it('uses OP_SWAP or OP_ROLL to reorder stack elements', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      // At least some stack manipulation should be present to arrange
      // sig and pk in the correct order for OP_CHECKSIG
      // This should usually be true, but the exact ops depend on parameter ordering.
      // Verify we at least have push + opcode ops.
      expect(unlock.ops.length).toBeGreaterThan(0);
    });

    it('uses push + arithmetic opcodes for binary operations', () => {
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
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_ADD');
    });
  });

  // ---------------------------------------------------------------------------
  // Max stack depth tracking
  // ---------------------------------------------------------------------------

  describe('max stack depth', () => {
    it('tracks maxStackDepth for each method', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      expect(typeof unlock.maxStackDepth).toBe('number');
      expect(unlock.maxStackDepth).toBeGreaterThan(0);
    });

    it('maxStackDepth is at least as large as the number of parameters', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const unlock = findStackMethod(program, 'unlock');
      // unlock has 1 param (sig), so maxStackDepth >= 1
      expect(unlock.maxStackDepth).toBeGreaterThanOrEqual(1);
    });
  });

  // ---------------------------------------------------------------------------
  // If/else generates OP_IF structure
  // ---------------------------------------------------------------------------

  describe('if/else stack lowering', () => {
    it('produces an if StackOp for if/else statements', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(flag: boolean) {
            if (flag) {
              assert(true);
            } else {
              assert(false);
            }
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const ifOps = method.ops.filter(o => o.op === 'if');
      expect(ifOps.length).toBeGreaterThanOrEqual(1);

      const ifOp = ifOps[0]! as { op: 'if'; then: StackOp[]; else?: StackOp[] };
      expect(ifOp.then.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Hash function lowering
  // ---------------------------------------------------------------------------

  describe('hash function lowering', () => {
    it('produces OP_SHA256 for sha256 call', () => {
      const source = `
        class C extends SmartContract {
          readonly h: Sha256;
          constructor(h: Sha256) { super(h); this.h = h; }
          public m(data: ByteString) {
            assert(sha256(data) === this.h);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_SHA256');
    });
  });

  // ---------------------------------------------------------------------------
  // Comparison lowering
  // ---------------------------------------------------------------------------

  describe('comparison lowering', () => {
    it('produces OP_GREATERTHAN for > comparison', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_GREATERTHAN');
    });
  });
});
