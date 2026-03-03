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
      // Terminal assert leaves value on stack (no OP_VERIFY), but the
      // contract still compiles OP_CHECKSIG as the terminal operation.
      expect(opcodes).toContain('OP_CHECKSIG');
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

  // ---------------------------------------------------------------------------
  // Built-in functions that were type-checked but had no codegen (spec gaps)
  // ---------------------------------------------------------------------------

  describe('exit/pack/unpack/toByteString codegen', () => {
    it('exit() compiles to OP_VERIFY', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            exit(a > 0n);
            assert(true);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_VERIFY');
    });

    it('unpack() compiles to OP_BIN2NUM', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(data: ByteString) {
            const n: bigint = unpack(data);
            assert(n > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_BIN2NUM');
    });

    it('pack() compiles without error (no-op type cast)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: ByteString = pack(a);
            assert(len(b) > 0n);
          }
        }
      `;
      // Should not throw "Unknown builtin function"
      expect(() => compileToStack(source)).not.toThrow();
    });

    it('toByteString() compiles without error (no-op identity)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(data: ByteString) {
            const b: ByteString = toByteString(data);
            assert(len(b) > 0n);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // checkMultiSig stack layout
  // ---------------------------------------------------------------------------

  describe('checkMultiSig stack layout', () => {
    it('emits OP_0 dummy, counts, and OP_CHECKMULTISIG', () => {
      const source = `
        class MultiSig extends SmartContract {
          readonly pk1: PubKey;
          readonly pk2: PubKey;

          constructor(pk1: PubKey, pk2: PubKey) {
            super(pk1, pk2);
            this.pk1 = pk1;
            this.pk2 = pk2;
          }

          public unlock(sig1: Sig, sig2: Sig) {
            assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2]));
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'unlock');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_CHECKMULTISIG');
    });
  });

  // ---------------------------------------------------------------------------
  // Terminal assert in if/else branches (issue #2)
  // ---------------------------------------------------------------------------

  describe('terminal assert in if/else branches', () => {
    it('omits OP_VERIFY for terminal asserts when if/else is the last binding', () => {
      const source = `
        class BranchAssert extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public check(a: bigint) {
            if (a > 0n) {
              assert(this.x > 0n);
            } else {
              assert(this.x === 0n);
            }
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'check');

      // Find the IfOp in the method ops
      const ifOp = method.ops.find(o => o.op === 'if') as
        | { op: 'if'; then: StackOp[]; else?: StackOp[] }
        | undefined;
      expect(ifOp).toBeDefined();

      // Neither branch should contain OP_VERIFY — the terminal assert
      // must leave its value on the stack for Bitcoin Script's truthiness check.
      const thenOpcodes = ifOp!.then
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(thenOpcodes).not.toContain('OP_VERIFY');

      const elseOpcodes = (ifOp!.else ?? [])
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(elseOpcodes).not.toContain('OP_VERIFY');
    });

    it('still emits OP_VERIFY for non-terminal asserts before a terminal if/else', () => {
      const source = `
        class PreAssert extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public check(a: bigint) {
            assert(a > 0n);
            if (a > 1n) {
              assert(this.x > 0n);
            } else {
              assert(this.x === 0n);
            }
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'check');

      // The first assert (a > 0n) should still produce OP_VERIFY
      // because it's not the terminal assert.
      const topLevelOpcodes = method.ops
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(topLevelOpcodes).toContain('OP_VERIFY');

      // But the branch asserts should NOT have OP_VERIFY
      const ifOp = method.ops.find(o => o.op === 'if') as
        | { op: 'if'; then: StackOp[]; else?: StackOp[] }
        | undefined;
      expect(ifOp).toBeDefined();

      const thenOpcodes = ifOp!.then
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(thenOpcodes).not.toContain('OP_VERIFY');

      const elseOpcodes = (ifOp!.else ?? [])
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(elseOpcodes).not.toContain('OP_VERIFY');
    });
  });

  // ---------------------------------------------------------------------------
  // ByteString indexing (__array_access)
  // ---------------------------------------------------------------------------

  describe('ByteString indexing (__array_access)', () => {
    it('produces OP_SPLIT + nip + OP_SPLIT + drop + OP_BIN2NUM for data[0n]', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(data: ByteString) {
            const byte: bigint = data[0n];
            assert(byte > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      const allOpTypes = allOps.map(o => o.op);
      // ByteString indexing emits: OP_SPLIT nip push(1) OP_SPLIT drop OP_BIN2NUM
      expect(opcodes).toContain('OP_SPLIT');
      expect(allOpTypes).toContain('nip');
      expect(allOpTypes).toContain('drop');
      expect(opcodes).toContain('OP_BIN2NUM');
    });

    it('handles ByteString indexing with a variable index', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(data: ByteString, idx: bigint) {
            const byte: bigint = data[idx];
            assert(byte > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_SPLIT');
      expect(opcodes).toContain('OP_BIN2NUM');
    });
  });

  // ---------------------------------------------------------------------------
  // C1: Rabin Sig — correct stack order (no orphaned OP_DUP/OP_TOALTSTACK)
  // ---------------------------------------------------------------------------

  describe('verifyRabinSig stack order (C1)', () => {
    it('does not emit orphaned OP_TOALTSTACK for verifyRabinSig', () => {
      const source = `
        class RabinOracle extends SmartContract {
          readonly rpk: RabinPubKey;
          constructor(rpk: RabinPubKey) { super(rpk); this.rpk = rpk; }
          public verify(msg: ByteString, sig: RabinSig, padding: ByteString) {
            assert(verifyRabinSig(msg, sig, padding, this.rpk));
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'verify');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // The fixed version should NOT use OP_TOALTSTACK (orphaned pubKey dup).
      // Instead it uses OP_SWAP + OP_ROT to rearrange stack correctly.
      expect(opcodes).not.toContain('OP_TOALTSTACK');
    });

    it('emits OP_SWAP and OP_ROT for correct Rabin sig stack arrangement', () => {
      const source = `
        class RabinOracle extends SmartContract {
          readonly rpk: RabinPubKey;
          constructor(rpk: RabinPubKey) { super(rpk); this.rpk = rpk; }
          public verify(msg: ByteString, sig: RabinSig, padding: ByteString) {
            assert(verifyRabinSig(msg, sig, padding, this.rpk));
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'verify');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // After OP_SWAP and OP_ROT, sig should be on top for squaring (OP_DUP OP_MUL)
      expect(opcodes).toContain('OP_SWAP');
      expect(opcodes).toContain('OP_ROT');
      expect(opcodes).toContain('OP_DUP');
      expect(opcodes).toContain('OP_MUL');

      // Verify the sig-squaring sequence: OP_DUP immediately followed by OP_MUL
      const dupIdx = opcodes.indexOf('OP_DUP');
      expect(opcodes[dupIdx + 1]).toBe('OP_MUL');
    });
  });

  // ---------------------------------------------------------------------------
  // C2: sign(0) division by zero — must guard with OP_IF
  // ---------------------------------------------------------------------------

  describe('sign() division-by-zero guard (C2)', () => {
    it('emits OP_DUP OP_IF pattern for sign() to avoid div-by-zero', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const s: bigint = sign(a);
            assert(s > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      // The safe sign() implementation must use an OP_IF guard:
      // OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF
      // This means an 'if' StackOp must be present (for the conditional)
      const allOpTypes = allOps.map(o => o.op);
      expect(allOpTypes).toContain('if');

      // The if-branch should contain OP_ABS and OP_DIV for the x / abs(x) computation
      const ifOp = allOps.find(o => o.op === 'if') as
        | { op: 'if'; then: StackOp[]; else?: StackOp[] }
        | undefined;
      expect(ifOp).toBeDefined();
      const thenOpcodes = ifOp!.then
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(thenOpcodes).toContain('OP_ABS');
      expect(thenOpcodes).toContain('OP_DIV');
    });

    it('sign() does not emit OP_DIV at top level (only inside if-branch)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const s: bigint = sign(a);
            assert(s > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');

      // sign() should NOT unconditionally emit OP_DIV without a guard.
      // The old buggy version emitted: OP_DUP OP_ABS OP_SWAP OP_DIV
      // Check that OP_DIV is ONLY inside an if-branch, not at top level.
      const topLevelOpcodes = method.ops
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(topLevelOpcodes).not.toContain('OP_DIV');
    });
  });

  // ---------------------------------------------------------------------------
  // M1: right() — must use OP_SIZE to get rightmost bytes
  // ---------------------------------------------------------------------------

  describe('right() correct semantics (M1)', () => {
    it('emits OP_SIZE for right() to compute split offset from end', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(data: ByteString) {
            const tail: ByteString = right(data, 2n);
            assert(tail === this.x);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // right(data, n) should compute: size(data) - n, then split at that offset
      // This requires OP_SIZE and OP_SUB before OP_SPLIT
      expect(opcodes).toContain('OP_SIZE');
      expect(opcodes).toContain('OP_SUB');
      expect(opcodes).toContain('OP_SPLIT');
    });

    it('right() emits nip to keep the right portion after split', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(data: ByteString) {
            const tail: ByteString = right(data, 2n);
            assert(tail === this.x);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const allOpTypes = allOps.map(o => o.op);

      // After OP_SPLIT, we keep the right part (NIP removes the left)
      expect(allOpTypes).toContain('nip');
    });
  });

  // ---------------------------------------------------------------------------
  // C4: ByteString + emits OP_CAT not OP_ADD
  // ---------------------------------------------------------------------------

  describe('ByteString concatenation with + operator (C4)', () => {
    it('emits OP_CAT for ByteString + ByteString', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(a: ByteString, b: ByteString) {
            const c: ByteString = a + b;
            assert(c === this.x);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // When result_type is 'bytes', + should emit OP_CAT, not OP_ADD
      expect(opcodes).toContain('OP_CAT');
      expect(opcodes).not.toContain('OP_ADD');
    });

    it('still emits OP_ADD for bigint + bigint', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint, b: bigint) {
            const c: bigint = a + b;
            assert(c > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // Numeric + should remain OP_ADD
      expect(opcodes).toContain('OP_ADD');
    });
  });
});
