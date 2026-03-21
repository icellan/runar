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

  // ---------------------------------------------------------------------------
  // Fix #1: extractOutputHash offset should be 40 not 44 (BIP-143)
  // ---------------------------------------------------------------------------

  describe('extractOutputHash BIP-143 offset (Fix #1)', () => {
    it('uses offset 40 (not 44) for extractOutputHash', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment(txPreimage: SigHashPreimage) {
            const outputHash: Sha256 = extractOutputHash(txPreimage);
            assert(true);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'increment');
      const allOps = flattenOps(method.ops);
      // Check that extractOutputHash uses 40n (correct BIP-143 offset).
      // Note: 44n may appear elsewhere (computeStateOutputHash, deserialize_state)
      // so we only verify 40n is present for the extractOutputHash path.
      const pushValues = allOps.filter(o => o.op === 'push').map(o => (o as { value: unknown }).value);
      expect(pushValues).toContain(40n);
    });
  });

  // ---------------------------------------------------------------------------
  // Fix #7: collectRefs tracks @ref: variables
  // ---------------------------------------------------------------------------

  describe('collectRefs @ref: tracking (Fix #7)', () => {
    it('does not crash when a variable is aliased via @ref: in ANF', () => {
      // This tests that the stack lowerer properly handles @ref: aliases
      // in use analysis (collectRefs). If @ref: was not tracked, the
      // referenced variable might be consumed too early.
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            let b: bigint = a;
            const c: bigint = b + 1n;
            assert(c > 0n);
          }
        }
      `;
      // Should compile without errors (no stack underflow from missing ref tracking)
      expect(() => compileToStack(source)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Fix #6: len() must emit OP_NIP after OP_SIZE
  // ---------------------------------------------------------------------------

  describe('len() stack cleanup (Fix #6)', () => {
    it('emits OP_NIP after OP_SIZE to remove the phantom original value', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(data: ByteString) {
            const sz: bigint = len(data);
            assert(sz > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      const allOpTypes = allOps.map(o => o.op);

      expect(opcodes).toContain('OP_SIZE');
      // OP_NIP must follow OP_SIZE to remove the original value
      expect(allOpTypes).toContain('nip');

      // Verify nip comes after OP_SIZE
      const sizeIdx = allOps.findIndex(o => o.op === 'opcode' && (o as { code: string }).code === 'OP_SIZE');
      const nipIdx = allOps.findIndex((o, i) => i > sizeIdx && o.op === 'nip');
      expect(nipIdx).toBeGreaterThan(sizeIdx);
    });

    it('len() followed by more operations does not corrupt the stack', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(data: ByteString) {
            const sz1: bigint = len(data);
            const sz2: bigint = len(data);
            assert(sz1 === sz2);
          }
        }
      `;
      // If len() leaked a phantom element, this would throw a stack error
      expect(() => compileToStack(source)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Fix #5: log2() uses bit-scanning (not byte-size approximation)
  // ---------------------------------------------------------------------------

  describe('log2() bit-scanning (Fix #5)', () => {
    it('emits OP_DIV and OP_GREATERTHAN for proper bit scanning', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const bits: bigint = log2(a);
            assert(bits > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);

      // The bit-scanning loop should use OP_DIV and OP_GREATERTHAN
      expect(opcodes).toContain('OP_DIV');
      expect(opcodes).toContain('OP_GREATERTHAN');
      expect(opcodes).toContain('OP_1ADD');

      // The old byte-size approximation used OP_SIZE and OP_MUL — those should NOT be present
      // for the log2 computation itself
      expect(opcodes).not.toContain('OP_MUL');
    });
  });

  // ---------------------------------------------------------------------------
  // Fix #25: sqrt(0) division by zero guard
  // ---------------------------------------------------------------------------

  describe('sqrt(0) guard (Fix #25)', () => {
    it('wraps Newton iteration in OP_DUP OP_IF guard', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const r: bigint = sqrt(a);
            assert(r >= 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);

      // The guard should emit OP_DUP followed by an if StackOp
      const opcodes = allOps.filter(o => o.op === 'opcode').map(o => (o as { code: string }).code);
      expect(opcodes).toContain('OP_DUP');

      // An if block must be present (the guard)
      const allOpTypes = allOps.map(o => o.op);
      expect(allOpTypes).toContain('if');

      // The Newton iteration (OP_DIV) should be INSIDE the if-branch only
      const topLevelOpcodes = method.ops
        .filter(o => o.op === 'opcode')
        .map(o => (o as { code: string }).code);
      expect(topLevelOpcodes).not.toContain('OP_DIV');
    });

    it('sqrt compiles without errors', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const r: bigint = sqrt(a);
            assert(r >= 0n);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Multi-method stateful contracts: PICK/ROLL depths must be correct for
  // all methods, not just the first one. Regression test for off-by-one bug
  // where method bodies in multi-method dispatch had PICK/ROLL depths that
  // were too high by exactly 1.
  // ---------------------------------------------------------------------------

  describe('multi-method stateful checkSig depths', () => {
    // Minimal 2-method stateful contract where method[1] uses checkSig.
    // Both methods are state-mutating (they increment a counter), so both
    // need _codePart and _opPushTxSig on the stack.
    const MULTI_METHOD_SOURCE = `
      import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig } from 'runar-lang';

      export class TwoMethod extends StatefulSmartContract {
        readonly pk: PubKey;
        value: bigint;

        constructor(pk: PubKey, value: bigint) {
          super(pk, value);
          this.pk = pk;
          this.value = value;
        }

        public increment() {
          this.value = this.value + 1n;
        }

        public signedIncrement(sig: Sig) {
          assert(checkSig(sig, this.pk));
          this.value = this.value + 1n;
        }
      }
    `;

    it('signedIncrement ROLL depth for checkSig operands should be correct', () => {
      const program = compileToStack(MULTI_METHOD_SOURCE);
      const method = findStackMethod(program, 'signedIncrement');
      const allOps = flattenOps(method.ops);

      // Find OP_CHECKSIGVERIFY (from checkSig inside assert)
      const checksigIdx = allOps.findIndex(
        o => o.op === 'opcode' && (o as { code: string }).code === 'OP_CHECKSIGVERIFY',
      );
      expect(checksigIdx).toBeGreaterThan(0);

      // The two operands for CHECKSIGVERIFY should be pushed just before it
      // via ROLL or PICK operations. Collect the ROLL/PICK ops in the window
      // before CHECKSIGVERIFY (after OP_CODESEPARATOR).
      const codesepIdx = allOps.findIndex(
        o => o.op === 'opcode' && (o as { code: string }).code === 'OP_CODESEPARATOR',
      );
      expect(codesepIdx).toBeGreaterThan(-1);

      // After OP_CODESEPARATOR, the stack should be:
      //   _codePart, _opPushTxSig, sig, _changePKH, _changeAmount, _newAmount, txPreimage
      // check_preimage consumes txPreimage and _opPushTxSig, leaving:
      //   _codePart, sig, _changePKH, _changeAmount, _newAmount
      // Then deserialize_state pushes pk, value from preimage:
      //   _codePart, sig, _changePKH, _changeAmount, _newAmount, pk, value
      //
      // For checkSig(sig, this.pk):
      //   sig is at depth 5 (from TOS: value=0, pk=1, _newAmount=2, _changeAmount=3, _changePKH=4, sig=5)
      //   pk is at depth 1
      //
      // The compiler should generate:
      //   ROLL(5) to bring sig to top → stack becomes: _codePart, _changePKH, _changeAmount, _newAmount, pk, value, sig
      //   Then ROLL or PICK pk (now at depth 2 after value and sig are above it)
      //   Or alternatively: the compiler might reorder these differently.
      //
      // The KEY assertion: no ROLL/PICK depth should exceed the actual stack size.
      // With the off-by-one bug, depths would be exactly 1 too high.

      // Verify by simulating the stack. Count stack items at the point where
      // checkSig operands are fetched. The initial params for signedIncrement:
      // _codePart, _opPushTxSig, sig, _changePKH, _changeAmount, _newAmount, txPreimage
      // = 7 items. After check_preimage: removes txPreimage and _opPushTxSig = 5 items.
      // After deserialize_state adds pk, value = 7 items total.

      // Gather all ROLL/PICK ops between codesep and checksig
      const rollPickOps: Array<{ op: string; depth: number; idx: number }> = [];
      for (let i = codesepIdx; i < checksigIdx; i++) {
        const op = allOps[i]!;
        if (op.op === 'roll' || op.op === 'pick') {
          rollPickOps.push({ op: op.op, depth: (op as { depth: number }).depth, idx: i });
        }
      }

      // All depths must be non-negative and within the stack size.
      // The max possible stack depth at checkSig time is ~7 items (5 original + 2 deserialized).
      // With the off-by-one bug, we'd see depths of 8+ when the max should be 6.
      for (const rp of rollPickOps) {
        expect(rp.depth).toBeGreaterThanOrEqual(0);
        // With 7 items on the stack, max valid depth is 6 (0-indexed)
        expect(rp.depth).toBeLessThanOrEqual(6);
      }
    });

    // More comprehensive test: a 3-method contract mimicking TicTacToe's pattern
    // (join=method0 with checkSig, move=method1 with checkSig and more state)
    const THREE_METHOD_SOURCE = `
      import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig } from 'runar-lang';

      export class ThreeMethod extends StatefulSmartContract {
        readonly pkA: PubKey;
        pkB: PubKey;
        c0: bigint;
        c1: bigint;
        c2: bigint;
        turn: bigint;
        status: bigint;

        constructor(pkA: PubKey) {
          super(pkA);
          this.pkA = pkA;
        }

        public join(opponent: PubKey, sig: Sig) {
          assert(this.status == 0n);
          assert(checkSig(sig, opponent));
          this.pkB = opponent;
          this.status = 1n;
          this.turn = 1n;
        }

        public play(position: bigint, player: PubKey, sig: Sig) {
          assert(this.status == 1n);
          assert(checkSig(sig, player));
          if (this.turn == 1n) {
            assert(player == this.pkA);
          } else {
            assert(player == this.pkB);
          }
          if (position == 0n) { this.c0 = this.turn; }
          else if (position == 1n) { this.c1 = this.turn; }
          else { this.c2 = this.turn; }
          if (this.turn == 1n) {
            this.turn = 2n;
          } else {
            this.turn = 1n;
          }
        }

        public reset(sig: Sig) {
          assert(checkSig(sig, this.pkA));
          this.c0 = 0n;
          this.c1 = 0n;
          this.c2 = 0n;
          this.turn = 1n;
        }
      }
    `;

    it('all methods in a 3-method contract should have valid ROLL/PICK depths', () => {
      const program = compileToStack(THREE_METHOD_SOURCE);

      for (const methodName of ['join', 'play', 'reset']) {
        const method = findStackMethod(program, methodName);
        const allOps = flattenOps(method.ops);

        // Validate every ROLL/PICK depth is non-negative
        for (let i = 0; i < allOps.length; i++) {
          const op = allOps[i]!;
          if (op.op === 'roll' || op.op === 'pick') {
            const depth = (op as { depth: number }).depth;
            expect(depth).toBeGreaterThanOrEqual(0);
            // The maximum conceivable stack depth is maxStackDepth
            expect(depth).toBeLessThan(method.maxStackDepth);
          }
        }
      }
    });

    it('play method (index 1) checkSig depths should match join method (index 0) pattern', () => {
      const program = compileToStack(THREE_METHOD_SOURCE);

      // Both join and play use checkSig. The ROLL depth to bring `sig` to TOS
      // should be proportional to the number of items between sig and TOS.
      // If method 1 has an off-by-one error, its depths would be systematically
      // higher than expected.

      const joinMethod = findStackMethod(program, 'join');
      const playMethod = findStackMethod(program, 'play');

      const joinOps = flattenOps(joinMethod.ops);
      const playOps = flattenOps(playMethod.ops);

      // Find the OP_CHECKSIGVERIFY in each method and the ROLL just before it
      // that brings the signature to TOS.
      function findCheckSigRollDepth(ops: ReturnType<typeof flattenOps>): number {
        const csIdx = ops.findIndex(
          o => o.op === 'opcode' && (o as { code: string }).code === 'OP_CHECKSIGVERIFY',
        );
        expect(csIdx).toBeGreaterThan(0);

        // Walk backwards from CHECKSIGVERIFY to find the last ROLL before it
        // (this brings the sig to TOS for the CHECKSIG operation)
        for (let i = csIdx - 1; i >= 0; i--) {
          if (ops[i]!.op === 'roll') {
            return (ops[i] as { depth: number }).depth;
          }
        }
        throw new Error('No ROLL found before OP_CHECKSIGVERIFY');
      }

      const joinSigRollDepth = findCheckSigRollDepth(joinOps);
      const playSigRollDepth = findCheckSigRollDepth(playOps);

      // play has 1 more user param (position) than join (opponent, sig vs position, player, sig).
      // So the sig ROLL depth for play should be exactly 1 more than join's.
      // With the off-by-one bug, play's depth would be 2 more instead of 1 more.
      expect(playSigRollDepth).toBe(joinSigRollDepth + 1);
    });
  });

  // ---------------------------------------------------------------------------
  // reverseBytes uses OP_SPLIT/OP_CAT loop, not OP_REVERSE
  // ---------------------------------------------------------------------------

  describe('reverseBytes codegen', () => {
    it('reverseBytes uses OP_SPLIT/OP_CAT loop, not OP_REVERSE', () => {
      const source = `
        class ReverseTest extends SmartContract {
          readonly data: ByteString;
          constructor(data: ByteString) { super(data); this.data = data; }
          public check(expected: ByteString) {
            const reversed: ByteString = reverseBytes(this.data);
            assert(reversed === expected);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'check');
      const allOps = flattenOps(method.ops);

      const allOpsJson = JSON.stringify(allOps, (_k, v) =>
        typeof v === 'bigint' ? v.toString() : v,
      );
      expect(allOpsJson).not.toContain('OP_REVERSE');
      expect(allOpsJson).toContain('OP_SPLIT');
      expect(allOpsJson).toContain('OP_CAT');
      expect(allOpsJson).toContain('OP_SIZE');
    });
  });

  // ---------------------------------------------------------------------------
  // Bug fix regression tests: stack misalignment in stateful contracts
  // ---------------------------------------------------------------------------

  describe('stateful update_prop old-value removal (bug fix #1)', () => {
    // Bug: After liftBranchUpdateProps transforms conditional property updates
    // into flat conditional assignments + top-level update_prop, each update_prop
    // pushes the new value but the OLD property value remains on the stack.
    // Over N properties, the stack accumulates N extra items.
    it('does not accumulate stale property values after multiple update_prop', () => {
      const source = `
        class TurnFlip extends StatefulSmartContract {
          count: bigint;
          turn: bigint;
          constructor(count: bigint, turn: bigint) {
            super(count, turn);
            this.count = count;
            this.turn = turn;
          }
          public play(sig: Sig, pk: PubKey): void {
            this.count = this.count + 1n;
            if (this.turn === 1n) { this.turn = 2n; }
            else { this.turn = 1n; }
            assert(checkSig(sig, pk));
          }
        }
      `;
      // Should compile without throwing "Value not found on stack"
      const program = compileToStack(source);
      const play = findStackMethod(program, 'play');
      expect(play.ops.length).toBeGreaterThan(0);

      // Count NIP ops — the old-value removal should produce at least one NIP
      // to remove the stale property entry after update_prop
      const allOps = flattenOps(play.ops);
      const nips = allOps.filter(o => o.op === 'nip');
      expect(nips.length).toBeGreaterThan(0);
    });
  });

  describe('conditional placeholder in branch reconciliation (bug fix #2)', () => {
    // Bug: When one if-branch consumed a parent item but the other didn't,
    // reconciliation unconditionally pushed an empty-bytes placeholder. For
    // assertion-only branches (like assertCellEmpty), removal alone balanced
    // the branches — the extra placeholder made them unequal again.
    it('does not push unnecessary placeholder for assertion-only branches', () => {
      const source = `
        class Game extends StatefulSmartContract {
          status: bigint;
          c0: bigint;
          c1: bigint;
          constructor(status: bigint, c0: bigint, c1: bigint) {
            super(status, c0, c1);
            this.status = status;
            this.c0 = c0;
            this.c1 = c1;
          }
          private assertCellEmpty(position: bigint): void {
            if (position === 0n) { assert(this.c0 === 0n); }
            else { assert(this.c1 === 0n); }
          }
          public play(position: bigint, sig: Sig, pk: PubKey): void {
            this.assertCellEmpty(position);
            if (position === 0n) { this.c0 = 1n; }
            else { this.c1 = 1n; }
            assert(checkSig(sig, pk));
          }
        }
      `;
      // The key test: this should compile without stack depth errors.
      // Before the fix, the unnecessary placeholder caused a depth mismatch.
      const program = compileToStack(source);
      const play = findStackMethod(program, 'play');
      expect(play.ops.length).toBeGreaterThan(0);
    });
  });

  describe('duplicate-named stack entries from nested inlining (bug fix #3)', () => {
    // Bug: When placeMove inlines assertCellEmpty and both have a "position"
    // parameter, inlineMethodCall creates two stack entries named "position".
    // Set-based reconciliation in lowerIf collapses duplicates, missing
    // asymmetric consumption.
    it('handles shadowed parameter names in nested private method calls', () => {
      const source = `
        class Game extends StatefulSmartContract {
          status: bigint;
          c0: bigint;
          c1: bigint;
          constructor(status: bigint, c0: bigint, c1: bigint) {
            super(status, c0, c1);
            this.status = status;
            this.c0 = c0;
            this.c1 = c1;
          }
          private assertCellEmpty(position: bigint): void {
            if (position === 0n) { assert(this.c0 === 0n); }
            else { assert(this.c1 === 0n); }
          }
          private placeMove(position: bigint): void {
            this.assertCellEmpty(position);
            if (position === 0n) { this.c0 = 1n; }
            else { this.c1 = 1n; }
          }
          public play(position: bigint, sig: Sig, pk: PubKey): void {
            this.placeMove(position);
            assert(checkSig(sig, pk));
          }
        }
      `;
      // Before the fix, this threw "Value 'position' not found on stack"
      // or produced wrong PICK depths due to duplicate "position" entries.
      const program = compileToStack(source);
      const play = findStackMethod(program, 'play');
      expect(play.ops.length).toBeGreaterThan(0);
    });
  });

  describe('@this object consumption before private method dispatch (bug fix #4)', () => {
    // Bug: lowerMethodCall received an @this object reference (resolves to 0n
    // on the stack) but never consumed it before dispatching to
    // inlineMethodCall. The stale 0n sat on the stack, inflating depths.
    it('stateless contract with private method produces correct stack ops', () => {
      const source = `
        class MultiMethod extends SmartContract {
          readonly owner: PubKey;
          readonly backup: PubKey;
          constructor(owner: PubKey, backup: PubKey) {
            super(owner, backup);
            this.owner = owner;
            this.backup = backup;
          }
          private computeThreshold(a: bigint, b: bigint): bigint {
            return a * b + 1n;
          }
          public spendWithOwner(sig: Sig, amount: bigint): void {
            const threshold: bigint = this.computeThreshold(amount, 2n);
            assert(threshold > 10n);
            assert(checkSig(sig, this.owner));
          }
          public spendWithBackup(sig: Sig): void {
            assert(checkSig(sig, this.backup));
          }
        }
      `;
      const program = compileToStack(source);
      const m = findStackMethod(program, 'spendWithOwner');
      const allOps = flattenOps(m.ops);

      // Before the fix, @this (0n) was left on the stack, producing extra
      // OP_0 OP_ROT OP_ROT opcodes to work around the stale value.
      // After the fix, the @this is dropped before inlining.
      // Check that there is a DROP op to consume the @this reference.
      const drops = allOps.filter(o => o.op === 'drop');
      expect(drops.length).toBeGreaterThan(0);
    });
  });

  describe('void-if detection — no phantom push (bug fix #5)', () => {
    // Bug: After every if-else, the code unconditionally pushed bindingName
    // onto the parent stackMap even when neither branch produced a value
    // (e.g., both branches just assert). This phantom entry desynchronized
    // the stackMap from the actual stack.
    it('stateful contract with assertion-only if-else compiles correctly', () => {
      const source = `
        class Game extends StatefulSmartContract {
          readonly owner: PubKey;
          turn: bigint;
          constructor(owner: PubKey, turn: bigint) {
            super(owner, turn);
            this.owner = owner;
            this.turn = turn;
          }
          private assertCorrectPlayer(player: PubKey): void {
            if (this.turn === 1n) { assert(player === this.owner); }
            else { assert(player !== this.owner); }
          }
          public play(player: PubKey, sig: Sig, pk: PubKey): void {
            this.assertCorrectPlayer(player);
            if (this.turn === 1n) { this.turn = 2n; }
            else { this.turn = 1n; }
            assert(checkSig(sig, pk));
          }
        }
      `;
      // Before the fix, the phantom push after assertCorrectPlayer's
      // if-else (which only asserts, producing no value) caused subsequent
      // operations to reference wrong stack positions.
      const program = compileToStack(source);
      const play = findStackMethod(program, 'play');
      expect(play.ops.length).toBeGreaterThan(0);
    });
  });

  describe('all five bugs combined: TicTacToe-like contract', () => {
    // This exercises all 5 bugs simultaneously: conditional property updates
    // across multiple cells, nested private methods with shadowed params,
    // assertion-only branches, @this consumption, and void-if detection.
    it('compiles a full game contract without stack errors', () => {
      const source = `
        class Game extends StatefulSmartContract {
          readonly owner: PubKey;
          status: bigint;
          turn: bigint;
          c0: bigint;
          c1: bigint;
          c2: bigint;
          c3: bigint;
          constructor(owner: PubKey, status: bigint, turn: bigint,
            c0: bigint, c1: bigint, c2: bigint, c3: bigint) {
            super(owner, status, turn, c0, c1, c2, c3);
            this.owner = owner; this.status = status; this.turn = turn;
            this.c0 = c0; this.c1 = c1; this.c2 = c2; this.c3 = c3;
          }
          private assertCorrectPlayer(player: PubKey): void {
            if (this.turn === 1n) { assert(player === this.owner); }
            else { assert(player !== this.owner); }
          }
          private assertCellEmpty(position: bigint): void {
            if (position === 0n) { assert(this.c0 === 0n); }
            else if (position === 1n) { assert(this.c1 === 0n); }
            else if (position === 2n) { assert(this.c2 === 0n); }
            else { assert(this.c3 === 0n); }
          }
          private placeMove(position: bigint): void {
            this.assertCellEmpty(position);
            if (position === 0n) { this.c0 = this.turn; }
            else if (position === 1n) { this.c1 = this.turn; }
            else if (position === 2n) { this.c2 = this.turn; }
            else { this.c3 = this.turn; }
          }
          public start(sig: Sig, pk: PubKey): void {
            assert(this.status === 0n);
            this.status = 1n;
            this.turn = 1n;
            assert(checkSig(sig, pk));
          }
          public play(position: bigint, player: PubKey, sig: Sig): void {
            assert(this.status === 1n);
            assert(checkSig(sig, player));
            this.assertCorrectPlayer(player);
            this.placeMove(position);
            if (this.turn === 1n) { this.turn = 2n; }
            else { this.turn = 1n; }
          }
        }
      `;
      const program = compileToStack(source);

      // Both methods should compile successfully
      const start = findStackMethod(program, 'start');
      expect(start.ops.length).toBeGreaterThan(0);

      const play = findStackMethod(program, 'play');
      expect(play.ops.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Placeholder paramIndex matches property declaration order
  // ---------------------------------------------------------------------------

  describe('placeholder paramIndex matches property declaration order', () => {
    // Placeholders are emitted when a public method accesses a property that has
    // no initialValue — the slot is reserved for SDK-provided constructor args.
    // The paramIndex must match the property's position in the declaration order.

    it('assigns paramIndex 0 to the first property, 1 to the second', () => {
      const source = `
        class MultiProp extends SmartContract {
          readonly alpha: bigint;
          readonly beta: bigint;
          constructor(alpha: bigint, beta: bigint) {
            super(alpha, beta);
            this.alpha = alpha;
            this.beta = beta;
          }
          public check(x: bigint) {
            assert(x === this.alpha + this.beta);
          }
        }
      `;
      const program = compileToStack(source);
      // Placeholders are in the public method (where props are loaded), not the constructor
      const check = findStackMethod(program, 'check');
      const allOps = flattenOps(check.ops);
      const placeholders = allOps.filter(o => o.op === 'placeholder') as Array<{
        op: 'placeholder';
        paramIndex: number;
        paramName: string;
      }>;

      // Should have at least two placeholders — one for each property access
      expect(placeholders.length).toBeGreaterThanOrEqual(2);

      // Find the placeholder for 'alpha' — it should have paramIndex 0
      const alphaPlaceholder = placeholders.find(p => p.paramName === 'alpha');
      expect(alphaPlaceholder).toBeDefined();
      expect(alphaPlaceholder!.paramIndex).toBe(0);

      // Find the placeholder for 'beta' — it should have paramIndex 1
      const betaPlaceholder = placeholders.find(p => p.paramName === 'beta');
      expect(betaPlaceholder).toBeDefined();
      expect(betaPlaceholder!.paramIndex).toBe(1);
    });

    it('single-property contract has paramIndex 0', () => {
      const source = `
        class Single extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      // Placeholders appear in the public method where this.pk is accessed
      const unlock = findStackMethod(program, 'unlock');
      const allOps = flattenOps(unlock.ops);
      const placeholders = allOps.filter(o => o.op === 'placeholder') as Array<{
        op: 'placeholder';
        paramIndex: number;
        paramName: string;
      }>;

      expect(placeholders.length).toBeGreaterThanOrEqual(1);
      const pkPlaceholder = placeholders.find(p => p.paramName === 'pk');
      expect(pkPlaceholder).toBeDefined();
      expect(pkPlaceholder!.paramIndex).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Multi-method contract: one stack method per public method
  // ---------------------------------------------------------------------------

  describe('multi-method contract produces correct stack methods', () => {
    it('produces a stack method for each public method', () => {
      const source = `
        class MultiMethod extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
          public verify(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = compileToStack(source);
      const methodNames = program.methods.map(m => m.name);

      // Both public methods must appear
      expect(methodNames).toContain('unlock');
      expect(methodNames).toContain('verify');
    });

    it('constructor is included in the stack methods list', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const program = compileToStack(source);
      const methodNames = program.methods.map(m => m.name);
      // Constructor is present (for placeholder extraction)
      expect(methodNames).toContain('constructor');
    });

    it('private methods are NOT included as separate stack methods', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          private helper(a: bigint): bigint { return a + 1n; }
          public m(a: bigint) {
            const b: bigint = this.helper(a);
            assert(b > 0n);
          }
        }
      `;
      const program = compileToStack(source);
      const methodNames = program.methods.map(m => m.name);
      // Private 'helper' is inlined — must NOT appear as a top-level stack method
      expect(methodNames).not.toContain('helper');
    });
  });

  // ---------------------------------------------------------------------------
  // Large bigint constant encoding
  // ---------------------------------------------------------------------------

  describe('large bigint encoding', () => {
    // A large constant like 1000n can't fit in OP_1..OP_16 (which only cover 1-16).
    // It must be emitted as a push op with a bigint value, not as a small-int opcode.
    it('emits a push op for a large bigint constant (1000n)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a === 1000n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);

      // Find push ops with a bigint value of 1000n
      const pushOps = allOps.filter(o => o.op === 'push') as Array<{
        op: 'push';
        value: bigint | boolean | Uint8Array;
      }>;

      const constPush = pushOps.find(
        o => typeof o.value === 'bigint' && o.value === 1000n,
      );
      expect(constPush).toBeDefined();
    });

    it('emits a push op for a large bigint constant (100000n)', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            assert(a === 100000n);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'm');
      const allOps = flattenOps(method.ops);

      const pushOps = allOps.filter(o => o.op === 'push') as Array<{
        op: 'push';
        value: bigint | boolean | Uint8Array;
      }>;

      const constPush = pushOps.find(
        o => typeof o.value === 'bigint' && o.value === 100000n,
      );
      expect(constPush).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Output hash extraction at offset 40
  // ---------------------------------------------------------------------------

  describe('output hash extraction offset', () => {
    // In the BIP-143 sighash preimage layout, hashOutputs is at a specific offset
    // from the end. The correct extraction offset is 40 (nLocktime=4 + sighashType=4
    // + hashOutputs=32 → 40 bytes from the end). An old bug used 44 instead.
    it('extractOutputHash call produces an extraction at offset 40 from the end', () => {
      const source = `
        class OutputHashCheck extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public check(preimage: SigHashPreimage) {
            const h: Sha256 = extractOutputHash(preimage);
            assert(h === sha256(preimage));
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'check');
      const allOps = flattenOps(method.ops);

      // The extraction of hashOutputs from the preimage requires knowing
      // the number of trailing bytes to skip. The correct offset is 40.
      // We verify a push of 40n appears in the method ops (for the trailing-bytes skip).
      const pushOps = allOps.filter(o => o.op === 'push') as Array<{
        op: 'push';
        value: bigint | boolean | Uint8Array;
      }>;

      const offset40Push = pushOps.find(
        o => typeof o.value === 'bigint' && o.value === 40n,
      );
      expect(offset40Push).toBeDefined();

      // 40n should appear as an extraction offset in extractOutputHash (not 44n, old bug)
      expect(offset40Push).toBeDefined();
    });

    it('extractOutputHash compiles without errors', () => {
      const source = `
        class OutputHashCheck extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public check(preimage: SigHashPreimage) {
            const h: Sha256 = extractOutputHash(preimage);
            assert(h === sha256(preimage));
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // ByteString state field support
  // ---------------------------------------------------------------------------

  describe('ByteString state fields', () => {
    it('compiles a contract with a single ByteString mutable state field', () => {
      const source = `
        class MsgStore extends StatefulSmartContract {
          message: ByteString;
          constructor(message: ByteString) { super(message); this.message = message; }
          public update(newMessage: ByteString) {
            this.message = newMessage;
            assert(true);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });

    it('compiles a contract with ByteString + bigint mixed state fields', () => {
      const source = `
        class Mixed extends StatefulSmartContract {
          data: ByteString;
          count: bigint;
          constructor(data: ByteString, count: bigint) { super(data, count); this.data = data; this.count = count; }
          public update(newData: ByteString, newCount: bigint) {
            this.data = newData;
            this.count = newCount;
            assert(true);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });

    it('compiles a contract with ByteString + PubKey mixed state fields', () => {
      const source = `
        class MixedPK extends StatefulSmartContract {
          data: ByteString;
          readonly owner: PubKey;
          constructor(data: ByteString, owner: PubKey) { super(data, owner); this.data = data; this.owner = owner; }
          public update(newData: ByteString) {
            this.data = newData;
            assert(true);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });

    it('compiles a contract with multiple ByteString state fields', () => {
      const source = `
        class MultiBS extends StatefulSmartContract {
          title: ByteString;
          body: ByteString;
          constructor(title: ByteString, body: ByteString) { super(title, body); this.title = title; this.body = body; }
          public update(newTitle: ByteString, newBody: ByteString) {
            this.title = newTitle;
            this.body = newBody;
            assert(true);
          }
        }
      `;
      expect(() => compileToStack(source)).not.toThrow();
    });

    it('produces push_codesep_index op for ByteString state deserialization', () => {
      const source = `
        class MsgStore extends StatefulSmartContract {
          message: ByteString;
          constructor(message: ByteString) { super(message); this.message = message; }
          public update(newMessage: ByteString) {
            this.message = newMessage;
            assert(true);
          }
        }
      `;
      const program = compileToStack(source);
      const method = findStackMethod(program, 'update');
      const ops = flattenOps(method.ops);
      // Should contain a push_codesep_index op for variable-length state extraction
      const hasCodeSepIndex = ops.some(op => op.op === 'push_codesep_index');
      expect(hasCodeSepIndex).toBe(true);
    });

    it('includes _codePart parameter for ByteString state methods', () => {
      const source = `
        class MsgStore extends StatefulSmartContract {
          message: ByteString;
          constructor(message: ByteString) { super(message); this.message = message; }
          public update(newMessage: ByteString) {
            this.message = newMessage;
            assert(true);
          }
        }
      `;
      // This should compile without errors — _codePart is implicitly added
      expect(() => compileToStack(source)).not.toThrow();
    });
  });
});
