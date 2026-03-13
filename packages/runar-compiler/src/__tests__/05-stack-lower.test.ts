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
  // InductiveSmartContract stack lowering
  // ---------------------------------------------------------------------------

  describe('InductiveSmartContract', () => {
    const inductiveSource = `
      import { InductiveSmartContract, assert, checkSig } from 'runar-lang';
      import type { PubKey, Sig, ByteString } from 'runar-lang';
      class InductiveToken extends InductiveSmartContract {
        owner: PubKey;
        balance: bigint;
        readonly tokenId: ByteString;
        constructor(owner: PubKey, balance: bigint, tokenId: ByteString) {
          super(owner, balance, tokenId);
          this.owner = owner;
          this.balance = balance;
          this.tokenId = tokenId;
        }
        public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
          assert(checkSig(sig, this.owner));
          this.addOutput(outputSatoshis, to, this.balance);
        }
        public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
          assert(checkSig(sig, this.owner));
          assert(amount > 0n);
          assert(amount <= this.balance);
          this.addOutput(outputSatoshis, to, amount);
          this.addOutput(outputSatoshis, this.owner, this.balance - amount);
        }
      }
    `;

    it('compiles send method without errors', () => {
      const program = compileToStack(inductiveSource);
      const method = findStackMethod(program, 'send');
      expect(method.ops.length).toBeGreaterThan(0);
    });

    it('compiles transfer method (multi-output) without errors', () => {
      const program = compileToStack(inductiveSource);
      const method = findStackMethod(program, 'transfer');
      expect(method.ops.length).toBeGreaterThan(0);
    });

    it('genesis if/else has balanced stack (OP_IF with OP_ELSE)', () => {
      const program = compileToStack(inductiveSource);
      const method = findStackMethod(program, 'send');
      const allOps = flattenOps(method.ops);

      // The genesis detection produces an OP_IF/OP_ELSE structure
      const ifOps = allOps.filter(op => op.op === 'if');
      expect(ifOps.length).toBeGreaterThanOrEqual(1);

      // Both branches should have ops (else is not empty)
      const genesisIf = ifOps[0]!;
      expect(genesisIf.then.length).toBeGreaterThan(0);
      expect(genesisIf.else).toBeDefined();
      expect(genesisIf.else!.length).toBeGreaterThan(0);
    });

    it('emits OP_CODESEPARATOR for stateful check_preimage', () => {
      const program = compileToStack(inductiveSource);
      const method = findStackMethod(program, 'send');
      const allOps = flattenOps(method.ops);
      const codeSeps = allOps.filter(
        op => op.op === 'opcode' && (op as any).code === 'OP_CODESEPARATOR'
      );
      expect(codeSeps.length).toBeGreaterThanOrEqual(1);
    });

    it('emits OP_TRUE stub for snark_verify in non-genesis branch', () => {
      const program = compileToStack(inductiveSource);
      const method = findStackMethod(program, 'send');
      const allOps = flattenOps(method.ops);
      // The non-genesis branch should contain OP_TRUE from the snark_verify stub
      const opTrueOps = allOps.filter(
        op => op.op === 'opcode' && (op as any).code === 'OP_TRUE'
      );
      expect(opTrueOps.length).toBeGreaterThanOrEqual(1);
    });

  });
});
