import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import type { ContractNode } from '../ir/index.js';
import type {
  ANFProgram,
  ANFMethod,
  ANFBinding,
} from '../ir/index.js';

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

function lowerSource(source: string): ANFProgram {
  return lowerToANF(parseContract(source));
}

function findMethod(program: ANFProgram, name: string): ANFMethod {
  const method = program.methods.find(m => m.name === name);
  if (!method) {
    throw new Error(`Method '${name}' not found. Available: ${program.methods.map(m => m.name).join(', ')}`);
  }
  return method;
}

function bindingNames(bindings: ANFBinding[]): string[] {
  return bindings.map(b => b.name);
}

function bindingsOfKind(bindings: ANFBinding[], kind: string): ANFBinding[] {
  return bindings.filter(b => b.value.kind === kind);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Pass 4: ANF Lower', () => {
  // ---------------------------------------------------------------------------
  // Basic structure
  // ---------------------------------------------------------------------------

  describe('basic structure', () => {
    it('produces an ANFProgram with contract name', () => {
      const source = `
        class P2PKH extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) {
            super(pk);
            this.pk = pk;
          }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      expect(program.contractName).toBe('P2PKH');
    });

    it('lowers properties', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          count: bigint;
          constructor(pk: PubKey, count: bigint) {
            super(pk, count);
            this.pk = pk;
            this.count = count;
          }
          public m() { assert(true); }
        }
      `;
      const program = lowerSource(source);
      expect(program.properties).toHaveLength(2);
      expect(program.properties[0]).toEqual({ name: 'pk', type: 'PubKey', readonly: true });
      expect(program.properties[1]).toEqual({ name: 'count', type: 'bigint', readonly: false });
    });

    it('lowers constructor as a method named "constructor"', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) {
            super(x);
            this.x = x;
          }
          public m() { assert(true); }
        }
      `;
      const program = lowerSource(source);
      const ctor = findMethod(program, 'constructor');
      expect(ctor.isPublic).toBe(false);
      expect(ctor.params).toEqual([{ name: 'x', type: 'bigint' }]);
    });

    it('produces method params correctly', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      expect(unlock.isPublic).toBe(true);
      expect(unlock.params).toEqual([{ name: 'sig', type: 'Sig' }]);
    });
  });

  // ---------------------------------------------------------------------------
  // Sequential temp naming
  // ---------------------------------------------------------------------------

  describe('sequential temporary naming', () => {
    it('generates sequential temp names (t0, t1, t2...)', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const names = bindingNames(unlock.body);
      // All temp names should follow t<N> pattern or be named variables
      const tempNames = names.filter(n => /^t\d+$/.test(n));
      expect(tempNames.length).toBeGreaterThan(0);

      // Check that temp indices are sequential (no gaps or reuse)
      const indices = tempNames.map(n => parseInt(n.slice(1)));
      for (let i = 1; i < indices.length; i++) {
        expect(indices[i]).toBeGreaterThan(indices[i - 1]!);
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Nested expression flattening
  // ---------------------------------------------------------------------------

  describe('nested expression flattening', () => {
    it('flattens assert(checkSig(sig, this.pk)) into sequential bindings', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const kinds = unlock.body.map(b => b.value.kind);

      // Should see: load_param for sig, load_prop for pk, call for checkSig, assert
      expect(kinds).toContain('load_param');
      expect(kinds).toContain('load_prop');
      expect(kinds).toContain('call');
      expect(kinds).toContain('assert');
    });

    it('load_param is produced for method parameters', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const loadParams = bindingsOfKind(unlock.body, 'load_param');
      expect(loadParams.length).toBeGreaterThanOrEqual(1);
      const paramNames = loadParams.map(b => (b.value as { kind: 'load_param'; name: string }).name);
      expect(paramNames).toContain('sig');
    });

    it('load_prop is produced for this.pk access', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const loadProps = bindingsOfKind(unlock.body, 'load_prop');
      expect(loadProps.length).toBeGreaterThanOrEqual(1);
      const propNames = loadProps.map(b => (b.value as { kind: 'load_prop'; name: string }).name);
      expect(propNames).toContain('pk');
    });

    it('call binding references temp names for args', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const calls = bindingsOfKind(unlock.body, 'call');
      const checkSigCall = calls.find(b => (b.value as { func: string }).func === 'checkSig');
      expect(checkSigCall).toBeDefined();

      const callValue = checkSigCall!.value as { kind: 'call'; func: string; args: string[] };
      expect(callValue.args).toHaveLength(2);
      // Each arg should be a reference to a binding name (e.g. t0, t1)
      for (const arg of callValue.args) {
        expect(typeof arg).toBe('string');
      }
    });

    it('assert binding references the checkSig result temp', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public unlock(sig: Sig) {
            assert(checkSig(sig, this.pk));
          }
        }
      `;
      const program = lowerSource(source);
      const unlock = findMethod(program, 'unlock');
      const asserts = bindingsOfKind(unlock.body, 'assert');
      expect(asserts.length).toBeGreaterThanOrEqual(1);

      const assertVal = asserts[0]!.value as { kind: 'assert'; value: string };
      // The assert value should reference the call result
      expect(typeof assertVal.value).toBe('string');
    });
  });

  // ---------------------------------------------------------------------------
  // Binary expression lowering
  // ---------------------------------------------------------------------------

  describe('binary expression lowering', () => {
    it('lowers a + b into bin_op with references', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = a + this.x;
            assert(b > 0n);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const binOps = bindingsOfKind(method.body, 'bin_op');
      expect(binOps.length).toBeGreaterThanOrEqual(1);

      const addOp = binOps.find(b => (b.value as { op: string }).op === '+');
      expect(addOp).toBeDefined();
      const addVal = addOp!.value as { kind: 'bin_op'; op: string; left: string; right: string };
      expect(addVal.left).toBeTruthy();
      expect(addVal.right).toBeTruthy();
    });
  });

  // ---------------------------------------------------------------------------
  // If/else lowering
  // ---------------------------------------------------------------------------

  describe('if/else lowering', () => {
    it('creates nested ANF blocks for if/else', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            if (a > 0n) {
              assert(true);
            } else {
              assert(false);
            }
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const ifs = bindingsOfKind(method.body, 'if');
      expect(ifs.length).toBeGreaterThanOrEqual(1);

      const ifVal = ifs[0]!.value as {
        kind: 'if';
        cond: string;
        then: ANFBinding[];
        else: ANFBinding[];
      };
      expect(typeof ifVal.cond).toBe('string');
      expect(ifVal.then.length).toBeGreaterThan(0);
      expect(ifVal.else.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Property access lowering
  // ---------------------------------------------------------------------------

  describe('property access lowering', () => {
    it('lowers this.x to load_prop', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            const val: bigint = this.x;
            assert(val > 0n);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const loadProps = bindingsOfKind(method.body, 'load_prop');
      expect(loadProps.length).toBeGreaterThanOrEqual(1);
      expect((loadProps[0]!.value as { name: string }).name).toBe('x');
    });
  });

  // ---------------------------------------------------------------------------
  // Assert lowering
  // ---------------------------------------------------------------------------

  describe('assert lowering', () => {
    it('lowers assert(expr) into assert ANF node', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            assert(true);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const asserts = bindingsOfKind(method.body, 'assert');
      expect(asserts.length).toBeGreaterThanOrEqual(1);

      const assertNode = asserts[0]!.value as { kind: 'assert'; value: string };
      expect(assertNode.kind).toBe('assert');
      expect(typeof assertNode.value).toBe('string');
    });
  });

  // ---------------------------------------------------------------------------
  // Constants lowering
  // ---------------------------------------------------------------------------

  describe('constants lowering', () => {
    it('lowers bigint literals to load_const', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            const a: bigint = 42n;
            assert(a > 0n);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const consts = bindingsOfKind(method.body, 'load_const');
      const bigintConsts = consts.filter(
        b => typeof (b.value as { value: unknown }).value === 'bigint'
      );
      expect(bigintConsts.length).toBeGreaterThanOrEqual(1);
      const vals = bigintConsts.map(b => (b.value as { value: bigint }).value);
      expect(vals).toContain(42n);
    });

    it('lowers boolean literals to load_const', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            assert(true);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const consts = bindingsOfKind(method.body, 'load_const');
      const boolConsts = consts.filter(
        b => typeof (b.value as { value: unknown }).value === 'boolean'
      );
      expect(boolConsts.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ---------------------------------------------------------------------------
  // For-loop lowering
  // ---------------------------------------------------------------------------

  describe('for-loop lowering', () => {
    it('lowers a bounded for-loop into a loop ANF node', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < 5n; i++) {
              sum = sum + 1n;
            }
            assert(sum > 0n);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const loops = bindingsOfKind(method.body, 'loop');
      expect(loops.length).toBeGreaterThanOrEqual(1);

      const loopVal = loops[0]!.value as {
        kind: 'loop';
        count: number;
        body: ANFBinding[];
        iterVar: string;
      };
      expect(loopVal.count).toBe(5);
      expect(loopVal.iterVar).toBe('i');
      expect(loopVal.body.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Assignment lowering: update_prop
  // ---------------------------------------------------------------------------

  describe('property update lowering', () => {
    it('lowers this.x = expr to update_prop', () => {
      const source = `
        class C extends SmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() {
            this.count = this.count + 1n;
            assert(true);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'increment');
      const updateProps = bindingsOfKind(method.body, 'update_prop');
      expect(updateProps.length).toBeGreaterThanOrEqual(1);
      const upd = updateProps[0]!.value as { kind: 'update_prop'; name: string; value: string };
      expect(upd.name).toBe('count');
    });
  });

  // ---------------------------------------------------------------------------
  // super() call lowering
  // ---------------------------------------------------------------------------

  describe('super call lowering', () => {
    it('lowers super() to a call ANF node with func "super"', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const program = lowerSource(source);
      const ctor = findMethod(program, 'constructor');
      const calls = bindingsOfKind(ctor.body, 'call');
      const superCall = calls.find(b => (b.value as { func: string }).func === 'super');
      expect(superCall).toBeDefined();
    });
  });
});
