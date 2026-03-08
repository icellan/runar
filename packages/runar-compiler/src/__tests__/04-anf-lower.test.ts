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
  // ByteString + lowering (C4)
  // ---------------------------------------------------------------------------

  describe('ByteString concatenation lowering', () => {
    it('lowers ByteString + ByteString with result_type bytes', () => {
      const source = `
        class C extends SmartContract {
          readonly x: ByteString;
          constructor(x: ByteString) { super(x); this.x = x; }
          public m(y: ByteString) {
            const z: ByteString = this.x + y;
            assert(len(z) > 0n);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const binOps = bindingsOfKind(method.body, 'bin_op');
      const addOp = binOps.find(b => (b.value as { op: string }).op === '+');
      expect(addOp).toBeDefined();
      const addVal = addOp!.value as { kind: 'bin_op'; op: string; result_type?: string };
      expect(addVal.result_type).toBe('bytes');
    });
  });

  // ---------------------------------------------------------------------------
  // RabinSig/RabinPubKey equality lowering (M3)
  // ---------------------------------------------------------------------------

  describe('RabinSig/RabinPubKey equality lowering', () => {
    it('=== on two RabinPubKey values produces numeric equality (no result_type bytes)', () => {
      const source = `
        class C extends SmartContract {
          readonly rpk: RabinPubKey;
          constructor(rpk: RabinPubKey) { super(rpk); this.rpk = rpk; }
          public m(otherPk: RabinPubKey) {
            assert(this.rpk === otherPk);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');
      const binOps = bindingsOfKind(method.body, 'bin_op');
      const eqOp = binOps.find(b => (b.value as { op: string }).op === '===');
      expect(eqOp).toBeDefined();
      const eqVal = eqOp!.value as { kind: 'bin_op'; op: string; result_type?: string };
      expect(eqVal.result_type).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Non-constant loop bound error (M5)
  // ---------------------------------------------------------------------------

  describe('non-constant loop bound error', () => {
    it('throws an error for non-constant loop bound', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(n: bigint) {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < n; i++) {
              sum = sum + 1n;
            }
            assert(sum > 0n);
          }
        }
      `;
      expect(() => lowerSource(source)).toThrow(/loop bound|compile time/i);
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

  // ---------------------------------------------------------------------------
  // StatefulSmartContract auto-injection
  // ---------------------------------------------------------------------------

  describe('StatefulSmartContract auto-injection', () => {
    const COUNTER_STATEFUL = `
      class Counter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public increment() { this.count++; }
      }
    `;

    it('injects check_preimage at the start of public methods', () => {
      const program = lowerSource(COUNTER_STATEFUL);
      const method = findMethod(program, 'increment');
      const checkPreimages = bindingsOfKind(method.body, 'check_preimage');
      expect(checkPreimages.length).toBeGreaterThanOrEqual(1);
    });

    it('injects state continuation (get_state_script + computeStateOutput + change output + assert) for state-mutating methods', () => {
      const program = lowerSource(COUNTER_STATEFUL);
      const method = findMethod(program, 'increment');

      const getStateScripts = bindingsOfKind(method.body, 'get_state_script');
      expect(getStateScripts.length).toBeGreaterThanOrEqual(1);

      // Check that computeStateOutput is called (builds raw output bytes, no hash)
      const calls = bindingsOfKind(method.body, 'call');
      const computeOutputCall = calls.find(b => (b.value as { func: string }).func === 'computeStateOutput');
      expect(computeOutputCall).toBeDefined();

      // Check that buildChangeOutput is called (builds P2PKH change output)
      const buildChangeCall = calls.find(b => (b.value as { func: string }).func === 'buildChangeOutput');
      expect(buildChangeCall).toBeDefined();

      // Check that hash256 is called (hashes concatenated outputs)
      const hash256Call = calls.find(b => (b.value as { func: string }).func === 'hash256');
      expect(hash256Call).toBeDefined();

      const extractOutputHashCall = calls.find(b => (b.value as { func: string }).func === 'extractOutputHash');
      expect(extractOutputHashCall).toBeDefined();

      // Final assert for state continuation
      const asserts = bindingsOfKind(method.body, 'assert');
      expect(asserts.length).toBeGreaterThanOrEqual(2); // checkPreimage assert + state continuation assert
    });

    it('appends txPreimage as an implicit parameter', () => {
      const program = lowerSource(COUNTER_STATEFUL);
      const method = findMethod(program, 'increment');
      const preimageParam = method.params.find(p => p.name === 'txPreimage');
      expect(preimageParam).toBeDefined();
      expect(preimageParam!.type).toBe('SigHashPreimage');
    });

    it('does not inject state continuation for non-mutating methods', () => {
      const source = `
        class Auction extends StatefulSmartContract {
          readonly auctioneer: PubKey;
          highestBid: bigint;
          constructor(auctioneer: PubKey, highestBid: bigint) {
            super(auctioneer, highestBid);
            this.auctioneer = auctioneer;
            this.highestBid = highestBid;
          }
          public close(sig: Sig) {
            assert(checkSig(sig, this.auctioneer));
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'close');

      // Should have check_preimage
      const checkPreimages = bindingsOfKind(method.body, 'check_preimage');
      expect(checkPreimages.length).toBeGreaterThanOrEqual(1);

      // Should NOT have get_state_script (close does not mutate state)
      const getStateScripts = bindingsOfKind(method.body, 'get_state_script');
      expect(getStateScripts).toHaveLength(0);
    });

    it('injects state continuation for methods that mutate state via assignment', () => {
      const source = `
        class Auction extends StatefulSmartContract {
          readonly auctioneer: PubKey;
          highestBid: bigint;
          constructor(auctioneer: PubKey, highestBid: bigint) {
            super(auctioneer, highestBid);
            this.auctioneer = auctioneer;
            this.highestBid = highestBid;
          }
          public bid(amount: bigint) {
            assert(amount > this.highestBid);
            this.highestBid = amount;
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'bid');

      // Should have get_state_script (bid mutates highestBid)
      const getStateScripts = bindingsOfKind(method.body, 'get_state_script');
      expect(getStateScripts.length).toBeGreaterThanOrEqual(1);
    });

    it('lowers this.txPreimage as load_param instead of load_prop', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          readonly deadline: bigint;
          constructor(count: bigint, deadline: bigint) {
            super(count, deadline);
            this.count = count;
            this.deadline = deadline;
          }
          public increment() {
            assert(extractLocktime(this.txPreimage) < this.deadline);
            this.count++;
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'increment');

      // this.txPreimage should be lowered as load_param, not load_prop
      const loadParams = bindingsOfKind(method.body, 'load_param');
      const txPreimageParams = loadParams.filter(
        b => (b.value as { name: string }).name === 'txPreimage'
      );
      expect(txPreimageParams.length).toBeGreaterThanOrEqual(1);

      // It should NOT appear as load_prop
      const loadProps = bindingsOfKind(method.body, 'load_prop');
      const txPreimageProps = loadProps.filter(
        b => (b.value as { name: string }).name === 'txPreimage'
      );
      expect(txPreimageProps).toHaveLength(0);
    });

    it('lowers this.addOutput() to add_output nodes', () => {
      const source = `
        class FT extends StatefulSmartContract {
          owner: PubKey;
          balance: bigint;
          constructor(owner: PubKey, balance: bigint) {
            super(owner, balance);
            this.owner = owner;
            this.balance = balance;
          }
          public transfer(to: PubKey, amount: bigint, sats: bigint) {
            assert(amount > 0n);
            this.addOutput(sats, to, amount);
            this.addOutput(sats, this.owner, this.balance - amount);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'transfer');

      const addOutputs = bindingsOfKind(method.body, 'add_output');
      expect(addOutputs).toHaveLength(2);

      // Each add_output has satoshis and stateValues
      const first = addOutputs[0]!.value as { kind: 'add_output'; satoshis: string; stateValues: string[] };
      expect(first.stateValues).toHaveLength(2);
    });

    it('injects multi-output continuation when addOutput is used', () => {
      const source = `
        class FT extends StatefulSmartContract {
          owner: PubKey;
          balance: bigint;
          constructor(owner: PubKey, balance: bigint) {
            super(owner, balance);
            this.owner = owner;
            this.balance = balance;
          }
          public transfer(to: PubKey, amount: bigint, sats: bigint) {
            this.addOutput(sats, to, amount);
            this.addOutput(sats, this.owner, this.balance - amount);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'transfer');

      // Should have cat (to concatenate outputs), hash256, extractOutputHash, and final assert
      const calls = bindingsOfKind(method.body, 'call');
      const catCall = calls.find(b => (b.value as { func: string }).func === 'cat');
      expect(catCall).toBeDefined();
      const hash256Call = calls.find(b => (b.value as { func: string }).func === 'hash256');
      expect(hash256Call).toBeDefined();
      const extractCall = calls.find(b => (b.value as { func: string }).func === 'extractOutputHash');
      expect(extractCall).toBeDefined();
    });

    it('does not inject single-output continuation when addOutput is used', () => {
      const source = `
        class FT extends StatefulSmartContract {
          owner: PubKey;
          balance: bigint;
          constructor(owner: PubKey, balance: bigint) {
            super(owner, balance);
            this.owner = owner;
            this.balance = balance;
          }
          public send(to: PubKey, sats: bigint) {
            this.addOutput(sats, to, this.balance);
          }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'send');

      // Should NOT have get_state_script (uses addOutput instead)
      const getStateScripts = bindingsOfKind(method.body, 'get_state_script');
      expect(getStateScripts).toHaveLength(0);

      // Should have add_output
      const addOutputs = bindingsOfKind(method.body, 'add_output');
      expect(addOutputs).toHaveLength(1);
    });

    it('does not affect regular SmartContract methods', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m() { assert(true); }
        }
      `;
      const program = lowerSource(source);
      const method = findMethod(program, 'm');

      // Regular SmartContract: no auto-injected check_preimage
      const checkPreimages = bindingsOfKind(method.body, 'check_preimage');
      expect(checkPreimages).toHaveLength(0);

      // No txPreimage param
      const preimageParam = method.params.find(p => p.name === 'txPreimage');
      expect(preimageParam).toBeUndefined();
    });
  });
});
