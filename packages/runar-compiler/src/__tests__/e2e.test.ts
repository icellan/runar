import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Contract source strings
// ---------------------------------------------------------------------------

const P2PKH_SOURCE = `
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

const ESCROW_SOURCE = `
class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public release(sig: Sig) {
    assert(checkSig(sig, this.buyer));
  }

  public refund(sig: Sig) {
    assert(checkSig(sig, this.seller));
  }
}
`;

const HASH_LOCK_SOURCE = `
class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('End-to-end: compile()', () => {
  // ---------------------------------------------------------------------------
  // P2PKH compilation
  // ---------------------------------------------------------------------------

  describe('P2PKH contract', () => {
    it('compiles successfully with success = true', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.success).toBe(true);
    });

    it('produces no error diagnostics', () => {
      const result = compile(P2PKH_SOURCE);
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toEqual([]);
    });

    it('produces a ContractNode', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('produces an ANFProgram', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.anf).not.toBeNull();
      expect(result.anf!.contractName).toBe('P2PKH');
    });

    it('ANF has properties', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.anf!.properties).toHaveLength(1);
      expect(result.anf!.properties[0]!.name).toBe('pk');
      expect(result.anf!.properties[0]!.type).toBe('PubKey');
    });

    it('ANF has methods (constructor + unlock)', () => {
      const result = compile(P2PKH_SOURCE);
      const methodNames = result.anf!.methods.map(m => m.name);
      expect(methodNames).toContain('constructor');
      expect(methodNames).toContain('unlock');
    });

    it('compiled script contains OP_CHECKSIG', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.success).toBe(true);
      expect(typeof result.scriptHex).toBe('string');
      const hex = (result.scriptHex as string).toLowerCase();
      // OP_CHECKSIG = 0xac
      expect(hex).toContain('ac');
    });
  });

  // ---------------------------------------------------------------------------
  // Escrow multi-method contract
  // ---------------------------------------------------------------------------

  describe('Escrow contract (multi-method)', () => {
    it('compiles successfully', () => {
      const result = compile(ESCROW_SOURCE);
      expect(result.success).toBe(true);
    });

    it('has 3 properties', () => {
      const result = compile(ESCROW_SOURCE);
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['buyer', 'seller', 'arbiter']);
    });

    it('has 2 public methods (release and refund)', () => {
      const result = compile(ESCROW_SOURCE);
      const publicMethods = result.contract!.methods.filter(m => m.visibility === 'public');
      expect(publicMethods).toHaveLength(2);
      expect(publicMethods.map(m => m.name)).toEqual(['release', 'refund']);
    });

    it('ANF has both method entries', () => {
      const result = compile(ESCROW_SOURCE);
      const anfMethodNames = result.anf!.methods.map(m => m.name);
      expect(anfMethodNames).toContain('release');
      expect(anfMethodNames).toContain('refund');
    });

    it('both methods are public in ANF', () => {
      const result = compile(ESCROW_SOURCE);
      const release = result.anf!.methods.find(m => m.name === 'release');
      const refund = result.anf!.methods.find(m => m.name === 'refund');
      expect(release!.isPublic).toBe(true);
      expect(refund!.isPublic).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // HashLock contract
  // ---------------------------------------------------------------------------

  describe('HashLock contract', () => {
    it('compiles successfully', () => {
      const result = compile(HASH_LOCK_SOURCE);
      expect(result.success).toBe(true);
    });

    it('ANF contains sha256 call -> equality check -> assert in correct order', () => {
      const result = compile(HASH_LOCK_SOURCE);
      const unlock = result.anf!.methods.find(m => m.name === 'unlock')!;
      const body = unlock.body;

      // Find the sha256 call and verify it's calling the right builtin
      const sha256Binding = body.find(
        b => b.value.kind === 'call' && (b.value as { func?: string }).func === 'sha256',
      );
      expect(sha256Binding).toBeDefined();

      // Find the equality comparison and verify it uses ===
      const eqBinding = body.find(
        b => b.value.kind === 'bin_op' && (b.value as { op?: string }).op === '===',
      );
      expect(eqBinding).toBeDefined();

      // Find the assert
      const assertBinding = body.find(b => b.value.kind === 'assert');
      expect(assertBinding).toBeDefined();

      // Verify ordering: sha256 call comes before equality, equality before assert
      const sha256Idx = body.indexOf(sha256Binding!);
      const eqIdx = body.indexOf(eqBinding!);
      const assertIdx = body.indexOf(assertBinding!);
      expect(sha256Idx).toBeLessThan(eqIdx);
      expect(eqIdx).toBeLessThan(assertIdx);

      // No checkSig in this contract
      const checkSigBinding = body.find(
        b => b.value.kind === 'call' && (b.value as { func?: string }).func === 'checkSig',
      );
      expect(checkSigBinding).toBeUndefined();
    });

    it('compiled script contains OP_SHA256 and OP_EQUAL', () => {
      const result = compile(HASH_LOCK_SOURCE);
      expect(result.success).toBe(true);
      expect(typeof result.scriptHex).toBe('string');
      const hex = (result.scriptHex as string).toLowerCase();
      // OP_SHA256 = 0xa8, OP_EQUAL = 0x87
      expect(hex).toContain('a8');
      expect(hex).toContain('87');
      // Should NOT contain OP_CHECKSIG (0xac) — this is a hash lock, not a signature check
      // Note: 'ac' could appear in push data, so we check the script ends without it
      // as the final opcode
      const lastByte = hex.slice(-2);
      expect(lastByte).not.toBe('ac');
    });
  });

  // ---------------------------------------------------------------------------
  // Options: parseOnly, validateOnly, typecheckOnly
  // ---------------------------------------------------------------------------

  describe('compile options: early stopping', () => {
    it('parseOnly stops after parsing (no ANF)', () => {
      const result = compile(P2PKH_SOURCE, { parseOnly: true });
      expect(result.success).toBe(true);
      expect(result.contract).not.toBeNull();
      expect(result.anf).toBeNull();
    });

    it('validateOnly stops after validation (no ANF)', () => {
      const result = compile(P2PKH_SOURCE, { validateOnly: true });
      expect(result.success).toBe(true);
      expect(result.contract).not.toBeNull();
      expect(result.anf).toBeNull();
    });

    it('typecheckOnly stops after type-checking (no ANF)', () => {
      const result = compile(P2PKH_SOURCE, { typecheckOnly: true });
      expect(result.success).toBe(true);
      expect(result.contract).not.toBeNull();
      expect(result.anf).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // Custom fileName option
  // ---------------------------------------------------------------------------

  describe('compile options: fileName', () => {
    it('uses provided fileName in the contract', () => {
      const result = compile(P2PKH_SOURCE, { fileName: 'my-contract.ts' });
      expect(result.contract!.sourceFile).toBe('my-contract.ts');
    });

    it('defaults to contract.ts when fileName is not provided', () => {
      const result = compile(P2PKH_SOURCE);
      expect(result.contract!.sourceFile).toBe('contract.ts');
    });
  });

  // ---------------------------------------------------------------------------
  // Error collection on invalid contracts
  // ---------------------------------------------------------------------------

  describe('error collection', () => {
    it('collects parse errors for missing SmartContract', () => {
      const source = `const x = 42;`;
      const result = compile(source);
      expect(result.success).toBe(false);
      expect(result.contract).toBeNull();
      expect(result.diagnostics.length).toBeGreaterThan(0);
      expect(result.diagnostics[0]!.severity).toBe('error');
    });

    it('collects validation errors when public method lacks assert', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) { super(x); this.x = x; }
          public m(a: bigint) {
            const b: bigint = a + 1n;
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(false);
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors.some(e => e.message.includes('assert'))).toBe(true);
    });

    it('collects type errors and stops before ANF lowering', () => {
      const source = `
        class C extends SmartContract {
          readonly pk: PubKey;
          constructor(pk: PubKey) { super(pk); this.pk = pk; }
          public m(val: bigint) {
            assert(checkSig(val, this.pk));
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(false);
      expect(result.anf).toBeNull();
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });

    it('returns success=false with diagnostics for multiple errors', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;
          constructor(x: bigint) {
            this.x = x;
          }
          public m() {}
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(false);
      // Should have at least "must call super()" error
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Diagnostics structure
  // ---------------------------------------------------------------------------

  describe('diagnostics structure', () => {
    it('each diagnostic has message, severity, and optional loc', () => {
      const source = `const x = 42;`;
      const result = compile(source);
      for (const d of result.diagnostics) {
        expect(typeof d.message).toBe('string');
        expect(['error', 'warning']).toContain(d.severity);
      }
    });

    it('diagnostics with loc have file, line, column', () => {
      const source = `const x = 42;`;
      const result = compile(source);
      const withLoc = result.diagnostics.filter(d => d.loc);
      for (const d of withLoc) {
        expect(typeof d.loc!.file).toBe('string');
        expect(typeof d.loc!.line).toBe('number');
        expect(typeof d.loc!.column).toBe('number');
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Counter (stateful) contract
  // ---------------------------------------------------------------------------

  describe('stateful contract compilation', () => {
    it('compiles a counter contract with mutable state', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;

          constructor(count: bigint) {
            super(count);
            this.count = count;
          }

          public increment() {
            this.count = this.count + 1n;
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(result.anf).not.toBeNull();

      // count is a non-readonly property
      const countProp = result.anf!.properties.find(p => p.name === 'count');
      expect(countProp).toBeDefined();
      expect(countProp!.readonly).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Contract with private helper methods
  // ---------------------------------------------------------------------------

  describe('contract with private helper methods', () => {
    it('parses and validates a contract with private helper + public method', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          helper(a: bigint): bigint {
            return a + 1n;
          }

          public m(a: bigint) {
            const b: bigint = this.helper(a);
            assert(b > 0n);
          }
        }
      `;
      // Note: the type checker currently returns '<inferred>' for private method
      // return types (see inferMethodReturnType), so a full compile will report
      // a type error. Verify that parse + validate passes at least.
      const result = compile(source, { validateOnly: true });
      expect(result.success).toBe(true);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.methods.find(m => m.name === 'helper')).toBeDefined();
      expect(result.contract!.methods.find(m => m.name === 'helper')!.visibility).toBe('private');
    });

    it('correctly infers private method return type from return statements', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          helper(a: bigint): bigint {
            return a + 1n;
          }

          public m(a: bigint) {
            const b: bigint = this.helper(a);
            assert(b > 0n);
          }
        }
      `;
      // Private method return type is inferred from `return a + 1n` -> bigint,
      // so assigning to `const b: bigint` succeeds without type errors.
      const result = compile(source);
      expect(result.success).toBe(true);
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Complex expressions
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // StatefulSmartContract compilation
  // ---------------------------------------------------------------------------

  describe('StatefulSmartContract compilation', () => {
    it('compiles a StatefulSmartContract counter successfully', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
          public decrement() {
            assert(this.count > 0n);
            this.count--;
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(result.anf).not.toBeNull();
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });

    it('ANF has implicit txPreimage parameter for public methods', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = compile(source);
      const increment = result.anf!.methods.find(m => m.name === 'increment')!;
      const preimageParam = increment.params.find(p => p.name === 'txPreimage');
      expect(preimageParam).toBeDefined();
      expect(preimageParam!.type).toBe('SigHashPreimage');
    });

    it('compiles a multi-method StatefulSmartContract with mixed mutation', () => {
      const source = `
        class Auction extends StatefulSmartContract {
          readonly auctioneer: PubKey;
          highestBidder: PubKey;
          highestBid: bigint;
          readonly deadline: bigint;

          constructor(auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint) {
            super(auctioneer, highestBidder, highestBid, deadline);
            this.auctioneer = auctioneer;
            this.highestBidder = highestBidder;
            this.highestBid = highestBid;
            this.deadline = deadline;
          }

          public bid(bidder: PubKey, bidAmount: bigint) {
            assert(bidAmount > this.highestBid);
            assert(extractLocktime(this.txPreimage) < this.deadline);
            this.highestBidder = bidder;
            this.highestBid = bidAmount;
          }

          public close(sig: Sig) {
            assert(checkSig(sig, this.auctioneer));
            assert(extractLocktime(this.txPreimage) >= this.deadline);
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);

      // Both methods should be in the ANF
      const bid = result.anf!.methods.find(m => m.name === 'bid')!;
      const close = result.anf!.methods.find(m => m.name === 'close')!;
      expect(bid).toBeDefined();
      expect(close).toBeDefined();
      expect(bid.isPublic).toBe(true);
      expect(close.isPublic).toBe(true);
    });

    it('produces hex script output for StatefulSmartContract', () => {
      const source = `
        class Counter extends StatefulSmartContract {
          count: bigint;
          constructor(count: bigint) { super(count); this.count = count; }
          public increment() { this.count++; }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(result.artifact).toBeDefined();
      expect(result.artifact!.script.length).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // addOutput multi-output compilation
  // ---------------------------------------------------------------------------

  describe('addOutput compilation', () => {
    it('compiles a FungibleToken with addOutput for splitting', () => {
      const source = `
        class FungibleToken extends StatefulSmartContract {
          owner: PubKey;
          balance: bigint;

          constructor(owner: PubKey, balance: bigint) {
            super(owner, balance);
            this.owner = owner;
            this.balance = balance;
          }

          public transfer(sig: Sig, to: PubKey, amount: bigint, sats: bigint) {
            assert(checkSig(sig, this.owner));
            assert(amount > 0n);
            assert(amount <= this.balance);
            this.addOutput(sats, to, amount);
            this.addOutput(sats, this.owner, this.balance - amount);
          }

          public send(sig: Sig, to: PubKey, sats: bigint) {
            assert(checkSig(sig, this.owner));
            this.addOutput(sats, to, this.balance);
          }

          public merge(sig: Sig, totalBalance: bigint, sats: bigint) {
            assert(checkSig(sig, this.owner));
            assert(totalBalance >= this.balance);
            this.addOutput(sats, this.owner, totalBalance);
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(result.artifact).toBeDefined();
      expect(result.artifact!.script.length).toBeGreaterThan(0);
    });

    it('ANF contains add_output nodes for methods using addOutput', () => {
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
      const result = compile(source);
      expect(result.success).toBe(true);
      const transfer = result.anf!.methods.find(m => m.name === 'transfer')!;
      const addOutputs = transfer.body.filter(b => b.value.kind === 'add_output');
      expect(addOutputs).toHaveLength(2);
    });
  });

  describe('complex expression compilation', () => {
    it('compiles nested binary expressions', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m(a: bigint, b: bigint) {
            const result: bigint = (a + b) * (a - b);
            assert(result >= 0n);
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
      expect(result.anf).not.toBeNull();
    });

    it('compiles contracts with for-loops', () => {
      const source = `
        class C extends SmartContract {
          readonly x: bigint;

          constructor(x: bigint) {
            super(x);
            this.x = x;
          }

          public m() {
            let sum: bigint = 0n;
            for (let i: bigint = 0n; i < 5n; i++) {
              sum = sum + i;
            }
            assert(sum >= 0n);
          }
        }
      `;
      const result = compile(source);
      expect(result.success).toBe(true);
    });
  });
});
