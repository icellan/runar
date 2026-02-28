import { describe, it, expect } from 'vitest';
import {
  SmartContract,
  // Type constructors
  toByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  Addr,
  SigHashPreimage,
  OpCodeType,
  SigHash,
  // Builtins
  sha256,
  ripemd160,
  hash160,
  hash256,
  checkSig,
  checkMultiSig,
  len,
  cat,
  substr,
  left,
  right,
  split,
  reverseBytes,
  num2bin,
  bin2num,
  int2str,
  assert,
  abs,
  min,
  max,
  within,
  verifyRabinSig,
  // Preimage
  checkPreimage,
  extractVersion,
  extractHashPrevouts,
  extractHashSequence,
  extractOutpoint,
  extractInputIndex,
  extractScriptCode,
  extractAmount,
  extractSequence,
  extractOutputHash,
  extractOutputs,
  extractLocktime,
  extractSigHashType,
} from '../index.js';

// ---------------------------------------------------------------------------
// SmartContract base class
// ---------------------------------------------------------------------------

describe('SmartContract', () => {
  it('can be extended by a subclass', () => {
    class TestContract extends SmartContract {
      public readonly value: bigint;

      constructor(value: bigint) {
        super(value);
        this.value = value;
      }
    }

    const contract = new TestContract(42n);
    expect(contract).toBeInstanceOf(SmartContract);
    expect(contract).toBeInstanceOf(TestContract);
    expect(contract.value).toBe(42n);
  });

  it('getStateScript() throws at runtime', () => {
    class TestContract extends SmartContract {
      constructor() {
        super();
      }

      // Expose the protected method for testing
      public callGetStateScript() {
        return this.getStateScript();
      }
    }

    const contract = new TestContract();
    expect(() => contract.callGetStateScript()).toThrow(
      'cannot be called at runtime',
    );
    expect(() => contract.callGetStateScript()).toThrow('compile this contract');
  });

  it('buildP2PKH() throws at runtime', () => {
    class TestContract extends SmartContract {
      constructor() {
        super();
      }

      // Expose the protected method for testing
      public callBuildP2PKH(addr: Parameters<SmartContract['buildP2PKH']>[0]) {
        return this.buildP2PKH(addr);
      }
    }

    const contract = new TestContract();
    const dummyAddr = Addr('ab'.repeat(20));
    expect(() => contract.callBuildP2PKH(dummyAddr)).toThrow(
      'cannot be called at runtime',
    );
    expect(() => contract.callBuildP2PKH(dummyAddr)).toThrow(
      'compile this contract',
    );
  });

  it('constructor accepts arbitrary arguments', () => {
    class MultiArgContract extends SmartContract {
      constructor(a: bigint, b: string, c: boolean) {
        super(a, b, c);
      }
    }

    // Should not throw
    expect(() => new MultiArgContract(1n, 'hello', true)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// All expected exports exist
// ---------------------------------------------------------------------------

describe('package exports', () => {
  describe('type constructors are exported', () => {
    it('toByteString', () => expect(typeof toByteString).toBe('function'));
    it('PubKey', () => expect(typeof PubKey).toBe('function'));
    it('Sig', () => expect(typeof Sig).toBe('function'));
    it('Ripemd160', () => expect(typeof Ripemd160).toBe('function'));
    it('Sha256', () => expect(typeof Sha256).toBe('function'));
    it('Addr', () => expect(typeof Addr).toBe('function'));
    it('SigHashPreimage', () => expect(typeof SigHashPreimage).toBe('function'));
    it('OpCodeType', () => expect(typeof OpCodeType).toBe('function'));
    it('SigHash', () => expect(typeof SigHash).toBe('object'));
  });

  describe('builtins are exported', () => {
    const builtinFns = {
      sha256,
      ripemd160,
      hash160,
      hash256,
      checkSig,
      checkMultiSig,
      len,
      cat,
      substr,
      left,
      right,
      split,
      reverseBytes,
      num2bin,
      bin2num,
      int2str,
      assert,
      abs,
      min,
      max,
      within,
      verifyRabinSig,
    };

    for (const [name, fn] of Object.entries(builtinFns)) {
      it(`${name}`, () => expect(typeof fn).toBe('function'));
    }
  });

  describe('preimage functions are exported', () => {
    const preimageFns = {
      checkPreimage,
      extractVersion,
      extractHashPrevouts,
      extractHashSequence,
      extractOutpoint,
      extractInputIndex,
      extractScriptCode,
      extractAmount,
      extractSequence,
      extractOutputHash,
      extractOutputs,
      extractLocktime,
      extractSigHashType,
    };

    for (const [name, fn] of Object.entries(preimageFns)) {
      it(`${name}`, () => expect(typeof fn).toBe('function'));
    }
  });

  describe('SmartContract is exported', () => {
    it('SmartContract is a constructor function', () => {
      expect(typeof SmartContract).toBe('function');
    });
  });
});

// ---------------------------------------------------------------------------
// Preimage functions throw at runtime
// ---------------------------------------------------------------------------

describe('preimage stubs throw at runtime', () => {
  const dummyPreimage = 'aabb' as never;

  const preimageFns: Array<[string, (p: never) => unknown]> = [
    ['checkPreimage', checkPreimage],
    ['extractVersion', extractVersion],
    ['extractHashPrevouts', extractHashPrevouts],
    ['extractHashSequence', extractHashSequence],
    ['extractOutpoint', extractOutpoint],
    ['extractInputIndex', extractInputIndex],
    ['extractScriptCode', extractScriptCode],
    ['extractAmount', extractAmount],
    ['extractSequence', extractSequence],
    ['extractOutputHash', extractOutputHash],
    ['extractOutputs', extractOutputs],
    ['extractLocktime', extractLocktime],
    ['extractSigHashType', extractSigHashType],
  ];

  for (const [name, fn] of preimageFns) {
    it(`${name} throws "compile this contract"`, () => {
      expect(() => fn(dummyPreimage)).toThrow('compile this contract');
    });
  }
});
