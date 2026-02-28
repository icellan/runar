import { describe, it, expect } from 'vitest';
import {
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
} from '../builtins.js';

// ---------------------------------------------------------------------------
// assert — the one builtin that works at runtime
// ---------------------------------------------------------------------------

describe('assert', () => {
  it('does nothing when condition is true', () => {
    expect(() => assert(true)).not.toThrow();
  });

  it('throws with default message when condition is false', () => {
    expect(() => assert(false)).toThrow('assert failed');
  });

  it('throws with custom message when provided', () => {
    expect(() => assert(false, 'custom error')).toThrow('custom error');
  });

  it('does not throw for truthy values cast to boolean', () => {
    // The function signature takes boolean, but let's confirm behavior
    expect(() => assert(true)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Compiler stubs — all should throw "compile this contract"
// ---------------------------------------------------------------------------

describe('compiler stubs throw at runtime', () => {
  // We use a dummy ByteString value since the functions never actually
  // read their arguments — they throw immediately.
  const dummyBS = 'aabb' as never;
  const dummySig = '3006aabbccdd' as never;
  const dummyPK = '02' + 'ab'.repeat(32) as never;
  const dummyBigint = 42n as never;

  const expectCompilerError = (fn: () => unknown, name: string) => {
    expect(fn).toThrow('compile this contract');
    expect(fn).toThrow(`${name}()`);
  };

  describe('cryptographic hash functions', () => {
    it('sha256 throws', () => {
      expectCompilerError(() => sha256(dummyBS), 'sha256');
    });

    it('ripemd160 throws', () => {
      expectCompilerError(() => ripemd160(dummyBS), 'ripemd160');
    });

    it('hash160 throws', () => {
      expectCompilerError(() => hash160(dummyBS), 'hash160');
    });

    it('hash256 throws', () => {
      expectCompilerError(() => hash256(dummyBS), 'hash256');
    });
  });

  describe('signature verification', () => {
    it('checkSig throws', () => {
      expectCompilerError(() => checkSig(dummySig, dummyPK), 'checkSig');
    });

    it('checkMultiSig throws', () => {
      expectCompilerError(() => checkMultiSig([dummySig], [dummyPK]), 'checkMultiSig');
    });
  });

  describe('byte-string operations', () => {
    it('len throws', () => {
      expectCompilerError(() => len(dummyBS), 'len');
    });

    it('cat throws', () => {
      expectCompilerError(() => cat(dummyBS, dummyBS), 'cat');
    });

    it('substr throws', () => {
      expectCompilerError(() => substr(dummyBS, dummyBigint, dummyBigint), 'substr');
    });

    it('left throws', () => {
      expectCompilerError(() => left(dummyBS, dummyBigint), 'left');
    });

    it('right throws', () => {
      expectCompilerError(() => right(dummyBS, dummyBigint), 'right');
    });

    it('split throws', () => {
      expectCompilerError(() => split(dummyBS, dummyBigint), 'split');
    });

    it('reverseBytes throws', () => {
      expectCompilerError(() => reverseBytes(dummyBS), 'reverseBytes');
    });
  });

  describe('conversion functions', () => {
    it('num2bin throws', () => {
      expectCompilerError(() => num2bin(dummyBigint, dummyBigint), 'num2bin');
    });

    it('bin2num throws', () => {
      expectCompilerError(() => bin2num(dummyBS), 'bin2num');
    });

    it('int2str throws', () => {
      expectCompilerError(() => int2str(dummyBigint, dummyBigint), 'int2str');
    });
  });

  describe('math functions', () => {
    it('abs throws', () => {
      expectCompilerError(() => abs(dummyBigint), 'abs');
    });

    it('min throws', () => {
      expectCompilerError(() => min(dummyBigint, dummyBigint), 'min');
    });

    it('max throws', () => {
      expectCompilerError(() => max(dummyBigint, dummyBigint), 'max');
    });

    it('within throws', () => {
      expectCompilerError(() => within(dummyBigint, dummyBigint, dummyBigint), 'within');
    });
  });

  describe('rabin signature', () => {
    it('verifyRabinSig throws', () => {
      expectCompilerError(
        () => verifyRabinSig(dummyBS, dummyBigint, dummyBS, dummyBigint),
        'verifyRabinSig',
      );
    });
  });
});

// ---------------------------------------------------------------------------
// All builtins are exported from the module
// ---------------------------------------------------------------------------

describe('builtins module exports', () => {
  it('exports all expected functions', () => {
    const expectedExports = [
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
    ];

    for (const fn of expectedExports) {
      expect(typeof fn).toBe('function');
    }
  });
});
