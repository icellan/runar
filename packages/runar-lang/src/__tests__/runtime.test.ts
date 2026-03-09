import { describe, it, expect } from 'vitest';
import {
  // Crypto
  sha256,
  hash256,
  hash160,
  ripemd160,
  // Signature verification
  checkSig,
  checkMultiSig,
  // Byte operations
  len,
  cat,
  substr,
  left,
  right,
  split,
  reverseBytes,
  // Conversion
  num2bin,
  bin2num,
  int2str,
  // Math
  abs,
  min,
  max,
  within,
  safediv,
  safemod,
  clamp,
  sign,
  pow,
  mulDiv,
  percentOf,
  sqrt,
  gcd,
  divmod,
  log2,
  bool,
  // EC
  ecAdd,
  ecMul,
  ecMulGen,
  ecNegate,
  ecOnCurve,
  ecModReduce,
  ecEncodeCompressed,
  ecMakePoint,
  ecPointX,
  ecPointY,
  // Mocks
  checkPreimage,
  extractAmount,
  extractVersion,
  extractLocktime,
  extractSigHashType,
  // Post-quantum
  verifyWOTS,
  verifySLHDSA_SHA2_128s,
  // Rabin
  verifyRabinSig,
  // Types & constructors
  toByteString,
  PubKey,
  Sig,
  SigHashPreimage,
  // Constants
  EC_G,
  EC_P,
  EC_N,
  // Base classes
  SmartContract,
  StatefulSmartContract,
} from '../runtime/index.js';

describe('runtime builtins', () => {
  // ---- Crypto hashes ----

  describe('crypto hashes', () => {
    it('sha256 of empty string', () => {
      const result = sha256(toByteString(''));
      expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('hash256 (double sha256) of empty string', () => {
      const result = hash256(toByteString(''));
      // sha256(sha256('')) = sha256(e3b0c4...)
      expect(result).toHaveLength(64);
    });

    it('hash160 of empty string', () => {
      const result = hash160(toByteString(''));
      expect(result).toHaveLength(40); // 20 bytes
    });

    it('ripemd160 of empty string', () => {
      const result = ripemd160(toByteString(''));
      expect(result).toHaveLength(40);
    });

    it('sha256 of known data', () => {
      // SHA-256("abc") where "abc" = 616263
      const result = sha256(toByteString('616263'));
      expect(result).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });
  });

  // ---- Signature verification (mocked) ----

  describe('signature verification (mocked)', () => {
    it('checkSig returns true', () => {
      expect(checkSig(
        Sig('3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980220483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
        PubKey('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
      )).toBe(true);
    });

    it('checkMultiSig returns true', () => {
      expect(checkMultiSig([], [])).toBe(true);
    });
  });

  // ---- Byte operations ----

  describe('byte operations', () => {
    it('len counts bytes', () => {
      expect(len(toByteString('aabb'))).toBe(2n);
      expect(len(toByteString(''))).toBe(0n);
      expect(len(toByteString('aabbccdd'))).toBe(4n);
    });

    it('cat concatenates', () => {
      expect(cat(toByteString('aa'), toByteString('bb'))).toBe('aabb');
    });

    it('substr extracts', () => {
      expect(substr(toByteString('aabbccdd'), 1n, 2n)).toBe('bbcc');
    });

    it('left takes prefix bytes', () => {
      expect(left(toByteString('aabbccdd'), 2n)).toBe('aabb');
    });

    it('right takes suffix bytes', () => {
      expect(right(toByteString('aabbccdd'), 2n)).toBe('ccdd');
    });

    it('split at position', () => {
      const [l, r] = split(toByteString('aabbccdd'), 2n);
      expect(l).toBe('aabb');
      expect(r).toBe('ccdd');
    });

    it('reverseBytes', () => {
      expect(reverseBytes(toByteString('aabbccdd'))).toBe('ddccbbaa');
    });
  });

  // ---- Conversion ----

  describe('conversion', () => {
    it('num2bin / bin2num round-trip', () => {
      const encoded = num2bin(42n, 4n);
      expect(bin2num(encoded)).toBe(42n);
    });

    it('num2bin negative round-trip', () => {
      const encoded = num2bin(-7n, 4n);
      expect(bin2num(encoded)).toBe(-7n);
    });

    it('num2bin zero', () => {
      const encoded = num2bin(0n, 4n);
      expect(encoded).toBe('00000000');
      expect(bin2num(encoded)).toBe(0n);
    });

    it('int2str is alias for num2bin', () => {
      expect(int2str(42n, 4n)).toBe(num2bin(42n, 4n));
    });
  });

  // ---- Math ----

  describe('math', () => {
    it('abs', () => {
      expect(abs(-5n)).toBe(5n);
      expect(abs(5n)).toBe(5n);
      expect(abs(0n)).toBe(0n);
    });

    it('min / max', () => {
      expect(min(3n, 7n)).toBe(3n);
      expect(max(3n, 7n)).toBe(7n);
    });

    it('within', () => {
      expect(within(5n, 3n, 7n)).toBe(true);
      expect(within(7n, 3n, 7n)).toBe(false); // exclusive upper
      expect(within(2n, 3n, 7n)).toBe(false);
    });

    it('safediv / safemod', () => {
      expect(safediv(10n, 3n)).toBe(3n);
      expect(safemod(10n, 3n)).toBe(1n);
      expect(() => safediv(1n, 0n)).toThrow('division by zero');
      expect(() => safemod(1n, 0n)).toThrow('division by zero');
    });

    it('clamp', () => {
      expect(clamp(5n, 0n, 10n)).toBe(5n);
      expect(clamp(-1n, 0n, 10n)).toBe(0n);
      expect(clamp(11n, 0n, 10n)).toBe(10n);
    });

    it('sign', () => {
      expect(sign(42n)).toBe(1n);
      expect(sign(-42n)).toBe(-1n);
      expect(sign(0n)).toBe(0n);
    });

    it('pow', () => {
      expect(pow(2n, 10n)).toBe(1024n);
      expect(pow(3n, 0n)).toBe(1n);
    });

    it('mulDiv', () => {
      expect(mulDiv(100n, 3n, 4n)).toBe(75n);
    });

    it('percentOf', () => {
      expect(percentOf(1000n, 500n)).toBe(50n); // 5% of 1000
    });

    it('sqrt', () => {
      expect(sqrt(16n)).toBe(4n);
      expect(sqrt(0n)).toBe(0n);
      expect(sqrt(15n)).toBe(3n); // floor
    });

    it('gcd', () => {
      expect(gcd(12n, 8n)).toBe(4n);
      expect(gcd(7n, 13n)).toBe(1n);
    });

    it('divmod', () => {
      expect(divmod(10n, 3n)).toBe(3n);
    });

    it('log2', () => {
      expect(log2(1n)).toBe(0n);
      expect(log2(8n)).toBe(3n);
      expect(log2(1024n)).toBe(10n);
    });

    it('bool', () => {
      expect(bool(0n)).toBe(false);
      expect(bool(1n)).toBe(true);
      expect(bool(-1n)).toBe(true);
    });
  });

  // ---- Mocks ----

  describe('preimage mocks', () => {
    const pre = SigHashPreimage('00');

    it('checkPreimage returns true', () => {
      expect(checkPreimage(pre)).toBe(true);
    });

    it('extractAmount returns 10000', () => {
      expect(extractAmount(pre)).toBe(10000n);
    });

    it('extractVersion returns 1', () => {
      expect(extractVersion(pre)).toBe(1n);
    });

    it('extractLocktime returns 0', () => {
      expect(extractLocktime(pre)).toBe(0n);
    });

    it('extractSigHashType returns 0x41', () => {
      expect(extractSigHashType(pre)).toBe(0x41n);
    });
  });

  // ---- Post-quantum / Rabin mocks ----

  describe('verification mocks', () => {
    it('verifyWOTS returns true', () => {
      expect(verifyWOTS(toByteString(''), toByteString(''), toByteString(''))).toBe(true);
    });

    it('verifySLHDSA_SHA2_128s returns true', () => {
      expect(verifySLHDSA_SHA2_128s(toByteString(''), toByteString(''), toByteString(''))).toBe(true);
    });

    it('verifyRabinSig returns true', () => {
      expect(verifyRabinSig(toByteString(''), 0n, toByteString(''), 0n)).toBe(true);
    });
  });

  // ---- EC operations ----

  describe('EC operations', () => {
    const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
    const Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

    it('ecPointX / ecPointY extract coordinates from EC_G', () => {
      expect(ecPointX(EC_G)).toBe(Gx);
      expect(ecPointY(EC_G)).toBe(Gy);
    });

    it('ecMakePoint constructs from coordinates', () => {
      const pt = ecMakePoint(Gx, Gy);
      expect(ecPointX(pt)).toBe(Gx);
      expect(ecPointY(pt)).toBe(Gy);
    });

    it('ecOnCurve validates generator', () => {
      expect(ecOnCurve(EC_G)).toBe(true);
    });

    it('ecOnCurve rejects bad point', () => {
      const bad = ecMakePoint(1n, 1n);
      expect(ecOnCurve(bad)).toBe(false);
    });

    it('ecAdd: G + G = 2G', () => {
      const twoG = ecAdd(EC_G, EC_G);
      const twoGviaM = ecMul(EC_G, 2n);
      expect(ecPointX(twoG)).toBe(ecPointX(twoGviaM));
      expect(ecPointY(twoG)).toBe(ecPointY(twoGviaM));
    });

    it('ecMulGen matches ecMul with G', () => {
      const k = 7n;
      const a = ecMul(EC_G, k);
      const b = ecMulGen(k);
      expect(ecPointX(a)).toBe(ecPointX(b));
      expect(ecPointY(a)).toBe(ecPointY(b));
    });

    it('ecNegate: G + (-G) = identity check', () => {
      const negG = ecNegate(EC_G);
      expect(ecPointY(negG)).toBe(EC_P - Gy);
      expect(ecOnCurve(negG)).toBe(true);
    });

    it('ecModReduce', () => {
      expect(ecModReduce(-3n, EC_N)).toBe(EC_N - 3n);
      expect(ecModReduce(5n, EC_N)).toBe(5n);
    });

    it('ecEncodeCompressed', () => {
      const compressed = ecEncodeCompressed(EC_G);
      // Gy is even, so prefix is 02
      expect(compressed.slice(0, 2)).toBe('02');
      // EC_G uses uppercase hex; ecEncodeCompressed preserves the x-coord from the Point
      expect(compressed.slice(2).toLowerCase()).toBe(EC_G.slice(0, 64).toLowerCase());
      expect(compressed).toHaveLength(66); // 33 bytes
    });
  });

  // ---- Base classes ----

  describe('base classes', () => {
    it('SmartContract.getStateScript returns empty', () => {
      class TestContract extends SmartContract {
        readonly value: bigint;
        constructor(value: bigint) {
          super(value);
          this.value = value;
        }
        public check() {
          return (this as any).getStateScript();
        }
      }
      const c = new TestContract(42n);
      expect(c.check()).toBe('');
    });

    it('SmartContract.buildP2PKH returns P2PKH script', () => {
      class TestContract extends SmartContract {
        constructor() { super(); }
        public getP2PKH(addr: string) {
          return (this as any).buildP2PKH(addr);
        }
      }
      const c = new TestContract();
      const addr = '0000000000000000000000000000000000000000';
      expect(c.getP2PKH(addr)).toBe('76a914' + addr + '88ac');
    });

    it('StatefulSmartContract.addOutput does not throw', () => {
      class TestCounter extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) {
          super(count);
          this.count = count;
        }
        public increment() {
          this.count++;
          (this as any).addOutput(10000n, this.count);
        }
      }
      const c = new TestCounter(0n);
      expect(() => c.increment()).not.toThrow();
      expect(c.count).toBe(1n);
    });
  });
});
