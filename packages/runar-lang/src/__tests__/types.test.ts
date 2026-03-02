import { describe, it, expect } from 'vitest';
import {
  toByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  Addr,
  SigHashPreimage,
  OpCodeType,
  SigHash,
} from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** 33-byte compressed pubkey with 02 prefix (66 hex chars). */
const VALID_PUBKEY_02 =
  '02' + 'ab'.repeat(32);

/** 33-byte compressed pubkey with 03 prefix. */
const VALID_PUBKEY_03 =
  '03' + 'cd'.repeat(32);

/** Minimal valid DER-encoded signature (starts with 30, >= 8 bytes). */
const VALID_SIG = '30' + '06' + '0201ff0201ff' + 'aabb';

/** 20-byte hash (40 hex chars). */
const VALID_RIPEMD160 = 'ab'.repeat(20);

/** 32-byte hash (64 hex chars). */
const VALID_SHA256 = 'cd'.repeat(32);

// ---------------------------------------------------------------------------
// toByteString
// ---------------------------------------------------------------------------

describe('toByteString', () => {
  it('accepts an empty hex string', () => {
    const bs = toByteString('');
    expect(bs).toBe('');
  });

  it('accepts valid even-length hex', () => {
    const bs = toByteString('aabbcc');
    expect(bs).toBe('aabbcc');
  });

  it('accepts uppercase hex', () => {
    const bs = toByteString('AABBCC');
    expect(bs).toBe('AABBCC');
  });

  it('accepts mixed-case hex', () => {
    const bs = toByteString('aAbBcC');
    expect(bs).toBe('aAbBcC');
  });

  it('rejects odd-length strings', () => {
    expect(() => toByteString('abc')).toThrow('even-length hex');
  });

  it('rejects non-hex characters', () => {
    expect(() => toByteString('zzzz')).toThrow('even-length hex');
  });

  it('rejects strings with spaces', () => {
    expect(() => toByteString('aa bb')).toThrow('even-length hex');
  });

  it('rejects 0x prefix', () => {
    expect(() => toByteString('0xaabb')).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// PubKey
// ---------------------------------------------------------------------------

describe('PubKey', () => {
  it('accepts valid 33-byte pubkey with 02 prefix', () => {
    const pk = PubKey(VALID_PUBKEY_02);
    expect(pk).toBe(VALID_PUBKEY_02);
  });

  it('accepts valid 33-byte pubkey with 03 prefix', () => {
    const pk = PubKey(VALID_PUBKEY_03);
    expect(pk).toBe(VALID_PUBKEY_03);
  });

  it('rejects wrong length (too short)', () => {
    expect(() => PubKey('02' + 'ab'.repeat(31))).toThrow('33 bytes');
  });

  it('rejects wrong length (too long)', () => {
    expect(() => PubKey('02' + 'ab'.repeat(33))).toThrow('33 bytes');
  });

  it('rejects invalid prefix (04 uncompressed)', () => {
    expect(() => PubKey('04' + 'ab'.repeat(32))).toThrow('prefix 02 or 03');
  });

  it('rejects invalid prefix (00)', () => {
    expect(() => PubKey('00' + 'ab'.repeat(32))).toThrow('prefix 02 or 03');
  });

  it('rejects non-hex input', () => {
    expect(() => PubKey('zz' + 'ab'.repeat(32))).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// Sig
// ---------------------------------------------------------------------------

describe('Sig', () => {
  it('accepts a valid DER signature', () => {
    const sig = Sig(VALID_SIG);
    expect(sig).toBe(VALID_SIG);
  });

  it('rejects a signature that is too short (< 8 bytes = 16 hex chars)', () => {
    // 7 bytes = 14 hex chars, starts with 30
    expect(() => Sig('30' + 'aa'.repeat(6))).toThrow('too short');
  });

  it('rejects signature without DER prefix 0x30', () => {
    // 8 bytes but starts with 0x31
    expect(() => Sig('31' + 'aa'.repeat(7))).toThrow('DER prefix 0x30');
  });

  it('rejects invalid hex', () => {
    expect(() => Sig('zz' + 'aa'.repeat(7))).toThrow('even-length hex');
  });

  it('accepts long DER signatures', () => {
    // A realistic-length DER sig: 71 bytes
    const longSig = '30' + 'ab'.repeat(70);
    expect(Sig(longSig)).toBe(longSig);
  });
});

// ---------------------------------------------------------------------------
// Ripemd160
// ---------------------------------------------------------------------------

describe('Ripemd160', () => {
  it('accepts a valid 20-byte hash', () => {
    const h = Ripemd160(VALID_RIPEMD160);
    expect(h).toBe(VALID_RIPEMD160);
  });

  it('rejects wrong length (19 bytes)', () => {
    expect(() => Ripemd160('ab'.repeat(19))).toThrow('20 bytes');
  });

  it('rejects wrong length (21 bytes)', () => {
    expect(() => Ripemd160('ab'.repeat(21))).toThrow('20 bytes');
  });

  it('rejects invalid hex', () => {
    expect(() => Ripemd160('gg'.repeat(20))).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// Sha256
// ---------------------------------------------------------------------------

describe('Sha256', () => {
  it('accepts a valid 32-byte hash', () => {
    const h = Sha256(VALID_SHA256);
    expect(h).toBe(VALID_SHA256);
  });

  it('rejects wrong length (31 bytes)', () => {
    expect(() => Sha256('ab'.repeat(31))).toThrow('32 bytes');
  });

  it('rejects wrong length (33 bytes)', () => {
    expect(() => Sha256('ab'.repeat(33))).toThrow('32 bytes');
  });

  it('rejects invalid hex', () => {
    expect(() => Sha256('zz'.repeat(32))).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// Addr (alias for Ripemd160)
// ---------------------------------------------------------------------------

describe('Addr', () => {
  it('accepts a valid 20-byte address', () => {
    const addr = Addr(VALID_RIPEMD160);
    expect(addr).toBe(VALID_RIPEMD160);
  });

  it('rejects wrong length', () => {
    expect(() => Addr('ab'.repeat(19))).toThrow('20 bytes');
  });

  it('rejects invalid hex', () => {
    expect(() => Addr('zz'.repeat(20))).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// SigHashPreimage
// ---------------------------------------------------------------------------

describe('SigHashPreimage', () => {
  it('accepts valid hex string', () => {
    const preimage = SigHashPreimage('aabbccdd');
    expect(preimage).toBe('aabbccdd');
  });

  it('accepts empty hex string', () => {
    const preimage = SigHashPreimage('');
    expect(preimage).toBe('');
  });

  it('rejects invalid hex', () => {
    expect(() => SigHashPreimage('xyz')).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// OpCodeType
// ---------------------------------------------------------------------------

describe('OpCodeType', () => {
  it('accepts valid hex', () => {
    const op = OpCodeType('6a');
    expect(op).toBe('6a');
  });

  it('rejects invalid hex', () => {
    expect(() => OpCodeType('zz')).toThrow('even-length hex');
  });
});

// ---------------------------------------------------------------------------
// SigHash constants
// ---------------------------------------------------------------------------

describe('SigHash', () => {
  it('ALL is 0x01', () => {
    expect(SigHash.ALL).toBe(0x01n);
  });

  it('NONE is 0x02', () => {
    expect(SigHash.NONE).toBe(0x02n);
  });

  it('SINGLE is 0x03', () => {
    expect(SigHash.SINGLE).toBe(0x03n);
  });

  it('FORKID is 0x40', () => {
    expect(SigHash.FORKID).toBe(0x40n);
  });

  it('ANYONECANPAY is 0x80', () => {
    expect(SigHash.ANYONECANPAY).toBe(0x80n);
  });

  it('ALL | FORKID produces the expected combined flag', () => {
    expect(SigHash.ALL | SigHash.FORKID).toBe(0x41n);
  });

  it('ALL | FORKID | ANYONECANPAY produces the expected combined flag', () => {
    expect(SigHash.ALL | SigHash.FORKID | SigHash.ANYONECANPAY).toBe(0xc1n);
  });

  it('all constants are bigint type', () => {
    expect(typeof SigHash.ALL).toBe('bigint');
    expect(typeof SigHash.NONE).toBe('bigint');
    expect(typeof SigHash.SINGLE).toBe('bigint');
    expect(typeof SigHash.FORKID).toBe('bigint');
    expect(typeof SigHash.ANYONECANPAY).toBe('bigint');
  });
});
