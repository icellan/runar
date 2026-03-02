import { describe, it, expect } from 'vitest';
import {
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
  bytesToHex,
  disassemble,
} from '../vm/index.js';

// ---------------------------------------------------------------------------
// encodeScriptNumber / decodeScriptNumber roundtrip
// ---------------------------------------------------------------------------

describe('encodeScriptNumber / decodeScriptNumber roundtrip', () => {
  const testValues: bigint[] = [
    0n,
    1n,
    -1n,
    127n,
    128n,
    -128n,
    255n,
    256n,
    -256n,
    32767n,
    -32767n,
    65535n,
    -65535n,
    2147483647n, // max 32-bit signed
    -2147483647n,
    1000000000000n, // large number
    -1000000000000n,
  ];

  for (const n of testValues) {
    it(`roundtrips ${n}`, () => {
      const encoded = encodeScriptNumber(n);
      const decoded = decodeScriptNumber(encoded);
      expect(decoded).toBe(n);
    });
  }
});

describe('encodeScriptNumber specific encodings', () => {
  it('encodes 0 as empty bytes', () => {
    const encoded = encodeScriptNumber(0n);
    expect(encoded.length).toBe(0);
  });

  it('encodes 1 as [0x01]', () => {
    const encoded = encodeScriptNumber(1n);
    expect(bytesToHex(encoded)).toBe('01');
  });

  it('encodes -1 as [0x81]', () => {
    const encoded = encodeScriptNumber(-1n);
    expect(bytesToHex(encoded)).toBe('81');
  });

  it('encodes 127 as [0x7f]', () => {
    const encoded = encodeScriptNumber(127n);
    expect(bytesToHex(encoded)).toBe('7f');
  });

  it('encodes 128 as [0x80, 0x00] (needs extra byte for sign)', () => {
    const encoded = encodeScriptNumber(128n);
    expect(bytesToHex(encoded)).toBe('8000');
  });

  it('encodes -128 as [0x80, 0x80]', () => {
    const encoded = encodeScriptNumber(-128n);
    expect(bytesToHex(encoded)).toBe('8080');
  });

  it('encodes 255 as [0xff, 0x00]', () => {
    const encoded = encodeScriptNumber(255n);
    expect(bytesToHex(encoded)).toBe('ff00');
  });

  it('encodes 256 as [0x00, 0x01]', () => {
    const encoded = encodeScriptNumber(256n);
    expect(bytesToHex(encoded)).toBe('0001');
  });

  it('encodes -256 as [0x00, 0x81]', () => {
    const encoded = encodeScriptNumber(-256n);
    expect(bytesToHex(encoded)).toBe('0081');
  });
});

// ---------------------------------------------------------------------------
// isTruthy
// ---------------------------------------------------------------------------

describe('isTruthy', () => {
  it('empty bytes is falsy', () => {
    expect(isTruthy(new Uint8Array([]))).toBe(false);
  });

  it('all-zero bytes [0x00] is falsy', () => {
    expect(isTruthy(new Uint8Array([0x00]))).toBe(false);
  });

  it('all-zero bytes [0x00, 0x00] is falsy', () => {
    expect(isTruthy(new Uint8Array([0x00, 0x00]))).toBe(false);
  });

  it('negative zero [0x80] is falsy', () => {
    expect(isTruthy(new Uint8Array([0x80]))).toBe(false);
  });

  it('negative zero [0x00, 0x80] is falsy', () => {
    expect(isTruthy(new Uint8Array([0x00, 0x80]))).toBe(false);
  });

  it('[0x01] is truthy', () => {
    expect(isTruthy(new Uint8Array([0x01]))).toBe(true);
  });

  it('[0xff] is truthy', () => {
    expect(isTruthy(new Uint8Array([0xff]))).toBe(true);
  });

  it('[0x00, 0x01] is truthy', () => {
    expect(isTruthy(new Uint8Array([0x00, 0x01]))).toBe(true);
  });

  it('[0x01, 0x00] is truthy (non-zero byte before the last)', () => {
    expect(isTruthy(new Uint8Array([0x01, 0x00]))).toBe(true);
  });

  it('[0x81] is truthy (negative one)', () => {
    expect(isTruthy(new Uint8Array([0x81]))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// hexToBytes / bytesToHex roundtrip
// ---------------------------------------------------------------------------

describe('hexToBytes / bytesToHex roundtrip', () => {
  it('roundtrips empty string', () => {
    const bytes = hexToBytes('');
    expect(bytesToHex(bytes)).toBe('');
    expect(bytes.length).toBe(0);
  });

  it('roundtrips "00"', () => {
    const bytes = hexToBytes('00');
    expect(bytes.length).toBe(1);
    expect(bytes[0]).toBe(0);
    expect(bytesToHex(bytes)).toBe('00');
  });

  it('roundtrips "ff"', () => {
    const bytes = hexToBytes('ff');
    expect(bytesToHex(bytes)).toBe('ff');
  });

  it('roundtrips "aabbccdd"', () => {
    const bytes = hexToBytes('aabbccdd');
    expect(bytesToHex(bytes)).toBe('aabbccdd');
  });

  it('roundtrips uppercase hex', () => {
    const bytes = hexToBytes('AABBCCDD');
    expect(bytesToHex(bytes)).toBe('aabbccdd');
  });

  it('hexToBytes rejects odd-length strings', () => {
    expect(() => hexToBytes('abc')).toThrow('odd length');
  });

  it('hexToBytes rejects invalid hex chars', () => {
    expect(() => hexToBytes('zz')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// disassemble
// ---------------------------------------------------------------------------

describe('disassemble', () => {
  it('disassembles OP_1 OP_1 OP_ADD', () => {
    const script = hexToBytes('515193');
    const result = disassemble(script);
    expect(result).toContain('OP_1');
    expect(result).toContain('OP_ADD');
  });

  it('disassembles OP_DUP OP_HASH160', () => {
    const script = hexToBytes('76a9');
    const result = disassemble(script);
    expect(result).toContain('OP_DUP');
    expect(result).toContain('OP_HASH160');
  });

  it('disassembles a script with push data', () => {
    // Push 2 bytes "aabb", then OP_DROP
    const script = hexToBytes('02aabb75');
    const result = disassemble(script);
    expect(result).toContain('aabb');
    expect(result).toContain('OP_DROP');
  });

  it('produces readable output for empty script', () => {
    const script = hexToBytes('');
    const result = disassemble(script);
    expect(result).toBe('');
  });

  it('disassembles OP_0 correctly', () => {
    const script = hexToBytes('00');
    const result = disassemble(script);
    expect(result).toBe('OP_0');
  });

  it('disassembles OP_IF OP_ELSE OP_ENDIF', () => {
    const script = hexToBytes('636768');
    const result = disassemble(script);
    expect(result).toContain('OP_IF');
    expect(result).toContain('OP_ELSE');
    expect(result).toContain('OP_ENDIF');
  });
});
