import { describe, it, expect } from 'vitest';
import { Hash, Utils } from '@bsv/sdk';
import { buildP2PKHScript } from '../script-utils.js';

// ---------------------------------------------------------------------------
// buildP2PKHScript — single consolidated P2PKH script builder
// ---------------------------------------------------------------------------

describe('buildP2PKHScript', () => {
  // A known 20-byte pubkey hash (hex)
  const knownHash160 = 'aabbccddee11223344556677889900aabbccddee';

  it('40-char hex input treated as raw hash160', () => {
    const script = buildP2PKHScript(knownHash160);
    expect(script).toBe('76a914' + knownHash160 + '88ac');
  });

  it('66-char compressed public key is auto-hashed', () => {
    // A real compressed public key (33 bytes = 66 hex chars)
    const compressedPubKey =
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const expectedHash = Utils.toHex(
      Hash.hash160(Utils.toArray(compressedPubKey, 'hex')),
    );

    const script = buildP2PKHScript(compressedPubKey);
    expect(script).toBe('76a914' + expectedHash + '88ac');
    expect(script.length).toBe(50); // 76a914 (6) + 40 + 88ac (4) = 50
  });

  it('130-char uncompressed public key is auto-hashed', () => {
    // A real uncompressed public key (65 bytes = 130 hex chars)
    const uncompressedPubKey =
      '04' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
    const expectedHash = Utils.toHex(
      Hash.hash160(Utils.toArray(uncompressedPubKey, 'hex')),
    );

    const script = buildP2PKHScript(uncompressedPubKey);
    expect(script).toBe('76a914' + expectedHash + '88ac');
  });

  it('Base58Check address is decoded correctly', () => {
    // Use a known mainnet address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    const address = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
    const script = buildP2PKHScript(address);

    // Script should be 50 chars: 76a914 + 40 hex chars + 88ac
    expect(script).toMatch(/^76a914[0-9a-f]{40}88ac$/);
  });

  it('all output formats produce valid P2PKH scripts', () => {
    const inputs = [
      knownHash160,
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    ];

    for (const input of inputs) {
      const script = buildP2PKHScript(input);
      expect(script).toMatch(/^76a914[0-9a-f]{40}88ac$/);
    }
  });

  it('compressed pubkey and its hash160 produce the same script', () => {
    const pubKey =
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const hash160 = Utils.toHex(Hash.hash160(Utils.toArray(pubKey, 'hex')));

    expect(buildP2PKHScript(pubKey)).toBe(buildP2PKHScript(hash160));
  });
});
