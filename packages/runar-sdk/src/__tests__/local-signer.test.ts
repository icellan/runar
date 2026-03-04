import { describe, it, expect } from 'vitest';
import { LocalSigner } from '../signers/local.js';

// ---------------------------------------------------------------------------
// Known valid secp256k1 private keys
// ---------------------------------------------------------------------------

/** Private key = 1 (the generator point). Produces a well-known public key. */
const PRIV_KEY_1 =
  '0000000000000000000000000000000000000000000000000000000000000001';

/** Another valid private key for cross-comparison tests. */
const PRIV_KEY_2 =
  '0000000000000000000000000000000000000000000000000000000000000002';

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

describe('LocalSigner constructor validation', () => {
  it('rejects non-hex input', () => {
    expect(() => new LocalSigner('not-hex-at-all-but-64-chars-long!padding!!')).toThrow();
  });

  it('rejects wrong length (too short)', () => {
    // 4 hex chars = 2 bytes, not 32
    expect(() => new LocalSigner('aabb')).toThrow();
  });

  it('rejects wrong length (too long)', () => {
    expect(() => new LocalSigner('aa'.repeat(33))).toThrow();
  });

  it('accepts a valid 64-char hex private key', () => {
    expect(() => new LocalSigner(PRIV_KEY_1)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// WIF key support
// ---------------------------------------------------------------------------

describe('LocalSigner WIF key support', () => {
  // WIF for private key 1 (uncompressed): 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
  // WIF for private key 1 (compressed):   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
  const WIF_COMPRESSED =
    'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';

  it('accepts a WIF-encoded private key', () => {
    expect(() => new LocalSigner(WIF_COMPRESSED)).not.toThrow();
  });

  it('WIF key produces the same public key as hex key', async () => {
    const fromHex = new LocalSigner(PRIV_KEY_1);
    const fromWif = new LocalSigner(WIF_COMPRESSED);
    const pubHex = await fromHex.getPublicKey();
    const pubWif = await fromWif.getPublicKey();
    expect(pubWif).toBe(pubHex);
  });

  it('WIF key produces the same address as hex key', async () => {
    const fromHex = new LocalSigner(PRIV_KEY_1);
    const fromWif = new LocalSigner(WIF_COMPRESSED);
    const addrHex = await fromHex.getAddress();
    const addrWif = await fromWif.getAddress();
    expect(addrWif).toBe(addrHex);
  });

  it('getPrivateKeyHex returns the raw hex regardless of input format', () => {
    const fromWif = new LocalSigner(WIF_COMPRESSED);
    const hex = fromWif.getPrivateKeyHex();
    expect(hex.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(hex)).toBe(true);
  });

  it('rejects invalid WIF keys', () => {
    expect(() => new LocalSigner('5Invalid')).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Public key derivation
// ---------------------------------------------------------------------------

describe('LocalSigner.getPublicKey', () => {
  it('returns a 33-byte compressed public key (66 hex chars)', async () => {
    const signer = new LocalSigner(PRIV_KEY_1);
    const pubKey = await signer.getPublicKey();
    expect(pubKey.length).toBe(66);
    // Compressed pubkeys start with 02 or 03
    expect(pubKey.slice(0, 2)).toMatch(/^0[23]$/);
    // All hex chars
    expect(/^[0-9a-f]+$/.test(pubKey)).toBe(true);
  });

  it('returns the known public key for private key 1', async () => {
    // The public key for private key = 1 is the secp256k1 generator point G.
    // Compressed form: 02 + x-coordinate of G
    // G.x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    const signer = new LocalSigner(PRIV_KEY_1);
    const pubKey = await signer.getPublicKey();
    expect(pubKey.toLowerCase()).toBe(
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    );
  });
});

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

describe('LocalSigner.getAddress', () => {
  it('returns a non-empty string', async () => {
    const signer = new LocalSigner(PRIV_KEY_1);
    const address = await signer.getAddress();
    expect(typeof address).toBe('string');
    expect(address.length).toBeGreaterThan(0);
  });

  it('returns a BSV address starting with 1 (mainnet P2PKH)', async () => {
    const signer = new LocalSigner(PRIV_KEY_1);
    const address = await signer.getAddress();
    // Standard uncompressed/compressed mainnet P2PKH addresses start with 1
    expect(address[0]).toBe('1');
  });
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

describe('LocalSigner determinism', () => {
  it('two signers from the same key produce the same pubkey', async () => {
    const signer1 = new LocalSigner(PRIV_KEY_1);
    const signer2 = new LocalSigner(PRIV_KEY_1);
    const pub1 = await signer1.getPublicKey();
    const pub2 = await signer2.getPublicKey();
    expect(pub1).toBe(pub2);
  });

  it('two signers from the same key produce the same address', async () => {
    const signer1 = new LocalSigner(PRIV_KEY_1);
    const signer2 = new LocalSigner(PRIV_KEY_1);
    const addr1 = await signer1.getAddress();
    const addr2 = await signer2.getAddress();
    expect(addr1).toBe(addr2);
  });
});

// ---------------------------------------------------------------------------
// Different keys produce different outputs
// ---------------------------------------------------------------------------

describe('LocalSigner different keys', () => {
  it('different private keys produce different public keys', async () => {
    const signer1 = new LocalSigner(PRIV_KEY_1);
    const signer2 = new LocalSigner(PRIV_KEY_2);
    const pub1 = await signer1.getPublicKey();
    const pub2 = await signer2.getPublicKey();
    expect(pub1).not.toBe(pub2);
  });

  it('different private keys produce different addresses', async () => {
    const signer1 = new LocalSigner(PRIV_KEY_1);
    const signer2 = new LocalSigner(PRIV_KEY_2);
    const addr1 = await signer1.getAddress();
    const addr2 = await signer2.getAddress();
    expect(addr1).not.toBe(addr2);
  });
});
