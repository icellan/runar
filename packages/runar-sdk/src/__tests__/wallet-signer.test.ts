import { describe, it, expect, vi } from 'vitest';
import { WalletSigner } from '../signers/wallet.js';
import { Hash, Utils, type SecurityLevel } from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Mock WalletClient
// ---------------------------------------------------------------------------

const MOCK_PUB_KEY =
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

// A valid DER-encoded signature as a byte array (wallet returns number[])
const MOCK_DER_BYTES: number[] = [
  0x30, 0x44,
  0x02, 0x20, ...Array(32).fill(0xab),
  0x02, 0x20, ...Array(32).fill(0xcd),
];

function createMockWallet() {
  return {
    getPublicKey: vi.fn().mockResolvedValue({ publicKey: MOCK_PUB_KEY }),
    createSignature: vi.fn().mockResolvedValue({ signature: MOCK_DER_BYTES }),
  };
}

const DEFAULT_OPTS = {
  protocolID: [2 as SecurityLevel, 'test app'] as [SecurityLevel, string],
  keyID: '1',
};

// A minimal valid transaction hex with 1 input and 1 output.
const MINIMAL_TX_HEX =
  '01000000' + // version 1
  '01' + // 1 input
  '00'.repeat(32) + // prevTxid (32 zero bytes)
  '00000000' + // prevIndex 0
  '00' + // empty scriptSig
  'ffffffff' + // sequence
  '01' + // 1 output
  '5000000000000000' + // 80 satoshis (LE)
  '01' + // script length 1
  '51' + // OP_1
  '00000000'; // locktime 0

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe('WalletSigner constructor', () => {
  it('accepts a mock wallet', () => {
    const wallet = createMockWallet();
    expect(
      () => new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// getPublicKey
// ---------------------------------------------------------------------------

describe('WalletSigner.getPublicKey', () => {
  it('calls wallet.getPublicKey with correct protocolID and keyID', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const pubKey = await signer.getPublicKey();

    expect(pubKey).toBe(MOCK_PUB_KEY);
    expect(wallet.getPublicKey).toHaveBeenCalledWith({
      protocolID: [2, 'test app'],
      keyID: '1',
    });
  });

  it('caches the public key after the first call', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    await signer.getPublicKey();
    await signer.getPublicKey();
    await signer.getPublicKey();

    expect(wallet.getPublicKey).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// getAddress
// ---------------------------------------------------------------------------

describe('WalletSigner.getAddress', () => {
  it('returns hash160 of the public key as 40-char hex', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const address = await signer.getAddress();

    // Compute expected hash160
    const pubKeyBytes = Utils.toArray(MOCK_PUB_KEY, 'hex');
    const expectedHash = Utils.toHex(Hash.hash160(pubKeyBytes));

    expect(address).toBe(expectedHash);
    expect(address.length).toBe(40);
    expect(/^[0-9a-f]+$/.test(address)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

describe('WalletSigner.sign', () => {
  it('calls createSignature with hashToDirectlySign', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    await signer.sign(MINIMAL_TX_HEX, 0, '51', 100);

    expect(wallet.createSignature).toHaveBeenCalledTimes(1);
    const callArgs = wallet.createSignature.mock.calls[0]![0];
    expect(callArgs.protocolID).toEqual([2, 'test app']);
    expect(callArgs.keyID).toBe('1');
    // hashToDirectlySign should be a number array (32 bytes = hash256 output)
    expect(callArgs.hashToDirectlySign).toBeDefined();
    expect(Array.isArray(callArgs.hashToDirectlySign)).toBe(true);
    expect(callArgs.hashToDirectlySign.length).toBe(32);
  });

  it('returns DER hex + sighash flag byte', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const sig = await signer.sign(MINIMAL_TX_HEX, 0, '51', 100, 0x41);

    // Should end with '41' (SIGHASH_ALL | FORKID)
    expect(sig.slice(-2)).toBe('41');
    // Should start with DER prefix '30'
    expect(sig.slice(0, 2)).toBe('30');
    // All hex chars
    expect(/^[0-9a-f]+$/.test(sig)).toBe(true);
  });

  it('uses SIGHASH_ALL_FORKID (0x41) by default', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const sig = await signer.sign(MINIMAL_TX_HEX, 0, '51', 100);

    expect(sig.slice(-2)).toBe('41');
  });

  it('respects custom sigHashType', async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const sig = await signer.sign(MINIMAL_TX_HEX, 0, '51', 100, 0xc1);

    expect(sig.slice(-2)).toBe('c1');
  });

  it('produces deterministic sighash for the same inputs', async () => {
    const wallet1 = createMockWallet();
    const wallet2 = createMockWallet();
    const signer1 = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet1 as any });
    const signer2 = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet2 as any });

    await signer1.sign(MINIMAL_TX_HEX, 0, '51', 100);
    await signer2.sign(MINIMAL_TX_HEX, 0, '51', 100);

    const hash1 = wallet1.createSignature.mock.calls[0]![0].hashToDirectlySign;
    const hash2 = wallet2.createSignature.mock.calls[0]![0].hashToDirectlySign;
    expect(hash1).toEqual(hash2);
  });
});
