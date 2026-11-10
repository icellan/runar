import { describe, it, expect, vi } from 'vitest';
import { WalletSigner } from '../signers/wallet.js';
import { Hash, Utils, PrivateKey, ECDSA, BigNumber, type SecurityLevel } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { LocalSigner } from '../signers/local.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { buildP2PKHScript } from '../script-utils.js';

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
      counterparty: 'self',
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
  // F-146: Signer.getAddress is specified as a Base58Check P2PKH address
  // (signer.ts). WalletSigner used to return the 40-char hex hash160, which a
  // provider keying UTXOs by address (WhatsOnChain /address/{address}/unspent,
  // MockProvider) never matches.
  // Proves: for the same key WalletSigner yields byte-for-byte LocalSigner's
  // mainnet Base58Check address, and RunarContract.deploy finds a UTXO keyed
  // by that address. Does not prove: anything about a real WalletClient or a
  // live WhatsOnChain query (both stubbed here).
  it("returns the same Base58Check P2PKH address as LocalSigner for the same key", async () => {
    const wallet = createMockWallet();
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });

    const address = await signer.getAddress();

    // MOCK_PUB_KEY is the generator point G, i.e. private key 1.
    const local = new LocalSigner('00'.repeat(31) + '01');
    expect(await local.getPublicKey()).toBe(MOCK_PUB_KEY);
    expect(address).toBe(await local.getAddress());
    expect(address).toBe('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
    expect(address).not.toMatch(/^[0-9a-f]{40}$/);

    // The Base58 payload is still the key's hash160.
    const pkh = Utils.toHex(Hash.hash160(Utils.toArray(MOCK_PUB_KEY, 'hex')));
    expect(buildP2PKHScript(address)).toBe('76a914' + pkh + '88ac');
  });

  it('lets RunarContract.deploy find a funding UTXO keyed by the address', async () => {
    // A stub wallet that really signs the digest with key 1, as ProtoWallet
    // does for hashToDirectlySign, so MockProvider's script check passes.
    const key = PrivateKey.fromHex('00'.repeat(31) + '01');
    const wallet = {
      getPublicKey: vi.fn().mockResolvedValue({ publicKey: MOCK_PUB_KEY }),
      createSignature: vi.fn(async ({ hashToDirectlySign }: { hashToDirectlySign: number[] }) => ({
        signature: ECDSA.sign(new BigNumber(hashToDirectlySign), key, true).toDER() as number[],
      })),
    };
    const signer = new WalletSigner({ ...DEFAULT_OPTS, wallet: wallet as any });
    const local = new LocalSigner('00'.repeat(31) + '01');

    const provider = new MockProvider('mainnet');
    provider.addUtxo(await local.getAddress(), {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: buildP2PKHScript(MOCK_PUB_KEY),
    });

    const artifact: RunarArtifact = {
      version: 'runar-v0.1.0',
      compilerVersion: '0.1.0',
      contractName: 'Test',
      asm: '',
      buildTimestamp: '2026-03-02T00:00:00.000Z',
      script: '51',
      abi: { constructor: { params: [] }, methods: [] },
    };
    const contract = new RunarContract(artifact, []);
    const { txid } = await contract.deploy(provider, signer, { satoshis: 1000 });

    expect(txid).toMatch(/^[0-9a-f]{64}$/);
    expect(provider.getBroadcastedTxs().length).toBe(1);
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
