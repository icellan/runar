/**
 * Issue #107 — WalletProvider broadcaster injection (Shape B: additive, non-breaking).
 *
 * A downstream layer (e.g. wallet-toolbox) that already owns a configured
 * `@bsv/sdk` Broadcaster can hand it to `WalletProvider` so both layers
 * broadcast through ONE instance/config. Parent and child txs then land at the
 * same ARC deployment, avoiding the `SEEN_IN_ORPHAN_MEMPOOL` divergence.
 *
 * These tests pin the delegation contract:
 *   - injected broadcaster is used INSTEAD of the hardcoded ARC fetch path;
 *   - a `BroadcastFailure` return flattens to a thrown Error;
 *   - with no injection, the default fetch path (BSV Broadcaster) is used.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import {
  Transaction as BsvTransaction,
  LockingScript,
  UnlockingScript,
  type WalletClient,
  type Broadcaster,
  type BroadcastResponse,
  type BroadcastFailure,
} from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

/** A parent tx and a child spending it, with the parent attached as
 *  sourceTransaction so the EF-assembly loop needs no parent fetch. */
function makeChildWithParent(): BsvTransaction {
  const parent = new BsvTransaction();
  parent.addInput({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  parent.addOutput({ satoshis: 50000, lockingScript: LockingScript.fromHex('51') });

  const child = new BsvTransaction();
  child.addInput({
    sourceTransaction: parent,
    sourceOutputIndex: 0,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  child.addOutput({ satoshis: 49000, lockingScript: LockingScript.fromHex('51') });
  return child;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WalletProvider broadcaster injection (#107)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('delegates to the injected broadcaster instead of the hardcoded ARC fetch path', async () => {
    const child = makeChildWithParent();
    const injectedTxid = child.id('hex');

    // If the default path ran, it would hit fetch() on the default endpoint.
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const broadcast = vi.fn(
      async (_tx: BsvTransaction): Promise<BroadcastResponse> => ({
        status: 'success',
        txid: injectedTxid,
        message: 'ok',
      }),
    );
    const broadcaster: Broadcaster = { broadcast };

    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      broadcaster,
    });

    const txid = await provider.broadcast(child);

    expect(txid).toBe(injectedTxid);
    expect(broadcast).toHaveBeenCalledTimes(1);
    // The hardcoded ARC path must NOT have been used.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('flattens a BroadcastFailure return into a thrown Error', async () => {
    const child = makeChildWithParent();

    const broadcaster: Broadcaster = {
      broadcast: async (_tx: BsvTransaction): Promise<BroadcastFailure> => ({
        status: 'error',
        code: '461',
        description: 'preimage mismatch',
      }),
    };

    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      broadcaster,
    });

    await expect(provider.broadcast(child)).rejects.toThrow(/461/);
  });

  it('with no injected broadcaster, the default fetch path is used', async () => {
    const child = makeChildWithParent();
    const childTxid = child.id('hex');

    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/tx')) {
        return new Response(JSON.stringify({ txid: childTxid }), { status: 202 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      // no broadcaster
    });

    const txid = await provider.broadcast(child);

    expect(txid).toBe(childTxid);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
