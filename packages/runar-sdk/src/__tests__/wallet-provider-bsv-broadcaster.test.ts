/**
 * WalletProvider's default broadcast path posts EF to BSV Broadcaster.
 *
 * BSV Broadcaster (called Arcade before 0.19.0) serves `POST /tx`, not ARC's
 * `POST /v1/tx`, and answers an accepted transaction with
 * `202 {"txid": "...", "status": 202, "txStatus": "RECEIVED"}`. An explicit
 * `arcUrl` keeps the ARC path.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import {
  Transaction as BsvTransaction,
  LockingScript,
  UnlockingScript,
  type WalletClient,
} from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

const base = { wallet: stubWallet, signer: stubSigner, basket: 'test-basket' };

/** A child tx with its parent attached, so no parent fetch is needed. */
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

describe('WalletProvider default broadcaster (BSV Broadcaster)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    ['testnet', 'https://arcade-v2-testnet-us-1.bsvblockchain.tech/tx'],
    ['mainnet', 'https://arcade-us-1.bsvblockchain.tech/tx'],
  ] as const)('posts EF to the %s BSV Broadcaster /tx endpoint', async (network, url) => {
    const child = makeChildWithParent();
    const childTxid = child.id('hex');

    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(
        JSON.stringify({ txid: childTxid, status: 202, txStatus: 'RECEIVED' }),
        { status: 202 },
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const provider = new WalletProvider({ ...base, network });
    const txid = await provider.broadcast(child);

    expect(txid).toBe(childTxid);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchMock.mock.calls[0]!;
    expect(calledUrl).toBe(url);
    expect(init?.method).toBe('POST');
    expect((init?.headers as Record<string, string>)['Content-Type']).toBe(
      'application/octet-stream',
    );
    expect(new Uint8Array(init?.body as ArrayBuffer)).toEqual(
      new Uint8Array(child.toEFUint8Array()),
    );
    // The broadcast tx is cached for later EF parent lookups.
    expect(await provider.getRawTransaction(childTxid)).toBe(child.toHex());
  });

  it('names BSV Broadcaster when the default endpoint refuses a transaction', async () => {
    const child = makeChildWithParent();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'failed to parse transaction' }), { status: 400 }),
      ),
    );

    const provider = new WalletProvider({ ...base, network: 'testnet' });

    await expect(provider.broadcast(child)).rejects.toThrow(
      /BSV Broadcaster broadcast failed \(400\): .*failed to parse transaction/,
    );
  });

  it('keeps the ARC /v1/tx path when arcUrl is given', async () => {
    const child = makeChildWithParent();
    const childTxid = child.id('hex');

    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(JSON.stringify({ txid: childTxid }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const provider = new WalletProvider({
      ...base,
      network: 'testnet',
      arcUrl: 'https://arc.testnet.example',
    });
    await provider.broadcast(child);

    expect(fetchMock.mock.calls[0]![0]).toBe('https://arc.testnet.example/v1/tx');
  });

  it('names ARC when an explicit ARC endpoint refuses a transaction', async () => {
    const child = makeChildWithParent();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('bad', { status: 461 })));

    const provider = new WalletProvider({ ...base, arcUrl: 'https://arc.gorillapool.io' });

    await expect(provider.broadcast(child)).rejects.toThrow(/ARC broadcast failed \(461\): bad/);
  });
});
