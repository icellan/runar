/**
 * F-042 — WalletProvider's default ARC broadcast path must fail closed.
 *
 * The Ruby WalletProvider used to report a locally computed txid for a
 * transaction ARC never accepted. The TS reference already threw on a non-2xx
 * response and on a fetch rejection, but returned whatever txid a 200 carried
 * even when ARC's `txStatus` said REJECTED / DOUBLE_SPEND_ATTEMPTED /
 * SEEN_IN_ORPHAN_MEMPOOL, when the body carried an ARC error `status`, when the
 * txid was missing (`undefined`), or when it named a different transaction.
 *
 * PROVES: with `fetch` stubbed as ARC, broadcast rejects on a 500, a 4xx with an
 * ARC error body, each rejecting txStatus, a 200 with an error `status` field,
 * a 200 with no txid, a 200 with another transaction's txid, a timeout and a
 * refused connection — and caches nothing in those cases. Only an accepting
 * 200 echoing this transaction's txid returns it.
 * DOES NOT PROVE: behaviour against the live ARC service, or the complete set
 * of txStatus values an ARC deployment may emit (the rejection list mirrors
 * @bsv/sdk's ARC broadcaster). The injected-broadcaster path (#107) is not
 * exercised here.
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

function makeProvider(): WalletProvider {
  return new WalletProvider({ wallet: stubWallet, signer: stubSigner, basket: 'b' });
}

function stubArc(respond: () => Promise<Response>): void {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/v1/tx')) return respond();
    throw new Error(`unexpected fetch: ${url}`);
  }));
}

async function expectRejected(pattern: RegExp): Promise<void> {
  const child = makeChildWithParent();
  const provider = makeProvider();
  await expect(provider.broadcast(child)).rejects.toThrow(pattern);
  // Nothing was cached as if broadcast: the lookup falls through to the
  // (stubbed) network and fails.
  await expect(provider.getRawTransaction(child.id('hex'))).rejects.toThrow();
}

describe('WalletProvider ARC broadcast fails closed (F-042)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('rejects on an HTTP 500', async () => {
    stubArc(async () => new Response('{"detail":"boom"}', { status: 500 }));
    await expectRejected(/500.*boom/s);
  });

  it('rejects on a 4xx carrying an ARC error body', async () => {
    stubArc(async () => new Response(JSON.stringify({
      type: 'https://bitcoin-sv.github.io/arc/#/errors?id=_461',
      title: 'Malformed transaction', status: 461, detail: 'Transaction is malformed',
    }), { status: 461 }));
    await expectRejected(/461.*Malformed/s);
  });

  for (const txStatus of ['REJECTED', 'DOUBLE_SPEND_ATTEMPTED', 'SEEN_IN_ORPHAN_MEMPOOL']) {
    it(`rejects on a 200 whose txStatus is ${txStatus}`, async () => {
      const txid = makeChildWithParent().id('hex');
      stubArc(async () => new Response(
        JSON.stringify({ txid, txStatus, extraInfo: 'nope', status: 200 }), { status: 200 }));
      await expectRejected(new RegExp(txStatus));
    });
  }

  it('rejects on a 200 carrying an ARC error status field', async () => {
    const txid = makeChildWithParent().id('hex');
    stubArc(async () => new Response(
      JSON.stringify({ txid, status: 465, title: 'Fee too low', detail: 'fee too low' }), { status: 200 }));
    await expectRejected(/465.*Fee too low/s);
  });

  it('rejects on a 200 without a txid', async () => {
    stubArc(async () => new Response('{"txStatus":"SEEN_ON_NETWORK"}', { status: 200 }));
    await expectRejected(/txid/);
  });

  it("rejects on a 200 whose txid is not this transaction's", async () => {
    const local = makeChildWithParent().id('hex');
    stubArc(async () => new Response(
      JSON.stringify({ txid: 'cc'.repeat(32), txStatus: 'SEEN_ON_NETWORK' }), { status: 200 }));
    await expectRejected(new RegExp(`${'cc'.repeat(32)}.*${local}`, 's'));
  });

  it('rejects on a timeout', async () => {
    stubArc(async () => { throw new DOMException('The operation timed out.', 'TimeoutError'); });
    await expectRejected(/NOT broadcast.*timed out/s);
  });

  it('rejects on a refused connection', async () => {
    stubArc(async () => {
      throw new TypeError('fetch failed', { cause: new Error('connect ECONNREFUSED 127.0.0.1:1') });
    });
    await expectRejected(/NOT broadcast.*fetch failed/s);
  });

  it("returns ARC's txid on an accepting 200", async () => {
    const child = makeChildWithParent();
    const txid = child.id('hex');
    stubArc(async () => new Response(
      JSON.stringify({ txid, txStatus: 'SEEN_ON_NETWORK', status: 200, title: 'OK' }), { status: 200 }));
    const provider = makeProvider();
    expect(await provider.broadcast(child)).toBe(txid);
    expect(await provider.getRawTransaction(txid)).toBe(child.toHex());
  });
});
