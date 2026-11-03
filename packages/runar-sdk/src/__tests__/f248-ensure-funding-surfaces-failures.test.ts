/**
 * F-248 (CL-BUG-141): `WalletProvider.ensureFunding` swallowed both the
 * funding-tx BEEF parse failure and the funding-tx broadcast failure.
 *
 *   await this.broadcastTx(Transaction.fromHex(rawHex)).catch((e) =>
 *     warnNonFatal('funding-tx broadcast', e),
 *   );
 *   ...
 *   catch (e) {
 *     warnNonFatal('funding-tx parse', e);
 *   }
 *
 * R-273 turned the original silent `.catch(() => {})` / bare `catch {}` into a
 * `console.warn`, but `ensureFunding` still resolved normally either way. A
 * method whose entire purpose is to *guarantee* spendable funding returned
 * success when the wallet handed back garbage it could not parse, or when the
 * funding tx was never actually accepted onto the network. The caller then
 * proceeds to deploy against a funding UTXO that may not exist, and fails
 * later (if at all) with an error that has nothing to do with the real cause.
 *
 * `checkArcAccepted` (this file's broadcast path) throws only for an explicit
 * ARC rejection (REJECTED/INVALID/ORPHAN/…) or a non-2xx response with a
 * matching txid check — "ARC already knows this tx" is a success path, not
 * one of its failure modes, so an explicit rejection is never a false
 * positive. This test does NOT prove the fix is free of false negatives in
 * general: `broadcastTx` also throws on a transient `fetch` network error or
 * a non-"ok" HTTP response (wallet-provider.ts), and a transient blip on this
 * best-effort extra ARC push — while the wallet's own `acceptDelayedBroadcast`
 * background broadcast already succeeded independently — will now throw too.
 * That tradeoff (favoring fail-closed over tolerating a transient push
 * failure) is the dispatcher-authorized behavior change this item makes, not
 * an oversight.
 *
 * Scope: this test covers `WalletProvider.ensureFunding` only.
 * `contract.ts#deployWithWallet` has the identical shape (`deploy-tx
 * broadcast` / `deploy-tx BEEF parse`) but is out of scope for this item —
 * N-038 owns contract.ts.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { Transaction, LockingScript } from '@bsv/sdk';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import type { WalletClient } from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

/** A wallet whose listOutputs reports no funds, forcing ensureFunding past
 * the early-return and into createAction. */
function makeWallet(createAction: WalletClient['createAction']): WalletClient {
  return {
    listOutputs: async () => ({ outputs: [], totalOutputs: 0 }),
    createAction,
  } as unknown as WalletClient;
}

function provider(wallet: WalletClient): WalletProvider {
  return new WalletProvider({ wallet, signer: stubSigner, basket: 'b' });
}

/** A valid, parseable AtomicBEEF for a single-output transaction. */
function validAtomicBeef(): { beef: number[]; txid: string } {
  const tx = new Transaction();
  tx.version = 1;
  tx.addOutput({ satoshis: 5000, lockingScript: LockingScript.fromHex('51') });
  return { beef: tx.toAtomicBEEF(true), txid: tx.id('hex') };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('F-248: ensureFunding surfaces failures instead of swallowing them', () => {
  it('rejects when the wallet returns a BEEF that does not parse', async () => {
    const wallet = makeWallet(async () => ({
      txid: 'aa'.repeat(32),
      // Not valid BEEF bytes: Transaction.fromAtomicBEEF must throw on this.
      tx: [1, 2, 3, 4],
    }));

    await expect(provider(wallet).ensureFunding(1000)).rejects.toThrow(/ensureFunding/);
    await expect(provider(wallet).ensureFunding(1000)).rejects.toThrow(/BEEF/);
  });

  it('rejects when the funding-tx broadcast is rejected by ARC', async () => {
    const { beef, txid } = validAtomicBeef();
    const wallet = makeWallet(async () => ({ txid, tx: beef }));

    // ARC responds 200 but refuses the transaction.
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ txStatus: 'REJECTED' }),
      { status: 200 },
    )));

    await expect(provider(wallet).ensureFunding(1000)).rejects.toThrow(/ensureFunding/);
    await expect(provider(wallet).ensureFunding(1000)).rejects.toThrow(/broadcast/i);
  });

  it('still resolves when the wallet funds successfully and ARC accepts', async () => {
    const { beef, txid } = validAtomicBeef();
    const wallet = makeWallet(async () => ({ txid, tx: beef }));

    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ txid }),
      { status: 200 },
    )));

    await expect(provider(wallet).ensureFunding(1000)).resolves.toBeUndefined();
  });
});
