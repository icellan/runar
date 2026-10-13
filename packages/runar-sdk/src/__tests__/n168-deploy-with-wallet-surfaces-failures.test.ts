/**
 * N-168: `RunarContract.deployWithWallet` swallowed both the deploy-tx BEEF
 * parse failure and the deploy-tx broadcast failure, via the same shape
 * F-248 fixed in `WalletProvider.ensureFunding`:
 *
 *   } catch (e) {
 *     warnNonFatal('deploy-tx BEEF parse', e);
 *   }
 *   ...
 *   await walletProvider.broadcast(tx).catch((e) =>
 *     warnNonFatal('deploy-tx broadcast', e),
 *   );
 *
 * `deployWithWallet`'s whole job is to hand the caller back a real
 * `{ txid, outputIndex }` for a contract UTXO that exists on chain. Routing
 * both failures through `warnNonFatal` (a `console.warn`) meant the method
 * still resolved normally when the wallet handed back a BEEF blob that could
 * not be parsed, or when the extra ARC push this method makes was explicitly
 * rejected — the caller then tries to spend a UTXO that was never actually
 * broadcast, and fails later (if at all) with an error unrelated to the real
 * cause.
 *
 * `checkArcAccepted` (reached via `WalletProvider.broadcast`) throws only for
 * an explicit ARC rejection (REJECTED/INVALID/ORPHAN/…) or a non-2xx response
 * with a mismatched txid — "ARC already knows this tx" is a success path,
 * never one of its failure modes, so an explicit rejection case 2 below
 * exercises is never a false positive. This test does NOT prove the fix is
 * free of false negatives in general: a transient `fetch` network error on
 * this best-effort extra ARC push — while the wallet's own background
 * broadcast already succeeded independently — now throws too. That tradeoff
 * (fail-closed over tolerating a transient push failure) is the same
 * dispatcher-authorized behavior change F-248 made for `ensureFunding`.
 *
 * Scope: this test covers `RunarContract.deployWithWallet` only.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { Transaction, LockingScript } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import type { RunarArtifact } from 'runar-ir-schema';
import type { WalletClient } from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

/** A wallet whose createAction returns a caller-supplied result (BEEF, txid). */
function makeWallet(createAction: WalletClient['createAction']): WalletClient {
  return { createAction } as unknown as WalletClient;
}

const artifact: RunarArtifact = {
  version: 'runar-v1.0.0-rc.1',
  compilerVersion: '1.0.0-rc.1-ts',
  contractName: 'Counter',
  abi: { constructor: { params: [] }, methods: [] },
  script: '51', // OP_1 — matches getLockingScript() for an artifact with no stateFields
  asm: 'OP_1',
  buildTimestamp: '2026-09-13T00:00:00Z',
} as RunarArtifact;

function connectTo(wallet: WalletClient): RunarContract {
  const provider = new WalletProvider({ wallet, signer: stubSigner, basket: 'test-basket' });
  const contract = new RunarContract(artifact, []);
  contract.connect(provider, stubSigner);
  return contract;
}

/**
 * A valid, parseable AtomicBEEF for a two-output transaction. The contract's
 * locking script ('51') sits at vout 1, behind an unrelated dummy output at
 * vout 0 — so an assertion on `outputIndex === 1` actually proves the
 * BEEF-output scan found the right vout rather than defaulting to 0.
 */
function validAtomicBeef(): { beef: number[]; txid: string } {
  const tx = new Transaction();
  tx.version = 1;
  tx.addOutput({ satoshis: 999, lockingScript: LockingScript.fromHex('00') });
  tx.addOutput({ satoshis: 5000, lockingScript: LockingScript.fromHex('51') });
  return { beef: tx.toAtomicBEEF(true), txid: tx.id('hex') };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('N-168: deployWithWallet surfaces failures instead of swallowing them', () => {
  it('rejects when the wallet returns a BEEF that does not parse', async () => {
    const wallet = makeWallet(async () => ({
      txid: 'aa'.repeat(32),
      // Not valid BEEF bytes: Transaction.fromAtomicBEEF must throw on this.
      tx: [1, 2, 3, 4],
    }));
    const contract = connectTo(wallet);

    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(
      /deployWithWallet/,
    );
    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(/BEEF/);
  });

  it('rejects when the deploy-tx broadcast is rejected by ARC', async () => {
    const { beef, txid } = validAtomicBeef();
    const wallet = makeWallet(async () => ({ txid, tx: beef }));
    const contract = connectTo(wallet);

    // ARC responds 200 but refuses the transaction.
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ txStatus: 'REJECTED' }),
      { status: 200 },
    )));

    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(
      /deployWithWallet/,
    );
    await expect(contract.deployWithWallet({ satoshis: 1 })).rejects.toThrow(/broadcast/i);
  });

  it('CONTROL: still resolves (with the correct vout) when the wallet funds and ARC accepts', async () => {
    const { beef, txid } = validAtomicBeef();
    const wallet = makeWallet(async () => ({ txid, tx: beef }));
    const contract = connectTo(wallet);

    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ txid }),
      { status: 200 },
    )));

    const res = await contract.deployWithWallet({ satoshis: 1 });
    expect(res.txid).toBe(txid);
    expect(res.outputIndex).toBe(1);
  });
});
