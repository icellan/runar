/**
 * N-040 — ARC broadcast has no request timeout; the injected-broadcaster path
 * returns the broadcaster's txid unchecked.
 *
 * Before this fix, `WalletProvider.broadcastTx`'s default ARC path called
 * `fetch(`${this.arcUrl}/v1/tx`, ...)` with no `signal`, so a server that
 * accepts the connection but never responds hangs the broadcast forever —
 * there is no bounded failure mode. Separately, the `this.broadcaster`
 * (issue #107) delegation path returned `result.txid` straight from the
 * injected broadcaster with no check that it names the transaction actually
 * sent — the same class of bug F-042 already fixed for the hardcoded ARC
 * path (an ARC response naming a different transaction is rejected there).
 *
 * PROVES: (1) against a REAL local HTTP server that accepts the TCP
 * connection and never calls `res.end()`, `broadcast()` rejects within the
 * configured `arcTimeoutMs` rather than hanging — this exercises the actual
 * fetch/AbortSignal wiring, not a mocked rejection; (2) an injected
 * broadcaster that resolves with a txid other than the local transaction's
 * txid causes `broadcast()` to reject, naming both txids.
 * DOES NOT PROVE: behavior against a live ARC deployment, or that
 * `arcTimeoutMs`'s default (30s) is the right value for production — only
 * that the option is wired through to the real request.
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import {
  Transaction as BsvTransaction,
  LockingScript,
  UnlockingScript,
  type WalletClient,
  type Broadcaster,
  type BroadcastResponse,
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

describe('WalletProvider ARC timeout and injected-broadcaster txid check (N-040)', () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = undefined;
    }
  });

  it('rejects within arcTimeoutMs against a real server that never responds', async () => {
    server = http.createServer((_req, _res) => {
      // Deliberately never call res.end() / res.write() — the request hangs
      // on the server side exactly like an ARC deployment that accepted the
      // TCP connection but never answers.
    });
    const port: number = await new Promise((resolve) => {
      server!.listen(0, '127.0.0.1', () => {
        resolve((server!.address() as { port: number }).port);
      });
    });

    const child = makeChildWithParent();
    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      arcUrl: `http://127.0.0.1:${port}`,
      arcTimeoutMs: 200,
    });

    const start = Date.now();
    await expect(provider.broadcast(child)).rejects.toThrow(/NOT broadcast/i);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(5000);
  });

  it('rejects when an injected broadcaster resolves with a foreign txid', async () => {
    const child = makeChildWithParent();
    const localTxid = child.id('hex');
    const foreignTxid = 'cc'.repeat(32);

    const broadcaster: Broadcaster = {
      broadcast: async (_tx: BsvTransaction): Promise<BroadcastResponse> => ({
        status: 'success',
        txid: foreignTxid,
        message: 'ok',
      }),
    };

    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      broadcaster,
    });

    await expect(provider.broadcast(child)).rejects.toThrow(
      new RegExp(`${foreignTxid}.*${localTxid}`, 's'),
    );
  });
});
