/**
 * WalletProvider extensibility: subclasses must be able to reach the
 * provider's configuration and override its transport methods without
 * `as any` casts or duplicating every field.
 *
 * The runtime assertions pin the polymorphic dispatch (the base broadcast
 * pipeline calls the subclass's fetchRawTx override); the protected-member
 * accesses in ExtendedProvider are compile-time assertions enforced by the
 * package typecheck.
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

/** A parent tx and a child tx spending it (child input has no sourceTransaction). */
function makeTxPair(): { parent: BsvTransaction; child: BsvTransaction } {
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
    sourceTXID: parent.id('hex'),
    sourceOutputIndex: 0,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  child.addOutput({ satoshis: 49000, lockingScript: LockingScript.fromHex('51') });
  return { parent, child };
}

// ---------------------------------------------------------------------------
// Subclass exercising the protected surface
// ---------------------------------------------------------------------------

class ExtendedProvider extends WalletProvider {
  fetchRawTxCalls: string[] = [];
  private readonly localTxs = new Map<string, string>();

  addLocalTx(txid: string, rawHex: string): void {
    this.localTxs.set(txid, rawHex);
  }

  /** Route parent lookups through a local store instead of the overlay. */
  protected override async fetchRawTx(txid: string): Promise<string> {
    this.fetchRawTxCalls.push(txid);
    const local = this.localTxs.get(txid);
    if (local) return local;
    return super.fetchRawTx(txid);
  }

  /** Compile-time assertions: protected config is reachable from subclasses. */
  describeConfig(): string {
    return `${this.basket}/${this.fundingTag} via ${this.arcUrl} (${this._network}, ${this._feeRate} sats/KB, overlay: ${this.overlayUrl ?? 'none'})`;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WalletProvider extensibility', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('base broadcast pipeline dispatches to a subclass fetchRawTx override', async () => {
    const { parent, child } = makeTxPair();
    const childTxid = child.id('hex');

    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/v1/tx')) {
        return new Response(JSON.stringify({ txid: childTxid }), { status: 200 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const provider = new ExtendedProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
    });
    provider.addLocalTx(parent.id('hex'), parent.toHex());

    const txid = await provider.broadcast(child);

    expect(txid).toBe(childTxid);
    // The base class's EF assembly used the override, not its own overlay path.
    expect(provider.fetchRawTxCalls).toEqual([parent.id('hex')]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('exposes protected configuration to subclasses', () => {
    // R-179: this case used to omit arcUrl and assert that a TESTNET provider
    // described itself as broadcasting via https://arc.gorillapool.io — the
    // mainnet endpoint. The assertion was pinning the defect, not the feature
    // under test, which is that a subclass can read the protected fields. A
    // testnet provider now has to name its own endpoint, so it does.
    const provider = new ExtendedProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
      fundingTag: 'fees',
      network: 'testnet',
      arcUrl: 'https://arc.testnet.example',
      feeRate: 1000,
    });

    expect(provider.describeConfig()).toBe(
      'test-basket/fees via https://arc.testnet.example (testnet, 1000 sats/KB, overlay: none)',
    );
  });

  it('exposes the wallet client and basket through typed getters', () => {
    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'test-basket',
    });

    expect(provider.walletClient).toBe(stubWallet);
    expect(provider.basketName).toBe('test-basket');
  });
});
