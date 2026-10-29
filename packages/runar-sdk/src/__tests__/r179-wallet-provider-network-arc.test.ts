/**
 * R-179 (CL-BUG-072): WalletProvider's ARC endpoint ignored the network it was
 * configured with.
 *
 * `arcUrl` and `network` were defaulted independently:
 *
 *   this.arcUrl   = options.arcUrl ?? 'https://arc.gorillapool.io';
 *   this._network = options.network ?? 'mainnet';
 *
 * so a caller who asked for testnet and did not also know to pass an explicit
 * `arcUrl` got a provider that reported `getNetwork() === 'testnet'` and
 * broadcast every transaction to the MAINNET ARC. Nothing warned. The sibling
 * GorillaPoolProvider in the same directory derives its base URL from the
 * network (`providers/gorillapool.ts:73-79`), which is what makes this an
 * inconsistency inside one SDK rather than a policy question.
 *
 * The repo's own test pinned the defect: `wallet-provider-extensibility.test.ts`
 * asserted the description string
 *
 *   'test-basket/fees via https://arc.gorillapool.io (testnet, 1000 sats/KB, overlay: none)'
 *
 * — a testnet provider describing a mainnet broadcaster, read past by everyone.
 *
 * The first fix was fail-closed, because there was no canonical testnet ARC
 * endpoint to default to. The default broadcaster is now BSV Broadcaster, the
 * BSV Association's broadcaster, which publishes an endpoint per network, so
 * the default is derived from the network the same way GorillaPoolProvider
 * derives its base URL. The invariant these tests pin is unchanged: a provider
 * never broadcasts to a network other than the one it reports.
 */

import { describe, it, expect } from 'vitest';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import type { WalletClient } from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

const base = { wallet: stubWallet, signer: stubSigner, basket: 'test-basket' };

const MAINNET_SUBMIT = 'https://arcade-us-1.bsvblockchain.tech/tx';
const TESTNET_SUBMIT = 'https://arcade-v2-testnet-us-1.bsvblockchain.tech/tx';

/** Reach the protected field the way a subclass would. */
function broadcastUrlOf(p: WalletProvider): string {
  return (p as unknown as { broadcastUrl: string }).broadcastUrl;
}

describe('R-179: the broadcast endpoint must agree with the configured network', () => {
  it('defaults a testnet provider to the testnet BSV Broadcaster', () => {
    const p = new WalletProvider({ ...base, network: 'testnet' });
    expect(p.getNetwork()).toBe('testnet');
    expect(broadcastUrlOf(p)).toBe(TESTNET_SUBMIT);
  });

  it('defaults a mainnet provider to the mainnet BSV Broadcaster', () => {
    const implicit = new WalletProvider({ ...base });
    expect(implicit.getNetwork()).toBe('mainnet');
    expect(broadcastUrlOf(implicit)).toBe(MAINNET_SUBMIT);

    const explicit = new WalletProvider({ ...base, network: 'mainnet' });
    expect(explicit.getNetwork()).toBe('mainnet');
    expect(broadcastUrlOf(explicit)).toBe(MAINNET_SUBMIT);
  });

  it('lets a testnet provider name its own ARC endpoint', () => {
    const p = new WalletProvider({
      ...base,
      network: 'testnet',
      arcUrl: 'https://arc.testnet.example',
    });
    expect(p.getNetwork()).toBe('testnet');
    expect(broadcastUrlOf(p)).toBe('https://arc.testnet.example/v1/tx');
  });

  it('lets a mainnet provider override the endpoint with an ARC URL', () => {
    const p = new WalletProvider({
      ...base,
      network: 'mainnet',
      arcUrl: 'https://arc.gorillapool.io',
    });
    expect(broadcastUrlOf(p)).toBe('https://arc.gorillapool.io/v1/tx');
  });

  it('never leaves a provider whose network and default endpoint disagree', () => {
    // The invariant, stated once: a provider the caller did not point anywhere
    // broadcasts to the network it reports.
    for (const network of ['mainnet', 'testnet'] as const) {
      const p = new WalletProvider({ ...base, network });
      const url = broadcastUrlOf(p);
      expect(url === TESTNET_SUBMIT).toBe(network === 'testnet');
    }
  });
});
