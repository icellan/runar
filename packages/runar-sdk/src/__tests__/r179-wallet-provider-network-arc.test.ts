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
 * The fix is fail-closed rather than a derived testnet URL: this repo has no
 * canonical testnet ARC endpoint (the only other ARC reference in the tree is
 * `https://arc.taal.com` in docs/integration-guide.md), and inventing one would
 * be worse than asking. A testnet provider with no explicit `arcUrl` now
 * refuses to construct.
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

/** Reach the protected field the way a subclass would. */
function arcUrlOf(p: WalletProvider): string {
  return (p as unknown as { arcUrl: string }).arcUrl;
}

describe('R-179: the ARC endpoint must agree with the configured network', () => {
  it('refuses to build a testnet provider pointing at the mainnet ARC', () => {
    expect(() => new WalletProvider({ ...base, network: 'testnet' })).toThrow(
      /testnet/i,
    );
    expect(() => new WalletProvider({ ...base, network: 'testnet' })).toThrow(
      /arc\.gorillapool\.io/,
    );
  });

  it('accepts a testnet provider that names its own ARC endpoint', () => {
    const p = new WalletProvider({
      ...base,
      network: 'testnet',
      arcUrl: 'https://arc.testnet.example',
    });
    expect(p.getNetwork()).toBe('testnet');
    expect(arcUrlOf(p)).toBe('https://arc.testnet.example');
  });

  it('leaves the mainnet default exactly as it was', () => {
    const implicit = new WalletProvider({ ...base });
    expect(implicit.getNetwork()).toBe('mainnet');
    expect(arcUrlOf(implicit)).toBe('https://arc.gorillapool.io');

    const explicit = new WalletProvider({ ...base, network: 'mainnet' });
    expect(explicit.getNetwork()).toBe('mainnet');
    expect(arcUrlOf(explicit)).toBe('https://arc.gorillapool.io');
  });

  it('lets a mainnet provider override the endpoint', () => {
    const p = new WalletProvider({
      ...base,
      network: 'mainnet',
      arcUrl: 'https://arc.taal.com',
    });
    expect(arcUrlOf(p)).toBe('https://arc.taal.com');
  });

  it('never leaves a provider whose network and endpoint disagree', () => {
    // The invariant, stated once: for every provider that constructs, a
    // testnet network implies an endpoint the caller chose.
    const built = [
      new WalletProvider({ ...base }),
      new WalletProvider({ ...base, network: 'mainnet' }),
      new WalletProvider({ ...base, network: 'testnet', arcUrl: 'https://arc.testnet.example' }),
    ];
    for (const p of built) {
      if (p.getNetwork() === 'testnet') {
        expect(arcUrlOf(p)).not.toBe('https://arc.gorillapool.io');
      }
    }
  });
});
