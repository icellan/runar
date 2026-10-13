// N-239: TokenWallet.merge / .transfer are deprecated and unsafe.
//
// The ABI they drive — merge(sig, otherSupply, otherHolder) and
// transfer(sig, to: Addr) — cannot be made sound: merge cannot authenticate
// its companion input (the holder can inflate supply on one input), and
// transfer cannot re-key a PubKey holder from an Addr. User decision R92:
// deprecate (marker + one-time runtime warning + docs), do not redesign or
// remove.
//
// Proves: each method carries an `@deprecated` JSDoc marker; calling it emits
// a console.warn naming its specific unsoundness and pointing to token-ft
// (FungibleTokenExample); the warning fires once per process, not per call;
// the method's own behaviour (here, its error path) is unchanged.
// Does NOT prove: that anyone reads the warning, or anything about the
// on-chain contract — the methods' happy paths stay covered by the f045 /
// n042 / r274 suites.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TokenWallet } from '../tokens.js';
import { MockProvider } from '../providers/mock.js';
import type { RunarArtifact } from 'runar-ir-schema';

const ARTIFACT = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'WalletToken',
  abi: { constructor: { params: [] }, methods: [] },
  script: '76a988ac',
  asm: '',
  buildTimestamp: '2026-10-13T00:00:00.000Z',
} as unknown as RunarArtifact;

function makeWallet(): TokenWallet {
  const signer = {
    getAddress: vi.fn().mockResolvedValue('mocked-address'),
    getPublicKey: vi.fn().mockResolvedValue('02' + 'aa'.repeat(32)),
    sign: vi.fn().mockResolvedValue('00'.repeat(72)),
  };
  return new TokenWallet(ARTIFACT, new MockProvider(), signer);
}

function warningsMentioning(spy: ReturnType<typeof vi.spyOn>, needle: string): string[] {
  return spy.mock.calls
    .map((args) => args.map(String).join(' '))
    .filter((msg) => msg.includes(needle));
}

describe('N-239: TokenWallet merge/transfer are deprecated', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('merge warns once about supply inflation and points to token-ft', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const wallet = makeWallet();

    await expect(wallet.merge()).rejects.toThrow('need at least 2 UTXOs to merge');
    await expect(wallet.merge()).rejects.toThrow('need at least 2 UTXOs to merge');

    const hits = warningsMentioning(warn, 'TokenWallet.merge');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toContain('deprecated');
    expect(hits[0]).toContain('supply inflation');
    expect(hits[0]).toContain('token-ft');
    expect(hits[0]).toContain('FungibleTokenExample');
  });

  it('transfer warns once about holder re-key and points to token-ft', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const wallet = makeWallet();

    await expect(wallet.transfer('recipient', 1n)).rejects.toThrow('no token UTXOs found');
    await expect(wallet.transfer('recipient', 1n)).rejects.toThrow('no token UTXOs found');

    const hits = warningsMentioning(warn, 'TokenWallet.transfer');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toContain('deprecated');
    expect(hits[0]).toContain('re-key');
    expect(hits[0]).toContain('token-ft');
    expect(hits[0]).toContain('FungibleTokenExample');
  });

  it('both methods carry an @deprecated JSDoc marker', () => {
    const src = readFileSync(fileURLToPath(new URL('../tokens.ts', import.meta.url)), 'utf8');
    for (const method of ['transfer', 'merge']) {
      const re = new RegExp(`@deprecated[^*]*(?:\\*(?!/)[^*]*)*\\*/\\s*async ${method}\\(`);
      expect(src, `${method} lacks an @deprecated marker`).toMatch(re);
    }
  });
});
