/**
 * R-273 (CL-GAP-032): four fire-and-forget error swallows in this SDK reported
 * nothing at all.
 *
 *   providers/wallet-provider.ts  this.submitToOverlay(tx).catch(() => {})   x2
 *   providers/wallet-provider.ts  broadcastTx(...).catch(() => {})
 *                                 catch { /* funding tx parse failure ... *\/ }
 *   contract.ts                   catch { /* BEEF parse failure ... *\/ }
 *
 * Being non-fatal is correct: the caller's transaction is already broadcast,
 * and an indexing or caching failure must not turn a successful spend into a
 * thrown error. Reporting nothing is not — an overlay that is down looks
 * exactly like an overlay that is fine, from inside and from outside.
 *
 * The rest of the SDK already uses console.warn for advisory failures
 * (contract.ts:595, :932, :1130, :1857; providers/mock.ts:56), so these four
 * now match rather than inventing a mechanism.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import { WalletProvider } from '../providers/wallet-provider.js';
import { warnNonFatal } from '../providers/provider.js';
import type { Signer } from '../signers/signer.js';
import type { WalletClient } from '@bsv/sdk';

const __dirname_ = dirname(fileURLToPath(import.meta.url));

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

/** A child tx with a real sourceTransaction, so EF serialisation works. */
function sampleTx(): Transaction {
  const parent = new Transaction();
  parent.version = 1;
  parent.addOutput({ satoshis: 2000, lockingScript: new LockingScript() });

  const tx = new Transaction();
  tx.version = 1;
  tx.addInput({
    sourceTransaction: parent,
    sourceOutputIndex: 0,
    sequence: 0xffffffff,
    unlockingScript: new UnlockingScript(),
  });
  tx.addOutput({ satoshis: 1000, lockingScript: new LockingScript() });
  return tx;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('R-273: non-fatal failures are reported, not discarded', () => {
  it('warns when the overlay submission fails, and still returns the txid', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const tx = sampleTx();

    // ARC accepts; the overlay is down.
    const fetchMock = vi.fn(async (url: unknown) => {
      if (String(url).includes('/submit')) throw new Error('overlay is down');
      return {
        ok: true,
        status: 200,
        json: async () => ({ txid: tx.id('hex') }),
        text: async () => '',
      } as unknown as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    const provider = new WalletProvider({
      wallet: stubWallet,
      signer: stubSigner,
      basket: 'b',
      overlayUrl: 'https://overlay.example',
      overlayTopics: ['tm_runar'],
    });

    const txid = await provider.broadcast(tx);
    expect(txid).toBe(tx.id('hex'));

    // The submission is fire-and-forget; let its rejection settle.
    await new Promise((r) => setTimeout(r, 0));

    expect(warn).toHaveBeenCalled();
    const said = warn.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(said).toMatch(/overlay/i);
  });

  it('warnNonFatal names the context and carries the original error', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cause = new Error('the underlying reason');
    warnNonFatal('overlay submission', cause);

    expect(warn).toHaveBeenCalledTimes(1);
    const [msg, err] = warn.mock.calls[0]!;
    expect(String(msg)).toContain('overlay submission');
    expect(String(msg)).toContain('non-fatal');
    expect(err).toBe(cause);
  });

  it('leaves no silent swallow behind in either file', () => {
    // The regression guard: `.catch(() => {})` and an empty `catch {}` are the
    // two spellings this finding is about.
    for (const rel of ['../providers/wallet-provider.ts', '../contract.ts']) {
      const src = readFileSync(join(__dirname_, rel), 'utf8');
      const offenders: string[] = [];
      src.split('\n').forEach((line, i) => {
        if (/\.catch\(\(\)\s*=>\s*\{\s*\}\)/.test(line)) {
          offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        }
        if (/catch\s*\{\s*\/\*/.test(line) && !/warnNonFatal/.test(line)) {
          offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        }
      });
      expect(offenders, 'silent error swallows').toEqual([]);
    }
  });
});
