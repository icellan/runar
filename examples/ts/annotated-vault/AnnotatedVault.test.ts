/**
 * N-044 — AnnotatedVault: a mutable ByteString (`memo`) stored before the
 * mutable `owner`. The on-chain reader must decode memo's PUSHDATA length
 * unsigned, or a 128-byte memo (framed `4c 80`) reads as length 0 and the
 * memo's first 33 bytes become `owner`.
 *
 * The deployed script is spent through a MockProvider, whose pre-broadcast
 * dry-run replays the contract input on the @bsv/sdk Spend engine. Expected
 * verdicts are derived by hand from the source: anyone may annotate, only the
 * owner may withdraw. The seven-tier, both-fold-mode version of this check is
 * packages/runar-testing/src/__tests__/n044-state-length-sign-spend.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
// Relative imports — the repo vitest.config.ts does not alias runar-sdk.
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../../packages/runar-sdk/src/signers/local.js';
import { buildP2PKHScript } from '../../../packages/runar-sdk/src/script-utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'AnnotatedVault.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const OWNER_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
const STRANGER_KEY = '0000000000000000000000000000000000000000000000000000000000000002';

function artifact(): RunarArtifact {
  const r = compile(source, { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

/** Deploy with an empty memo, let the stranger annotate `memoLen` bytes that
 *  start with their pubkey, then try `withdraw` as `who`. */
async function run(memoLen: number, who: 'owner' | 'stranger'): Promise<{ ok: boolean; error?: string }> {
  const owner = new LocalSigner(OWNER_KEY);
  const stranger = new LocalSigner(STRANGER_KEY);
  const provider = new MockProvider();
  for (const [i, s] of [owner, stranger].entries()) {
    provider.addUtxo(await s.getAddress(), {
      txid: String(i + 1).repeat(64),
      outputIndex: 0,
      satoshis: 500_000,
      script: buildP2PKHScript(await s.getPublicKey()),
    });
  }
  const contract = new RunarContract(artifact(), ['', await owner.getPublicKey(), 1000n]);
  await contract.deploy(provider, owner, {});
  const memo = (await stranger.getPublicKey()) + '00'.repeat(memoLen - 33);
  await contract.call('annotate', [memo], provider, stranger);
  try {
    await contract.call('withdraw', [null], provider, who === 'owner' ? owner : stranger);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  return { ok: true };
}

describe('AnnotatedVault — PUSHDATA state lengths are unsigned (Spend engine)', () => {
  it('the stranger cannot withdraw after writing a 128-byte memo that starts with their pubkey', async () => {
    const r = await run(128, 'stranger');
    expect(r.ok).toBe(false);
    // Rejected by the real script engine on the CONTRACT input (MockProvider's
    // broadcast validation), not by a fee/value check.
    expect(r.error).toMatch(/\(C8\): input 0: Script evaluation error/);
  });

  for (const len of [127, 128, 129, 256]) {
    it(`the owner can still withdraw after a ${len}-byte memo`, async () => {
      const r = await run(len, 'owner');
      expect(r.ok, r.error).toBe(true);
    });
  }
});
