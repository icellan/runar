/**
 * N-016 — PropertyShadow: a local that shares a property's name never
 * captures `this.<prop>`.
 *
 * Two halves, so the source semantics and the compiled script are checked
 * independently of each other:
 *   - the interpreter (TestContract) reads the SOURCE semantics;
 *   - the deployed script is spent through a validating MockProvider, whose
 *     pre-broadcast dry-run replays the contract input on the @bsv/sdk Spend
 *     engine — the half that caught the bug, since before N-016 every tier
 *     compiled `assert(target == this.target)` to OP_DUP OP_NUMEQUAL.
 *
 * Expected values are derived by hand from the source: bump(n) needs
 * n + 1 == target and commits count + n.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { TestContract } from 'runar-testing';
import type { RunarArtifact } from 'runar-ir-schema';
// Relative imports — the repo vitest.config.ts does not alias runar-sdk.
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../../packages/runar-sdk/src/signers/local.js';
import { buildP2PKHScript } from '../../../packages/runar-sdk/src/script-utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'PropertyShadow.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const KEY = '0000000000000000000000000000000000000000000000000000000000000001';

function artifact(): RunarArtifact {
  const r = compile(source, { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

async function spend(target: bigint, count: bigint, n: bigint): Promise<{ ok: boolean; state?: unknown; error?: string }> {
  const signer = new LocalSigner(KEY);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact(), [target, count]);
  await contract.deploy(provider, signer, {});
  try {
    await contract.call('bump', [n], provider, signer);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  return { ok: true, state: contract.state };
}

describe('PropertyShadow — source semantics (interpreter)', () => {
  it('bump(9) with target 10, count 4 commits count 13', () => {
    const c = TestContract.fromSource(source, { target: 10n, count: 4n }, FILE);
    const r = c.call('bump', { n: 9n });
    expect(r.success, r.error).toBe(true);
    expect(c.state.count).toBe(13n);
  });

  it('bump(5) with target 10 is refused (5 + 1 != 10)', () => {
    const c = TestContract.fromSource(source, { target: 10n, count: 4n }, FILE);
    expect(c.call('bump', { n: 5n }).success).toBe(false);
  });
});

describe('PropertyShadow — compiled script on the Spend engine', () => {
  it('the target guard is not the always-true self-comparison', () => {
    expect(artifact().script).not.toContain('8b769c');
  });

  it('bump(9) with target 10, count 4 is ACCEPTED and commits count 13 (pre-fix: 18)', async () => {
    const v = await spend(10n, 4n, 9n);
    expect(v.ok, v.error).toBe(true);
    expect(v.state).toEqual({ count: 13n });
  });

  it('bump(5) with target 10 is REJECTED (the pre-fix script accepted it)', async () => {
    const v = await spend(10n, 4n, 5n);
    expect(v.ok).toBe(false);
  });
});
