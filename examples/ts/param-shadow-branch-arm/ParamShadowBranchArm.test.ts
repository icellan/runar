/**
 * N-007 — ParamShadowBranchArm: a parameter that shares a mutable property's
 * name is still the parameter inside an `if` arm.
 *
 * Two halves, so the source semantics and the compiled script are checked
 * independently of each other:
 *   - the interpreter (TestContract) reads the SOURCE semantics;
 *   - the deployed script is spent through a validating MockProvider, whose
 *     pre-broadcast dry-run replays the contract input on the @bsv/sdk Spend
 *     engine — the half that caught the bug, since before N-007 the TS tier
 *     compiled the in-arm `count` to a copy of the deserialized state.
 *
 * Expected values are derived by hand from the source: set(count, flag)
 * needs count == 5 when flag is true, and commits count.
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
const FILE = 'ParamShadowBranchArm.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const KEY = '0000000000000000000000000000000000000000000000000000000000000001';

function artifact(): RunarArtifact {
  const r = compile(source, { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

async function spend(state: bigint, count: bigint, flag: boolean): Promise<{ ok: boolean; state?: unknown; error?: string }> {
  const signer = new LocalSigner(KEY);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact(), [state]);
  await contract.deploy(provider, signer, {});
  try {
    await contract.call('set', [count, flag], provider, signer);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  return { ok: true, state: contract.state };
}

describe('ParamShadowBranchArm — source semantics (interpreter)', () => {
  it('set(5, true) with state 5 commits count 5', () => {
    const c = TestContract.fromSource(source, { count: 5n }, FILE);
    const r = c.call('set', { count: 5n, flag: true });
    expect(r.success, r.error).toBe(true);
    expect(c.state.count).toBe(5n);
  });

  it('set(7, true) with state 5 is refused (the argument 7 != 5)', () => {
    const c = TestContract.fromSource(source, { count: 5n }, FILE);
    expect(c.call('set', { count: 7n, flag: true }).success).toBe(false);
  });
});

describe('ParamShadowBranchArm — compiled script on the Spend engine', () => {
  it('set(7, true) with state 5 is REJECTED (the pre-fix TS script accepted it)', async () => {
    const v = await spend(5n, 7n, true);
    expect(v.ok).toBe(false);
  });

  it('set(5, true) with state 5 is ACCEPTED and commits count 5', async () => {
    const v = await spend(5n, 5n, true);
    expect(v.ok, v.error).toBe(true);
    expect(v.state).toEqual({ count: 5n });
  });

  it('set(7, false) skips the arm, is ACCEPTED and commits count 7', async () => {
    const v = await spend(5n, 7n, false);
    expect(v.ok, v.error).toBe(true);
    expect(v.state).toEqual({ count: 7n });
  });

  it('set(5, true) with state 7 is ACCEPTED (the guard reads the argument, not the state)', async () => {
    const v = await spend(7n, 5n, true);
    expect(v.ok, v.error).toBe(true);
    expect(v.state).toEqual({ count: 5n });
  });
});
