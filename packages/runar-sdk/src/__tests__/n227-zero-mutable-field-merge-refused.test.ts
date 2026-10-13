/**
 * N-227 Part 2: a zero-mutable-field `StatefulSmartContract` call that also
 * merges `additionalContractInputs` must fail closed rather than broadcast
 * an invalid tx.
 *
 * `AllReadonlyCleanstack` (same fixture N-085 uses) has ZERO mutable fields,
 * so `prepareCall`'s `isStateful` is `false` for its `claim()` method — even
 * though the contract IS `parentStateful` and still auto-injects
 * `checkPreimage`. `prepareCall`'s `isStateful` branch builds a REAL
 * per-input unlock (its own OP_PUSH_TX preimage + signed Sig args) for every
 * extra contract input via `buildStatefulUnlock`. The "stateless" branch
 * `claim()` takes has no equivalent: before this fix it only ever reused the
 * SIZING placeholder unlock (72 zero-byte sig + args + witness) for extra
 * inputs in its N-085 rebuild, shipping that placeholder as the FINAL
 * unlocking script — an invalid spend for every input after the primary.
 *
 * What this test proves: `RunarContract.call()` throws (refusing to
 * broadcast) when `additionalContractInputs` is set on a zero-mutable-field
 * StatefulSmartContract call, instead of silently shipping unvalidatable
 * placeholder-unlock bytes.
 *
 * What this test does NOT prove: that a real per-input-unlock fix is
 * impossible, or that the same guard exists in Go/Rust/Python/Ruby (it
 * does, as a parallel port — this file covers TS only). Java and Zig
 * support merge on a zero-mutable-field contract via a unified code path
 * (not this branch-patch) — that is a documented cross-tier divergence
 * this item does not close.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';
import fs from 'fs';
import path from 'path';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

describe('N-227 Part 2 — zero-mutable-field StatefulSmartContract merge is refused', () => {
  it('claim() with additionalContractInputs throws instead of shipping a placeholder unlock', async () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'),
      'utf8',
    );
    const artifact = compileSource(source, 'AllReadonlyCleanstack.runar.ts');

    expect(artifact.parentClass).toBe('StatefulSmartContract');
    expect(artifact.stateFields ?? []).toEqual([]);

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();

    const provider = new MockProvider();
    provider.addUtxo(address, {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: buildP2PKHScript(pubKey),
    });

    const contract = new RunarContract(artifact, [pubKey]);
    await contract.deploy(provider, signer, { satoshis: 5000, changeAddress: address });

    // The "extra" merge input's content is irrelevant — the guard must fire
    // before any unlock is built for it. Reuse the deployed contract's own
    // locking script so it is at least well-formed hex.
    const extraUtxo = {
      txid: 'cc'.repeat(32),
      outputIndex: 0,
      satoshis: 5000,
      script: contract.getLockingScript(),
    };

    await expect(
      contract.call('claim', [null, null], provider, signer, {
        additionalContractInputs: [extraUtxo],
      }),
    ).rejects.toThrow(/additionalContractInputs is not supported/);
  });
});
