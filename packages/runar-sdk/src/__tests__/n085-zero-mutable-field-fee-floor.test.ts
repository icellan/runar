/**
 * N-085: a zero-mutable-field `StatefulSmartContract` call underpaid
 * MockProvider's 100 sat/KB fee floor.
 *
 * `AllReadonlyCleanstack` (same fixture `examples/ts/all-readonly-cleanstack/`
 * uses for the issue #44 regression) has ZERO mutable fields, so its
 * `stateFields` is empty and `prepareCall`'s `isStateful` is `false` — even
 * though the contract IS `parentStateful` (parentClass ===
 * 'StatefulSmartContract') and still auto-injects `checkPreimage` /
 * OP_CODESEPARATOR at method entry. That routed the call through
 * `prepareCall`'s "stateless" branch (`needsOpPushTx`), which never recomputes
 * fee/change from the REAL (final) unlocking script the way the `isStateful`
 * branch does.
 *
 * The injected OP_CODESEPARATOR sits right at method entry, so the BIP-143
 * scriptCode (everything after it) is almost the WHOLE locking script —
 * far bigger than the short placeholder preimage (`'00'.repeat(181)`) the
 * earlier sizing pass assumed. The real unlocking script ends up hundreds of
 * bytes bigger than what fee/change were computed against, so the broadcast
 * tx paid far less than the fee its own (now larger) byte size requires.
 *
 * What this test proves: a zero-mutable-field StatefulSmartContract's call()
 * is accepted by MockProvider with the fee floor enforced (default) — i.e.
 * the actual broadcast tx pays >= ceil(txSize * feeRate / 1000).
 *
 * What this test does NOT prove: the same fix in the other six SDKs (Go,
 * Rust, Python, Zig, Ruby, Java) — this item is scoped to sdk:ts. It also
 * does not prove anything about continuation-bearing (non-empty stateFields)
 * stateful calls, which already take the `isStateful` branch and were
 * unaffected by this bug.
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

describe('N-085 — zero-mutable-field StatefulSmartContract call pays the fee floor', () => {
  it('claim() on AllReadonlyCleanstack is accepted by MockProvider with the fee floor enforced', async () => {
    const source = fs.readFileSync(
      path.join(__dirname, '../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts'),
      'utf8',
    );
    const artifact = compileSource(source, 'AllReadonlyCleanstack.runar.ts');

    // Sanity on the premise: zero mutable state fields, but still a real
    // StatefulSmartContract (auto-injects checkPreimage).
    expect(artifact.parentClass).toBe('StatefulSmartContract');
    expect(artifact.stateFields ?? []).toEqual([]);

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();

    const provider = new MockProvider(); // fee floor enforced by default (P1-2)
    provider.addUtxo(address, {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: buildP2PKHScript(pubKey),
    });

    const contract = new RunarContract(artifact, [pubKey]);
    await contract.deploy(provider, signer, { satoshis: 5000, changeAddress: address });

    // MockProvider.broadcast() (default `enforceFeeFloor: true`, P1-2)
    // computes `actualFee = totalKnownIn - totalOut` from the ACTUAL
    // broadcast tx and throws unless it is >= `ceil(txSize * feeRate /
    // 1000)` — so a successful call() here (no throw) IS the fee-floor
    // assertion, computed against the real tx this registers, not an
    // estimate.
    const { txid } = await contract.call('claim', [null, null], provider, signer);
    expect(txid).toMatch(/^[0-9a-f]{64}$/);
  });
});
