/**
 * N-227 Part 2, retargeted by N-258 (user decision R99): a call that spends
 * `additionalContractInputs` on a path with NO real per-input unlock builder
 * must fail closed rather than broadcast an invalid tx.
 *
 * N-227 originally pinned this on a zero-mutable-field StatefulSmartContract
 * (`AllReadonlyCleanstack`). N-258 gave that path real per-input unlocks
 * (its own OP_PUSH_TX preimage + signed Sig for every extra input — see
 * n258-zero-mutable-field-merge.test.ts, which proves the merge is Spend-valid),
 * and narrowed the guard to the paths that still only have the SIZING
 * placeholder: a plain `SmartContract` (no auto-injected checkPreimage, so no
 * per-input preimage to build) or a caller-supplied preimage. This test pins
 * the plain-`SmartContract` case, so the fail-closed invariant stays covered.
 *
 * What this test proves: `RunarContract.call()` throws, and broadcasts
 * nothing, when `additionalContractInputs` is set on a plain SmartContract
 * call, instead of shipping placeholder-unlock bytes.
 *
 * What this test does NOT prove: the caller-supplied-preimage case, or the
 * same guard in Go/Rust/Python/Ruby (each tier pins its own).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

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

describe('N-227 Part 2 — a merge with no per-input unlock builder is refused', () => {
  it('a plain SmartContract call with additionalContractInputs throws instead of shipping a placeholder unlock', async () => {
    const source = `import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class P2PKOnly extends SmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public unlock(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
`;
    const artifact = compileSource(source, 'P2PKOnly.runar.ts');
    expect(artifact.parentClass).toBe('SmartContract');

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const lockingHex = new RunarContract(artifact, [pubKey]).getLockingScript();
    const primary = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: lockingHex };
    // Both contract outpoints are KNOWN to the provider, so a rejection can
    // only come from the guard, not from MockProvider's unknown-input check.
    const extraUtxo = { txid: 'cc'.repeat(32), outputIndex: 1, satoshis: 7000, script: lockingHex };

    const provider = new MockProvider();
    provider.addUtxo(address, {
      txid: 'bb'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: buildP2PKHScript(pubKey),
    });
    provider.addContractUtxo(lockingHex, primary);
    provider.addContractUtxo(lockingHex + ':extra', extraUtxo);

    const contract = RunarContract.fromUtxo(artifact, primary);
    await expect(
      contract.call('unlock', [null], provider, signer, {
        additionalContractInputs: [extraUtxo],
      }),
    ).rejects.toThrow(/additionalContractInputs is not supported/);
    expect(provider.getBroadcastedTxs().length).toBe(0);
  });
});
