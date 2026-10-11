/**
 * F-247 (CL-BUG-136, MEDIUM/P2): `finalizeCall` broadcasts a 72-byte
 * all-zero placeholder when a declared `sigIndices` slot is left unfilled.
 *
 * `prepareCall` stubs every auto-signed `Sig` param with the `'00'.repeat(72)`
 * placeholder (contract.ts, "// placeholder") and records its arg index in
 * `sigIndices`. `finalizeCall` only overwrites `resolvedArgs[idx]` for the
 * indices actually present in the caller-supplied `signatures` map — nothing
 * checks that `Object.keys(signatures)` covers every entry in
 * `prepared.sigIndices` before the primary unlocking script is assembled and
 * handed to `provider.broadcast()`. A caller who forgets one declared slot
 * (e.g. in a multi-signer flow) therefore gets a tx built with a well-formed
 * but all-zero `OP_PUSHDATA 72-zero-bytes` signature, which is broadcast
 * unconditionally unless the caller opted into `CallOptions.dryRun` (off by
 * default). The one-shot `PreparedCall` consume guard has already marked the
 * call spent by this point, so a real network rejection forces a full rebuild.
 *
 * Fix: `finalizeCall` must refuse — throwing a descriptive error naming the
 * missing sigIndex slot(s) — before assembling/broadcasting anything, whether
 * or not `dryRun` is set.
 *
 * This test deliberately does NOT use MockProvider's always-ack constructor
 * option (which would need an `always-ack-allowlist.json`
 * entry and the allowlist's entry count is ratcheted at its current ceiling —
 * see that file's `$comment`). Instead it hand-rolls a minimal `Provider`
 * whose `broadcast()` acks anything unconditionally, like a real network
 * node that does not pre-validate scripts before accepting a tx — this is
 * explicitly out of that gate's scope (see `always-ack-allowlist.test.ts`'s
 * SCOPE note and its `issue-107-broadcaster-injection.test.ts` precedent). A
 * provider that DOES pre-validate (MockProvider's default) would also reject
 * the placeholder-signed broadcast, but for the wrong reason (script
 * invalidity caught AT broadcast time) — masking whether `finalizeCall`
 * itself refuses BEFORE ever calling `provider.broadcast()`, which is what
 * this fix is about.
 *
 * What this test proves: with `dryRun` NOT set (the default) and a provider
 * that accepts any broadcast without validation, calling `finalizeCall` with
 * an empty `signatures` map for a method with one declared `sigIndices`
 * entry throws — naming the missing index/method — before
 * `provider.broadcast()` is ever reached.
 *
 * What this test does NOT prove: multi-signer (2+ sigIndices) coverage with
 * SOME but not all slots filled — covered logically by the same
 * `missingSigIndices` filter in the fix, but not exercised by a dedicated
 * fixture here — nor does it exercise a real on-chain broadcast.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { Provider } from '../providers/provider.js';
import { txToTransactionData } from '../providers/provider.js';
import type { Transaction, TransactionData, UTXO } from '../types.js';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000007';

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

const SRC = `
  import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
  import type { PubKey, Sig } from 'runar-lang';

  class OwnerBump extends StatefulSmartContract {
    readonly owner: PubKey;
    counter: bigint;
    constructor(owner: PubKey, counter: bigint) {
      super(owner, counter);
      this.owner = owner;
      this.counter = counter;
    }
    public bump(sig: Sig): void {
      assert(checkSig(sig, this.owner));
      this.counter = this.counter + 1n;
    }
  }
`;

/**
 * Delegates every read to an underlying `MockProvider` (so UTXO lookups,
 * fee rate, etc. behave normally) but `broadcast()` acks any tx
 * unconditionally — no script validation — mirroring a real network
 * provider that does not pre-validate before accepting a broadcast. Not a
 * `MockProvider` always-ack usage: a plain hand-rolled `Provider`.
 */
class AckAnythingProvider implements Provider {
  readonly broadcastedTxs: string[] = [];
  constructor(private readonly inner: MockProvider) {}
  getTransaction(txid: string): Promise<TransactionData> { return this.inner.getTransaction(txid); }
  getUtxos(address: string): Promise<UTXO[]> { return this.inner.getUtxos(address); }
  getContractUtxo(scriptHash: string): Promise<UTXO | null> { return this.inner.getContractUtxo(scriptHash); }
  getNetwork(): 'mainnet' | 'testnet' { return this.inner.getNetwork(); }
  getFeeRate(): Promise<number> { return this.inner.getFeeRate(); }
  getRawTransaction(txid: string): Promise<string> { return this.inner.getRawTransaction(txid); }
  async broadcast(tx: Transaction): Promise<string> {
    this.broadcastedTxs.push(tx.toHex());
    const txid = tx.id('hex') as string;
    // Register with the inner mock (no validation) so subsequent
    // getTransaction/getUtxos lookups resolve normally, same as a real
    // provider would once a broadcast is accepted.
    this.inner.addTransaction(txToTransactionData(txid, tx));
    return txid;
  }
}

async function deployOwnerBump() {
  const artifact = compileSource(SRC, 'OwnerBump.runar.ts');
  const mock = new MockProvider('testnet');
  const signer = new LocalSigner(SIGNER_KEY);
  const address = await signer.getAddress();
  const pubKeyHex = await signer.getPublicKey();
  mock.addUtxo(address, {
    txid: SIGNER_KEY.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(pubKeyHex),
  });
  const provider = new AckAnythingProvider(mock);
  const contract = new RunarContract(artifact, [pubKeyHex, 0n]);
  contract.connect(provider, signer);
  await contract.deploy(provider, signer, {});
  return { contract, provider, signer };
}

describe('F-247 — finalizeCall must refuse a missing sigIndices slot instead of broadcasting a placeholder', () => {
  it('finalizeCall with no dryRun and an unfilled declared sigIndex throws instead of broadcasting', async () => {
    const { contract, provider } = await deployOwnerBump();

    const prepared = await contract.prepareCall('bump', [null]);
    expect(prepared.sigIndices).toEqual([0]);

    const broadcastCountBefore = provider.broadcastedTxs.length;

    // Caller forgets the one declared signature slot entirely.
    await expect(contract.finalizeCall(prepared, {})).rejects.toThrow(/sigIndices|signature|slot 0|index 0/i);

    // Must not have reached provider.broadcast() with the all-zero placeholder.
    // (`contract.state` is updated eagerly during `prepareCall` to reflect the
    // locally-computed next state — unrelated to whether finalizeCall actually
    // broadcasts — so it is not a useful signal here; the broadcast count is.)
    expect(provider.broadcastedTxs.length).toBe(broadcastCountBefore);
  });
});
