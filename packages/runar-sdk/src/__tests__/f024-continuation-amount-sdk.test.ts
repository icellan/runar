/**
 * F-024 (R14) — the SDK's ANF interpreter must evaluate `continuationAmount()`
 * and `extractAmount(txPreimage)` with the call's real values.
 *
 * `RunarContract.call` derives the post-call state with the ANF interpreter
 * BEFORE the transaction exists, then the covenant re-derives it on-chain and
 * compares hashOutputs. If the interpreter reads `continuationAmount()` (the
 * injected `_newAmount`) or `extractAmount(txPreimage)` as anything other than
 * the continuation's satoshis and the spent UTXO's satoshis, a contract whose
 * state depends on them computes a different state off-chain than on-chain and
 * every call is refused.
 *
 * What this proves: for a contract that stores the deposit
 * (`continuationAmount() - extractAmount(this.txPreimage)`) in state, the TS SDK
 * computes the same state the script does — the call is accepted by
 * MockProvider's `@bsv/sdk` Spend validation and the tracked state holds the
 * real delta. What it does NOT prove: the other six SDKs (their own suites).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { MockProvider } from '../providers/mock.js';
import { RunarContract } from '../contract.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { computeNewState } from '../anf-interpreter.js';
import type { RunarArtifact } from 'runar-ir-schema';

const PRIV = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725';

const TIP = `
class Tip extends StatefulSmartContract {
  lastDeposit: bigint;
  constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }
  public deposit() {
    this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);
  }
}
`;

function artifact(): RunarArtifact {
  const r = compile(TIP, { fileName: 'Tip.runar.ts' });
  if (!r.success || !r.artifact) throw new Error(r.diagnostics.map((d) => d.message).join('; '));
  return r.artifact as unknown as RunarArtifact;
}

describe('F-024 SDK interpreter: continuationAmount() / extractAmount()', () => {
  it('a state value derived from both round-trips through a validated spend', async () => {
    const signer = new LocalSigner(PRIV);
    const provider = new MockProvider();
    provider.addUtxo(await signer.getAddress(), {
      txid: 'ab'.repeat(32), outputIndex: 0, satoshis: 500_000, script: buildP2PKHScript(await signer.getPublicKey()),
    });
    const contract = new RunarContract(artifact(), [0n]);
    contract.connect(provider, signer);
    await contract.deploy({ satoshis: 10_000 });
    await contract.call('deposit', [], { satoshis: 12_500 });
    expect(contract.state).toEqual({ lastDeposit: 2_500n });
    expect(contract.getUtxo()!.satoshis).toBe(12_500);
  });

  it('computeNewState reads both from the caller-supplied _newAmount / input amount', () => {
    const a = artifact();
    const out = computeNewState(a.anf!, 'deposit', { lastDeposit: 0n }, { _newAmount: 7_000n }, [], { inputAmount: 5_000n });
    expect(out).toEqual({ lastDeposit: 2_000n });
  });
});
