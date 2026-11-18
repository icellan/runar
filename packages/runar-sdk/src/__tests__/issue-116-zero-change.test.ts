/**
 * Issue #116 — the stateful continuation hashes a change output
 * unconditionally, but the SDK's buildCallTransaction OMITS the change output
 * when `change <= 0` (and passes `_changeAmount = 0`). So an exact-cover call
 * (funding inputs == outputs + fee, change 0) can never validate: the script
 * commits to a change output the SDK never built.
 *
 * Repro: call a state-mutating method with NO funding inputs, keeping the full
 * contract value in the continuation output. `change = totalInput - outputs -
 * fee` clamps to 0, so the SDK emits only the continuation output. Today the
 * script still folds `buildChangeOutput(pkh, 0)` into the hashed output set →
 * INVALID. The fix gates the change segment on `_changeAmount != 0` so the
 * hashed set matches the SDK at the zero boundary → VALID.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// Funded deployer + an unfunded caller (so the call has no funding UTXOs and
// the continuation keeps the full contract value → change clamps to 0).
const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const CALLER_KEY = '0000000000000000000000000000000000000000000000000000000000000004';

const SRC = `
  class Counter extends StatefulSmartContract {
    n: bigint;
    constructor(n: bigint) { super(n); this.n = n; }
    public bump(): void { this.n = this.n + 1n; }
  }
`;

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

async function fundedSigner(provider: MockProvider, privKey: string, satoshis: number) {
  const signer = new LocalSigner(privKey);
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: privKey.slice(0, 64),
    outputIndex: 0,
    satoshis,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  return signer;
}

function validateSpend(tx: Transaction, inputIdx: number, sourceTx: Transaction, sourceOutputIdx: number): boolean {
  const input = tx.inputs[inputIdx]!;
  const sourceOutput = sourceTx.outputs[sourceOutputIdx]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp: { sourceOutputIndex: number; sourceTXID?: string; sequence?: number }, idx: number) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: tx.outputs.map((o: { lockingScript: unknown; satoshis?: number }) => ({
      lockingScript: o.lockingScript,
      satoshis: o.satoshis,
    })),
    unlockingScript: input.unlockingScript,
    inputIndex: inputIdx,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });
  return spend.validate();
}

describe('#116 — exact-cover call (change 0) omits the change output', () => {
  it('a call with no change validates (script must not demand a change output)', async () => {
    const artifact = compileSource(SRC, 'Counter.runar.ts');
    // The whole point of this test is a change-clamps-to-0 (fee 0) call —
    // opt out of P1-2's fee floor only; Spend + conservation still run via
    // validateSpend() below.
    const provider = new MockProvider('testnet', { enforceFeeFloor: false });
    const deployer = await fundedSigner(provider, DEPLOYER_KEY, 500_000);
    const caller = new LocalSigner(CALLER_KEY); // deliberately unfunded

    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, deployer, { satoshis: 50_000 });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    // No funding UTXOs for `caller` → the continuation keeps the full contract
    // value and `change` clamps to 0, so the SDK emits only the continuation
    // output (no change output).
    await contract.call('bump', [], provider, caller, { allowFeeBelowRate: true });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // Sanity: only the single continuation output — no change output.
    expect(callTx.outputs.length).toBe(1);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});
