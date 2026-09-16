/**
 * Regression test for GitHub issue #119.
 *
 * `RunarContract.fromUtxo` (and `fromTxId`, which delegates to it) filled the
 * constructor argument list with `0n` placeholders instead of parsing the real
 * values baked into the deployed locking script. Every restored contract then
 * operated on zeros:
 *   - the ANF interpreter computed the wrong state continuation (readonly ctor
 *     params feed the continuation formula — see contract.ts ~873), and
 *   - `adjustCodeSepOffset` computed a zero shift, so the OP_CODESEPARATOR /
 *     OP_PUSH_TX offset was wrong for methods after a ctor slot.
 *
 * Fix: `restoreConstructorArgs` parses the deployed script via
 * `extractConstructorArgs` and orders the values by ABI param (paramIndex).
 *
 * `Restorable` carries a readonly ctor slot (`tag`) whose value participates in
 * both public methods' continuation formulas, so a wrong `tag` makes the spend
 * unspendable.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
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

async function setupWallet(provider: MockProvider, privKey: string, satoshis: number) {
  const signer = new LocalSigner(privKey);
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: privKey.slice(0, 64),
    outputIndex: 0,
    satoshis,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  return { signer };
}

// Copied VERBATIM from issues-99-100-stateful-exec.test.ts.
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

const SRC = `
  class Restorable extends StatefulSmartContract {
    readonly tag: bigint;
    count: bigint;
    constructor(tag: bigint, count: bigint) { super(tag, count); this.tag = tag; this.count = count; }
    public bump(): void { this.count = this.count + this.tag; }
    public bumpTwo(): void { this.count = this.count + this.tag + this.tag; }
  }
`;

const TAG = 500n;
const COUNT = 10n;

async function deployRestorable() {
  const artifact = compileSource(SRC, 'Restorable.runar.ts');
  const provider = new MockProvider('testnet');
  const { signer } = await setupWallet(provider, SIGNER_KEY, 500_000);
  const contract = new RunarContract(artifact, [TAG, COUNT]);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  const out = deployTx.outputs[0]!;
  const utxo = {
    txid: deployTx.id('hex') as string,
    outputIndex: 0,
    satoshis: out.satoshis!,
    script: out.lockingScript.toHex(),
  };
  // M-1: `utxo.txid` is the deploy tx's REAL txid, whereas `broadcast()`
  // registered the deploy tx's outputs under MockProvider's deterministic
  // FAKE txid — so the outpoint the restored contract spends was unknown to
  // the provider, and the call broadcast below skipped both value
  // conservation and the fee floor. Register it explicitly so the broadcast
  // is actually validated, not merely acked.
  provider.addUtxo('restored-contract', utxo);
  return { artifact, provider, signer, deployTx, utxo };
}

describe('#119 — fromUtxo restores real constructor args from the deployed script', () => {
  it('restores the readonly ctor slot value (not a 0n placeholder)', async () => {
    const { artifact, utxo } = await deployRestorable();

    const restored = RunarContract.fromUtxo(artifact, utxo);
    const args = (restored as unknown as { constructorArgs: unknown[] }).constructorArgs;

    // paramIndex 0 = readonly `tag`, baked into the code via a constructor slot.
    expect(args[0]).toBe(TAG);
    // mutable state `count` restored from the OP_RETURN state section.
    expect(restored.state.count).toBe(COUNT);
  });

  it('restored contract round-trips: bump (index 0) spend validates', async () => {
    const { artifact, provider, signer, deployTx, utxo } = await deployRestorable();

    const restored = RunarContract.fromUtxo(artifact, utxo);
    restored.connect(provider, signer);
    await restored.call('bump', [], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs().at(-1)!);

    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });

  it('restored contract round-trips: bumpTwo (index 1, codesep after ctor slot) spend validates', async () => {
    const { artifact, provider, signer, deployTx, utxo } = await deployRestorable();

    const restored = RunarContract.fromUtxo(artifact, utxo);
    restored.connect(provider, signer);
    await restored.call('bumpTwo', [], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs().at(-1)!);

    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});
