/**
 * Regression test for GitHub issue #132.
 *
 * `getSubscriptForSigning` already byte-walks the real `_codeScript` via
 * `findCodesepOffsets` when the contract is chain-loaded (#42/#47). But its
 * sibling `computeOpPushTxWithCodeSep` still derived the OP_CODESEPARATOR byte
 * offset from `adjustCodeSepOffset`, which recomputes the shift from the
 * in-memory `constructorArgs`. When those args don't reflect the bytes baked
 * into `_codeScript` (the restore path before #119, or any caller that builds a
 * RunarContract with a real `_codeScript` but wrong/placeholder args), the
 * derived offset is wrong and the OP_PUSH_TX signature is computed over the
 * wrong scriptCode.
 *
 * Fix: when `_codeScript` is available, byte-walk it for the true offset,
 * mirroring `getSubscriptForSigning`; keep the `adjustCodeSepOffset` template
 * path only as the deploy-time fallback.
 *
 * This is verified INDEPENDENTLY of #119: the offset used by
 * `computeOpPushTxWithCodeSep` must not depend on `constructorArgs` once a real
 * `_codeScript` is present. (Fixing #119 also makes `adjustCodeSepOffset`
 * correct, but the byte-walk is the robust fix and must stand on its own.)
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

// tag is non-trivial so its 3-byte script push is larger than the 1-byte OP_0
// placeholder — this expansion shifts method index 1's OP_CODESEPARATOR.
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

describe('#132 — computeOpPushTxWithCodeSep byte-walks the real code script', () => {
  it('OP_PUSH_TX offset is independent of constructorArgs when _codeScript is set', async () => {
    const { artifact, provider, signer, deployTx, utxo } = await deployRestorable();

    // A real spending tx for method index 1 (bumpTwo) to feed the preimage.
    const txSource = RunarContract.fromUtxo(artifact, utxo);
    txSource.connect(provider, signer);
    await txSource.call('bumpTwo', [], provider, signer);
    const spendTx = Transaction.fromHex(provider.getBroadcastedTxs().at(-1)!);

    // Contract A: real restored args (paramIndex 0 = tag = 500n).
    const contractReal = RunarContract.fromUtxo(artifact, utxo);
    // Contract B: same real _codeScript, but forced placeholder args, exactly
    // the pre-#119 restore condition. adjustCodeSepOffset would compute a zero
    // shift for the tag slot and pick the wrong OP_CODESEPARATOR offset.
    const contractPlaceholder = RunarContract.fromUtxo(artifact, utxo);
    (contractPlaceholder as unknown as { constructorArgs: unknown[] }).constructorArgs = [0n, 0n];

    const real = contractReal.computeOpPushTxWithCodeSep(spendTx, 0, utxo.script, utxo.satoshis, 1);
    const placeholder = contractPlaceholder.computeOpPushTxWithCodeSep(spendTx, 0, utxo.script, utxo.satoshis, 1);

    // The BIP-143 preimage embeds the scriptCode trimmed at the codesep offset,
    // so equal preimages <=> equal offsets <=> offset independent of the args.
    expect(placeholder.preimageHex).toBe(real.preimageHex);
    expect(placeholder.sigHex).toBe(real.sigHex);
  });

  it('composition: restore via fromUtxo + call bumpTwo (index 1) → spend validates', async () => {
    const { artifact, provider, signer, deployTx, utxo } = await deployRestorable();

    const restored = RunarContract.fromUtxo(artifact, utxo);
    restored.connect(provider, signer);
    await restored.call('bumpTwo', [], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs().at(-1)!);

    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});
