/**
 * Issue #123 — end-to-end execution proof for per-method @sighash modes.
 *
 * Deploys + calls a stateful covenant whose public method declares a non-default
 * sighash mode, then replays the spend through @bsv/sdk's Spend interpreter
 * (the same harness as issues #99/#100/#116). The on-chain OP_PUSH_TX binding
 * must derive a signature under the declared flag byte, and the SDK must build
 * the BIP-143 preimage under the matching scope, or Spend rejects.
 *
 * Uses the #116 exact-cover trick (unfunded caller -> change clamps to 0) so the
 * continuation is the SOLE output at index 0, matching the covenant input at
 * index 0 — the same-index single output SINGLE requires.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, UnlockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const CALLER_KEY = '0000000000000000000000000000000000000000000000000000000000000004';

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

/** Recover the BIP-143 preimage (largest data push) from a covenant input's unlocking script. */
function preimageFromUnlock(tx: Transaction, inputIdx: number): number[] {
  const hex = tx.inputs[inputIdx]!.unlockingScript!.toHex();
  const chunks = UnlockingScript.fromHex(hex).chunks;
  let biggest: number[] = [];
  for (const c of chunks) {
    if (c.data && c.data.length > biggest.length) biggest = c.data;
  }
  return biggest;
}

/** Last 4 preimage bytes = sighashType (LE uint32) -> the flag byte is the first of those. */
function sighashByteOf(preimage: number[]): number {
  return preimage[preimage.length - 4]!;
}

describe('#123 (F1) — mutate-only SINGLE continuation is a compile REJECT, not a spend', () => {
  // This flow used to "deploy + exact-cover call + validate through Spend", but
  // the continuation output was sized by the caller-chosen `_newAmount`, which
  // BIP-143 SINGLE never pins. That made it value-skimmable: call bump with
  // `_newAmount` = dust, drive change to 0, and APPEND a draining output — the
  // covenant + OP_PUSH_TX binding still validate (they only see the same-index
  // continuation) while the protected funds are swept away. The compiler now
  // rejects the unsound mode up front, so there is no artifact to deploy.
  const SRC = `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }
  `;

  it('the compiler refuses to emit an artifact for the skimmable SINGLE mode', () => {
    expect(() => compileSource(SRC, 'Counter.runar.ts')).toThrow(
      /mutate-only SINGLE continuation is unsound|sized by the caller-chosen _newAmount/,
    );
  });
});

describe('#123 — ANYONECANPAY (crowdfund-style) method validates through Spend', () => {
  // ALL|ANYONECANPAY|FORKID = 0xC1: outputs are still committed (ALL base), but
  // only THIS input is signed, so other parties may add inputs freely. The
  // method reads no cross-input field, so the mode is sound.
  const SRC = `
    class Fund extends StatefulSmartContract {
      raised: bigint;
      constructor(raised: bigint) { super(raised); this.raised = raised; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public pledge(amount: bigint): void { this.raised = this.raised + amount; }
    }
  `;

  it('deploy + exact-cover call is VALID and the preimage sighash byte is 0xC1', async () => {
    const artifact = compileSource(SRC, 'Fund.runar.ts');
    expect(artifact.abi.methods.find((m) => m.name === 'pledge')!.sigHashType).toBe(0xc1);

    // #116 exact-cover trick deliberately drives change (and therefore fee)
    // to 0 — opt out of P1-2's fee floor, not broadcast validation itself
    // (Spend + conservation still run below via validateSpend()).
    const provider = new MockProvider('testnet', { enforceFeeFloor: false });
    const deployer = await fundedSigner(provider, DEPLOYER_KEY, 500_000);
    const caller = new LocalSigner(CALLER_KEY);

    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, deployer, { satoshis: 50_000 });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('pledge', [7n], provider, caller, { allowFeeBelowRate: true });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(contract.state.raised).toBe(7n);
    const pre = preimageFromUnlock(callTx, 0);
    expect(sighashByteOf(pre)).toBe(0xc1);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});

describe('#123 — default (no directive) still validates and uses 0x41', () => {
  const SRC = `
    class Plain extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public bump(): void { this.n = this.n + 1n; }
    }
  `;
  it('unchanged behaviour: preimage sighash byte is 0x41', async () => {
    const artifact = compileSource(SRC, 'Plain.runar.ts');
    expect(artifact.abi.methods.find((m) => m.name === 'bump')!.sigHashType).toBeUndefined();

    // #116 exact-cover trick deliberately drives change (and therefore fee)
    // to 0 — opt out of P1-2's fee floor, not broadcast validation itself
    // (Spend + conservation still run below via validateSpend()).
    const provider = new MockProvider('testnet', { enforceFeeFloor: false });
    const deployer = await fundedSigner(provider, DEPLOYER_KEY, 500_000);
    const caller = new LocalSigner(CALLER_KEY);
    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, deployer, { satoshis: 50_000 });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
    await contract.call('bump', [], provider, caller, { allowFeeBelowRate: true });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    const pre = preimageFromUnlock(callTx, 0);
    expect(sighashByteOf(pre)).toBe(0x41);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});
