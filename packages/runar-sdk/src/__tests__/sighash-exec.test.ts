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

describe('D25 — a mutate-only SINGLE continuation compiles, validates, and is the default', () => {
  // #123 (F1) used to refuse this mode: the continuation is sized by the
  // caller-chosen `_newAmount`, and SINGLE was thought not to pin it. BIP-143
  // SINGLE hashes the whole same-index output, value included, and the F-024
  // floor (`_newAmount >= extractAmount`) refuses a dust continuation, so the
  // mode is sound (dust refusal: d25-twin-input.test.ts). It is now the
  // DEFAULT for a contract whose continuation methods are all mutate-only.
  const SRC = `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }
  `;

  for (const [label, src] of [['explicit', SRC], ['default', SRC.replace('/** @sighash SINGLE|FORKID */', '')]] as const) {
    it(`${label}: deploy + call is VALID and the preimage sighash byte is 0x43`, async () => {
      const artifact = compileSource(src, 'Counter.runar.ts');
      expect(artifact.abi.methods.find((m) => m.name === 'bump')!.sigHashType).toBe(0x43);
      const provider = new MockProvider('testnet', { enforceFeeFloor: false });
      const deployer = await fundedSigner(provider, DEPLOYER_KEY, 500_000);
      const caller = new LocalSigner(CALLER_KEY);
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, deployer, { satoshis: 50_000 });
      const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
      await contract.call('bump', [], provider, caller, { allowFeeBelowRate: true });
      const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
      expect(contract.state.n).toBe(1n);
      expect(sighashByteOf(preimageFromUnlock(callTx, 0))).toBe(0x43);
      expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    });
  }
});

describe('#123 — ANYONECANPAY (crowdfund-style) method validates through Spend', () => {
  // ALL|ANYONECANPAY|FORKID: only THIS input is signed, so other parties may
  // add inputs freely. D25: in a contract whose continuation methods are all
  // mutate-only the ALL base becomes SINGLE (0xC3), so the pledge commits only
  // its own same-index continuation.
  const SRC = `
    class Fund extends StatefulSmartContract {
      raised: bigint;
      constructor(raised: bigint) { super(raised); this.raised = raised; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public pledge(amount: bigint): void { this.raised = this.raised + amount; }
    }
  `;

  it('deploy + exact-cover call is VALID and the preimage sighash byte is 0xC3', async () => {
    const artifact = compileSource(SRC, 'Fund.runar.ts');
    expect(artifact.abi.methods.find((m) => m.name === 'pledge')!.sigHashType).toBe(0xc3);

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
    expect(sighashByteOf(pre)).toBe(0xc3);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
  });
});

describe('#123 — default (no directive) still validates and uses 0x41', () => {
  // D25: the addOutput sibling keeps the contract on ALL (a contract whose
  // continuation methods are all mutate-only defaults to SINGLE instead).
  const SRC = `
    class Plain extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public bump(): void { this.n = this.n + 1n; }
      public put(): void { this.addOutput(1n, this.n); }
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
