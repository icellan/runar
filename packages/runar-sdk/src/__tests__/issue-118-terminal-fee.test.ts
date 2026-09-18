/**
 * Issue #118 — terminal transactions can't pay a miner fee.
 *
 * A true terminal method pays out the full contract balance, so fee == 0 and
 * ARC rejects. The covenant asserts its exact output set, so no change output
 * can absorb a fee. CallOptions.fundingUtxos existed in types.ts but was DEAD.
 * Fix: CallOptions.feeUtxo — a plain P2PKH input added to the terminal tx
 * BEFORE the OP_PUSH_TX preimage is computed (so hashPrevouts covers it),
 * consumed entirely as fee (no change output). Signed with fundingSigner ??
 * signer (composes with #134).
 */
import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact, } from 'runar-ir-schema';
import type { UTXO } from '../types.js';

const METHOD_KEY = '00'.repeat(31) + '03';
const FUNDING_KEY = '00'.repeat(31) + '07';

/** Replay one input offline; false instead of throwing on any failure. */
function trySpend(tx: Transaction, inputIdx: number, sourceScriptHex: string, sourceSats: number): boolean {
  try {
    const input = tx.inputs[inputIdx];
    if (!input) return false;
    const spend = new Spend({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: sourceSats,
      lockingScript: LockingScript.fromHex(sourceScriptHex),
      transactionVersion: tx.version,
      otherInputs: tx.inputs
        .filter((_: unknown, i: number) => i !== inputIdx)
        .map((inp, idx: number) => ({
          inputIndex: idx >= inputIdx ? idx + 1 : idx,
          sourceOutputIndex: inp.sourceOutputIndex,
          sourceTXID: inp.sourceTXID!,
          sequence: inp.sequence,
          unlockingScript: undefined as never,
          sourceSatoshis: 0,
          lockingScript: LockingScript.fromHex(''),
        })),
      outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
      unlockingScript: input.unlockingScript,
      inputIndex: inputIdx,
      inputSequence: input.sequence,
      lockTime: tx.lockTime,
    });
    return spend.validate();
  } catch {
    return false;
  }
}

const TRIVIAL_ARTIFACT: RunarArtifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'Escrow',
  asm: '',
  buildTimestamp: '2026-03-02T00:00:00.000Z',
  script: '51', // OP_TRUE — trivial covenant, output side stays exactly as asserted
  abi: { constructor: { params: [] }, methods: [{ name: 'settle', params: [], isPublic: true }] },
};

const CONTRACT_SATS = 50_000;
const FEE_SATS = 5_000;

async function setup() {
  const methodSigner = new LocalSigner(METHOD_KEY);
  // This file's whole subject is a terminal payout that pays fee 0 without
  // `feeUtxo` (the pre-#118 bug this option fixes) — opt out of P1-2's fee
  // floor only; Spend + conservation still run via trySpend()/outputSum().
  const provider = new MockProvider('testnet', { enforceFeeFloor: false });
  // Deploy funding coin under the method signer (locked to method signer).
  const methodAddr = await methodSigner.getAddress();
  provider.addUtxo(methodAddr, {
    txid: 'cc'.repeat(32),
    outputIndex: 0,
    satoshis: 200_000,
    script: buildP2PKHScript(await methodSigner.getPublicKey()),
  });
  const contract = new RunarContract(TRIVIAL_ARTIFACT, []);
  await contract.deploy(provider, methodSigner, { satoshis: CONTRACT_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { methodSigner, provider, contract, deployTx };
}

function outputSum(tx: Transaction): number {
  return tx.outputs.reduce((s, o) => s + (o.satoshis ?? 0), 0);
}

describe('#118 — terminal call pays a miner fee via CallOptions.feeUtxo', () => {
  const PAYOUT = '76a914' + 'bb'.repeat(20) + '88ac';

  it('without feeUtxo, a full-balance payout leaves fee = 0 (the bug)', async () => {
    const { methodSigner, provider, contract } = await setup();
    await contract.call('settle', [], provider, methodSigner, {
      terminalOutputs: [{ scriptHex: PAYOUT, satoshis: CONTRACT_SATS }],
    });
    const termTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(termTx.inputs.length).toBe(1); // only the contract input
    // inputs = CONTRACT_SATS, outputs = CONTRACT_SATS => fee 0
    expect(CONTRACT_SATS - outputSum(termTx)).toBe(0);
  });

  it('with feeUtxo (signed by fundingSigner), all inputs are VALID and fee > 0', async () => {
    const { methodSigner, provider, contract, deployTx } = await setup();
    const fundingSigner = new LocalSigner(FUNDING_KEY);
    const feeScript = buildP2PKHScript(await fundingSigner.getPublicKey());
    const feeUtxo: UTXO = { txid: 'ee'.repeat(32), outputIndex: 1, satoshis: FEE_SATS, script: feeScript };
    // M-1: register the fee coin so MockProvider can run `Spend` over input 1
    // and evaluate conservation over the whole tx. Unregistered, it silently
    // switched off conservation as well as the fee floor this file opts out of.
    provider.addUtxo('fee-funder', feeUtxo);

    await contract.call('settle', [], provider, methodSigner, {
      terminalOutputs: [{ scriptHex: PAYOUT, satoshis: CONTRACT_SATS }],
      feeUtxo,
      fundingSigner,
    });
    const termTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    expect(termTx.inputs.length).toBe(2); // contract + fee input
    // The covenant output side is untouched: still exactly the payout.
    expect(termTx.outputs.length).toBe(1);
    expect(outputSum(termTx)).toBe(CONTRACT_SATS);

    // Input 0: the OP_TRUE contract input (source = deploy output 0).
    expect(trySpend(termTx, 0, deployTx.outputs[0]!.lockingScript!.toHex(), CONTRACT_SATS)).toBe(true);
    // Input 1: the P2PKH fee input, signed by fundingSigner (#118 + #134).
    expect(trySpend(termTx, 1, feeScript, FEE_SATS)).toBe(true);

    // fee = sum(inputs) - sum(outputs) > 0
    const fee = (CONTRACT_SATS + FEE_SATS) - outputSum(termTx);
    expect(fee).toBe(FEE_SATS);
    expect(fee).toBeGreaterThan(0);
  });
});
