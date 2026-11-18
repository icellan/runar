/**
 * #197 — `call()` with raw / data outputs interleaved with MORE THAN ONE state
 * continuation: `addOutput(a); addRawOutput(fee, payee); addOutput(b)`.
 *
 * Every positive case goes through the validating MockProvider (default-ON),
 * which replays each broadcast through @bsv/sdk's Spend (real OP_PUSH_TX +
 * hashOutputs binding) and is additionally re-checked with Spend here. An
 * output-order or tracked-index mistake strands the funds, so each
 * continuation is also SPENT in a follow-up call.
 *
 * Proves: the tx is built from the interpreter's source order for any mix of
 * state / raw / data outputs, each continuation carries its OWN state, the
 * result reports every continuation (outputIndex, satoshis, state),
 * `currentUtxo` follows the index-first continuation (never a script
 * equality match), zero continuations clear `currentUtxo`, and both
 * continuations are spendable. Does not prove: the other six SDKs (they keep
 * their fail-closed refusal) or a broadcast on a real node (see
 * integration/ts/interleaved-continuations.test.ts).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

const KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const PAYEE = '76a914' + 'ab'.repeat(20) + '88ac';

const SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class Splitter extends StatefulSmartContract {
  owner: PubKey;
  count: bigint;

  constructor(owner: PubKey, count: bigint) {
    super(owner, count);
    this.owner = owner;
    this.count = count;
  }

  public split(sig: Sig, payee: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addOutput(1000n, this.owner, this.count + 1n);
    this.addRawOutput(546n, payee);
    this.addOutput(1000n, this.owner, this.count + 100n);
  }

  public splitData(sig: Sig, memo: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addOutput(1000n, this.owner, this.count + 1n);
    this.addDataOutput(0n, memo);
    this.addOutput(1000n, this.owner, this.count + 100n);
  }

  public rawFirst(sig: Sig, payee: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addRawOutput(546n, payee);
    this.addOutput(1000n, this.owner, this.count + 1n);
  }

  public payOnly(sig: Sig, payee: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addRawOutput(2000n, payee);
  }
}
`;

const artifact: RunarArtifact = (() => {
  const r = compile(SOURCE, { fileName: 'Splitter.runar.ts' });
  if (!r.artifact) throw new Error(`compile failed: ${JSON.stringify(r.diagnostics)}`);
  return r.artifact;
})();

async function setup(count = 0n) {
  const provider = new MockProvider('testnet');
  const signer = new LocalSigner(KEY);
  const pub = await signer.getPublicKey();
  provider.addUtxo(await signer.getAddress(), {
    txid: KEY.slice(0, 64), outputIndex: 0, satoshis: 500_000, script: buildP2PKHScript(pub),
  });
  const contract = new RunarContract(artifact, [pub, count]);
  await contract.deploy(provider, signer, { satoshis: 5000 });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, signer, pub, contract, deployTx };
}

/** Locking script of the contract in a given `count`, built independently of the call. */
function lockFor(pub: string, count: bigint): string {
  const c = new RunarContract(artifact, [pub, count]);
  return c.getLockingScript();
}

function spends(tx: Transaction, source: Transaction, srcIdx: number, inputIdx = 0): boolean {
  const inp = tx.inputs[inputIdx]!;
  const out = source.outputs[srcIdx]!;
  return !!new Spend({
    sourceTXID: inp.sourceTXID!, sourceOutputIndex: inp.sourceOutputIndex,
    sourceSatoshis: out.satoshis!, lockingScript: out.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs.filter((_, i) => i !== inputIdx),
    outputs: tx.outputs, inputIndex: inputIdx,
    unlockingScript: inp.unlockingScript!, inputSequence: inp.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
  }).validate();
}

describe('#197 addOutput; addRawOutput; addOutput', () => {
  it('is accepted, in source order, and reports BOTH continuations with their own state', async () => {
    const { provider, signer, pub, contract, deployTx } = await setup(0n);
    const result = await contract.call('split', [null, PAYEE], provider, signer);

    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    const a = lockFor(pub, 1n);
    const b = lockFor(pub, 100n);
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(a);
    expect(callTx.outputs[0]!.satoshis).toBe(1000);
    expect(callTx.outputs[1]!.lockingScript.toHex()).toBe(PAYEE);
    expect(callTx.outputs[1]!.satoshis).toBe(546);
    expect(callTx.outputs[2]!.lockingScript.toHex()).toBe(b);
    expect(callTx.outputs[2]!.satoshis).toBe(1000);
    expect(spends(callTx, deployTx, 0)).toBe(true);

    expect(result.continuations).toEqual([
      { outputIndex: 0, satoshis: 1000, state: { owner: pub, count: 1n } },
      { outputIndex: 2, satoshis: 1000, state: { owner: pub, count: 100n } },
    ]);
    // Tracked = index-ordered first; the object's state matches the tracked UTXO.
    expect(contract.currentUtxo).toMatchObject({ txid: result.txid, outputIndex: 0, satoshis: 1000, script: a });
    expect(contract.state.count).toBe(1n);
  });

  it('NEITHER continuation is stranded: both are spent in follow-up calls (Spend-validated)', async () => {
    const { provider, signer, pub, contract } = await setup(0n);
    const { txid, continuations } = await contract.call('split', [null, PAYEE], provider, signer);
    const parent = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    // Continuation 0: through the tracked contract itself.
    const second = RunarContract.fromUtxo(artifact, {
      txid, outputIndex: continuations![1]!.outputIndex, satoshis: continuations![1]!.satoshis,
      script: lockFor(pub, 100n),
    });
    second.connect(provider, signer);
    expect(second.state.count).toBe(100n);

    await contract.call('split', [null, PAYEE], provider, signer); // spends output 0 (count 1)
    expect(contract.state.count).toBe(2n);
    const afterFirst = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    expect(spends(afterFirst, parent, 0)).toBe(true);

    // Continuation 1 (output index 2): an independent contract object spends it.
    await second.call('rawFirst', [null, PAYEE], provider, signer);
    const afterSecond = Transaction.fromHex(provider.getBroadcastedTxs()[3]!);
    expect(spends(afterSecond, parent, 2)).toBe(true);
    expect(second.state.count).toBe(101n);
  });

  it('a data output sits AFTER every state/raw output wherever addDataOutput is written: [a][b][data]', async () => {
    const { provider, signer, pub, contract, deployTx } = await setup(0n);
    const memo = '6a04deadbeef';
    const result = await contract.call('splitData', [null, memo], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(lockFor(pub, 1n));
    expect(callTx.outputs[1]!.lockingScript.toHex()).toBe(lockFor(pub, 100n));
    expect(callTx.outputs[2]!.lockingScript.toHex()).toBe(memo);
    expect(spends(callTx, deployTx, 0)).toBe(true);
    expect(result.continuations!.map((c) => c.outputIndex)).toEqual([0, 1]);
  });
});

describe('#197 currentUtxo is set by output INDEX, never by script equality', () => {
  it('a raw output byte-identical to the continuation script ahead of it does not capture the tracking', async () => {
    const { provider, signer, pub, contract, deployTx } = await setup(0n);
    // rawFirst: [raw(546, payee)][state(1000, count+1)]. Make payee EQUAL the
    // continuation script: a findIndex-by-script would pick output 0 (the raw
    // output) and the next spend would be built against the wrong UTXO.
    const sameAsContinuation = lockFor(pub, 1n);
    const result = await contract.call('rawFirst', [null, sameAsContinuation], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(sameAsContinuation);
    expect(callTx.outputs[1]!.lockingScript.toHex()).toBe(sameAsContinuation);
    expect(spends(callTx, deployTx, 0)).toBe(true);

    expect(result.continuations).toEqual([{ outputIndex: 1, satoshis: 1000, state: { owner: pub, count: 1n } }]);
    expect(contract.currentUtxo!.outputIndex).toBe(1);
    expect(contract.currentUtxo!.satoshis).toBe(1000);
    // and the tracked UTXO is really spendable
    await contract.call('rawFirst', [null, PAYEE], provider, signer);
    expect(contract.state.count).toBe(2n);
  });

  it('a call that emits NO continuation clears currentUtxo (it must not fall back to a raw output)', async () => {
    const { provider, signer, contract, deployTx } = await setup(0n);
    const result = await contract.call('payOnly', [null, PAYEE], provider, signer);
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(PAYEE);
    expect(spends(callTx, deployTx, 0)).toBe(true);
    expect(result.continuations).toEqual([]);
    expect(contract.currentUtxo).toBeNull();
    expect(contract.state.count).toBe(0n);
  });
});

describe('#197 refuses ambiguous input instead of blending it', () => {
  it('newState with two continuations is refused (which continuation would it override?)', async () => {
    const { provider, signer, contract } = await setup(0n);
    await expect(
      contract.call('split', [null, PAYEE], provider, signer, { newState: { count: 9n } }),
    ).rejects.toThrow(/2 state continuations/);
    expect(contract.state.count).toBe(0n);
  });

  it('options.outputs alongside interpreter-derived raw outputs is refused', async () => {
    const { provider, signer, pub, contract } = await setup(0n);
    await expect(
      contract.call('split', [null, PAYEE], provider, signer, {
        outputs: [{ satoshis: 1000, state: { owner: pub, count: 1n } }],
      }),
    ).rejects.toThrow(/outputs/);
  });
});
