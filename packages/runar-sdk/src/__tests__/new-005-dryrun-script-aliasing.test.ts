/**
 * NEW-005 regression: a `{ dryRun: true }` call must not corrupt the validation
 * that follows it.
 *
 * Root cause (upstream, @bsv/sdk): `Spend` pushes a script chunk's `data` array
 * onto its stack BY REFERENCE, and `OP_NUM2BIN` mutates its operand in place
 * (`rawnum[rawnum.length - 1] &= 0x7f` in `Spend.js`). A stateful continuation
 * serialises each mutable state field with OP_NUM2BIN, so evaluating a call
 * that writes a NEGATIVE unlocking-script push into state strips the sign bit
 * off that push inside the caller's own `UnlockingScript` object. The damage is
 * invisible to serialisation — `Script.fromBinary` seeds `rawBytesCache` from
 * the original bytes and mutating `chunks[i].data` never invalidates it — so
 * `toHex()` keeps returning the true bytes and nothing wrong is ever broadcast.
 * What breaks is the NEXT in-memory evaluation of the same object: it sees
 * `+34` where the transaction really carries `-34`, the assert fails, and the
 * spend is rejected. A false rejection on a transaction the network accepts.
 *
 * Before the fix: `finalizeCall`'s dry-run evaluated the live
 * `finalTx.inputs[0].unlockingScript`, and `MockProvider.validateBroadcastTx`
 * then evaluated the same, now-corrupted, object and threw.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '1'.repeat(63) + '7';

/**
 * Minimised from fuzzer seed 7777001 (`FuzzStateful96.method4`). The load-
 * bearing detail is `this.prop82 = param92` with a NEGATIVE `param92`: the
 * continuation runs OP_NUM2BIN over a value that is a raw push from the
 * unlocking script.
 */
const SOURCE = `import { StatefulSmartContract, assert, abs, max } from 'runar-lang';

class FuzzStateful96 extends StatefulSmartContract {
  readonly prop22: bigint;
  prop82: bigint;

  constructor(prop22: bigint, prop82: bigint) {
    super(prop22, prop82);
    this.prop22 = prop22;
    this.prop82 = prop82;
  }

  public method4(param92: bigint, param54: bigint): void {
    let merge0: bigint = max(-19n, 83n);
    merge0 = this.prop22;
    assert((merge0 <= abs(this.prop22)));
    this.prop82 = param92;
  }
}`;

const FILE_NAME = 'FuzzStateful96.runar.ts';
const CTOR: unknown[] = [-13n, -60n];
const ARGS: unknown[] = [-34n, 53n];

function compileSource(): RunarArtifact {
  const result = compile(SOURCE, { fileName: FILE_NAME });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

/** Replay one input on the real consensus engine, aliasing nothing. */
function validateSpend(tx: Transaction, inputIdx: number, sourceTx: Transaction): boolean {
  const input = tx.inputs[inputIdx]!;
  const sourceOutput = sourceTx.outputs[0]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: LockingScript.fromHex(sourceOutput.lockingScript.toHex()),
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
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis ?? 0 })),
    unlockingScript: input.unlockingScript!,
    inputIndex: inputIdx,
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
  });
  return spend.validate();
}

/** Captures the LIVE in-flight `Transaction` object `finalizeCall` hands over. */
class CapturingProvider extends MockProvider {
  liveTxs: Transaction[] = [];
  override async broadcast(tx: Transaction): Promise<string> {
    this.liveTxs.push(tx);
    return await super.broadcast(tx);
  }
}

async function deployAndCall(dryRun: boolean): Promise<{
  provider: CapturingProvider;
  deployTx: Transaction;
  callTx: Transaction;
}> {
  const artifact = compileSource();
  const signer = new LocalSigner(SIGNER_KEY);
  const provider = new CapturingProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact, CTOR);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 50_000 });
  await contract.call('method4', ARGS, dryRun ? { dryRun: true } : {});
  const [deployHex, callHex] = provider.getBroadcastedTxs();
  return {
    provider,
    deployTx: Transaction.fromHex(deployHex!),
    callTx: Transaction.fromHex(callHex!),
  };
}

describe('NEW-005: dryRun must not corrupt the validation that follows', () => {
  it('accepts a { dryRun: true } call under MockProvider broadcast validation', async () => {
    // MockProvider validates broadcasts by default; this call must not throw.
    const { deployTx, callTx } = await deployAndCall(true);
    // Second, independent path: the same bytes on a freshly-parsed tx.
    expect(validateSpend(callTx, 0, deployTx)).toBe(true);
  });

  it('produces the same bytes with and without dryRun', async () => {
    const withDry = await deployAndCall(true);
    const withoutDry = await deployAndCall(false);
    expect(withDry.callTx.toHex()).toBe(withoutDry.callTx.toHex());
  });

  it('leaves the live broadcast tx object evaluable after validation', async () => {
    // Pins the provider side: `validateBroadcastTx` must evaluate a private
    // copy, so the caller's own transaction object survives a validated
    // broadcast and can still be replayed on the engine afterwards.
    const { provider, deployTx } = await deployAndCall(true);
    const liveCallTx = provider.liveTxs[1]!;
    expect(validateSpend(liveCallTx, 0, deployTx)).toBe(true);
  });
});
