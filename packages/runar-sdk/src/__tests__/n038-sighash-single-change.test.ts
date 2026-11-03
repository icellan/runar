/**
 * N-038 — a stateful `@sighash SINGLE|FORKID` method with one explicit
 * addOutput, called through the TS SDK by a FUNDED caller (so the call tx
 * carries a change output after the continuation).
 *
 * BIP-143 SINGLE commits hashOutputs = hash256(output[inputIndex]) only. Before
 * N-038 the compiler's continuation hashed (continuation || change) and the SDK
 * pushed the real `_changeAmount`, so every SINGLE call with change > 0 was
 * rejected by the node ("top stack element must be truthy"); only the #116
 * exact-cover shape (change clamped to 0) worked. N-038 (user decision R64):
 * under a SINGLE base the continuation hashes only the method's own output and
 * `_changePKH` / `_changeAmount` are not method params at all.
 *
 * Proves, on @bsv/sdk Spend (not the ANF interpreter, not TestContract):
 *   - the SDK-built call with a change output is ACCEPTED, and the next call on
 *     the continuation UTXO is accepted too (the continuation is spendable);
 *   - a tampered output[0] (state byte, or satoshis) is REJECTED;
 *   - the change output is NOT committed by the covenant (tampering it leaves
 *     input 0 valid) — that is what SINGLE means; the change is protected by
 *     the funding input's own ALL|FORKID signature, which MockProvider's
 *     broadcast validation checks for the untampered tx;
 *   - the ABI carries no `_changePKH` / `_changeAmount` for the SINGLE method
 *     and still marks it non-terminal.
 * Does NOT prove: anything about the other six SDKs (their own tests and the
 * shared vector in conformance/sdk-output cover those), multi-contract-input
 * SINGLE calls, or a live-node broadcast.
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

const SOURCE = `import { StatefulSmartContract } from 'runar-lang';

export class Pair extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  /** @sighash SINGLE|FORKID */
  public bump() {
    this.addOutput(1000n, this.count + 1n);
  }
}
`;

function compileArtifact(): RunarArtifact {
  const result = compile(SOURCE, { fileName: 'Pair.runar.ts' });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

function validateSpend(tx: Transaction, sourceTx: Transaction): { valid: boolean; error?: string } {
  const input = tx.inputs[0]!;
  const sourceOutput = sourceTx.outputs[0]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs.slice(1).map((inp, idx) => ({
      inputIndex: idx + 1,
      sourceOutputIndex: inp.sourceOutputIndex,
      sourceTXID: inp.sourceTXID!,
      sequence: inp.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: 0,
      lockingScript: LockingScript.fromHex(''),
    })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis })),
    unlockingScript: input.unlockingScript,
    inputIndex: 0,
    inputSequence: input.sequence,
    lockTime: tx.lockTime,
  });
  try {
    return { valid: spend.validate() };
  } catch (e) {
    if (e instanceof Error && /^Script evaluation error:/.test(e.message)) {
      return { valid: false, error: e.message };
    }
    throw e;
  }
}

function preimageSighashByte(tx: Transaction): number {
  let biggest: number[] = [];
  for (const c of UnlockingScript.fromHex(tx.inputs[0]!.unlockingScript!.toHex()).chunks) {
    if (c.data && c.data.length > biggest.length) biggest = c.data;
  }
  return biggest[biggest.length - 4]!;
}

function tamperOutput0(tx: Transaction, how: 'state' | 'satoshis' | 'change'): Transaction {
  const t = Transaction.fromHex(tx.toHex());
  if (how === 'change') {
    t.outputs[1]!.satoshis = t.outputs[1]!.satoshis! - 1;
  } else if (how === 'satoshis') {
    t.outputs[0]!.satoshis = t.outputs[0]!.satoshis! - 1;
  } else {
    const hex = t.outputs[0]!.lockingScript.toHex();
    const b = (parseInt(hex.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');
    t.outputs[0]!.lockingScript = LockingScript.fromHex(hex.slice(0, -2) + b);
  }
  return t;
}

async function deployAndCallFunded() {
  // Broadcast validation stays ON: MockProvider replays every input of every
  // broadcast tx (contract input + P2PKH funding inputs) through real Spend.
  const provider = new MockProvider('testnet');
  const deployer = new LocalSigner(DEPLOYER_KEY);
  provider.addUtxo(await deployer.getAddress(), {
    txid: DEPLOYER_KEY,
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await deployer.getPublicKey()),
  });
  const caller = new LocalSigner(CALLER_KEY);
  provider.addUtxo(await caller.getAddress(), {
    txid: CALLER_KEY,
    outputIndex: 0,
    satoshis: 100_000,
    script: buildP2PKHScript(await caller.getPublicKey()),
  });
  const contract = new RunarContract(compileArtifact(), [0n]);
  await contract.deploy(provider, deployer, { satoshis: 1000 });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  await contract.call('bump', [], provider, caller);
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return { callTx, deployTx, contract, provider, caller };
}

describe('N-038 — stateful SINGLE|FORKID addOutput call with a change output', () => {
  it('the ABI has no change params for the SINGLE method and keeps it non-terminal', () => {
    const bump = compileArtifact().abi.methods.find((m) => m.name === 'bump')!;
    expect(bump.sigHashType).toBe(0x43);
    expect(bump.params.map((p) => p.name)).toEqual(['txPreimage']);
    expect(bump.isTerminal).toBeUndefined();
  });

  it('the call with change is accepted by Spend, tracks state, and the continuation is spendable again', async () => {
    const { callTx, deployTx, contract, provider, caller } = await deployAndCallFunded();
    expect(preimageSighashByte(callTx)).toBe(0x43);
    expect(callTx.outputs.length).toBe(2);
    expect(callTx.outputs[0]!.satoshis).toBe(1000);
    expect(callTx.outputs[1]!.satoshis!).toBeGreaterThan(0);
    expect(validateSpend(callTx, deployTx)).toEqual({ valid: true });
    expect(contract.state.count).toBe(1n);

    await contract.call('bump', [], provider, caller);
    const callTx2 = Transaction.fromHex(provider.getBroadcastedTxs()[2]!);
    expect(callTx2.outputs.length).toBe(2);
    expect(validateSpend(callTx2, callTx)).toEqual({ valid: true });
    expect(contract.state.count).toBe(2n);
  });

  it('a tampered output[0] (state or satoshis) is rejected; a tampered change output is not covenant-committed', async () => {
    const { callTx, deployTx } = await deployAndCallFunded();
    const stateTamper = validateSpend(tamperOutput0(callTx, 'state'), deployTx);
    expect(stateTamper.valid).toBe(false);
    expect(stateTamper.error).toMatch(/Script evaluation error/);
    const satsTamper = validateSpend(tamperOutput0(callTx, 'satoshis'), deployTx);
    expect(satsTamper.valid).toBe(false);
    expect(satsTamper.error).toMatch(/Script evaluation error/);
    expect(validateSpend(tamperOutput0(callTx, 'change'), deployTx)).toEqual({ valid: true });
  });
});
