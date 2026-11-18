/**
 * D18 — execution proof: a public stateful method that writes state and calls
 * `addRawOutput` but never `addOutput` gets no state continuation, so its
 * state write is dropped and the contract's satoshis leave with the spend.
 *
 * The contract is issue #180's `Lock`:
 *
 *     n: bigint;
 *     public lock(p: Point) {
 *       this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
 *       this.n = this.n + 1n;
 *     }
 *
 * Any addOutput/addRawOutput replaces the auto-injected continuation: the
 * covenant hashes exactly the declared outputs plus change. `addRawOutput`
 * never carries state, so `lock` commits to `[raw(1000)] [change]`.
 *
 * RED leg (the compiler as it was before D18, reproduced by switching the D18
 * predicate off through a module mock; nothing else in the pipeline changes):
 * `lock` compiles, and a spend whose outputs carry NO continuation passes the
 * real @bsv/sdk Spend engine. No output of the spending tx carries the
 * contract's script, so the `n` write is gone and all of the contract's value
 * except the 1000-sat raw output leaves to the caller's change.
 *
 * GREEN legs: the real compiler refuses `Lock` with the shared D18 diagnostic;
 * the `addOutput` twin (same body plus `this.addOutput(...)`) still spends with
 * its state carried in a contract output; and a twin that writes nothing and
 * only emits the raw output (terminal by design) is still accepted.
 *
 * Does not prove: anything about the six native tiers (their corpus tests and
 * conformance/negatives/gk-frontend-parity.test.ts carry the refusal) or the
 * --ir path (conformance/negatives/ir-stateful-scaffold.test.ts).
 */
import { describe, it, expect, vi } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const gate = vi.hoisted(() => ({ bypassD18: false }));
vi.mock('../../../runar-compiler/src/passes/continuation-rules.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../runar-compiler/src/passes/continuation-rules.js')>();
  return {
    ...real,
    dropsContinuation: (...a: Parameters<typeof real.dropsContinuation>) =>
      gate.bypassD18 ? false : real.dropsContinuation(...a),
  };
});

const DEPLOYER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const CALLER_KEY = '0000000000000000000000000000000000000000000000000000000000000004';
const DEPLOY_SATS = 50_000;
const POINT = '22'.repeat(64);
const RAW_SCRIPT = '40' + POINT + '87';

const HEADER = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';

class Lock extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
`;
const RAW = `    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));\n`;
const LOCK = `${HEADER}
  public lock(p: Point) {
${RAW}    this.n = this.n + 1n;
  }
}
`;
const LOCK_ADD_OUTPUT = `${HEADER}
  public lock(p: Point) {
${RAW}    this.n = this.n + 1n;
    this.addOutput(${DEPLOY_SATS}n, this.n);
  }
}
`;
const LOCK_TERMINAL = `${HEADER}
  public bump() {
    this.n = this.n + 1n;
  }

  public lock(p: Point) {
${RAW}  }
}
`;

const D18 = "method 'lock' writes contract state on a path that reaches no addOutput()";

function artifactOf(src: string): RunarArtifact {
  const r = compile(src, { fileName: 'Lock.runar.ts' });
  if (!r.success || !r.artifact) {
    throw new Error(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('; '));
  }
  return r.artifact as unknown as RunarArtifact;
}

async function funded(provider: MockProvider, key: string): Promise<LocalSigner> {
  const s = new LocalSigner(key);
  provider.addUtxo(await s.getAddress(), {
    txid: key.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(await s.getPublicKey()),
  });
  return s;
}

/** Replay one input through @bsv/sdk's Spend interpreter. */
function validateSpend(tx: Transaction, inputIdx: number, sourceTx: Transaction, sourceOutputIdx: number): boolean {
  const input = tx.inputs[inputIdx]!;
  const src = sourceTx.outputs[sourceOutputIdx]!;
  return new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: src.satoshis!,
    lockingScript: src.lockingScript,
    transactionVersion: tx.version,
    otherInputs: tx.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp, idx) => ({
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
  }).validate();
}

/** Deploy `artifact`, call `method`, return both txs. */
async function deployAndCall(artifact: RunarArtifact, method: string, args: unknown[]) {
  const provider = new MockProvider('testnet');
  const deployer = await funded(provider, DEPLOYER_KEY);
  const caller = await funded(provider, CALLER_KEY);
  const contract = new RunarContract(artifact, [0n]);
  await contract.deploy(provider, deployer, { satoshis: DEPLOY_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  await contract.call(method, args, provider, caller);
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  const codePart = deployTx.outputs[0]!.lockingScript.toHex().split('6a')[0]!;
  return { deployTx, callTx, codePart };
}

describe('D18 — a state write with only raw outputs drops the continuation', () => {
  it('RED (pre-D18 compiler): Lock.lock spends with no continuation; the value leaves the contract', async () => {
    gate.bypassD18 = true;
    let artifact: RunarArtifact;
    try {
      artifact = artifactOf(LOCK);
    } finally {
      gate.bypassD18 = false;
    }
    const { deployTx, callTx } = await deployAndCall(artifact, 'lock', [POINT]);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    const contractScript = deployTx.outputs[0]!.lockingScript.toHex();
    const contractPrefix = contractScript.slice(0, 200);
    // No output carries the contract's script: the `n` write is gone.
    expect(callTx.outputs.some((o) => o.lockingScript.toHex().startsWith(contractPrefix))).toBe(false);
    // The only non-change output is the 1000-sat raw output; the rest of the
    // contract's 50,000 sats is not in any contract output.
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(RAW_SCRIPT);
    expect(callTx.outputs[0]!.satoshis).toBe(1000);
  }, 120_000);

  it('GREEN: the compiler refuses Lock with the shared diagnostic', () => {
    const r = compile(LOCK, { fileName: 'Lock.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('\n')).toContain(D18);
  });

  it('GREEN: the addOutput twin spends with its state carried in a contract output', async () => {
    const { deployTx, callTx } = await deployAndCall(artifactOf(LOCK_ADD_OUTPUT), 'lock', [POINT]);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    const contractPrefix = deployTx.outputs[0]!.lockingScript.toHex().slice(0, 200);
    const cont = callTx.outputs.find((o) => o.lockingScript.toHex().startsWith(contractPrefix));
    expect(cont, 'a continuation output').toBeDefined();
    expect(cont!.satoshis).toBe(DEPLOY_SATS);
  }, 120_000);

  it('GREEN: a twin that writes nothing and emits only the raw output still spends', async () => {
    const { deployTx, callTx } = await deployAndCall(artifactOf(LOCK_TERMINAL), 'lock', [POINT]);
    expect(validateSpend(callTx, 0, deployTx, 0)).toBe(true);
    expect(callTx.outputs[0]!.lockingScript.toHex()).toBe(RAW_SCRIPT);
  }, 120_000);
});
