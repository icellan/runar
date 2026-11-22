/**
 * D25 (D12 PRE-F1) — twin-input theft.
 *
 * Two UTXOs of one stateful contract spent in ONE transaction that reach the
 * same post-state used to be satisfied by ONE continuation output: every
 * covenant input rebuilt the identical whole output list
 * `hash256(continuation || change) == hashOutputs`, so the second input's
 * value left as the attacker's "change". Nobody had to sign anything (Counter).
 *
 * The fix binds the continuation to the input that made it, per contract:
 *
 *   class 1  every continuation method is mutate-only  -> SIGHASH_SINGLE by
 *            default. BIP-143 SINGLE commits hashOutputs to output[inputIndex]
 *            only, so two inputs can never share an output; the F-024 floor
 *            pins its value.
 *   class 2  a contract that mixes auto-continuation methods with addOutput
 *            methods -> every continuation of the contract carries
 *            sha256(spent outpoint) as a hidden last state field, so two
 *            inputs can never rebuild the same output list.
 *
 * Every attack below is built by the SDK's own `assembleMultiContractCall`
 * and every input is replayed on @bsv/sdk's Spend (`dryRunMultiContractInput`).
 * Before the fix each attack is ACCEPTed on every input; after it, at most one
 * input of the tx verifies. Honest controls must keep verifying.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { assembleMultiContractCall, buildContractUnlock, dryRunMultiContractInput } from '../multi-contract.js';
import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import type { MultiContractCallInput, MultiContractCallOutput } from '../multi-contract.js';
import type { UTXO } from '../types.js';

const ROOT = resolve(__dirname, '../../../..');
const COUNTER_SRC = readFileSync(resolve(ROOT, 'examples/ts/stateful-counter/Counter.runar.ts'), 'utf8');
const BINDING_FIELD = '_spentOutpointHash';
const ATTACKER = '22'.repeat(20);

/** Class 2: an auto-continuation method next to an UNSIGNED value-conserving addOutput (D12 C1 shape). */
const MIXED_SRC = `
import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

class MixedPot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
`;

function compileSource(source: string, fileName: string): RunarArtifact {
  const r = compile(source, { fileName });
  if (!r.artifact) {
    const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
    throw new Error(`compile failed: ${errs.join('; ')}`);
  }
  return r.artifact;
}

function counterWith(directive: string): string {
  return COUNTER_SRC
    .replace('public increment()', `/** @sighash ${directive} */\n  public increment()`)
    .replace('public decrement()', `/** @sighash ${directive} */\n  public decrement()`);
}

const p2pkh = (pkh: string) => '76a914' + pkh + '88ac';
const wireOutpoint = (txid: string, vout: number): string => {
  const le = Buffer.alloc(4);
  le.writeUInt32LE(vout);
  return Buffer.from(txid, 'hex').reverse().toString('hex') + le.toString('hex');
};
const sha256hex = (hex: string) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

function methodParams(art: RunarArtifact, method: string): string[] {
  return art.abi.methods.find((m) => m.name === method)!.params.map((p) => p.name);
}

/** The continuation locking script for `count`, bound to `spent` when the artifact carries the field. */
function nextScript(art: RunarArtifact, count: bigint, spent?: UTXO): string {
  const c = new RunarContract(art, [0n]);
  const state: Record<string, unknown> = { count };
  if (art.stateFields?.some((f) => f.name === BINDING_FIELD)) {
    state[BINDING_FIELD] = sha256hex(wireOutpoint(spent!.txid, spent!.outputIndex));
  }
  c.setState(state);
  return c.getLockingScript();
}

/** A contract UTXO holding `count`, at a distinct outpoint per `k`, never spent before (zero binding). */
function utxoOf(art: RunarArtifact, k: number, count: bigint, satoshis: number): UTXO {
  const c = new RunarContract(art, [count]);
  return {
    txid: (0xc0 + k).toString(16).repeat(32),
    outputIndex: k,
    satoshis,
    script: c.getLockingScript(),
  };
}

function inputOf(art: RunarArtifact, method: string, count: bigint, utxo: UTXO, changeAmount: bigint): MultiContractCallInput {
  const hasChange = methodParams(art, method).includes('_changePKH');
  return {
    contract: new RunarContract(art, [count]),
    method,
    args: [],
    utxo,
    ...(hasChange ? { changePKH: ATTACKER, changeAmount } : {}),
  };
}

async function verdicts(inputs: MultiContractCallInput[], outputs: MultiContractCallOutput[]): Promise<string[]> {
  const as = await assembleMultiContractCall(inputs, outputs, { dryRun: false });
  return inputs.map((inp, k) =>
    dryRunMultiContractInput(as.txHex, k, inp.utxo!.script, inp.utxo!.satoshis).valid ? 'ACCEPT' : 'reject',
  );
}

/** At most one covenant input of the tx may verify. */
function expectAtMostOne(v: string[]): void {
  expect(v.filter((x) => x === 'ACCEPT').length).toBeLessThanOrEqual(1);
}

async function honestCalls(art: RunarArtifact, methods: string[]): Promise<RunarContract> {
  const provider = new MockProvider();
  const signer = new LocalSigner('11'.repeat(32));
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ab'.repeat(32), outputIndex: 0, satoshis: 500_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const c = new RunarContract(art, [0n]);
  await c.deploy(provider, signer, { satoshis: 10_000 });
  for (const m of methods) await c.call(m, [], provider, signer, {});
  return c;
}

describe('D25 class 1: mutate-only stateful contract (Counter)', () => {
  const art = compileSource(COUNTER_SRC, 'Counter.runar.ts');

  it('twin: 2x Counter(0).increment satisfied by ONE continuation is refused', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 0n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 9_000n), inputOf(art, 'increment', 0n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('converging twin: Counter(0).increment + Counter(2).decrement -> one count=1 output is refused', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 2n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 9_000n), inputOf(art, 'decrement', 2n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('N=3 twin is refused', async () => {
    const us = [0, 1, 2].map((k) => utxoOf(art, k, 0n, 10_000));
    const v = await verdicts(
      us.map((u) => inputOf(art, 'increment', 0n, u, 19_000n)),
      [{ satoshis: 10_000, script: nextScript(art, 1n, us[0]) }, { satoshis: 19_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('defaults every continuation method to SIGHASH_SINGLE|FORKID (no change params)', () => {
    for (const m of ['increment', 'decrement']) {
      const abi = art.abi.methods.find((x) => x.name === m)!;
      expect(abi.sigHashType).toBe(0x43);
      expect(methodParams(art, m)).toEqual(['_newAmount', 'txPreimage']);
    }
  });

  it('honest: two chained call()s through the validating MockProvider', async () => {
    const c = await honestCalls(art, ['increment', 'increment', 'decrement']);
    expect(c.state.count).toBe(1n);
  });

  it('honest batch: two independent Counters, each continuation at its own input index', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 5n, 7_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 0n), inputOf(art, 'increment', 5n, u1, 0n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 7_000, script: nextScript(art, 6n, u1) }],
    );
    expect(v).toEqual(['ACCEPT', 'ACCEPT']);
  });

  it('#198 wallet-built tx, contract at input 1: [change, continuation] verifies, [continuation, change] does not', async () => {
    const results: Record<string, string> = {};
    for (const order of ['change-first', 'cont-first']) {
      const u = utxoOf(art, 9, 0n, 10_000);
      const tx = new Transaction(1, [], [], 0);
      tx.addInput({ sourceTXID: 'f0'.repeat(32), sourceOutputIndex: 0, unlockingScript: new UnlockingScript([]), sequence: 0xffffffff });
      tx.addInput({ sourceTXID: u.txid, sourceOutputIndex: u.outputIndex, unlockingScript: new UnlockingScript([]), sequence: 0xffffffff });
      const cont = { satoshis: 10_000, lockingScript: LockingScript.fromHex(nextScript(art, 1n, u)) };
      const change = { satoshis: 4_000, lockingScript: LockingScript.fromHex(p2pkh(ATTACKER)) };
      for (const o of order === 'change-first' ? [change, cont] : [cont, change]) tx.addOutput(o);
      try {
        await buildContractUnlock(tx, 1, inputOf(art, 'increment', 0n, u, 0n), { dryRun: true });
        results[order] = 'ACCEPT';
      } catch {
        results[order] = 'reject';
      }
    }
    expect(results).toEqual({ 'change-first': 'ACCEPT', 'cont-first': 'reject' });
  });

  it('honest: a dust continuation is still refused (F-024 floor under SINGLE)', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const inp = { ...inputOf(art, 'increment', 0n, u0, 0n), newAmount: 1n };
    const v = await verdicts([inp], [{ satoshis: 1, script: nextScript(art, 1n, u0) }]);
    expect(v).toEqual(['reject']);
  });
});

describe('D25 class 1 under ANYONECANPAY (ALL|ANYONECANPAY -> SINGLE|ANYONECANPAY)', () => {
  const art = compileSource(counterWith('ALL|ANYONECANPAY|FORKID'), 'Counter.runar.ts');

  it('twin is refused', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 0n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 9_000n), inputOf(art, 'increment', 0n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('is compiled as SINGLE|ANYONECANPAY|FORKID', () => {
    expect(art.abi.methods.find((m) => m.name === 'increment')!.sigHashType).toBe(0xc3);
  });
});

describe('D25 class 1: an ALL sibling would reopen the twin (design §4.1), so it is refused', () => {
  it('explicit @sighash ALL|FORKID on a mutate-only method of a mutate-only contract does not compile', () => {
    const src = COUNTER_SRC.replace('public decrement()', '/** @sighash ALL|FORKID */\n  public decrement()');
    const r = compile(src, { fileName: 'Counter.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.some((d) => d.severity === 'error' && /twin/i.test(d.message))).toBe(true);
  });
});

describe('D25 class 2: mixed auto-continuation + addOutput contract (MixedPot)', () => {
  const art = compileSource(MIXED_SRC, 'MixedPot.runar.ts');

  it('carries the spent-outpoint binding as the last state field (32 bytes, zero at deploy)', () => {
    const last = art.stateFields!.at(-1)!;
    expect(last.name).toBe(BINDING_FIELD);
    expect(art.abi.constructor.params.map((p) => p.name)).toEqual(['count']);
  });

  it('twin through the auto-continuation method is refused', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 0n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 9_000n), inputOf(art, 'increment', 0n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('twin through the unsigned addOutput(extractAmount) method is refused (D12 C1, third-party theft)', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 0n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'bump', 0n, u0, 9_000n), inputOf(art, 'bump', 0n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('cross-method twin (increment@0 + bump@1 -> one count=1 output) is refused', async () => {
    const u0 = utxoOf(art, 0, 0n, 10_000);
    const u1 = utxoOf(art, 1, 0n, 10_000);
    const v = await verdicts(
      [inputOf(art, 'increment', 0n, u0, 9_000n), inputOf(art, 'bump', 0n, u1, 9_000n)],
      [{ satoshis: 10_000, script: nextScript(art, 1n, u0) }, { satoshis: 9_000, script: p2pkh(ATTACKER) }],
    );
    expectAtMostOne(v);
  });

  it('honest: chained call()s of both methods through the validating MockProvider', async () => {
    const c = await honestCalls(art, ['increment', 'bump', 'increment']);
    expect(c.state.count).toBe(3n);
  });

  // The caller-supplied-state paths (CallOptions.outputs / newState) never
  // name the hidden field; the SDK must fill it with sha256(the outpoint this
  // call spends), not leave it out (serializeState refuses) or keep the
  // previous call's hash (the covenant rejects). Broadcast validation is ON.
  it('honest: CallOptions.outputs / newState without the hidden field get the spent-outpoint hash', async () => {
    const provider = new MockProvider();
    const signer = new LocalSigner('11'.repeat(32));
    provider.addUtxo(await signer.getAddress(), {
      txid: 'ab'.repeat(32), outputIndex: 0, satoshis: 500_000,
      script: buildP2PKHScript(await signer.getPublicKey()),
    });
    const c = new RunarContract(art, [1n]);
    await c.deploy(provider, signer, { satoshis: 10_000 });
    const spent = c.getUtxo()!;
    // (CallOptions.outputs does not advance `contract.state` — pre-existing
    // behaviour; the continuations are reported in the CallResult instead.)
    await c.call('bump', [], provider, signer, { outputs: [{ satoshis: spent.satoshis, state: { count: 2n } }] });
    const spent2 = c.getUtxo()!;
    expect(spent2.txid).not.toBe(spent.txid);
    await c.call('increment', [], provider, signer, { newState: { count: 3n } });
    expect(c.state.count).toBe(3n);
    expect(c.state[BINDING_FIELD]).toBe(sha256hex(wireOutpoint(spent2.txid, spent2.outputIndex)));
    // A state copied from `contract.state` carries the PREVIOUS outpoint's
    // hash; the SDK must replace it (the covenant would reject it as stale).
    const spent3 = c.getUtxo()!;
    const stale = c.state[BINDING_FIELD];
    await c.call('increment', [], provider, signer, { newState: { ...c.state, count: 4n } });
    expect(c.state[BINDING_FIELD]).toBe(sha256hex(wireOutpoint(spent3.txid, spent3.outputIndex)));
    expect(c.state[BINDING_FIELD]).not.toBe(stale);
    const spent4 = c.getUtxo()!;
    const r = await c.call('bump', [], provider, signer, {
      outputs: [{ satoshis: spent4.satoshis, state: { ...c.state, count: 5n } }],
    });
    expect(r.continuations[0]!.state[BINDING_FIELD]).toBe(sha256hex(wireOutpoint(spent4.txid, spent4.outputIndex)));
  });
});
