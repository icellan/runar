/**
 * F-145 (CL-BUG-135): the SDK ANF interpreter failed OPEN on everything it did
 * not model, so the fail-closed guard in `RunarContract.call` (the `try/catch`
 * around `computeNewStateAndDataOutputs`, "Refusing to broadcast") could not
 * fire for any of them:
 *
 * - an unknown ANF binding kind            -> `return undefined`
 * - `/` or `%` with a zero divisor         -> `return 0n`
 * - an unknown numeric binary operator     -> `return 0n`
 * - an unknown ByteString binary operator  -> `return ''`
 * - an unknown unary operator              -> returned the operand unchanged
 * - a `method_call` naming no private method -> `return undefined`
 *
 * The division arm is also a source-vs-script divergence: `/` and `%` lower to
 * `OP_DIV` / `OP_MOD`, which ABORT the script on a zero divisor (proved below
 * against `@bsv/sdk`'s `Spend` via `ScriptExecutionContract`), while the
 * interpreter carried on with `0n` and serialised a wrong-but-plausible state
 * into the continuation. The unknown-BUILTIN arm was already fixed by A-3
 * (`a3-unmodelled-builtin-fails-closed.test.ts`); it is re-pinned here as a
 * control.
 *
 * WHAT THIS PROVES: each of those arms now throws with a diagnostic naming the
 * offending kind / operator / method, and `RunarContract.call` turns the
 * divide-by-zero throw into a refusal, so nothing beyond the deploy reaches the
 * provider. The non-zero-divisor control still evaluates and builds a call
 * whose continuation the consensus engine accepts.
 *
 * WHAT THIS DOES NOT PROVE: that the interpreter's arithmetic matches the
 * script for every operand (other suites cover that, e.g. f134); anything about
 * the six peer SDK interpreters, whose division-by-zero arms are queued
 * separately (N-102); or that every ANF kind the compiler can emit is modelled
 * — only that an unmodelled one can no longer pass silently.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptExecutionContract } from 'runar-testing';
import type { ANFProgram, RunarArtifact } from 'runar-ir-schema';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import { computeNewStateAndDataOutputs } from '../anf-interpreter.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';

const SIGNER_KEY = '1'.repeat(63) + '7';
const FILE_NAME = 'Div.runar.ts';
const INITIAL = 100n;

const SOURCE = `import { StatefulSmartContract } from 'runar-lang';

class Div extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public divide(d: bigint): void {
    this.count = this.count / d;
  }

  public modulo(d: bigint): void {
    this.count = this.count % d;
  }
}`;

function compileSource(source: string, fileName = FILE_NAME): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

/** A one-method stateful ANF whose body is `t0 = <value>; count = t0`. */
function anfWith(body: unknown[], props = [{ name: 'count', type: 'bigint', readonly: false }]): ANFProgram {
  return {
    contractName: 'Probe',
    properties: props,
    methods: [{ name: 'm', isPublic: true, params: [], body }],
  } as unknown as ANFProgram;
}

function run(anf: ANFProgram, state: Record<string, unknown> = { count: INITIAL }) {
  return computeNewStateAndDataOutputs(anf, 'm', state, {});
}

function validateSpend(tx: Transaction, sourceTx: Transaction): boolean {
  const input = tx.inputs[0]!;
  const sourceOutput = sourceTx.outputs[0]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: LockingScript.fromHex(sourceOutput.lockingScript.toHex()),
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
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis ?? 0 })),
    unlockingScript: input.unlockingScript!,
    inputIndex: 0,
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
  });
  return spend.validate();
}

async function deployed(): Promise<{ contract: RunarContract; provider: MockProvider }> {
  const signer = new LocalSigner(SIGNER_KEY);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(compileSource(SOURCE), [INITIAL] as unknown[]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 50_000 });
  return { contract, provider };
}

describe('F-145 — premise: the deployed script aborts on a zero divisor', () => {
  // Stateless twin of `divide` / `modulo`, run through @bsv/sdk's Spend.
  const STATELESS = `import { SmartContract, assert } from 'runar-lang';

class DivCheck extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public divide(d: bigint) {
    const q: bigint = this.n / d;
    assert(q >= 0n || q < 0n);
  }

  public modulo(d: bigint) {
    const r: bigint = this.n % d;
    assert(r >= 0n || r < 0n);
  }
}`;
  const c = ScriptExecutionContract.fromSource(STATELESS, { n: INITIAL }, 'DivCheck.runar.ts');

  it('OP_DIV / OP_MOD with a zero divisor fail script evaluation', () => {
    expect(c.execute('divide', [0n]).success).toBe(false);
    expect(c.execute('modulo', [0n]).success).toBe(false);
  });

  it('CONTROL: a non-zero divisor evaluates', () => {
    expect(c.execute('divide', [3n]).success).toBe(true);
    expect(c.execute('modulo', [3n]).success).toBe(true);
  });
});

describe('F-145 — the interpreter refuses instead of inventing a value', () => {
  it('RED: `/` with a zero divisor throws (was: silently 0n)', () => {
    const artifact = compileSource(SOURCE);
    expect(() =>
      computeNewStateAndDataOutputs(artifact.anf!, 'divide', { count: INITIAL }, { d: 0n }),
    ).toThrow(/division by zero/);
  });

  it('RED: `%` with a zero divisor throws (was: silently 0n)', () => {
    const artifact = compileSource(SOURCE);
    expect(() =>
      computeNewStateAndDataOutputs(artifact.anf!, 'modulo', { count: INITIAL }, { d: 0n }),
    ).toThrow(/modulo by zero/);
  });

  it('CONTROL: a non-zero divisor still computes the truncating quotient / remainder', () => {
    const artifact = compileSource(SOURCE);
    expect(
      computeNewStateAndDataOutputs(artifact.anf!, 'divide', { count: INITIAL }, { d: 3n }).state.count,
    ).toBe(33n);
    expect(
      computeNewStateAndDataOutputs(artifact.anf!, 'modulo', { count: INITIAL }, { d: 3n }).state.count,
    ).toBe(1n);
    expect(
      computeNewStateAndDataOutputs(artifact.anf!, 'divide', { count: -7n }, { d: 2n }).state.count,
    ).toBe(-3n);
  });

  it('RED: an unknown ANF binding kind throws, naming the kind (was: undefined, state silently dropped)', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'totally_bogus_kind' } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't0' } },
    ]);
    expect(() => run(anf)).toThrow(/totally_bogus_kind/);
  });

  it('RED: `raw_script` (opaque asm) is refused — its result cannot be computed off-chain', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'raw_script', bytes: '93', in_arity: 2, out_arity: 1 } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't0' } },
    ]);
    expect(() => run(anf)).toThrow(/raw_script/);
  });

  it('CONTROL (teeth): a value-less `raw_script` (out_arity 0) is not refused — there is nothing to compute', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'raw_script', bytes: '75', in_arity: 1, out_arity: 0 } },
      { name: 't1', value: { kind: 'load_const', value: 7n } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't1' } },
    ]);
    expect(run(anf).state.count).toBe(7n);
  });

  it('RED: an unknown numeric binary operator throws, naming it (was: silently 0n)', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'load_const', value: 2n } },
      { name: 't1', value: { kind: 'bin_op', op: '**', left: 't0', right: 't0' } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't1' } },
    ]);
    expect(() => run(anf)).toThrow(/\*\*/);
  });

  it("RED: an unknown ByteString binary operator throws, naming it (was: silently '')", () => {
    const anf = anfWith(
      [
        { name: 't0', value: { kind: 'load_const', value: 'abcd' } },
        { name: 't1', value: { kind: 'bin_op', op: '-', left: 't0', right: 't0', result_type: 'bytes' } },
        { name: 'u0', value: { kind: 'update_prop', name: 'h', value: 't1' } },
      ],
      [{ name: 'h', type: 'ByteString', readonly: false }],
    );
    expect(() => run(anf, { h: 'ff' })).toThrow(/'-'/);
  });

  it('RED: an unknown unary operator throws, naming it (was: operand passed through)', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'load_const', value: 5n } },
      { name: 't1', value: { kind: 'unary_op', op: '?', operand: 't0' } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't1' } },
    ]);
    expect(() => run(anf)).toThrow(/'\?'/);
  });

  it('RED: an unknown ByteString unary operator throws, naming it (was: operand passed through)', () => {
    const anf = anfWith(
      [
        { name: 't0', value: { kind: 'load_const', value: 'abcd' } },
        { name: 't1', value: { kind: 'unary_op', op: '-', operand: 't0', result_type: 'bytes' } },
        { name: 'u0', value: { kind: 'update_prop', name: 'h', value: 't1' } },
      ],
      [{ name: 'h', type: 'ByteString', readonly: false }],
    );
    expect(() => run(anf, { h: 'ff' })).toThrow(/'-'/);
  });

  it('RED: a method_call naming no private method throws, naming it (was: undefined)', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'method_call', object: 'this', method: 'nosuch', args: [] } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't0' } },
    ]);
    expect(() => run(anf)).toThrow(/nosuch/);
  });

  it('CONTROL (teeth): `array_literal` is NOT refused — a stateful checkMultiSig method still evaluates', () => {
    // `array_literal` used to reach the blanket default. Its only consumer is
    // `checkMultiSig` (mocked true in lenient mode), so refusing it would
    // break every stateful multisig call for a value nothing else reads.
    const artifact = compileSource(
      `import { StatefulSmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';

class Ms extends StatefulSmartContract {
  count: bigint;
  readonly pk1: PubKey;
  readonly pk2: PubKey;

  constructor(count: bigint, pk1: PubKey, pk2: PubKey) {
    super(count, pk1, pk2);
    this.count = count;
    this.pk1 = pk1;
    this.pk2 = pk2;
  }

  public bump(s1: Sig, s2: Sig): void {
    assert(checkMultiSig([s1, s2], [this.pk1, this.pk2]));
    this.count = this.count + 1n;
  }
}`,
      'Ms.runar.ts',
    );
    expect(JSON.stringify(artifact.anf, (_k, v) => (typeof v === 'bigint' ? String(v) : v))).toContain(
      '"array_literal"',
    );
    const res = computeNewStateAndDataOutputs(
      artifact.anf!, 'bump', { count: 1n }, { s1: '30', s2: '30' }, [1n, '02' + '11'.repeat(32), '02' + '22'.repeat(32)],
    );
    expect(res.state.count).toBe(2n);
  });

  it('CONTROL (A-3, already fixed): an unknown builtin throws, naming it', () => {
    const anf = anfWith([
      { name: 't0', value: { kind: 'call', func: 'ecOnCurve', args: [] } },
      { name: 'u0', value: { kind: 'update_prop', name: 'count', value: 't0' } },
    ]);
    expect(() => run(anf)).toThrow(/ecOnCurve/);
  });
});

describe('F-145 — RunarContract.call refuses to broadcast', () => {
  it('RED: divide-by-zero is refused by the fail-closed guard; only the deploy is broadcast', async () => {
    const { contract, provider } = await deployed();
    // RED: resolved and broadcast a continuation committing count = 0.
    await expect(contract.call('divide', [0n], {})).rejects.toThrow(
      /ANF interpreter could not evaluate[\s\S]*division by zero/,
    );
    expect(provider.getBroadcastedTxs()).toHaveLength(1);
  });

  it('RED: modulo-by-zero is refused too', async () => {
    const { contract, provider } = await deployed();
    await expect(contract.call('modulo', [0n], {})).rejects.toThrow(
      /ANF interpreter could not evaluate[\s\S]*modulo by zero/,
    );
    expect(provider.getBroadcastedTxs()).toHaveLength(1);
  });

  it('CONTROL: a non-zero divisor builds a call the consensus engine accepts', async () => {
    const { contract, provider } = await deployed();
    await contract.call('divide', [3n], {});
    const [deployHex, callHex] = provider.getBroadcastedTxs();
    expect(callHex).toBeDefined();
    expect(validateSpend(Transaction.fromHex(callHex!), Transaction.fromHex(deployHex!))).toBe(true);
    expect(contract.state.count).toBe(33n);
  });
});
