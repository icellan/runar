/**
 * NEW-006: `RunarContract.call()` silently builds a stateful continuation
 * carrying the STALE state, and the network rejects the spend.
 *
 * TWO defects, pinned separately here.
 *
 * (a) THE ALIAS WIDTH GAP. `anf-interpreter.ts` threads each numeric
 *     byte-op's real stack bytes through a per-binding side map
 *     (`scriptBytes`) so a chained op sees the true (possibly non-minimal)
 *     width — but it does not carry that entry across the ALIAS binding a
 *     local rebind lowers to:
 *
 *       t12 = bin_op ^ t10 t11        <- scriptBytes['t12'] = [0x00]
 *       m0  = load_const "@ref:t12"   <- ALIAS; no scriptBytes entry
 *       t14 = bin_op ^ t13 m0         <- falls back to the minimal bytes of
 *                                        0n = [] -> 1 vs 0 -> throws
 *
 *     The compiler models exactly the propagation the interpreter is
 *     missing: `05-stack-lower.ts` carries its `rawSlots` marker across the
 *     same `@ref:` alias (and across a value-`if` arm). Symmetrically, an
 *     alias whose target has NO entry must CLEAR a stale one — the slot now
 *     holds the newly pushed, minimal bytes.
 *
 * (b) THE SILENT FALLBACK. `contract.ts` swallowed every interpreter failure
 *     (`} catch { /* falls through to the legacy newState-only path *\/ }`)
 *     and, with no explicit `newState`, built the continuation from the
 *     CURRENT state. Any interpreter failure — this one or a future one —
 *     therefore produced a wrong continuation and an unbroadcastable call
 *     with no diagnostic at all. Fixing (a) alone leaves that silence in
 *     place, so the last case here feeds `call()` an artifact whose ANF the
 *     interpreter provably cannot evaluate and requires it to fail closed.
 *
 * NOT fund loss (the covenant's hashOutputs binding rejects, so nothing is
 * misdirected) and NOT a miscompile — the script is correct, the SDK is
 * wrong. It is a silent "your call cannot be broadcast", plus silent loss of
 * that method's data / raw outputs.
 *
 * Found by `--state-oracle --num 200 --seed 424242` (FuzzStateful3.method8).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { TestContract } from 'runar-testing';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { computeNewStateAndDataOutputs } from '../anf-interpreter.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '1'.repeat(63) + '7';
const FILE_NAME = 'Min.runar.ts';
const INITIAL = -59n;

/**
 * Minimised from the fuzzer finding. `(4n ^ 4n)` is numerically zero but
 * leaves a 1-byte `0x00` buffer on the stack; the rebind aliases it, and the
 * next `^` must see that byte, not the empty minimal encoding of `0n`.
 */
const SOURCE = `import { StatefulSmartContract } from 'runar-lang';

class Min extends StatefulSmartContract {
  prop12: bigint;

  constructor(prop12: bigint) {
    super(prop12);
    this.prop12 = prop12;
  }

  public m(): void {
    let m0: bigint = (4n ^ 4n);
    m0 = (4n ^ m0);
    this.prop12 = 7n;
  }
}`;

/** Same shape with a NON-zero intermediate — the control. Always passed. */
const CONTROL = SOURCE.replace('(4n ^ 4n)', '(5n ^ 4n)');

/**
 * The other half of the alias rule: when the alias target has NO entry, the
 * 1-byte `0x00` left by `(4n ^ 4n)` must NOT survive onto the re-bound name.
 * On-chain `m0` then holds `push(300)` = `0x2c01`, and `& 255n` (`0xff00`) is
 * a 2-vs-2 byte op yielding 44.
 *
 * Honest status: this case is GREEN before the fix — today nothing ever keys
 * the side map by a re-bound local's name, so there is no stale entry to read.
 * It goes RED the moment the alias only PROPAGATES (verified: "OP_AND:
 * operands must be same length"). It is the guard that forces the fix to
 * clear as well as copy, not an independent pre-existing defect.
 */
const STALE = `import { StatefulSmartContract } from 'runar-lang';

class Min extends StatefulSmartContract {
  prop12: bigint;

  constructor(prop12: bigint) {
    super(prop12);
    this.prop12 = prop12;
  }

  public m(): void {
    let m0: bigint = (4n ^ 4n);
    m0 = 300n;
    this.prop12 = (m0 & 255n);
  }
}`;

/**
 * The same gap through a value-`if`: a ternary binds the `if` node, and the
 * rebind then aliases THAT. Two alias hops, so it needs both the `if`-result
 * adoption and the `@ref:` copy. `05-stack-lower.ts` names this exact shape
 * ("`c ? (a << 8) : 0n` must be re-minimised by its consumer") when it carries
 * its own `rawSlots` marker across the arm.
 */
const VALUE_IF = `import { StatefulSmartContract } from 'runar-lang';

class Min extends StatefulSmartContract {
  prop12: bigint;

  constructor(prop12: bigint) {
    super(prop12);
    this.prop12 = prop12;
  }

  public m(flag: boolean): void {
    let m0: bigint = flag ? (2n << 8n) : 0n;
    this.prop12 = (m0 | 5n);
  }
}`;

function compileSource(source: string): RunarArtifact {
  const result = compile(source, { fileName: FILE_NAME });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

/** Path 1 — the AST interpreter, which never touches ANF. */
function astPostState(source: string, args: Record<string, unknown> = {}): bigint {
  const tc = TestContract.fromSource(source, { prop12: INITIAL } as never, FILE_NAME);
  tc.call('m', args);
  return (tc.state as Record<string, bigint>).prop12;
}

/** Path 2 — the SDK's ANF interpreter, called directly. */
function anfPostState(artifact: RunarArtifact, args: Record<string, unknown> = {}): bigint {
  const r = computeNewStateAndDataOutputs(artifact.anf!, 'm', { prop12: INITIAL }, args);
  return (r.state as Record<string, bigint>).prop12;
}

/**
 * Path 3 — full consensus replay of a freshly-parsed transaction, aliasing
 * none of the objects the SDK handed to the provider.
 */
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

/** The 8-byte little-endian sign-magnitude state field the SDK committed. */
function committedState(callTx: Transaction): bigint {
  const cont = callTx.outputs[0]!.lockingScript.toHex();
  const stateHex = cont.slice(cont.lastIndexOf('6a') + 2);
  const bytes = stateHex.match(/../g)!.map((h) => parseInt(h, 16));
  let mag = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    mag = (mag << 8n) | BigInt(i === bytes.length - 1 ? bytes[i]! & 0x7f : bytes[i]!);
  }
  return (bytes[bytes.length - 1]! & 0x80) !== 0 ? -mag : mag;
}

async function deployAndCall(
  artifact: RunarArtifact,
): Promise<{ deployTx: Transaction; callTx: Transaction }> {
  const signer = new LocalSigner(SIGNER_KEY);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact, [INITIAL] as unknown[]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 50_000 });
  await contract.call('m', [], {});
  const [deployHex, callHex] = provider.getBroadcastedTxs();
  return {
    deployTx: Transaction.fromHex(deployHex!),
    callTx: Transaction.fromHex(callHex!),
  };
}

describe('NEW-006 (a): a byte-array width survives the alias a rebind lowers to', () => {
  it('evaluates the method whose intermediate bitwise result is zero', () => {
    // RED: throws `OP_XOR: operands must be same length`.
    expect(anfPostState(compileSource(SOURCE))).toBe(astPostState(SOURCE));
  });

  it('clears a stale width when the rebind aliases a plain constant', () => {
    // Green before the fix, red under a propagate-only fix (see STALE).
    expect(anfPostState(compileSource(STALE))).toBe(astPostState(STALE));
  });

  it('carries the width out of a taken ternary arm', () => {
    // RED: `OP_OR: operands must be same length` — the `if` binding drops the
    // arm's 1-byte 0x00 and the rebind alias drops it again.
    expect(anfPostState(compileSource(VALUE_IF), { flag: true }))
      .toBe(astPostState(VALUE_IF, { flag: true }));
  });

  it('still evaluates the non-zero control', () => {
    expect(anfPostState(compileSource(CONTROL))).toBe(astPostState(CONTROL));
  });
});

describe('NEW-006 (a): the built call transaction is spendable', () => {
  it('commits the POST-state, not the deploy-time state', async () => {
    const { callTx } = await deployAndCall(compileSource(SOURCE));
    // RED: commits -59 (the deploy-time value) instead of 7.
    expect(committedState(callTx)).toBe(astPostState(SOURCE));
  });

  it('is accepted by the consensus engine on freshly-parsed bytes', async () => {
    const { deployTx, callTx } = await deployAndCall(compileSource(SOURCE));
    // RED: "The top stack element must be truthy after script evaluation."
    expect(validateSpend(callTx, deployTx)).toBe(true);
  });

  it('is accepted for the stale-width variant too', async () => {
    const { deployTx, callTx } = await deployAndCall(compileSource(STALE));
    expect(committedState(callTx)).toBe(astPostState(STALE));
    expect(validateSpend(callTx, deployTx)).toBe(true);
  });

  it('still builds a spendable call for the non-zero control', async () => {
    const { deployTx, callTx } = await deployAndCall(compileSource(CONTROL));
    expect(committedState(callTx)).toBe(astPostState(CONTROL));
    expect(validateSpend(callTx, deployTx)).toBe(true);
  });
});

describe('NEW-006 (b): an interpreter failure must fail closed, not fall back', () => {
  /** An artifact whose ANF the interpreter provably cannot evaluate. */
  function unevaluatableArtifact(): RunarArtifact {
    const artifact = compileSource(CONTROL);
    const anf = JSON.parse(JSON.stringify(artifact.anf, (_k, v) =>
      typeof v === 'bigint' ? { __bigint: String(v) } : v,
    ), (_k, v) =>
      v && typeof v === 'object' && typeof v.__bigint === 'string' ? BigInt(v.__bigint) : v,
    );
    // The ABI still advertises `m`; the ANF no longer describes it, so
    // `runMethod` throws "method 'm' not found in ANF IR".
    anf.methods = anf.methods.filter((mm: { name: string }) => mm.name !== 'm');
    return { ...artifact, anf };
  }

  it('throws instead of broadcasting a continuation built from the stale state', async () => {
    const signer = new LocalSigner(SIGNER_KEY);
    const provider = new MockProvider();
    provider.addUtxo(await signer.getAddress(), {
      txid: 'ee'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000_000,
      script: buildP2PKHScript(await signer.getPublicKey()),
    });
    const contract = new RunarContract(unevaluatableArtifact(), [INITIAL] as unknown[]);
    contract.connect(provider, signer);
    await contract.deploy({ satoshis: 50_000 });

    // RED: resolves, having broadcast a continuation carrying the stale state.
    await expect(contract.call('m', [], {})).rejects.toThrow(
      /ANF interpreter could not evaluate/,
    );
    // And nothing beyond the deploy reached the network.
    expect(provider.getBroadcastedTxs()).toHaveLength(1);
  });
});
