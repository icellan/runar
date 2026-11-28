/**
 * Attack harness for Rúnar compiled contracts.
 *
 * Everything here runs the REAL compiled Bitcoin Script through @bsv/sdk's
 * production `Spend` interpreter (real secp256k1, real BIP-143 sighash).
 * Nothing trusts the ANF interpreter or the SDK's own opinion about whether a
 * spend is fine — after the SDK builds a transaction we re-validate the
 * contract input ourselves and read the continuation state back off the wire.
 *
 * Two amount rules the harness has to respect, both enforced by the compiler
 * and the covenant on current main, and both learned the hard way:
 *   - MockProvider checks fees the way a node does, so a funding UTXO exactly
 *     equal to the requested output is NOT fundable ("Need 500153 sats, have
 *     500000"). `fundingFor()` adds headroom.
 *   - A stateful contract's continuation output must carry AT LEAST its input
 *     value. `satoshis: 499_999` against a 500_000 contract input fails with
 *     `OP_VERIFY requires the top stack value to be truthy`; 500_000 and above
 *     pass. So an explicit `callOptions.satoshis` below the contract input is
 *     an ATTACK, not an amount — tests that are about something else (message
 *     length, say) must leave `satoshis` unset and let the SDK carry the value.
 *
 * Two entry points:
 *   - stateless(): hand-build an unlocking script out of arbitrary pushes and
 *     spend a single-input UTXO. Attacker controls every stack item.
 *   - stateful(): full deploy -> call through RunarContract, with the caller's
 *     economic knobs (satoshis, changePubKey, newState, locktime, sequence)
 *     exposed, then real-engine validation + state readback.
 */
import { compile } from 'runar-compiler';
import type { CompileResult } from 'runar-compiler';
import {
  LockingScript,
  UnlockingScript,
  Spend,
  Transaction,
  PrivateKey,
  Hash,
  TransactionSignature,
  type TransactionInput,
} from '@bsv/sdk';
import { RunarContract, MockProvider, LocalSigner, extractStateFromScript, buildP2PKHScript } from 'runar-sdk';
import type { RunarArtifact, ABIMethod } from 'runar-ir-schema';
import { TEST_KEYS } from 'runar-testing';

export const PUBKEY = (fill: string) => '03' + fill.repeat(32);

/** Sats to put behind a signing address so a requested output survives the fee
 *  check. A two-in/two-out contract tx costs ~150 sats at the mock fee rate and
 *  MockProvider refuses an unfundable build outright, so funding equal to the
 *  requested output is a false failure. 20 000 sats of headroom is far below
 *  every amount an attack test asserts on, so it cannot mask a value bug. */
const FEE_HEADROOM = 20_000;
export function fundingFor(requested: number | undefined, floor = 500_000): number {
  return Math.max(floor, (requested ?? 0) + FEE_HEADROOM);
}

/** What the consensus engine said about one spend attempt. `error` is the
 *  engine's own message, verbatim — never paraphrase it in a finding. */
export interface Verdict {
  ok: boolean;
  error?: string;
}

/** First line of a possibly-absent diagnostic, truncated.
 *  Under `noUncheckedIndexedAccess` (which the repo base config turns on) a
 *  `msg.split('\n')[0]` is `string | undefined`, so without this every engine
 *  error logged by a test is a type error — and the temptation becomes dropping
 *  the diagnostic rather than typing it. */
export function firstLine(msg: string | undefined, max = 110): string {
  return ((msg ?? '').split('\n')[0] ?? '').slice(0, max);
}

/** Satoshis behind a transaction input, resolved through its source transaction.
 *  Two traps here. `TransactionInput` has no `sourceSatoshis` field, so reading
 *  one yields `undefined` at compile time and silently printed `?` at runtime —
 *  which is what an early version of the A1 pot-drain log did. And a
 *  `Transaction` parsed back from hex (which is how every tx in this directory
 *  arrives, via `provider.getBroadcastedTxs()`) carries no parents at all, so
 *  this returns `'?'` by design: when the number matters, read it off the parent
 *  you still hold, e.g. `outSats(r.deployTx)` for input 0. */
export function inputSatoshis(input: TransactionInput): number | string {
  return input.sourceTransaction?.outputs[input.sourceOutputIndex]?.satoshis ?? '?';
}

/** Satoshi value of a transaction output. `TxOut.satoshis` is optional in the
 *  @bsv/sdk types, so a bare `tx.outputs[0]!.satoshis` is `number | undefined`
 *  and cannot be compared or logged as a number. Defaulting to 0 is honest here:
 *  a missing value in a test fixture is a broken fixture, and 0 makes that show
 *  up as an obviously-wrong assertion rather than a type cast. */
export function outSats(tx: Transaction, idx = 0): number {
  return tx.outputs[idx]?.satoshis ?? 0;
}

/** nSequence of a transaction input (0 if the SDK left it unset, which for the
 *  hand-built attacks in this directory means final-by-omission). */
export function inSeq(tx: Transaction, idx = 0): number {
  return tx.inputs[idx]?.sequence ?? 0;
}

export function key(name: string) {
  const k = TEST_KEYS.find((t) => t.name === name);
  if (!k) throw new Error(`unknown test key ${name}`);
  return k;
}

// --- push encoding -------------------------------------------------------

export function push(data: Uint8Array): Uint8Array {
  const n = data.length;
  if (n === 0) return new Uint8Array([0x00]);
  if (n <= 75) return concat([new Uint8Array([n]), data]);
  if (n <= 255) return concat([new Uint8Array([0x4c, n]), data]);
  if (n <= 65535)
    return concat([new Uint8Array([0x4d, n & 0xff, (n >> 8) & 0xff]), data]);
  return concat(
    [new Uint8Array([0x4e, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]), data],
  );
}

/** Canonical Bitcoin "script number" (CScriptNum) encoding, little-endian
 *  sign-magnitude. `minimal` follows consensus IsCanonical encoding rules. */
export function scriptNum(n: bigint, opts: { bytes?: number; negative?: boolean } = {}): Uint8Array {
  if (n === 0n) return new Uint8Array(opts.bytes ? new Uint8Array(opts.bytes) : new Uint8Array(0));
  const neg = opts.negative ?? n < 0n;
  let v = n < 0n ? -n : n;
  const out: number[] = [];
  while (v > 0n) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  const top = out[out.length - 1] ?? 0;
  if (top & 0x80) out.push(neg ? 0x80 : 0x00);
  else if (neg) out[out.length - 1] = top | 0x80;
  let bytes = new Uint8Array(out);
  if (opts.bytes && bytes.length < opts.bytes) {
    const padded = new Uint8Array(opts.bytes);
    padded.set(bytes);
    if (neg) padded[opts.bytes - 1] = 0x80;
    bytes = padded;
  }
  return bytes;
}

export function hex(s: string): Uint8Array {
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return b;
}

export function concat(arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// --- compile -------------------------------------------------------------

/** `build()` narrows `CompileResult` to the fields every attack test needs.
 *  Without this the return type widens back to `scriptHex?: string` at the
 *  function boundary and every call site has to re-prove the guard that `build`
 *  already ran — which is how ~70 `string | undefined` errors showed up the
 *  first time this directory was typechecked. */
export type Compiled = Omit<CompileResult, 'scriptHex' | 'artifact'> & {
  readonly scriptHex: string;
  readonly artifact: RunarArtifact;
};

export function build(source: string, fileName: string, constructorArgs: Record<string, unknown> = {}): Compiled {
  const res = compile(source, { fileName, constructorArgs: constructorArgs as any });
  if (!res.success || !res.artifact || !res.scriptHex) {
    throw new Error(
      `compile failed: ${res.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('; ')}`,
    );
  }
  return { ...res, scriptHex: res.scriptHex, artifact: res.artifact };
}

export function asm(hexStr: string): string {
  return LockingScript.fromHex(hexStr).toASM();
}

function publicMethods(artifact: RunarArtifact): ABIMethod[] {
  return artifact.abi.methods.filter((m) => m.isPublic);
}

// --- single-input stateless spend ---------------------------------------

export interface SpendCtx {
  sourceSatoshis?: number;
  outputs?: Array<{ script: string; satoshis: number }>;
  locktime?: number;
  sequence?: number;
  version?: number;
  otherInputs?: Array<{ sourceTXID: string; sourceOutputIndex: number; sequence: number; satoshis: number; script: string }>;
}

/** The BIP-143 preimage bytes @bsv/sdk's Spend will build for this context. */
export function preimageFor(lockingHex: string, ctx: SpendCtx = {}): { bytes: Uint8Array; scope: number } {
  const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
  const bytes = TransactionSignature.formatBytes({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: ctx.sourceSatoshis ?? 100000,
    transactionVersion: ctx.version ?? 2,
    otherInputs: (ctx.otherInputs ?? []).map((i, idx) => ({
      inputIndex: idx,
      sourceTXID: i.sourceTXID,
      sourceOutputIndex: i.sourceOutputIndex,
      sequence: i.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: i.satoshis,
      lockingScript: LockingScript.fromHex(i.script),
    })),
    outputs: (ctx.outputs ?? []).map((o) => ({
      lockingScript: LockingScript.fromHex(o.script),
      satoshis: o.satoshis,
    })),
    inputIndex: 0,
    subscript: LockingScript.fromHex(lockingHex),
    inputSequence: ctx.sequence ?? 0xffffffff,
    lockTime: ctx.locktime ?? 0,
    scope,
  });
  return { bytes, scope };
}

/** Real DER signature (with sighash byte appended) for the given context. */
export function signFor(
  keyName: string,
  lockingHex: string,
  ctx: SpendCtx = {},
  scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID,
): string {
  const bytes = TransactionSignature.formatBytes({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: ctx.sourceSatoshis ?? 100000,
    transactionVersion: ctx.version ?? 2,
    otherInputs: (ctx.otherInputs ?? []).map((i, idx) => ({
      inputIndex: idx,
      sourceTXID: i.sourceTXID,
      sourceOutputIndex: i.sourceOutputIndex,
      sequence: i.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: i.satoshis,
      lockingScript: LockingScript.fromHex(i.script),
    })),
    outputs: (ctx.outputs ?? []).map((o) => ({
      lockingScript: LockingScript.fromHex(o.script),
      satoshis: o.satoshis,
    })),
    inputIndex: 0,
    subscript: LockingScript.fromHex(lockingHex),
    inputSequence: ctx.sequence ?? 0xffffffff,
    lockTime: ctx.locktime ?? 0,
    scope,
  });
  const digest = Hash.sha256(Array.from(bytes));
  const sig = PrivateKey.fromHex(key(keyName).privKey).sign(digest);
  return Array.from(new TransactionSignature(sig.r, sig.s, scope).toChecksigFormat())
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** A stack item given as a *payload*; the harness adds the push prefix. */
export type StackItem = Uint8Array | string | bigint | boolean | { raw: Uint8Array };

export function encodeStackItem(item: StackItem): Uint8Array {
  if (typeof item === 'object' && item !== null && 'raw' in item) return item.raw;
  if (typeof item === 'string') return push(hex(item));
  if (typeof item === 'bigint') return push(scriptNum(item));
  if (typeof item === 'boolean') return new Uint8Array([item ? 0x51 : 0x00]);
  return push(item);
}

export interface StatelessAttack {
  /** Stack items in unlocking-script order (first ends up deepest). */
  stack?: StackItem[];
  /** Fully-encoded unlocking script (used instead of `stack` when set). */
  raw?: Uint8Array;
  ctx?: SpendCtx;
}

export interface AttackResult {
  ok: boolean;
  error?: string;
  lockingHex: string;
  unlockingHex: string;
  asm: string;
}

/** Spend a stateless contract UTXO with a hand-built unlocking script. */
export function spendStateless(
  compiled: { scriptHex: string },
  attack: StatelessAttack,
): AttackResult {
  const encoded = attack.raw ?? concat((attack.stack ?? []).map(encodeStackItem));
  const unlockingHex = Array.from(encoded)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const ctx = attack.ctx ?? {};
  let ok = false;
  let error: string | undefined;
  try {
    const spend = new Spend({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: ctx.sourceSatoshis ?? 100000,
      lockingScript: LockingScript.fromHex(compiled.scriptHex),
      transactionVersion: ctx.version ?? 2,
      otherInputs: (ctx.otherInputs ?? []).map((i, idx) => ({
        inputIndex: idx,
        sourceTXID: i.sourceTXID,
        sourceOutputIndex: i.sourceOutputIndex,
        sequence: i.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: i.satoshis,
        lockingScript: LockingScript.fromHex(i.script),
      })),
      outputs: (ctx.outputs ?? []).map((o) => ({
        lockingScript: LockingScript.fromHex(o.script),
        satoshis: o.satoshis,
      })),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      inputIndex: 0,
      inputSequence: ctx.sequence ?? 0xffffffff,
      lockTime: ctx.locktime ?? 0,
    });
    ok = spend.validate();
    if (!ok) error = 'script returned false / empty stack';
  } catch (e) {
    ok = false;
    error = e instanceof Error ? e.message : String(e);
  }
  return { ok, error, lockingHex: compiled.scriptHex, unlockingHex, asm: asm(compiled.scriptHex) };
}

// --- stateful deploy -> call --------------------------------------------

export interface StatefulRun {
  artifact: RunarArtifact;
  provider: MockProvider;
  contract: RunarContract;
  deployTx: Transaction;
  callTx: Transaction;
}

export async function deployAndCall(
  source: string,
  fileName: string,
  constructorArgs: unknown[],
  method: string,
  args: unknown[],
  opts: {
    /** Named constructor values for compile-time baking of readonly props. */
    bake?: Record<string, unknown>;
    signerKey?: string;
    /** Signer for the method call (defaults to `signerKey`). */
    callSignerKey?: string;
    fundingSatoshis?: number;
    callFundingSatoshis?: number;
    deployOptions?: Record<string, unknown>;
    callOptions?: Record<string, unknown>;
    /** Skip the call (deploy only). */
    deployOnly?: boolean;
  } = {},
): Promise<StatefulRun> {
  const res = build(source, fileName, opts.bake ?? {});
  const artifact = res.artifact!;
  const keyName = opts.signerKey ?? 'alice';
  const k = key(keyName);
  const signer = new LocalSigner(k.privKey);
  const provider = new MockProvider();
  const address = await signer.getAddress();
  provider.addUtxo(address, {
    txid: k.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: fundingFor(opts.deployOptions?.satoshis as number | undefined, opts.fundingSatoshis ?? 500_000),
    script: buildP2PKHScript(k.pubKey),
  });
  const contract = new RunarContract(artifact, constructorArgs as any);
  if (opts.callSignerKey && opts.callSignerKey !== keyName) {
    const callSigner = new LocalSigner(key(opts.callSignerKey).privKey);
    const callAddress = await callSigner.getAddress();
    provider.addUtxo(callAddress, {
      txid: key(opts.callSignerKey).privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: fundingFor(opts.callOptions?.satoshis as number | undefined, opts.callFundingSatoshis ?? 500_000),
      script: buildP2PKHScript(key(opts.callSignerKey).pubKey),
    });
  }
  await contract.deploy(provider, signer, (opts.deployOptions ?? {}) as any);
  if (opts.deployOnly) {
    return { artifact, provider, contract, deployTx: Transaction.fromHex(provider.getBroadcastedTxs()[0]!), callTx: undefined as unknown as Transaction };
  }
  await contract.call(method, args, provider, new LocalSigner(key(opts.callSignerKey ?? keyName).privKey), opts.callOptions as any);
  const txs = provider.getBroadcastedTxs();
  return {
    artifact,
    provider,
    contract,
    deployTx: Transaction.fromHex(txs[0]!),
    callTx: Transaction.fromHex(txs[1]!),
  };
}

/** Validate one input of a real transaction against its source output. */
export function validateInput(
  tx: Transaction,
  inputIdx: number,
  sourceTx: Transaction,
  sourceOutputIdx: number,
  mutate?: (tx: Transaction) => void,
): Verdict {
  const work = Transaction.fromHex(tx.toHex());
  mutate?.(work);
  const input = work.inputs[inputIdx]!;
  const sourceOutput = sourceTx.outputs[sourceOutputIdx]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: sourceOutput.lockingScript,
    transactionVersion: work.version,
    otherInputs: work.inputs
      .filter((_: unknown, i: number) => i !== inputIdx)
      .map((inp: any, idx: number) => ({
        inputIndex: idx >= inputIdx ? idx + 1 : idx,
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: undefined as never,
        sourceSatoshis: 0,
        lockingScript: LockingScript.fromHex(''),
      })),
    outputs: work.outputs.map((o) => ({
      lockingScript: o.lockingScript,
      satoshis: o.satoshis ?? 0,
    })),
    unlockingScript: input.unlockingScript!,
    inputIndex: inputIdx,
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: work.lockTime,
  });
  try {
    return { ok: spend.validate() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export function stateOf(artifact: RunarArtifact, tx: Transaction, outputIdx = 0) {
  return extractStateFromScript(artifact, tx.outputs[outputIdx]!.lockingScript.toHex());
}

export function methodAbi(artifact: RunarArtifact, name: string): ABIMethod {
  const m = publicMethods(artifact).find((m) => m.name === name);
  if (!m) throw new Error(`no public method ${name}`);
  return m;
}

export { publicMethods };

/**
 * Deploy then run a chain of method calls, each signed by a possibly
 * different key, returning every transaction so a test can validate step i
 * against its real parent (output 0 of step i-1).
 */
export async function callChain(
  source: string,
  fileName: string,
  constructorArgs: unknown[],
  bake: Record<string, unknown>,
  steps: Array<{
    method: string;
    args: unknown[];
    signerKey: string;
    callOptions?: Record<string, unknown>;
  }>,
  deployOptions: Record<string, unknown> = {},
  funding = 500_000,
): Promise<{ artifact: RunarArtifact; txs: Transaction[]; contract: RunarContract; provider: MockProvider }> {
  const res = build(source, fileName, bake);
  const artifact = res.artifact!;
  const provider = new MockProvider();
  const first = key(steps[0]!.signerKey);
  const signer0 = new LocalSigner(first.privKey);
  provider.addUtxo(await signer0.getAddress(), {
    txid: first.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: fundingFor(deployOptions.satoshis as number | undefined, funding),
    script: buildP2PKHScript(first.pubKey),
  });
  for (const s of steps.slice(1)) {
    const k = key(s.signerKey);
    const sg = new LocalSigner(k.privKey);
    provider.addUtxo(await sg.getAddress(), {
      txid: k.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: funding,
      script: buildP2PKHScript(k.pubKey),
    });
  }
  const contract = new RunarContract(artifact, constructorArgs as any);
  await contract.deploy(provider, signer0, deployOptions as any);
  const txs = [Transaction.fromHex(provider.getBroadcastedTxs()[0]!)];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i]!;
    await contract.call(s.method, s.args, provider, new LocalSigner(key(s.signerKey).privKey), (s.callOptions ?? {}) as any);
    txs.push(Transaction.fromHex(provider.getBroadcastedTxs()[i + 1]!));
  }
  return { artifact, txs, contract, provider };
}
