// ---------------------------------------------------------------------------
// runar-sdk/contract.ts — Main contract runtime wrapper
// ---------------------------------------------------------------------------

import type { RunarArtifact, ABIMethod } from 'runar-ir-schema';
import { InputLimits } from 'runar-ir-schema';
import { assertScriptHexUnderLimit, WitnessValueMissingError } from './errors.js';
import type { Provider } from './providers/provider.js';
import { txToTransactionData } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { TransactionData, UTXO, DeployOptions, CallOptions, PreparedCall } from './types.js';
import type { Inscription } from './ordinals/types.js';
import { buildDeployTransaction, selectUtxos } from './deployment.js';
import { buildCallTransaction, resolveInputSequence } from './calling.js';
import { serializeState, extractStateFromScript, findLastOpReturn } from './state.js';
import { computeOpPushTx } from './oppushtx.js';
import { buildP2PKHScript, extractConstructorArgs } from './script-utils.js';
import { computeNewStateAndDataOutputs } from './anf-interpreter.js';
import type { OrderedOutputEntry } from './anf-interpreter.js';
import { buildInscriptionEnvelope, parseInscriptionEnvelope } from './ordinals/envelope.js';
import { Utils, Hash, Transaction as BsvTransaction, LockingScript, UnlockingScript, Spend } from '@bsv/sdk';
import { WalletProvider } from './providers/wallet-provider.js';
import { detachUnlockingScript } from './spend-safety.js';

/**
 * Deep-review finding C8: opt-out for `finalizeCall`'s pre-broadcast local
 * dry-run, plus the internal field that carries it from `prepareCall` to
 * `finalizeCall`.
 *
 * This augments (does not redeclare) `CallOptions`/`PreparedCall` from
 * `./types.js` — kept here rather than in types.ts so this change stays
 * scoped to contract.ts, its only reader/writer, while that file is being
 * edited concurrently by other work in this tree.
 */
declare module './types.js' {
  interface CallOptions {
    /**
     * Run a local pre-broadcast Spend dry-run of the primary contract input
     * before `finalizeCall` broadcasts (deep-review C8). The dry-run replays
     * the fully-signed input through @bsv/sdk's production `Spend`
     * interpreter (real BIP-143, real OP_CHECKSIG) and throws instead of
     * broadcasting when the input would be rejected on-chain.
     *
     * **Default: OFF (opt-in).** C8 asked for this to default ON, and that is
     * still the goal — but it is not yet safe to. The local harness currently
     * produces at least one FALSE REJECTION: it rejects `Auction.bid()`
     * (`codeseparator-signing.test.ts`, a real contract signed by a real
     * `LocalSigner`) with "OP_CHECKSIGVERIFY requires that a valid signature
     * is provided", while the independent real-crypto oracle
     * (`conformance/witnesses/real-crypto/auction.json`, which drives the same
     * method deploy->call->Spend through `runStatefulSpend`) ACCEPTS it — so
     * the transaction is valid and the dry-run's tx modelling is wrong, not
     * the signature. Nine other pre-existing tests fail the same way on
     * synthetic stub artifacts whose scripts do not consume their pushed args
     * (clean-stack violations).
     *
     * For a FAIL-CLOSED pre-broadcast gate a false rejection is worse than the
     * hole it closes: it would block legitimate calls and strand funds. So the
     * capability ships opt-in until its fidelity is proven against the
     * real-crypto oracle across the fixture corpus. Flip the default to ON
     * once `dryRunContractInput` agrees with `runStatefulSpend` on every
     * `witnesses/real-crypto/*.json` accept case.
     *
     * Set `true` to opt in. Do not enable it for setups the local harness
     * cannot model — e.g. a covenant whose correctness depends on OTHER
     * inputs' final scripts that aren't known yet at `finalizeCall` time
     * (multi-party assembly finished by a later step), or a
     * deliberately-invalid tx built for negative testing.
     */
    dryRun?: boolean;
  }
  interface PreparedCall {
    /** @internal C8 — carries CallOptions.dryRun into finalizeCall. */
    _dryRun: boolean;
  }
}

/**
 * Producer-side marker (issue #106) for the deliberately-empty branch of an
 * OR-CHECKSIG method — `checkSig(sigA, pkA) || checkSig(sigB, pkB)`, where
 * `||` lowers to the non-lazy `OP_BOOLOR` so BOTH `OP_CHECKSIG`s run. Only the
 * matching branch supplies a real signature; the failing branch MUST push an
 * empty signature (OP_0) or BIP146 NULLFAIL rejects the whole spend.
 *
 * Pass `EMPTY_SIG` as the call arg for the non-matching `Sig` slot: the SDK
 * pushes OP_0 for it and never signs it, distinct from `null` (auto-sign) and
 * an explicit hex-bytes value. Coexists with `null` at the same call —
 * `call('execute', [null, EMPTY_SIG])` signs only slot 0.
 *
 * Uses the global symbol registry so identity holds across duplicate module
 * instances (bundlers).
 */
export const EMPTY_SIG: unique symbol = Symbol.for('runar.sdk.emptySig');

/**
 * Deep-review finding C29: `PreparedCall` hands the caller a live, mutable
 * `Transaction` (`prepared.tx`) with no consume guard. `finalizeCall`
 * mutates `prepared.tx.inputs[0].unlockingScript` in place and broadcasts —
 * nothing stops the SAME `PreparedCall` from being finalized a second time
 * against a tx that has already been consumed (and, on a real network,
 * already spent), producing signatures that no longer correspond to a
 * fresh, still-live UTXO.
 *
 * Tracked by object identity (not a field on `PreparedCall` itself) so the
 * public shape stays untouched — a `WeakSet` also lets consumed entries be
 * garbage-collected once the caller drops its reference. Full
 * freezing/defensive-copying of `prepared.tx` was considered but rejected:
 * `finalizeCall` itself must mutate `prepared.tx` in place to insert the
 * final unlocking script, so freezing the object would break the one
 * caller that legitimately needs to write to it.
 */
const consumedPreparedCalls = new WeakSet<PreparedCall>();

/** Type guard: is this call arg the {@link EMPTY_SIG} marker (issue #106)? */
export function isEmptySig(value: unknown): value is typeof EMPTY_SIG {
  return value === EMPTY_SIG;
}

/**
 * True when the locking script looks like OR-CHECKSIG (OP_BOOLOR + OP_CHECKSIG)
 * rather than multi-sig (OP_CHECKMULTISIG). Used to scope the multi-null-Sig
 * soft warning so genuine checkMultiSig unlocks are not spammed.
 *
 * Exported for unit tests.
 */
export function isLikelyOrCheckSigMethod(artifact: {
  asm?: string;
  script?: string;
  scriptHex?: string;
}): boolean {
  const asm = (artifact.asm ?? '').toUpperCase();
  if (asm.includes('OP_CHECKMULTISIG')) {
    return false;
  }
  if (asm.includes('OP_BOOLOR') && asm.includes('OP_CHECKSIG')) {
    return true;
  }
  // Fall back to hex when ASM is missing: OP_CHECKMULTISIG=0xae, OP_BOOLOR=0x9a
  const hex = (artifact.script ?? artifact.scriptHex ?? '').toLowerCase();
  if (hex.includes('ae') || hex.includes('af')) {
    // May false-positive inside push data; prefer ASM. If ASM empty and we see
    // ae, treat as multi-sig (safe: suppresses warning for MultiSig contracts).
    if (!asm) return false;
  }
  return false;
}

/**
 * Invalidate the @bsv/sdk Transaction's serialization caches after
 * directly modifying inputs/outputs. The SDK caches toHex()/toBinary()
 * results and only invalidates them through addInput/addOutput.
 */
function invalidateTxCache(tx: BsvTransaction): void {
  const t = tx as unknown as Record<string, unknown>;
  t.hexCache = undefined;
  t.rawBytesCache = undefined;
  t.cachedHash = undefined;
}

/**
 * The one ByteString parameter name whose `null` argument is auto-resolved to
 * the serialized outpoints of every input (deep-review finding G6). Must match
 * Go's `AutoPrevoutsParamName` and the Rust/Python/Ruby/Zig/Java equivalents —
 * this name is a cross-tier calling convention, not a per-tier ergonomic.
 */
const AUTO_PREVOUTS_PARAM_NAME = 'allPrevouts';

/**
 * Deep-review finding C8: offline dry-run of ONE input of a fully-assembled
 * tx through @bsv/sdk's production `Spend` interpreter (real `OP_CHECKSIG`,
 * real BIP-143). Used by `finalizeCall` to fail closed on a script-invalid
 * (or, via its caller, underfunded) tx BEFORE it reaches `provider.broadcast`.
 *
 * Deliberately self-contained rather than imported from `multi-contract.ts`
 * (which already has an equivalent `dryRunMultiContractInput`): that module
 * imports `encodeArg`/`encodePushData`/`encodeScriptNumber` FROM this file,
 * so importing back from it here would create a contract.ts <-> multi-contract.ts
 * import cycle. Keep both thin wrappers in sync if `Spend`'s constructor shape
 * ever changes.
 */
function dryRunContractInput(
  tx: BsvTransaction,
  inputIndex: number,
  utxoScriptHex: string,
  utxoSatoshis: number,
): { valid: boolean; error?: string } {
  const input = tx.inputs[inputIndex];
  if (!input) return { valid: false, error: `no input at index ${inputIndex}` };
  // `otherInputs` feeds BIP-143's hashPrevouts/hashSequence, so what it
  // contains matters: it must be exactly the OTHER inputs (current one
  // excluded), in their original relative order, or the input's
  // OP_CHECKSIG(VERIFY) fails for a perfectly valid transaction — a false
  // rejection, which for a fail-closed pre-broadcast gate is worse than the
  // hole C8 closes. Normalize to exactly the projection the proven harnesses
  // use (`validateSpend` in the SDK spend tests and `runStatefulSpend` in
  // runar-testing's real-crypto oracle, both of which agree with the
  // network).
  //
  // P2 (testing-gap remediation): the per-entry stubbing below
  // (`unlockingScript`/`sourceSatoshis`/`lockingScript`, and each entry's
  // own re-indexed `inputIndex`) is belt-and-braces, not load-bearing for
  // the sighash — `TransactionSignature.formatBip143` (the function `Spend`
  // delegates to) only ever reads `sourceTXID`, `sourceOutputIndex`, and
  // `sequence` off each `otherInputs` entry. Verified equivalent to
  // `providers/mock.ts`'s `validateBroadcastTx`, which passes the raw
  // filtered `tx.inputs` slice straight through with none of this stubbing —
  // both produce an identical sighash as long as the filter excludes exactly
  // the current input and preserves order, which both do. Keep both thin
  // wrappers in sync if `TransactionSignature`'s field usage ever changes.
  const otherInputs = tx.inputs
    .filter((_, i) => i !== inputIndex)
    .map((inp, idx) => ({
      inputIndex: idx >= inputIndex ? idx + 1 : idx,
      sourceOutputIndex: inp.sourceOutputIndex,
      sourceTXID: inp.sourceTXID!,
      sequence: inp.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: 0,
      lockingScript: LockingScript.fromHex(''),
    }));
  try {
    const spend = new Spend({
      sourceTXID: input.sourceTXID!,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: utxoSatoshis,
      lockingScript: LockingScript.fromHex(utxoScriptHex),
      transactionVersion: tx.version,
      otherInputs: otherInputs as unknown as ConstructorParameters<typeof Spend>[0]['otherInputs'],
      outputs: tx.outputs,
      inputIndex,
      // NEW-005: `Spend` mutates the script it executes in place, so it must
      // never be handed the live in-flight input's own object — the dry-run
      // would corrupt every evaluation that follows it (including
      // `MockProvider.validateBroadcastTx`, one line later in `finalizeCall`).
      // See spend-safety.ts.
      unlockingScript: detachUnlockingScript(input.unlockingScript!),
      inputSequence: input.sequence ?? 0xffffffff,
      lockTime: tx.lockTime,
    });
    // P2: @bsv/sdk's `Spend.validate()` never actually returns `false` —
    // every failure path throws `ScriptEvaluationError` instead, so this
    // line always returns `{ valid: true }` when reached; every rejection
    // exits through the `catch` below. The `!!` is defensive belt-and-
    // braces in case a future @bsv/sdk version reverts to a boolean.
    return { valid: !!spend.validate() };
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Walk a hex-encoded script and return the byte offsets of every
 * OP_CODESEPARATOR (0xab) that sits at a real opcode boundary (i.e. not inside
 * push-data). Correctly skips all BSV push opcodes (0x01..0x4b,
 * OP_PUSHDATA1/2/4).
 *
 * Used by getSubscriptForSigning to recover the true on-chain byte offsets when
 * the in-memory constructor args don't reflect what was actually baked into the
 * locking script (e.g. after fromTxid populates dummy placeholders).
 */
export function findCodesepOffsets(scriptHex: string): number[] {
  const out: number[] = [];
  let off = 0;
  const n = scriptHex.length;
  const b = (i: number): number => {
    const v = parseInt(scriptHex.slice(i, i + 2), 16);
    return Number.isNaN(v) ? 0 : v;
  };
  while (off + 2 <= n) {
    const op = b(off);
    const bytePos = off / 2;
    if (op === 0xab) {
      out.push(bytePos);
      off += 2;
    } else if (op >= 0x01 && op <= 0x4b) {
      off += 2 + op * 2;
    } else if (op === 0x4c) {
      if (off + 4 > n) break;
      const pushLen = b(off + 2);
      off += 4 + pushLen * 2;
    } else if (op === 0x4d) {
      if (off + 6 > n) break;
      const lo = b(off + 2);
      const hi = b(off + 4);
      const pushLen = lo | (hi << 8);
      off += 6 + pushLen * 2;
    } else if (op === 0x4e) {
      if (off + 10 > n) break;
      const b0 = b(off + 2);
      const b1 = b(off + 4);
      const b2 = b(off + 6);
      const b3 = b(off + 8);
      // >>> 0 forces uint32: with b3 >= 0x80 the signed OR result is negative,
      // which would walk the cursor backwards and never terminate the scan.
      const pushLen = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
      // A declared push length past the script end means a malformed script;
      // stop scanning rather than skipping into nothing.
      if (pushLen > (n - off - 10) / 2) break;
      off += 10 + pushLen * 2;
    } else {
      off += 2;
    }
  }
  return out;
}

/**
 * Runtime wrapper for a compiled Runar contract.
 *
 * Handles deployment, method invocation, state tracking, and script
 * construction. Works with any Provider and Signer implementation.
 *
 * ```ts
 * const artifact = JSON.parse(fs.readFileSync('./artifacts/Counter.json', 'utf8'));
 * const contract = new RunarContract(artifact, [0n]); // constructor args
 * const { txid } = await contract.deploy(provider, signer, { satoshis: 10000 });
 * ```
 */
export class RunarContract {
  readonly artifact: RunarArtifact;
  /**
   * Constructor arguments for the contract, typed as `unknown[]` because
   * they can be any of the Runar primitive types: `bigint`, `boolean`,
   * `ByteString` (hex string), `PubKey` (hex string), etc. TypeScript
   * generics are not practical here since the types depend on the specific
   * contract being used and are only known at runtime from the ABI.
   */
  private readonly constructorArgs: unknown[];
  private _state: Record<string, unknown> = {};
  private _codeScript: string | null = null;
  private _inscription: Inscription | null = null;
  private currentUtxo: UTXO | null = null;
  /** Returns the current UTXO tracked by this contract, if any. */
  getUtxo(): UTXO | null { return this.currentUtxo; }
  private _provider: Provider | null = null;
  private _signer: Signer | null = null;
  /**
   * Witness values for intent-covenant intrinsic auto-injected params.
   * `_prevOutScript_<i>` values are stored per-input-index in `_prevOutScripts`;
   * `_serialisedOutputs` is stored in `_serialisedOutputs`. Both are hex strings
   * (normalized in the setters). Read by the call-builder when assembling the
   * unlocking script for methods that use `extractPrevOutputScript` /
   * `requireOutputP2PKH`.
   */
  private _prevOutScripts: Map<number, string> = new Map();
  private _serialisedOutputs: string | null = null;

  constructor(artifact: RunarArtifact, constructorArgs: unknown[]) {
    this.artifact = artifact;
    this.constructorArgs = constructorArgs;

    // Validate constructor args match ABI
    const expected = artifact.abi.constructor.params.length;
    if (constructorArgs.length !== expected) {
      throw new Error(
        `RunarContract: expected ${expected} constructor args for ${artifact.contractName}, got ${constructorArgs.length}`,
      );
    }

    // Initialize state from constructor args for stateful contracts.
    // Properties with initialValue use their default; others are matched
    // to constructor args by name lookup in the ABI constructor params.
    if (artifact.stateFields && artifact.stateFields.length > 0) {
      for (const field of artifact.stateFields) {
        const fa = (field as { fixedArray?: { elementType: string; length: number; syntheticNames: string[] } }).fixedArray;
        if (fa) {
          // FixedArray state field. The assembler stores `initialValue`
          // (when every element has a compile-time default) as a real
          // JS array of element values — no more stringified-tuple
          // parsing. For nested arrays the stored value is a nested
          // JS array mirroring the declared shape. Leaf values may
          // still be bigint-as-string when the artifact was loaded
          // via a plain JSON import without the custom reviver, so
          // walk the tree and revive each leaf.
          const rawInit = (field as { initialValue?: unknown }).initialValue;
          if (Array.isArray(rawInit)) {
            this._state[field.name] = reviveNestedValue(rawInit, field.type);
          } else if (rawInit !== undefined) {
            // Defensive: we shouldn't hit this path anymore, but if a
            // third-party producer emits a scalar where we expect an
            // array, keep the value as-is instead of crashing.
            this._state[field.name] = rawInit;
          } else {
            const paramIdx = artifact.abi.constructor.params.findIndex(p => p.name === field.name);
            if (paramIdx >= 0 && paramIdx < constructorArgs.length) {
              this._state[field.name] = constructorArgs[paramIdx];
            } else if (field.index < constructorArgs.length) {
              this._state[field.name] = constructorArgs[field.index];
            }
          }
          continue;
        }
        if ((field as { initialValue?: unknown }).initialValue !== undefined) {
          // Property has a compile-time default value.
          // Revive BigInt strings ("0n") that occur when artifacts are loaded
          // via plain JSON import (without the bigintReviver).
          this._state[field.name] = reviveJsonValue((field as { initialValue: unknown }).initialValue, field.type);
        } else {
          // Match by name to constructor params
          const paramIdx = artifact.abi.constructor.params.findIndex(p => p.name === field.name);
          if (paramIdx >= 0 && paramIdx < constructorArgs.length) {
            this._state[field.name] = constructorArgs[paramIdx];
          } else if (field.index < constructorArgs.length) {
            // Fallback: use declaration index for backward compatibility
            this._state[field.name] = constructorArgs[field.index];
          }
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Connection
  // -------------------------------------------------------------------------

  /**
   * Store a provider and signer on this contract so they don't need to be
   * passed to every `deploy()` and `call()` invocation.
   */
  connect(provider: Provider, signer: Signer): void {
    this._provider = provider;
    this._signer = signer;
  }

  // -------------------------------------------------------------------------
  // Ordinals
  // -------------------------------------------------------------------------

  /**
   * Attach a 1sat ordinals inscription to this contract. The inscription
   * envelope is injected into the locking script between the compiled code
   * and the state section (if any). Once deployed, the inscription is
   * immutable — it persists identically across all state transitions.
   *
   * ```ts
   * contract.withInscription({ contentType: 'image/png', data: pngHex });
   * ```
   */
  withInscription(inscription: Inscription): this {
    this._inscription = inscription;
    return this;
  }

  /** Returns the current inscription, if any. */
  get inscription(): Inscription | null {
    return this._inscription;
  }

  /**
   * Resolve provider/signer: explicit args win, then connected, then error.
   */
  private resolveProviderSigner(
    provider?: Provider,
    signer?: Signer,
  ): { provider: Provider; signer: Signer } {
    const p = provider ?? this._provider;
    const s = signer ?? this._signer;
    if (!p || !s) {
      throw new Error(
        'No provider/signer available. Call connect() or pass them explicitly.',
      );
    }
    return { provider: p, signer: s };
  }

  // -------------------------------------------------------------------------
  // Deployment
  // -------------------------------------------------------------------------

  /**
   * Deploy the contract by creating a UTXO with the locking script.
   *
   * Provider and signer can be passed explicitly or omitted to use
   * the ones stored via `connect()`.
   */
  async deploy(options: DeployOptions): Promise<{ txid: string; tx: TransactionData }>;
  async deploy(
    provider: Provider,
    signer: Signer,
    options: DeployOptions,
  ): Promise<{ txid: string; tx: TransactionData }>;
  async deploy(
    providerOrOptions: Provider | DeployOptions,
    maybeSigner?: Signer,
    maybeOptions?: DeployOptions,
  ): Promise<{ txid: string; tx: TransactionData }> {
    let provider: Provider;
    let signer: Signer;
    let options: DeployOptions;

    if (maybeSigner !== undefined && maybeOptions !== undefined) {
      // Explicit: deploy(provider, signer, options)
      provider = providerOrOptions as Provider;
      signer = maybeSigner;
      options = maybeOptions;
    } else if (
      typeof providerOrOptions === 'object' &&
      !('getUtxos' in providerOrOptions)
    ) {
      // Connected: deploy(options)
      const resolved = this.resolveProviderSigner();
      provider = resolved.provider;
      signer = resolved.signer;
      options = providerOrOptions as DeployOptions;
    } else {
      throw new Error(
        'RunarContract.deploy: invalid arguments. Pass (options) or (provider, signer, options).',
      );
    }

    const address = await signer.getAddress();
    const changeAddress = options.changeAddress ?? address;
    const deploySatoshis = options.satoshis ?? 1;
    const lockingScript = this.getLockingScript();

    // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
    assertScriptHexUnderLimit(
      lockingScript,
      InputLimits.MAX_SCRIPT_BYTES,
      `${this.artifact.contractName}.deploy`,
    );

    // Fetch fee rate and funding UTXOs
    const feeRate = await provider.getFeeRate();
    const allUtxos = await provider.getUtxos(address);
    if (allUtxos.length === 0) {
      throw new Error(`RunarContract.deploy: no UTXOs found for address ${address}`);
    }
    const utxos = selectUtxos(allUtxos, deploySatoshis, lockingScript.length / 2, feeRate);

    // Build the deploy transaction
    const changeScript = buildP2PKHScript(changeAddress);
    const { tx, inputCount } = buildDeployTransaction(
      lockingScript,
      utxos,
      deploySatoshis,
      changeAddress,
      changeScript,
      feeRate,
    );

    // Sign all inputs — need unsigned hex for signer. Funding inputs are
    // signed by fundingSigner when set (issue #134): the deploy signer may not
    // own the funding coins. Defaults to the connected signer.
    const fundingSigner = options.fundingSigner ?? signer;
    const unsignedHex = tx.toHex();
    for (let i = 0; i < inputCount; i++) {
      const utxo = utxos[i]!;
      const sig = await fundingSigner.sign(unsignedHex, i, utxo.script, utxo.satoshis);
      const pubKey = await fundingSigner.getPublicKey();
      // Build P2PKH unlocking script: <sig> <pubkey>
      const unlockScript = encodePushData(sig) + encodePushData(pubKey);
      tx.inputs[i]!.unlockingScript = UnlockingScript.fromHex(unlockScript);
    }
    invalidateTxCache(tx);

    // Broadcast
    const txid = await provider.broadcast(tx);

    // Track the deployed UTXO
    this.currentUtxo = {
      txid,
      outputIndex: 0,
      satoshis: deploySatoshis,
      script: lockingScript,
    };

    const txData = await provider.getTransaction(txid).catch((err) => {
      // Audit finding C4: the fallback reports the transaction this SDK
      // actually broadcast, not an empty `inputs: []` / `outputs: []` shell
      // that reads as a real confirmed tx. The warn stays — this is
      // locally-derived, unconfirmed data.
      console.warn('Failed to fetch transaction after broadcast:', err);
      return txToTransactionData(txid, tx);
    });

    return { txid, tx: txData };
  }

  /**
   * Deploy the contract using a BRC-100 wallet. The wallet owns the coins
   * and creates the transaction itself via `createAction()`.
   *
   * Requires the contract to be connected to a `WalletProvider` (via `connect()`).
   *
   * @param options.satoshis     - Satoshis to lock in the contract output (default: 1).
   * @param options.description  - Description for the wallet action.
   */
  async deployWithWallet(options: {
    satoshis?: number;
    description?: string;
  } = {}): Promise<{ txid: string; outputIndex: number }> {
    if (!(this._provider instanceof WalletProvider)) {
      throw new Error(
        'deployWithWallet requires a connected WalletProvider. Call connect(walletProvider, signer) first.',
      );
    }
    const walletProvider = this._provider as WalletProvider;
    const wallet = walletProvider.walletClient;
    const basket = walletProvider.basketName;

    const lockingScript = this.getLockingScript();
    const satoshis = options.satoshis ?? 1;

    // DoS-bound: reject pathological scripts BEFORE involving the wallet.
    assertScriptHexUnderLimit(
      lockingScript,
      InputLimits.MAX_SCRIPT_BYTES,
      `${this.artifact.contractName}.deployWithWallet`,
    );

    const result = await wallet.createAction({
      description: options.description ?? 'Runar contract deployment',
      outputs: [{
        lockingScript,
        satoshis,
        outputDescription: `Deploy ${this.artifact.contractName}`,
        basket,
      }],
    });

    // Parse BEEF to find the correct vout for our locking script
    let outputIndex = 0;
    let actualSatoshis = satoshis;
    if (result.tx) {
      try {
        const tx = BsvTransaction.fromAtomicBEEF(result.tx);
        for (let i = 0; i < tx.outputs.length; i++) {
          const out = tx.outputs[i]!;
          if (out.lockingScript?.toHex() === lockingScript) {
            outputIndex = i;
            actualSatoshis = out.satoshis != null ? out.satoshis : satoshis;
            break;
          }
        }
        // Cache raw hex for EF child tx builds
        const txid = result.txid || '';
        if (txid) {
          walletProvider.cacheTx(txid, tx.toHex());
        }
        // Broadcast to ARC (may already be known — non-fatal)
        await walletProvider.broadcast(tx).catch(() => {});
      } catch { /* BEEF parse failure is non-fatal */ }
    }

    const txid = result.txid || '';

    // Track the deployed UTXO
    this.currentUtxo = {
      txid,
      outputIndex,
      satoshis: actualSatoshis,
      script: lockingScript,
    };

    return { txid, outputIndex };
  }

  // -------------------------------------------------------------------------
  // Method invocation
  // -------------------------------------------------------------------------

  /**
   * Call a public method on the contract (spend the UTXO).
   *
   * For stateful contracts, a new UTXO is created with the updated state.
   * Provider and signer can be passed explicitly or omitted to use
   * the ones stored via `connect()`.
   */
  async call(
    methodName: string,
    args: unknown[],
    options?: CallOptions,
  ): Promise<{ txid: string; tx: TransactionData }>;
  async call(
    methodName: string,
    args: unknown[],
    provider: Provider,
    signer: Signer,
    options?: CallOptions,
  ): Promise<{ txid: string; tx: TransactionData }>;
  async call(
    methodName: string,
    args: unknown[],
    providerOrOptions?: Provider | CallOptions,
    maybeSigner?: Signer,
    maybeOptions?: CallOptions,
  ): Promise<{ txid: string; tx: TransactionData }> {
    // If explicit provider/signer passed, temporarily connect them for
    // prepareCall / finalizeCall which use the connected references.
    if (maybeSigner !== undefined) {
      const prevProvider = this._provider;
      const prevSigner = this._signer;
      this._provider = providerOrOptions as Provider;
      this._signer = maybeSigner;
      try {
        const result = await this.call(methodName, args, maybeOptions);
        return result;
      } finally {
        this._provider = prevProvider;
        this._signer = prevSigner;
      }
    }

    let options: CallOptions | undefined;
    if (
      providerOrOptions === undefined ||
      (typeof providerOrOptions === 'object' &&
        !('getUtxos' in providerOrOptions))
    ) {
      options = providerOrOptions as CallOptions | undefined;
    } else {
      // providerOrOptions looks like a Provider but no signer — try connected
      const prevProvider = this._provider;
      this._provider = providerOrOptions as Provider;
      try {
        const result = await this.call(methodName, args, undefined);
        return result;
      } finally {
        this._provider = prevProvider;
      }
    }

    const prepared = await this.prepareCall(methodName, args, options);
    const signer = this._signer!;

    // Stateful contracts: checkPreimage is auto-injected at method entry, so
    // the user checkSig executes AFTER the OP_CODESEPARATOR — the sighash must
    // be computed over the subscript trimmed at that separator (issue #42: the
    // trim must land at the *real* on-chain codesep byte position, recovered by
    // getSubscriptForSigning's byte-walker).
    // Stateless contracts: the user controls statement order and may place
    // checkSig BEFORE the codesep (e.g. CovenantVault) — those must use the
    // FULL script, so the trim stays gated on the parent class. A stateful
    // contract with ZERO mutable fields (empty stateFields) still injects
    // checkPreimage at entry, so the trim is gated on `_parentStateful`
    // (artifact.parentClass), NOT `_isStateful` (issue #44).
    let mIdx = 0;
    if (prepared._parentStateful) {
      const pubMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
      if (pubMethods.length > 1) {
        const idx = pubMethods.findIndex((m) => m.name === methodName);
        if (idx >= 0) mIdx = idx;
      }
    }
    const sigSubscript = prepared._parentStateful
      ? this.getSubscriptForSigning(prepared._contractUtxo.script, mIdx)
      : prepared._contractUtxo.script;

    const signatures: Record<number, string> = {};
    const txHex = prepared.tx.toHex();
    for (const idx of prepared.sigIndices) {
      signatures[idx] = await signer.sign(
        txHex, 0, sigSubscript,
        prepared._contractUtxo.satoshis,
      );
    }
    return this.finalizeCall(prepared, signatures);
  }

  // -------------------------------------------------------------------------
  // prepareCall / finalizeCall — multi-signer support
  // -------------------------------------------------------------------------

  /**
   * Build the transaction for a method call without signing the primary
   * contract input's Sig params. Returns a `PreparedCall` containing the
   * BIP-143 sighash that external signers need, plus opaque internals for
   * `finalizeCall()`.
   *
   * P2PKH funding inputs and additional contract inputs ARE signed with the
   * connected signer. Only the primary contract input's Sig params are left
   * as 72-byte placeholders.
   */
  async prepareCall(
    methodName: string,
    args: unknown[],
    options?: CallOptions,
  ): Promise<PreparedCall> {
    const { provider, signer } = this.resolveProviderSigner();
    // Funding (and terminal fee) inputs are signed by fundingSigner when set
    // (issue #134). The method's own Sig args stay with the connected signer.
    const fundingSigner = options?.fundingSigner ?? signer;

    const method = this.findMethod(methodName);
    if (!method) {
      throw new Error(
        `RunarContract.prepareCall: method '${methodName}' not found in ${this.artifact.contractName}`,
      );
    }

    const isStateful =
      this.artifact.stateFields !== undefined &&
      this.artifact.stateFields.length > 0;
    // `isStateful` (derived from non-empty stateFields) drives continuation
    // params, op_push_tx, change outputs, etc. But a StatefulSmartContract
    // with ZERO mutable fields has empty stateFields yet STILL auto-injects
    // checkPreimage at method entry — so its user checkSig runs AFTER the
    // OP_CODESEPARATOR and needs the issue-#42 subscript trim. The parentClass
    // is the authoritative signal for the trim gate (issue #44). Fall back to
    // `isStateful` for older artifacts that predate the parentClass field.
    const parentStateful =
      this.artifact.parentClass !== undefined
        ? this.artifact.parentClass === 'StatefulSmartContract'
        : isStateful;
    const methodNeedsChange = method.params.some((p) => p.name === '_changePKH');
    const methodNeedsNewAmount = method.params.some((p) => p.name === '_newAmount');
    // Whether the unlocking script is prefixed with `_codePart`. New artifacts
    // carry the authoritative `usesCodePart` flag (true for continuation
    // builders AND terminal var-length-state readers — issue #100). Older
    // artifacts lack it; fall back to the legacy rule (codePart iff continuation).
    const methodUsesCodePart = method.usesCodePart ?? methodNeedsChange;
    // Drop auto-injected continuation params AND intent-intrinsic witness
    // params (`_prevOutScript_<i>`, `_serialisedOutputs`) from the
    // user-facing arg count check. Witness values come from
    // setPrevOutScript / setSerialisedOutputs, not from the args array.
    const isAutoInjectedWitnessParam = (name: string): boolean =>
      name.startsWith('_prevOutScript_') || name === '_serialisedOutputs';
    const userParams = isStateful
      ? method.params.filter(
          (p) =>
            p.type !== 'SigHashPreimage' &&
            p.name !== '_changePKH' &&
            p.name !== '_changeAmount' &&
            p.name !== '_newAmount' &&
            !isAutoInjectedWitnessParam(p.name),
        )
      : method.params.filter((p) => !isAutoInjectedWitnessParam(p.name));

    if (userParams.length !== args.length) {
      throw new Error(
        `RunarContract.prepareCall: method '${methodName}' expects ${userParams.length} args, got ${args.length}`,
      );
    }

    if (!this.currentUtxo) {
      throw new Error(
        'RunarContract.prepareCall: contract is not deployed. Call deploy() or fromTxId() first.',
      );
    }

    // DoS-bound: reject pathological scripts BEFORE any signing / broadcast.
    // Guards the current locking script (existing UTXO) AND the new locking
    // script if this is a stateful continuation, since both cross the wire.
    assertScriptHexUnderLimit(
      this.currentUtxo.script,
      InputLimits.MAX_SCRIPT_BYTES,
      `${this.artifact.contractName}.call(${methodName})`,
    );

    const contractUtxo: UTXO = { ...this.currentUtxo };
    const address = await signer.getAddress();
    const changeAddress = options?.changeAddress ?? address;

    // Detect auto-compute params (user passed null)
    const sigIndices: number[] = [];
    const prevoutsIndices: number[] = [];
    let preimageIndex = -1;
    const resolvedArgs = [...args];
    for (let i = 0; i < userParams.length; i++) {
      if (userParams[i]!.type === 'Sig' && args[i] === null) {
        sigIndices.push(i);
        resolvedArgs[i] = '00'.repeat(72); // placeholder
      }
      if (userParams[i]!.type === 'PubKey' && args[i] === null) {
        resolvedArgs[i] = await signer.getPublicKey();
      }
      if (userParams[i]!.type === 'SigHashPreimage' && args[i] === null) {
        preimageIndex = i;
        resolvedArgs[i] = '00'.repeat(181);
      }
      if (userParams[i]!.type === 'ByteString' && args[i] === null) {
        // Finding G6: this stub used to be TYPE-blind — ANY null ByteString got
        // the allPrevouts outpoint stub, so a caller who passed null for an
        // ordinary ByteString param (say `memo`) silently got real outpoint
        // bytes spliced into their own parameter. That builds a tx which
        // broadcasts and then fails at script execution with an opaque error.
        // Gate on the documented parameter NAME instead: `allPrevouts` keeps
        // its auto-compute convention (used by the token-ft integration tests
        // across tiers), everything else fails loudly at build time naming the
        // offending parameter. Matches Go `isAutoPrevoutsParam`/`errNilNonSigArg`
        // and the Rust/Python/Ruby/Zig/Java equivalents.
        if (userParams[i]!.name !== AUTO_PREVOUTS_PARAM_NAME) {
          throw new Error(
            `RunarContract.prepareCall: null arg for ByteString param ` +
              `'${userParams[i]!.name}' (index ${i}): null is only auto-resolved for ` +
              `Sig (auto-signed), PubKey (taken from the signer), SigHashPreimage, ` +
              `and the '${AUTO_PREVOUTS_PARAM_NAME}' outpoint slot. Pass an explicit ` +
              `value (hex string, or '' for an empty ByteString).`,
          );
        }
        prevoutsIndices.push(i);
        const estimatedInputs = 1 + (options?.additionalContractInputs?.length ?? 0) + 1;
        resolvedArgs[i] = '00'.repeat(36 * estimatedInputs);
      }
      // EMPTY_SIG (issue #106) is intentionally NOT handled here: it is not
      // `null`, so it is never added to `sigIndices` and never signed. It stays
      // in `resolvedArgs` and `encodeArg` emits OP_0 (empty sig) for it.
    }

    // Soft heuristic (issue #106): more than one auto-signed Sig slot on an
    // OR-CHECKSIG method (`checkSig || checkSig` → OP_BOOLOR) usually means
    // the non-matching branch should use EMPTY_SIG — otherwise every branch
    // gets the same real signature and the failing CHECKSIG trips BIP146
    // NULLFAIL on broadcast.
    //
    // Do NOT warn for genuine multi-sig (OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY):
    // those require multiple real signatures (AND-style), not EMPTY_SIG.
    if (sigIndices.length >= 2 && isLikelyOrCheckSigMethod(this.artifact)) {
      console.warn(
        `runar-sdk: ${this.artifact.contractName}.call('${methodName}') has ` +
          `${sigIndices.length} auto-signed Sig slots. If this is an OR-CHECKSIG ` +
          `method, pass EMPTY_SIG for the non-matching branch(es) to satisfy ` +
          `BIP146 NULLFAIL (issue #106).`,
      );
    }

    const needsOpPushTx = preimageIndex >= 0 || isStateful;

    // Compute method selector and method index (needed for both terminal and non-terminal)
    let methodSelectorHex = '';
    let methodIndex = 0;
    if (isStateful) {
      const publicMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
      if (publicMethods.length > 1) {
        const idx = publicMethods.findIndex((m) => m.name === methodName);
        if (idx >= 0) {
          methodSelectorHex = encodeScriptNumber(BigInt(idx));
          methodIndex = idx;
        }
      }
    }

    // Compute change PKH for stateful methods that need it
    let changePKHHex = '';
    if (isStateful && methodNeedsChange) {
      const changePubKeyHex = options?.changePubKey ?? await signer.getPublicKey();
      const pubKeyBytes = Utils.toArray(changePubKeyHex, 'hex');
      const hash160Bytes = Hash.hash160(pubKeyBytes);
      changePKHHex = Utils.toHex(hash160Bytes);
    }

    // Pre-resolve intent-intrinsic witness hex (throws WitnessValueMissingError
    // if a `_prevOutScript_<i>` or `_serialisedOutputs` param wasn't set on the
    // contract). Resolving up-front means the error is raised BEFORE any
    // signing / broadcast work, mirroring the deploy/call script-size guard.
    const witnessHex = this.buildIntentWitnessHex(method);

    // -------------------------------------------------------------------
    // Terminal method path
    // -------------------------------------------------------------------
    if (options?.terminalOutputs) {
      const terminalOutputs = options.terminalOutputs;

      let termUnlockScript: string;
      if (needsOpPushTx) {
        termUnlockScript = encodePushData('00'.repeat(72)) +
          this.buildUnlockingScript(methodName, resolvedArgs);
      } else {
        termUnlockScript = this.buildUnlockingScript(methodName, resolvedArgs);
      }
      // Witness values are appended to the size-estimation script too so
      // the BIP-143 preimage sees the same input weight that the final
      // stateful unlock will produce (the real final unlock is built by
      // `buildUnlock` below which inserts witnessHex in the correct ABI slot).
      termUnlockScript += witnessHex;

      // Sequence (issue #131): all-final inputs make nLockTime a consensus
      // no-op — when a non-zero locktime is set, default to 0xfffffffe so the
      // terminal method's extractLocktime assertion is actually enforced.
      const termSequence = resolveInputSequence(options?.locktime, options?.sequence);

      const buildTerminalTx = (unlock: string): BsvTransaction => {
        const ttx = new BsvTransaction();
        // Terminal calls (auction close/claim/withdraw) typically assert
        // `extractLocktime(preimage) >= deadline`. Default 0 preserves legacy
        // behavior for contracts that don't check locktime.
        ttx.lockTime = options?.locktime ?? 0;
        ttx.addInput({
          sourceTXID: contractUtxo.txid,
          sourceOutputIndex: contractUtxo.outputIndex,
          unlockingScript: UnlockingScript.fromHex(unlock),
          sequence: termSequence,
        });
        // Fee input (issue #118): a plain P2PKH input added BEFORE the
        // OP_PUSH_TX preimage is computed so hashPrevouts covers it. Consumed
        // entirely as fee (no change output) — the covenant's terminal output
        // assertions are untouched; only the input side grows. Its P2PKH sig is
        // filled in after the tx structure is final (below).
        if (options?.feeUtxo) {
          ttx.addInput({
            sourceTXID: options.feeUtxo.txid,
            sourceOutputIndex: options.feeUtxo.outputIndex,
            unlockingScript: new UnlockingScript(),
            sequence: termSequence,
          });
        }
        for (const out of terminalOutputs) {
          ttx.addOutput({
            satoshis: out.satoshis,
            lockingScript: LockingScript.fromHex(out.scriptHex),
          });
        }
        return ttx;
      };

      let termTx = buildTerminalTx(termUnlockScript);
      let finalOpPushTxSig = '';
      let finalPreimage = '';

      if (isStateful) {
        // Build stateful terminal unlock with PLACEHOLDER user sigs
        const buildUnlock = (tx: BsvTransaction): { unlock: string; opSig: string; preimage: string } => {
          const { sigHex: opSig, preimageHex: preimage } = this.computeOpPushTxWithCodeSep(
            tx, 0, contractUtxo.script, contractUtxo.satoshis, methodIndex,
          );
          let argsHex = '';
          for (const arg of resolvedArgs) argsHex += encodeArg(arg);
          let changeHex = '';
          if (methodNeedsChange && changePKHHex) {
            changeHex = encodePushData(changePKHHex) + encodeArg(0n);
          }
          let newAmountHex = '';
          if (methodNeedsNewAmount) {
            newAmountHex = encodeArg(BigInt(contractUtxo.satoshis));
          }
          const unlock = this.buildStatefulPrefix(opSig, methodUsesCodePart) + argsHex + changeHex + newAmountHex + encodePushData(preimage) + witnessHex + methodSelectorHex;
          return { unlock, opSig, preimage };
        };

        // First pass
        const first = buildUnlock(termTx);
        termTx = buildTerminalTx(first.unlock);

        // Second pass
        const second = buildUnlock(termTx);
        termTx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(second.unlock);
        invalidateTxCache(termTx);
        finalOpPushTxSig = second.opSig;
        finalPreimage = second.preimage;
      } else if (needsOpPushTx || sigIndices.length > 0) {
        // Stateless terminal — keep placeholder sigs
        if (needsOpPushTx) {
          const { sigHex, preimageHex } = this.computeOpPushTxWithCodeSep(
            termTx, 0, contractUtxo.script, contractUtxo.satoshis, methodIndex,
          );
          finalOpPushTxSig = sigHex;
          resolvedArgs[preimageIndex] = preimageHex;
        }
        // Don't sign Sig params — keep 72-byte placeholders
        let realUnlock = this.buildUnlockingScript(methodName, resolvedArgs);
        if (needsOpPushTx && finalOpPushTxSig) {
          realUnlock = this.buildStatefulPrefix(finalOpPushTxSig) + realUnlock;
          termTx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(realUnlock);
          invalidateTxCache(termTx);
          const { sigHex: finalSig, preimageHex: finalPre } = this.computeOpPushTxWithCodeSep(
            termTx, 0, contractUtxo.script, contractUtxo.satoshis, methodIndex,
          );
          resolvedArgs[preimageIndex] = finalPre;
          finalOpPushTxSig = finalSig;
          finalPreimage = finalPre;
          realUnlock = this.buildStatefulPrefix(finalSig) +
            this.buildUnlockingScript(methodName, resolvedArgs);
        }
        termTx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(realUnlock);
        invalidateTxCache(termTx);
        if (!finalPreimage && needsOpPushTx) {
          finalPreimage = resolvedArgs[preimageIndex] as string;
        }
      }

      // Sign the fee input (issue #118). Its BIP-143 P2PKH sighash covers only
      // hashPrevouts / hashOutputs / its own outpoint — NOT input 0's scriptSig
      // — so it stays valid even after finalizeCall rewrites input 0. Owned by
      // fundingSigner ?? signer (composes with #134). The fee input sits at
      // index 1 (right after the primary contract input).
      if (options?.feeUtxo) {
        const feeInputIdx = 1;
        const feeTxHex = termTx.toHex();
        const feeSig = await fundingSigner.sign(
          feeTxHex, feeInputIdx, options.feeUtxo.script, options.feeUtxo.satoshis,
        );
        const feePubKey = await fundingSigner.getPublicKey();
        termTx.inputs[feeInputIdx]!.unlockingScript = UnlockingScript.fromHex(
          encodePushData(feeSig) + encodePushData(feePubKey),
        );
        invalidateTxCache(termTx);

        // #118: a feeUtxo is consumed ENTIRELY as fee — there is no change
        // output, because the covenant binds the exact terminal output set.
        // An oversized feeUtxo therefore silently BURNS the excess. Warn (but
        // never block) when it dwarfs the terminal tx's estimated fee.
        // Heuristic: excess is burned if the feeUtxo is > 5x the estimated fee
        // AND at least ~1000 sats of excess would be burned (an absolute floor
        // so a slightly-generous fee on a tiny tx does not nag). Best-effort:
        // any failure fetching the fee rate skips the advisory silently.
        try {
          const feeRate = await provider.getFeeRate(); // sat/KB
          const termTxSizeBytes = termTx.toHex().length / 2;
          const estimatedFee = Math.max(1, Math.ceil((termTxSizeBytes * feeRate) / 1000));
          const excess = options.feeUtxo.satoshis - estimatedFee;
          const OVERSIZE_FEE_MULTIPLE = 5;
          const OVERSIZE_MIN_EXCESS_SATS = 1000;
          if (
            options.feeUtxo.satoshis > estimatedFee * OVERSIZE_FEE_MULTIPLE &&
            excess > OVERSIZE_MIN_EXCESS_SATS
          ) {
            console.warn(
              `runar-sdk: ${this.artifact.contractName}.call('${methodName}'): feeUtxo is ` +
                `${options.feeUtxo.satoshis} sats but the terminal tx needs only ~${estimatedFee} sats ` +
                `of fee. A feeUtxo is consumed ENTIRELY as fee (no change output — the covenant binds ` +
                `the exact terminal outputs), so ~${excess} sats will be BURNED. Size the feeUtxo close ` +
                `to the intended fee (issue #118).`,
            );
          }
        } catch {
          // Advisory only — never fail a call because the fee-rate lookup threw.
        }
      }

      // Compute sighash from preimage (C19: the true BIP-143 digest external
      // signers must ECDSA-sign — hash256(preimage), not sha256(preimage)).
      const sighash = finalPreimage ? computeBip143Sighash(finalPreimage) : '';

      return {
        sighash,
        preimage: finalPreimage,
        opPushTxSig: finalOpPushTxSig,
        tx: termTx,
        sigIndices,
        _methodName: methodName,
        _resolvedArgs: resolvedArgs,
        _methodSelectorHex: methodSelectorHex,
        _isStateful: isStateful,
        _parentStateful: parentStateful,
        _isTerminal: true,
        _needsOpPushTx: needsOpPushTx,
        _methodNeedsChange: methodNeedsChange,
        _methodUsesCodePart: methodUsesCodePart,
        _changePKHHex: changePKHHex,
        _changeAmount: 0,
        _methodNeedsNewAmount: false,
        _newAmount: 0,
        _preimageIndex: preimageIndex,
        _contractUtxo: contractUtxo,
        _newLockingScript: '',
        _newSatoshis: 0,
        _hasMultiOutput: false,
        _contractOutputs: [],
        _intentWitnessHex: witnessHex,
        _dryRun: options?.dryRun ?? false,
      };
    }

    // -------------------------------------------------------------------
    // Non-terminal path
    // -------------------------------------------------------------------

    // Build the initial unlocking script (with placeholders). Intent-witness
    // hex is suffixed so size estimation (and any downstream
    // assertScriptHexUnderLimit / fee math) accounts for the witness pushes.
    // The real ABI-correct unlock is rebuilt by buildStatefulUnlock below for
    // stateful methods.
    let unlockingScript: string;
    if (needsOpPushTx) {
      unlockingScript = encodePushData('00'.repeat(72)) +
        this.buildUnlockingScript(methodName, resolvedArgs) + witnessHex;
    } else {
      unlockingScript = this.buildUnlockingScript(methodName, resolvedArgs) + witnessHex;
    }

    let newLockingScript: string | undefined;
    let newSatoshis: number | undefined;
    let contractOutputs: Array<{ script: string; satoshis: number }> | undefined;
    const extraContractUtxos = options?.additionalContractInputs ?? [];
    const hasMultiOutput = options?.outputs && options.outputs.length > 0;

    // Data outputs declared via this.addDataOutput(...). Explicit
    // options.dataOutputs wins; otherwise populated by the ANF
    // interpreter pass below.
    let resolvedDataOutputs: Array<{ script: string; satoshis: number }> =
      options?.dataOutputs
        ? options.dataOutputs.map((d) => ({ script: d.script, satoshis: Number(d.satoshis) }))
        : [];

    // Always run the ANF interpreter on stateful artifacts so addDataOutput
    // payloads are extracted even when the caller pre-supplied newState.
    // newState only overrides the state continuation; data outputs are
    // method-body behaviour and the on-chain continuation hash check fails
    // at spend time if they're omitted. Mirrors Go SDK + Ruby SDK.
    let autoComputedState: Record<string, unknown> | undefined;
    let autoFlatState: Record<string, unknown> | undefined;
    // State-class outputs (state continuation + raw) in source order, from the
    // ANF interpreter. Empty for methods that emit no `this.addRawOutput(...)`
    // (finding G1) — the raw-output branch below is a no-op in that case.
    let anfOrderedOutputs: OrderedOutputEntry[] = [];
    if (isStateful && this.artifact.anf) {
      const namedArgs = buildNamedArgs(userParams, resolvedArgs);
      const flatState = flattenFixedArrayState(this._state, this.artifact.stateFields);
      const flatCtorArgs = flattenFixedArrayArgs(this.constructorArgs, this.artifact.abi.constructor.params);
      try {
        const { state: computed, dataOutputs: anfDataOutputs, outputs: anfOutputs } = computeNewStateAndDataOutputs(
          this.artifact.anf, methodName, flatState, namedArgs,
          flatCtorArgs,
        );
        autoComputedState = computed;
        autoFlatState = flatState;
        anfOrderedOutputs = anfOutputs;
        if (anfDataOutputs.length > 0 && resolvedDataOutputs.length === 0) {
          resolvedDataOutputs = anfDataOutputs.map((d) => ({
            script: d.script,
            satoshis: Number(d.satoshis),
          }));
        }
      } catch (err) {
        // FAIL CLOSED (NEW-006). The legacy behaviour was to swallow this and
        // build the continuation from the CURRENT state, which the covenant's
        // hashOutputs binding then rejects — a silent "your call cannot be
        // broadcast", plus silent loss of the method's data / raw outputs.
        // The interpreter is the only thing that knows this method's post-state
        // and its addDataOutput/addRawOutput payloads, so there is nothing to
        // fall back TO: an explicit `newState` covers only the state field and
        // still leaves the outputs missing.
        throw new Error(
          `RunarContract.call('${methodName}'): the ANF interpreter could not evaluate ` +
            `the method body, so the state continuation and data outputs this call would ` +
            `commit cannot be derived. Refusing to broadcast a transaction built from the ` +
            `pre-call state. Cause: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
    }

    if (isStateful && hasMultiOutput) {
      const codeScript = this._codeScript ?? this.buildCodeScript();
      contractOutputs = options!.outputs!.map((out) => {
        const stateHex = serializeState(this.artifact.stateFields!, out.state);
        return { script: codeScript + '6a' + stateHex, satoshis: out.satoshis ?? 1 };
      });
    } else if (isStateful) {
      // Honor an explicit `this.addOutput(<sats>, ...)` state continuation: the
      // ANF interpreter records that amount in `anfOrderedOutputs` (one
      // `kind:'state'` entry per addOutput). A method with a single explicit
      // addOutput and no raw output must build its continuation at that amount,
      // not default to the spent input's value — otherwise the covenant's
      // hashOutputs binding rejects the spend and funds are stranded. Finding G1
      // reads the same satoshis but only on the raw-output-present branch below;
      // this generalizes it to the no-raw single-continuation path. With no
      // explicit addOutput (the auto-injected continuation) `anfOrderedOutputs`
      // is empty and the input-value default is kept.
      const anfStateEntries = anfOrderedOutputs.filter((o) => o.kind === 'state');
      const singleExplicitStateSats =
        anfOrderedOutputs.length === 1 && anfStateEntries.length === 1
          ? Number(anfStateEntries[0]!.satoshis)
          : undefined;
      newSatoshis = options?.satoshis ?? singleExplicitStateSats ?? this.currentUtxo.satoshis;
      if (options?.newState) {
        // Explicit newState takes priority (backward compat)
        this._state = { ...this._state, ...options.newState };
      } else if (methodNeedsChange && autoComputedState && autoFlatState) {
        const merged = { ...autoFlatState, ...autoComputedState };
        const regrouped = regroupFixedArrayState(merged, this.artifact.stateFields);
        this._state = { ...this._state, ...regrouped };
      }
      newLockingScript = this.getLockingScript();
      // DoS-bound: also reject pathological continuation scripts BEFORE broadcast.
      assertScriptHexUnderLimit(
        newLockingScript,
        InputLimits.MAX_SCRIPT_BYTES,
        `${this.artifact.contractName}.call(${methodName}).continuation`,
      );
    }

    // Finding G1: a method that calls `this.addRawOutput(...)` folds the raw
    // output(s) into the covenant's continuation hashOutputs IN SOURCE ORDER,
    // interleaved with the state continuation `this.addOutput(...)`. The
    // single-stateful branch above only builds the state continuation, so the
    // built tx's outputs would mismatch hashOutputs and input 0's OP_VERIFY
    // would reject. Rebuild an ORDERED `contractOutputs` from the interpreter's
    // source-ordered output list. Purely additive: absent raw outputs this is a
    // no-op and existing behaviour is untouched.
    if (isStateful && anfOrderedOutputs.some((o) => o.kind === 'raw')) {
      const stateEntries = anfOrderedOutputs.filter((o) => o.kind === 'state');
      // Fail closed. The current SDK only builds raw outputs alongside a SINGLE
      // state continuation (the covenant machinery below threads exactly one
      // newLockingScript/newAmount). Multi-output calls, multiple continuations,
      // or a missing continuation script are not representable — throw rather
      // than silently drop outputs and strand the funds.
      if (hasMultiOutput || stateEntries.length >= 2 || (stateEntries.length === 1 && !newLockingScript)) {
        throw new Error(
          `RunarContract.call('${methodName}'): cannot build a transaction that interleaves ` +
            `raw outputs with ${stateEntries.length} state continuations; the SDK currently ` +
            `supports raw outputs alongside a single state continuation only (finding G1).`,
        );
      }
      contractOutputs = anfOrderedOutputs.map((o) =>
        o.kind === 'raw'
          ? { script: o.script!, satoshis: Number(o.satoshis) }
          : { script: newLockingScript!, satoshis: Number(o.satoshis) },
      );
      // Keep the preimage's newAmount (buildStatefulUnlock) in step with the
      // continuation output's sats — `this.addOutput(0n, ...)` makes it 0, not
      // the input value the single-stateful branch defaulted to.
      newSatoshis = stateEntries.length === 1 ? Number(stateEntries[0]!.satoshis) : newSatoshis;
    }

    const feeRate = await provider.getFeeRate();
    const changeScript = buildP2PKHScript(changeAddress);
    const allFundingUtxos = await provider.getUtxos(address);
    const candidateFundingUtxos = allFundingUtxos.filter(
      (u) => !(u.txid === this.currentUtxo!.txid && u.outputIndex === this.currentUtxo!.outputIndex),
    );

    // Resolve per-input args for additional contract inputs. Hoisted ABOVE the
    // funding coin-selection (was below it) so the merge unlock placeholders —
    // and therefore the contract-input byte size the funding fee must cover —
    // are known before we size the funding. Consumed again later when the real
    // merge unlocks are built.
    const resolvedPerInputArgs: unknown[][] | undefined = options?.additionalContractInputArgs
      ? options.additionalContractInputArgs.map((inputArgs) => {
          const resolved = [...inputArgs];
          for (let i = 0; i < userParams.length; i++) {
            if (userParams[i]!.type === 'Sig' && resolved[i] === null) {
              resolved[i] = '00'.repeat(72);
            }
            if (userParams[i]!.type === 'PubKey' && resolved[i] === null) {
              resolved[i] = resolvedArgs[userParams.findIndex((p) => p.type === 'PubKey')];
            }
            if (userParams[i]!.type === 'ByteString' && resolved[i] === null) {
              const estimatedInputs = 1 + (options?.additionalContractInputs?.length ?? 0) + 1;
              resolved[i] = '00'.repeat(36 * estimatedInputs);
            }
          }
          return resolved;
        })
      : undefined;

    // Build placeholder unlocking scripts for merge inputs (witnessHex
    // suffixed for sizing — buildStatefulUnlock builds the real scripts).
    const extraUnlockPlaceholders = extraContractUtxos.map((_, i) => {
      const argsForPlaceholder = resolvedPerInputArgs?.[i] ?? resolvedArgs;
      return encodePushData('00'.repeat(72)) + this.buildUnlockingScript(methodName, argsForPlaceholder) + witnessHex;
    });

    // Coin selection for funding inputs (issue #133): don't sweep the whole
    // wallet. Compute how much the funding must cover — the contract's own
    // input value already offsets the contract/data outputs — and pick the
    // smallest largest-first set via selectUtxos (the strategy deploy uses).
    const contractOutputSats =
      (contractOutputs
        ? contractOutputs.reduce((sum, o) => sum + o.satoshis, 0)
        : (newSatoshis ?? 0))
      + resolvedDataOutputs.reduce((sum, o) => sum + o.satoshis, 0);
    const contractInputSats =
      this.currentUtxo.satoshis
      + extraContractUtxos.reduce((sum, u) => sum + u.satoshis, 0);
    const fundingTarget = Math.max(0, contractOutputSats - contractInputSats);
    // Fee sizing hint for selectUtxos: the continuation script length (falls
    // back to the first multi-output script, else 0 for stateless calls).
    const fundingLockLen =
      (newLockingScript?.length ?? contractOutputs?.[0]?.script.length ?? 0) / 2;
    // Contract-input unlock bytes. selectUtxos/estimateDeployFee otherwise model
    // ONLY the funding inputs (148-byte P2PKH each) + continuation + change —
    // they are blind to the contract input(s) being spent. For a MERGE each
    // covenant input embeds both parent txs as method args (tens of KB), so
    // ignoring them under-provisions the funding; buildCallTransaction then sees
    // change <= 0 and DROPS the change output, and the merge covenant — which
    // reconstructs [continuation][P2PKH change] UNCONDITIONALLY — fails its
    // hashOutputs OP_VERIFY. Size the funding fee against the SAME serialized
    // per-input bytes buildCallTransaction uses (32 outpoint + 4 index + varint +
    // script + 4 sequence) for the primary contract input plus every extra one.
    // Over-estimating is safe (a little more funding / higher change); under-
    // estimating is the bug. Small ops (single covenant input, tiny unlock) add
    // a correspondingly small term and are unaffected.
    const perInputBytes = (unlockHex: string): number => {
      const len = unlockHex.length / 2;
      const vi = len < 0xfd ? 1 : len <= 0xffff ? 3 : len <= 0xffffffff ? 5 : 9;
      return 32 + 4 + vi + len + 4;
    };
    // The `unlockingScript` / `extraUnlockPlaceholders` above are SIZING
    // placeholders: `encodePushData(sig72) + buildUnlockingScript(args) +
    // witnessHex`. For a stateful call the REAL unlock buildStatefulUnlock emits
    // is larger — it prepends the opSig codePart prefix and appends the BIP-143
    // preimage (whose scriptCode ≈ the locking script), the change + new-amount
    // pushes, and the method selector. That gap (~6.5 KB per input for the EAC
    // merge) is exactly what would make selectUtxos stop one UTXO short, leaving
    // change <= 0 so the covenant's [continuation][change] reconstruction fails.
    // Add a per-contract-input overestimate covering those omitted components:
    // codePart (≈ locking script) + preimage scriptCode (≈ locking script) + a
    // fixed buffer for sig/amount/selector/varint framing. Over-estimating only
    // pulls slightly more funding (bigger change) — always safe.
    const numContractInputs = 1 + extraContractUtxos.length;
    const perContractInputOverhead = 2 * Math.ceil(fundingLockLen) + 512;
    const contractInputBytes =
      perInputBytes(unlockingScript)
      + extraUnlockPlaceholders.reduce((sum, u) => sum + perInputBytes(u), 0)
      + numContractInputs * perContractInputOverhead;
    // C15: size the funding fee against ALL outputs, not just the single
    // continuation that `fundingLockLen` already covers. estimateDeployFee counts
    // one output of `fundingLockLen` bytes; add the framing (8 + varint +
    // scriptLen) of every OTHER contract output (extra multi-outputs + raw
    // outputs, finding G1) and every data output so selection does not stop one
    // UTXO short on multi-output / large-dataOutput calls. Single-output calls
    // net 0 (estimate unchanged). Over-estimating only pulls slightly more
    // funding (bigger change) — always safe.
    const outputFraming = (byteLen: number): number => {
      const vi = byteLen < 0xfd ? 1 : byteLen <= 0xffff ? 3 : byteLen <= 0xffffffff ? 5 : 9;
      return 8 + vi + byteLen;
    };
    const allOutputByteLens = [
      ...(contractOutputs
        ? contractOutputs.map((o) => o.script.length / 2)
        : newLockingScript ? [newLockingScript.length / 2] : []),
      ...resolvedDataOutputs.map((o) => o.script.length / 2),
    ];
    const totalOutputFraming = allOutputByteLens.reduce((s, n) => s + outputFraming(n), 0);
    const extraOutputBytes = Math.max(
      0, totalOutputFraming - outputFraming(Math.ceil(fundingLockLen)),
    );
    const additionalUtxos =
      candidateFundingUtxos.length > 0
        ? selectUtxos(candidateFundingUtxos, fundingTarget, fundingLockLen, feeRate, contractInputBytes, extraOutputBytes)
        : [];

    // Cap funding inputs when the caller sets maxFundingInputs. selectUtxos
    // returns the minimal largest-first set; if that still exceeds the cap the
    // funding can't cover outputs + fee within the budget, so fail loudly
    // instead of broadcasting an underfunded tx.
    if (
      options?.maxFundingInputs !== undefined &&
      additionalUtxos.length > options.maxFundingInputs
    ) {
      throw new Error(
        `RunarContract.call(${methodName}): funding requires ${additionalUtxos.length} input(s) ` +
          `but maxFundingInputs=${options.maxFundingInputs}. Increase maxFundingInputs, ` +
          `use larger UTXOs, or consolidate.`,
      );
    }

    // (resolvedPerInputArgs + extraUnlockPlaceholders are computed above, before
    // funding coin-selection, so their byte sizes feed the funding fee estimate.)

    let { tx, inputCount, changeAmount } = buildCallTransaction(
      this.currentUtxo,
      unlockingScript,
      newLockingScript,
      newSatoshis,
      changeAddress,
      changeScript,
      additionalUtxos.length > 0 ? additionalUtxos : undefined,
      feeRate,
      {
        contractOutputs,
        additionalContractInputs: extraContractUtxos.length > 0
          ? extraContractUtxos.map((utxo, i) => ({ utxo, unlockingScript: extraUnlockPlaceholders[i]! }))
          : undefined,
        dataOutputs: resolvedDataOutputs.length > 0 ? resolvedDataOutputs : undefined,
        // Thread CallOptions.locktime so contracts asserting
        // extractLocktime(preimage) can succeed. Default unset → 0.
        locktime: options?.locktime,
        // Thread CallOptions.sequence (issue #131): a non-zero locktime needs
        // non-final input sequences or consensus ignores nLockTime.
        sequence: options?.sequence,
      },
    );

    // Sign P2PKH funding inputs (with fundingSigner — issue #134)
    let txHex = tx.toHex();
    const p2pkhStartIdx = 1 + extraContractUtxos.length;
    for (let i = p2pkhStartIdx; i < inputCount; i++) {
      const utxo = additionalUtxos[i - p2pkhStartIdx];
      if (utxo) {
        const sig = await fundingSigner.sign(txHex, i, utxo.script, utxo.satoshis);
        const pubKey = await fundingSigner.getPublicKey();
        const unlockScript = encodePushData(sig) + encodePushData(pubKey);
        tx.inputs[i]!.unlockingScript = UnlockingScript.fromHex(unlockScript);
        invalidateTxCache(tx);
        txHex = tx.toHex();
      }
    }

    let finalOpPushTxSig = '';
    let finalPreimage = '';

    if (isStateful) {
      const perInputArgs = options?.additionalContractInputArgs;

      // Helper: build a stateful unlock. For inputIdx===0 (primary), keeps
      // placeholder Sig params. For inputIdx>0 (extra), signs with signer.
      const buildStatefulUnlock = async (
        currentTx: BsvTransaction, inputIdx: number, subscript: string, sats: number,
        argsOverride?: unknown[], txChangeAmount?: number,
      ): Promise<{ unlock: string; opSig: string; preimage: string }> => {
        const { sigHex: opSig, preimageHex: preimage } = this.computeOpPushTxWithCodeSep(
          currentTx, inputIdx, subscript, sats, methodIndex,
        );
        const baseArgs = argsOverride ?? resolvedArgs;
        const inputArgs = [...baseArgs];
        // Only sign Sig params for extra inputs, not the primary
        if (inputIdx > 0) {
          // Stateful: user checkSig is AFTER OP_CODESEPARATOR — use trimmed script.
          const trimmedSubscript = this.getSubscriptForSigning(subscript, methodIndex);
          const currentHex = currentTx.toHex();
          for (const idx of sigIndices) {
            inputArgs[idx] = await signer.sign(currentHex, inputIdx, trimmedSubscript, sats);
          }
        }
        if (prevoutsIndices.length > 0) {
          let allPrevoutsHex = '';
          for (const inp of currentTx.inputs) {
            const txidLE = inp.sourceTXID!.match(/.{2}/g)!.reverse().join('');
            const voutLE = inp.sourceOutputIndex.toString(16).padStart(8, '0')
              .match(/.{2}/g)!.reverse().join('');
            allPrevoutsHex += txidLE + voutLE;
          }
          for (const idx of prevoutsIndices) {
            inputArgs[idx] = allPrevoutsHex;
          }
        }
        let argsHex = '';
        for (const arg of inputArgs) argsHex += encodeArg(arg);
        let changeHex = '';
        if (methodNeedsChange && changePKHHex) {
          changeHex = encodePushData(changePKHHex) + encodeArg(BigInt(txChangeAmount ?? 0));
        }
        let newAmountHex = '';
        if (methodNeedsNewAmount) {
          newAmountHex = encodeArg(BigInt(newSatoshis ?? this.currentUtxo!.satoshis));
        }
        const unlock = this.buildStatefulPrefix(opSig, methodUsesCodePart) + argsHex + changeHex + newAmountHex + encodePushData(preimage) + witnessHex + methodSelectorHex;
        return { unlock, opSig, preimage };
      };

      // First pass
      const { unlock: input0Unlock } = await buildStatefulUnlock(
        tx, 0, contractUtxo.script, contractUtxo.satoshis,
        undefined, changeAmount,
      );
      const extraUnlocks: string[] = [];
      for (let i = 0; i < extraContractUtxos.length; i++) {
        const mu = extraContractUtxos[i]!;
        const extraArgs = perInputArgs?.[i] ? resolvedPerInputArgs?.[i] : undefined;
        const { unlock } = await buildStatefulUnlock(tx, i + 1, mu.script, mu.satoshis, extraArgs, changeAmount);
        extraUnlocks.push(unlock);
      }

      // Rebuild TX with real unlocking scripts.
      //
      // Deep-review finding C13: the funding coin-selection above ran against
      // an ESTIMATE (placeholder unlock + the `perContractInputOverhead`
      // heuristic), not this REAL unlock — and there is no re-selection pass
      // here if the real size turns out bigger than estimated. Investigated:
      // this IS reachable (e.g. a stateful method whose current — spent —
      // locking script is far larger than its new/continuation one, since the
      // heuristic only has the NEW script's length to go on; see
      // `c13-call-funding-fee-bound.test.ts`). It can NEVER produce an
      // invalid or overspending tx, though: `buildCallTransaction` always
      // computes fee/change from these REAL bytes (not the estimate), and
      // finding C3's fail-closed guard guarantees `totalInput >=
      // contractOutputSats`, so the worst case is a lower-than-intended fee
      // down to (and never below) 0 — the same zero-fee "exact cover" floor
      // issue #116 already established as valid/intentional. No re-selection
      // loop is added here; see the linked test for the invariant this bound
      // relies on.
      ({ tx, inputCount, changeAmount } = buildCallTransaction(
        this.currentUtxo,
        input0Unlock,
        newLockingScript,
        newSatoshis,
        changeAddress,
        changeScript,
        additionalUtxos.length > 0 ? additionalUtxos : undefined,
        feeRate,
        {
          contractOutputs,
          additionalContractInputs: extraContractUtxos.length > 0
            ? extraContractUtxos.map((utxo, i) => ({ utxo, unlockingScript: extraUnlocks[i]! }))
            : undefined,
          dataOutputs: resolvedDataOutputs.length > 0 ? resolvedDataOutputs : undefined,
          // Rebuild path must honor the override too: a preimage computed on a
          // rebuilt tx with locktime 0 would mismatch the final on-chain tx.
          locktime: options?.locktime,
          // Same for sequence — the second-pass preimage must see the final
          // input sequences (issue #131).
          sequence: options?.sequence,
        },
      ));

      // Second pass: recompute with final tx
      const { unlock: finalInput0Unlock, opSig, preimage } = await buildStatefulUnlock(
        tx, 0, contractUtxo.script, contractUtxo.satoshis,
        undefined, changeAmount,
      );
      finalOpPushTxSig = opSig;
      finalPreimage = preimage;
      tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(finalInput0Unlock);
      invalidateTxCache(tx);

      for (let i = 0; i < extraContractUtxos.length; i++) {
        const mu = extraContractUtxos[i]!;
        const extraArgs = perInputArgs?.[i] ? resolvedPerInputArgs?.[i] : undefined;
        const { unlock: finalMergeUnlock } = await buildStatefulUnlock(tx, i + 1, mu.script, mu.satoshis, extraArgs, changeAmount);
        tx.inputs[i + 1]!.unlockingScript = UnlockingScript.fromHex(finalMergeUnlock);
        invalidateTxCache(tx);
      }

      // Re-sign P2PKH funding inputs (with fundingSigner — issue #134)
      txHex = tx.toHex();
      for (let i = p2pkhStartIdx; i < inputCount; i++) {
        const utxo = additionalUtxos[i - p2pkhStartIdx];
        if (utxo) {
          const sig = await fundingSigner.sign(txHex, i, utxo.script, utxo.satoshis);
          const pubKey = await fundingSigner.getPublicKey();
          const unlockScript = encodePushData(sig) + encodePushData(pubKey);
          tx.inputs[i]!.unlockingScript = UnlockingScript.fromHex(unlockScript);
          invalidateTxCache(tx);
          txHex = tx.toHex();
        }
      }

      // Update resolvedArgs with real prevouts so finalizeCall can
      // rebuild the primary unlock with correct allPrevouts values.
      if (prevoutsIndices.length > 0) {
        let allPrevoutsHex = '';
        for (const inp of tx.inputs) {
          const txidLE = inp.sourceTXID!.match(/.{2}/g)!.reverse().join('');
          const voutLE = inp.sourceOutputIndex.toString(16).padStart(8, '0')
            .match(/.{2}/g)!.reverse().join('');
          allPrevoutsHex += txidLE + voutLE;
        }
        for (const idx of prevoutsIndices) {
          resolvedArgs[idx] = allPrevoutsHex;
        }
      }
    } else if (needsOpPushTx || sigIndices.length > 0) {
      // Stateless: keep placeholder sigs, compute OP_PUSH_TX
      if (needsOpPushTx) {
        const { sigHex, preimageHex } = this.computeOpPushTxWithCodeSep(
          tx, 0, contractUtxo.script, contractUtxo.satoshis, methodIndex,
        );
        finalOpPushTxSig = sigHex;
        resolvedArgs[preimageIndex] = preimageHex;
      }
      // Don't sign Sig params — keep placeholders
      let realUnlockingScript = this.buildUnlockingScript(methodName, resolvedArgs);
      if (needsOpPushTx && finalOpPushTxSig) {
        realUnlockingScript = this.buildStatefulPrefix(finalOpPushTxSig) + realUnlockingScript;
        tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(realUnlockingScript);
        invalidateTxCache(tx);
        const { sigHex: finalSig, preimageHex: finalPre } = this.computeOpPushTxWithCodeSep(
          tx, 0, contractUtxo.script, contractUtxo.satoshis, methodIndex,
        );
        resolvedArgs[preimageIndex] = finalPre;
        finalOpPushTxSig = finalSig;
        finalPreimage = finalPre;
        realUnlockingScript = this.buildStatefulPrefix(finalSig) +
          this.buildUnlockingScript(methodName, resolvedArgs);
      }
      tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(realUnlockingScript);
      invalidateTxCache(tx);
      if (!finalPreimage && needsOpPushTx) {
        finalPreimage = resolvedArgs[preimageIndex] as string;
      }
    }

    // Compute sighash from preimage (C19: the true BIP-143 digest external
    // signers must ECDSA-sign — hash256(preimage), not sha256(preimage)).
    const sighash = finalPreimage ? computeBip143Sighash(finalPreimage) : '';

    return {
      sighash,
      preimage: finalPreimage,
      opPushTxSig: finalOpPushTxSig,
      tx,
      sigIndices,
      _methodName: methodName,
      _resolvedArgs: resolvedArgs,
      _methodSelectorHex: methodSelectorHex,
      _isStateful: isStateful,
      _parentStateful: parentStateful,
      _isTerminal: false,
      _needsOpPushTx: needsOpPushTx,
      _methodNeedsChange: methodNeedsChange,
        _methodUsesCodePart: methodUsesCodePart,
      _changePKHHex: changePKHHex,
      _changeAmount: changeAmount,
      _methodNeedsNewAmount: methodNeedsNewAmount,
      _newAmount: newSatoshis ?? this.currentUtxo.satoshis,
      _preimageIndex: preimageIndex,
      _contractUtxo: contractUtxo,
      _newLockingScript: newLockingScript ?? '',
      _newSatoshis: newSatoshis ?? 0,
      _hasMultiOutput: !!hasMultiOutput,
      _contractOutputs: contractOutputs ?? [],
      _intentWitnessHex: witnessHex,
      _dryRun: options?.dryRun ?? false,
    };
  }

  /**
   * Complete a prepared call by injecting external signatures and broadcasting.
   *
   * @param prepared    — The `PreparedCall` returned by `prepareCall()`.
   * @param signatures  — Map from arg index to DER signature hex (with sighash byte).
   *                      Each key must be one of `prepared.sigIndices`.
   */
  async finalizeCall(
    prepared: PreparedCall,
    signatures: Record<number, string>,
  ): Promise<{ txid: string; tx: TransactionData }> {
    // C29: one-shot guard. Mark consumed BEFORE any mutation/broadcast work
    // so a second call fails fast regardless of whether the first attempt
    // succeeded, was rejected by the C8 dry-run, or threw during broadcast —
    // `prepared.tx` may already have been mutated by that first attempt in
    // every one of those cases.
    if (consumedPreparedCalls.has(prepared)) {
      throw new Error(
        'RunarContract.finalizeCall: this PreparedCall has already been finalized (deep-review C29). ' +
          'A PreparedCall is one-shot — call prepareCall() again to build a fresh one.',
      );
    }
    consumedPreparedCalls.add(prepared);

    const { provider } = this.resolveProviderSigner();

    // Replace placeholder sigs with real signatures
    const resolvedArgs = [...prepared._resolvedArgs];
    for (const idx of prepared.sigIndices) {
      if (signatures[idx] !== undefined) {
        resolvedArgs[idx] = signatures[idx];
      }
    }

    // Assemble the primary unlocking script
    let primaryUnlock: string;
    if (prepared._isStateful) {
      let argsHex = '';
      for (const arg of resolvedArgs) argsHex += encodeArg(arg);
      let changeHex = '';
      if (prepared._methodNeedsChange && prepared._changePKHHex) {
        changeHex = encodePushData(prepared._changePKHHex) +
          encodeArg(BigInt(prepared._changeAmount));
      }
      let newAmountHex = '';
      if (prepared._methodNeedsNewAmount) {
        newAmountHex = encodeArg(BigInt(prepared._newAmount));
      }
      primaryUnlock =
        this.buildStatefulPrefix(prepared.opPushTxSig, prepared._methodUsesCodePart ?? prepared._methodNeedsChange) +
        argsHex +
        changeHex +
        newAmountHex +
        encodePushData(prepared.preimage) +
        prepared._intentWitnessHex +
        prepared._methodSelectorHex;
    } else if (prepared._needsOpPushTx) {
      // Stateless with SigHashPreimage: put preimage into resolvedArgs
      if (prepared._preimageIndex >= 0) {
        resolvedArgs[prepared._preimageIndex] = prepared.preimage;
      }
      primaryUnlock = this.buildStatefulPrefix(prepared.opPushTxSig) +
        this.buildUnlockingScript(prepared._methodName, resolvedArgs);
    } else {
      primaryUnlock = this.buildUnlockingScript(prepared._methodName, resolvedArgs);
    }

    // Insert primary unlock into the transaction
    const finalTx = prepared.tx;
    finalTx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(primaryUnlock);
    invalidateTxCache(finalTx);

    // C8: local pre-broadcast dry-run. Replay the fully-signed primary
    // contract input through @bsv/sdk's production Spend interpreter and fail
    // closed — instead of broadcasting a tx the network would reject — unless
    // the caller opted IN (CallOptions.dryRun, threaded via prepareCall).
    // Opt-in rather than default-on: see the CallOptions.dryRun docstring for
    // the false-rejection evidence that forced this polarity.
    if (prepared._dryRun) {
      const dryRun = dryRunContractInput(
        finalTx, 0, prepared._contractUtxo.script, prepared._contractUtxo.satoshis,
      );
      if (!dryRun.valid) {
        throw new Error(
          `RunarContract.finalizeCall: local pre-broadcast dry-run rejected the primary ` +
            `contract input (deep-review C8)${dryRun.error ? `: ${dryRun.error}` : ' (script evaluated to false)'}. ` +
            `Refusing to broadcast a tx the network would reject. Omit { dryRun: true } in ` +
            `CallOptions to bypass (see PreparedCall docs).`,
        );
      }
    }

    // Broadcast
    const txid = await provider.broadcast(finalTx);

    // Update tracked UTXO
    if (prepared._isStateful && prepared._hasMultiOutput && prepared._contractOutputs.length > 0) {
      this.currentUtxo = {
        txid,
        outputIndex: 0,
        satoshis: prepared._contractOutputs[0]!.satoshis,
        script: prepared._contractOutputs[0]!.script,
      };
    } else if (prepared._isStateful && prepared._newLockingScript) {
      // The state continuation is normally output 0, but a method that also
      // calls `this.addRawOutput(...)` (finding G1) can push raw outputs ahead
      // of it. `_contractOutputs`, when populated (the raw-output path),
      // records the real source order and each output's satoshis — so track the
      // continuation at its actual index and value (which may legitimately be
      // 0). Empty `_contractOutputs` (the common case) keeps the legacy
      // index-0 / `_newSatoshis`-fallback behaviour byte-for-byte unchanged.
      const contIdx = prepared._contractOutputs.length > 0
        ? prepared._contractOutputs.findIndex((o) => o.script === prepared._newLockingScript)
        : -1;
      this.currentUtxo = contIdx >= 0
        ? {
            txid,
            outputIndex: contIdx,
            satoshis: prepared._contractOutputs[contIdx]!.satoshis,
            script: prepared._newLockingScript,
          }
        : {
            txid,
            outputIndex: 0,
            satoshis: prepared._newSatoshis || prepared._contractUtxo.satoshis,
            script: prepared._newLockingScript,
          };
    } else if (prepared._isTerminal) {
      this.currentUtxo = null;
    } else {
      this.currentUtxo = null;
    }

    const txData = await provider.getTransaction(txid).catch((err) => {
      // Audit finding C4 — see the peer fallback in `deploy()`.
      console.warn('Failed to fetch transaction after broadcast:', err);
      return txToTransactionData(txid, finalTx);
    });

    return { txid, tx: txData };
  }

  // -------------------------------------------------------------------------
  // State access
  // -------------------------------------------------------------------------

  /** Get the current contract state (for stateful contracts). */
  get state(): Record<string, unknown> {
    return { ...this._state };
  }

  /** Update state values directly (for stateful contracts). */
  setState(newState: Record<string, unknown>): void {
    this._state = { ...this._state, ...newState };
  }

  // -------------------------------------------------------------------------
  // Intent-intrinsic witness values
  // -------------------------------------------------------------------------

  /**
   * Supply the prev-output locking-script witness for input `inputIndex`.
   * Required for methods that call `extractPrevOutputScript(inputIndex)`,
   * which the compiler lowers into an auto-injected
   * `_prevOutScript_<inputIndex>` ABI param.
   *
   * @param inputIndex the literal input index passed to extractPrevOutputScript
   * @param bytes      hex string (with or without 0x prefix) or raw bytes
   */
  setPrevOutScript(inputIndex: number, bytes: string | Uint8Array): void {
    this._prevOutScripts.set(inputIndex, normalizeWitnessBytes(bytes));
  }

  /**
   * Supply the serialised-outputs witness for the current call.
   * Required for methods that call `requireOutputP2PKH(...)`, which the
   * compiler lowers into an auto-injected `_serialisedOutputs` ABI param.
   *
   * @param bytes hex string (with or without 0x prefix) or raw bytes
   */
  setSerialisedOutputs(bytes: string | Uint8Array): void {
    this._serialisedOutputs = normalizeWitnessBytes(bytes);
  }

  /**
   * Build the trailing witness-hex for the auto-injected intent-intrinsic
   * params of a method, in ABI order (`_prevOutScript_*` first, then
   * `_serialisedOutputs`). Each value is pushed via PUSHDATA so that the
   * on-chain method body's `load_param` lifts the exact bytes the caller set.
   *
   * Throws {@link WitnessValueMissingError} for any auto-injected param the
   * caller hasn't supplied via setPrevOutScript / setSerialisedOutputs.
   */
  private buildIntentWitnessHex(method: ABIMethod): string {
    let hex = '';
    for (const p of method.params) {
      if (p.name.startsWith('_prevOutScript_')) {
        const idxStr = p.name.slice('_prevOutScript_'.length);
        const idx = Number(idxStr);
        const val = this._prevOutScripts.get(idx);
        if (val === undefined) {
          throw new WitnessValueMissingError({
            paramName: p.name,
            methodName: method.name,
            contractName: this.artifact.contractName,
          });
        }
        hex += encodePushData(val);
      } else if (p.name === '_serialisedOutputs') {
        if (this._serialisedOutputs === null) {
          throw new WitnessValueMissingError({
            paramName: p.name,
            methodName: method.name,
            contractName: this.artifact.contractName,
          });
        }
        hex += encodePushData(this._serialisedOutputs);
      }
    }
    return hex;
  }

  // -------------------------------------------------------------------------
  // Script construction
  // -------------------------------------------------------------------------

  /**
   * Get the full locking script hex for the contract.
   *
   * For stateful contracts this includes the code followed by OP_RETURN and
   * the serialized state fields.
   */
  getLockingScript(): string {
    // Use stored code script from chain if available (reconnected contract).
    // When loaded from chain, _codeScript already contains the inscription
    // envelope (if any). When built from the template, we splice it in.
    const builtFromTemplate = this._codeScript === null;
    let script = this._codeScript ?? this.buildCodeScript();

    // Inject inscription envelope between code and state (template-built only;
    // chain-loaded _codeScript already includes it).
    if (builtFromTemplate && this._inscription) {
      script += buildInscriptionEnvelope(
        this._inscription.contentType,
        this._inscription.data,
      );
    }

    // Append state section for stateful contracts
    if (this.artifact.stateFields && this.artifact.stateFields.length > 0) {
      const stateHex = serializeState(this.artifact.stateFields, this._state);
      if (stateHex.length > 0) {
        script += '6a'; // OP_RETURN
        script += stateHex;
      }
    }

    return script;
  }

  /**
   * Build the code portion of the locking script from the artifact and
   * constructor args. This is the script without any state suffix.
   */
  private buildCodeScript(): string {
    let script = this.artifact.script;

    const hasConstructorSlots = this.artifact.constructorSlots && this.artifact.constructorSlots.length > 0;
    const hasCodeSepSlots = this.artifact.codeSepIndexSlots && this.artifact.codeSepIndexSlots.length > 0;

    if (hasConstructorSlots || hasCodeSepSlots) {
      // Build a unified list of all template slot substitutions, then process
      // them in descending byte-offset order so each splice doesn't invalidate
      // the positions of earlier (higher-offset) entries.
      type Substitution = { byteOffset: number; encoded: string };
      const subs: Substitution[] = [];

      // Constructor arg slots: replace OP_0 placeholder with encoded arg
      if (hasConstructorSlots) {
        for (const slot of this.artifact.constructorSlots!) {
          subs.push({
            byteOffset: slot.byteOffset,
            encoded: encodeArg(this.constructorArgs[slot.paramIndex]),
          });
        }
      }

      // CodeSepIndex slots: replace OP_0 placeholder with encoded adjusted
      // codeSeparatorIndex. The adjusted value accounts for constructor arg
      // expansion AND earlier codeSepIndex slot expansions that shift
      // OP_CODESEPARATOR positions in the substituted script.
      if (hasCodeSepSlots) {
        const resolved = this._resolvedCodeSepSlotValues();
        for (const rs of resolved) {
          subs.push({
            byteOffset: rs.templateByteOffset,
            encoded: encodeScriptNumber(BigInt(rs.adjustedValue)),
          });
        }
      }

      // Sort descending by byte offset and apply
      subs.sort((a, b) => b.byteOffset - a.byteOffset);
      for (const sub of subs) {
        const hexOffset = sub.byteOffset * 2;
        // Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded value
        script = script.slice(0, hexOffset) + sub.encoded + script.slice(hexOffset + 2);
      }
    } else if (!this.artifact.stateFields || this.artifact.stateFields.length === 0) {
      // Backward compatibility: old stateless artifacts without constructorSlots.
      // For stateful contracts, constructor args initialize the state section
      // (after OP_RETURN), not the code portion.
      for (const arg of this.constructorArgs) {
        script += encodeArg(arg);
      }
    }

    return script;
  }

  /**
   * Build the unlocking script for a method call.
   *
   * The unlocking script pushes the method arguments onto the stack in
   * order, followed by a method selector (the method index as a Script
   * number) if the contract has multiple public methods.
   */
  buildUnlockingScript(methodName: string, args: unknown[]): string {
    let script = '';

    // Push each argument
    for (const arg of args) {
      script += encodeArg(arg);
    }

    // If there are multiple public methods, push the method selector
    const publicMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
    if (publicMethods.length > 1) {
      const methodIndex = publicMethods.findIndex((m) => m.name === methodName);
      if (methodIndex < 0) {
        throw new Error(
          `buildUnlockingScript: public method '${methodName}' not found`,
        );
      }
      script += encodeScriptNumber(BigInt(methodIndex));
    }

    return script;
  }

  /**
   * Get the code script hex (locking script without state) for use as _codePart.
   * Returns the code portion that the on-chain contract uses for output reconstruction.
   * Includes the inscription envelope if one is attached — this is required for
   * stateful contracts where the on-chain hashOutputs verification includes
   * the envelope as part of the codePart.
   *
   * Public low-level assembly surface: needed for cross-artifact transaction
   * assembly (see `assembleMultiContractCall`), where a spending tx mixes
   * covenant inputs from DIFFERENT artifacts and each input's `_codePart` /
   * continuation script must be built outside `call()`.
   */
  getCodePartHex(): string {
    if (this._codeScript) return this._codeScript;
    let code = this.buildCodeScript();
    if (this._inscription) {
      code += buildInscriptionEnvelope(this._inscription.contentType, this._inscription.data);
    }
    return code;
  }

  /**
   * Adjust a code separator byte offset from the base (template) script to
   * the fully-substituted script. Both constructor arg slots and codeSepIndex
   * slots replace OP_0 (1 byte) with encoded push data, shifting subsequent
   * byte offsets.
   */
  private adjustCodeSepOffset(baseOffset: number): number {
    let shift = 0;
    if (this.artifact.constructorSlots) {
      for (const slot of this.artifact.constructorSlots) {
        if (slot.byteOffset < baseOffset) {
          const encoded = encodeArg(this.constructorArgs[slot.paramIndex]);
          shift += encoded.length / 2 - 1; // encoded bytes minus the 1-byte OP_0 placeholder
        }
      }
    }
    // Account for codeSepIndex slot expansions. Each slot's encoded value
    // is the fully-adjusted codeSep index, computed by resolveCodeSepSlotValues.
    const resolvedSlots = this._resolvedCodeSepSlotValues();
    for (const rs of resolvedSlots) {
      if (rs.templateByteOffset < baseOffset) {
        const encoded = encodeScriptNumber(BigInt(rs.adjustedValue));
        shift += encoded.length / 2 - 1;
      }
    }
    return baseOffset + shift;
  }

  /**
   * Resolve the adjusted codeSep index values for all codeSepIndex slots,
   * processing them in ascending template byte-offset order so that each
   * slot's value correctly accounts for earlier slots' expansions.
   */
  private _resolvedCodeSepSlotValues(): Array<{ templateByteOffset: number; adjustedValue: number }> {
    if (!this.artifact.codeSepIndexSlots || this.artifact.codeSepIndexSlots.length === 0) {
      return [];
    }
    // Sort by template byte offset ascending (left-to-right in the script)
    const sorted = [...this.artifact.codeSepIndexSlots].sort(
      (a, b) => a.byteOffset - b.byteOffset,
    );
    const result: Array<{ templateByteOffset: number; adjustedValue: number }> = [];
    for (const slot of sorted) {
      // Compute the fully-adjusted codeSep index: constructor expansion +
      // expansion from earlier codeSepIndex slots that precede this slot's codeSepIndex.
      let shift = 0;
      if (this.artifact.constructorSlots) {
        for (const cs of this.artifact.constructorSlots) {
          if (cs.byteOffset < slot.codeSepIndex) {
            const encoded = encodeArg(this.constructorArgs[cs.paramIndex]);
            shift += encoded.length / 2 - 1;
          }
        }
      }
      for (const prev of result) {
        if (prev.templateByteOffset < slot.codeSepIndex) {
          const prevEncoded = encodeScriptNumber(BigInt(prev.adjustedValue));
          shift += prevEncoded.length / 2 - 1;
        }
      }
      result.push({ templateByteOffset: slot.byteOffset, adjustedValue: slot.codeSepIndex + shift });
    }
    return result;
  }

  /**
   * Get the subscript trimmed at the OP_CODESEPARATOR for a given method.
   * Used for BIP-143 sighash computation for the user CHECKSIG whenever the
   * script contains an OP_CODESEPARATOR before it (per BIP-143 / BSV consensus,
   * for stateful AND terminal methods alike). Returns the full script unchanged
   * when no OP_CODESEPARATOR is present.
   *
   * When `_codeScript` is set (the contract is loaded from chain, or the deploy
   * script has already been built from real constructor args), walk the actual
   * script and trim at the true on-chain byte position. This is required
   * because `fromTxid` populates constructorArgs with dummy placeholders — the
   * real arg bytes are already baked into the on-chain locking script — so
   * `adjustCodeSepOffset` computes a shift of zero and returns the wrong offset
   * whenever the OP_CODESEPARATOR sits after constructor slots that expand at
   * deploy time. The symptom of using the wrong offset is NULLFAIL at
   * OP_CHECKSIG for terminal methods.
   *
   * Public low-level assembly surface: multi-contract tx assembly must sign
   * each covenant input's user `Sig` over ITS artifact's codesep-trimmed
   * subscript, which `call()` only does for its own single primary input.
   */
  getSubscriptForSigning(fullScript: string, methodIndex?: number): string {
    if (this._codeScript !== null) {
      const realOffsets = findCodesepOffsets(this._codeScript);
      if (realOffsets.length > 0) {
        const indices = this.artifact.codeSeparatorIndices;
        let off: number | undefined;
        if (indices && methodIndex !== undefined && methodIndex < indices.length
            && methodIndex < realOffsets.length) {
          off = realOffsets[methodIndex];
        } else if (this.artifact.codeSeparatorIndex !== undefined) {
          off = realOffsets[0];
        }
        if (off !== undefined) {
          return fullScript.slice((off + 1) * 2);
        }
      }
    }

    const indices = this.artifact.codeSeparatorIndices;
    let codeSepIdx: number | undefined;
    if (indices && methodIndex !== undefined && methodIndex < indices.length) {
      codeSepIdx = indices[methodIndex];
    } else {
      codeSepIdx = this.artifact.codeSeparatorIndex;
    }
    if (codeSepIdx !== undefined) {
      codeSepIdx = this.adjustCodeSepOffset(codeSepIdx);
      // Skip past the separator byte (+1 byte = +2 hex chars)
      return fullScript.slice((codeSepIdx + 1) * 2);
    }
    return fullScript;
  }

  /**
   * Wrap computeOpPushTx to automatically pass the correct codeSeparatorIndex.
   * For multi-method contracts, each method has its own separator at a different
   * byte offset. Uses codeSeparatorIndices[methodIndex] if available, otherwise
   * falls back to the single codeSeparatorIndex.
   *
   * When `_codeScript` is set (chain-loaded, or a deploy script already built
   * from real constructor args), byte-walk the actual script for the true
   * on-chain OP_CODESEPARATOR offset — mirroring `getSubscriptForSigning`.
   * `adjustCodeSepOffset` derives the shift from the in-memory
   * `constructorArgs`, which are placeholders on the restore path (issue #132);
   * the byte-walk is independent of those args. The template `adjustCodeSepOffset`
   * path remains only for template-built (deploy-time) contracts.
   *
   * Public low-level assembly surface: each covenant input of a
   * multi-contract tx needs its own OP_PUSH_TX signature + BIP-143 preimage
   * computed against ITS artifact's code separator layout.
   */
  computeOpPushTxWithCodeSep(
    tx: BsvTransaction,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    methodIndex?: number,
  ): { sigHex: string; preimageHex: string } {
    let codeSepIdx: number | undefined;

    if (this._codeScript !== null) {
      const realOffsets = findCodesepOffsets(this._codeScript);
      if (realOffsets.length > 0) {
        const indices = this.artifact.codeSeparatorIndices;
        if (indices && methodIndex !== undefined && methodIndex < indices.length
            && methodIndex < realOffsets.length) {
          codeSepIdx = realOffsets[methodIndex];
        } else if (this.artifact.codeSeparatorIndex !== undefined) {
          codeSepIdx = realOffsets[0];
        }
      }
    }

    if (codeSepIdx === undefined) {
      // Template (deploy-time) path: derive the shifted offset from the args.
      codeSepIdx = this.artifact.codeSeparatorIndex;
      const indices = this.artifact.codeSeparatorIndices;
      if (indices && methodIndex !== undefined && methodIndex < indices.length) {
        codeSepIdx = indices[methodIndex];
      }
      if (codeSepIdx !== undefined) {
        codeSepIdx = this.adjustCodeSepOffset(codeSepIdx);
      }
    }

    // Issue #123: build the preimage under the method's declared @sighash mode.
    // `methodIndex` indexes the public-methods list (same convention as the
    // codeSeparatorIndices lookup above); a method with no directive carries no
    // `sigHashType` and falls back to 0x41 (ALL|FORKID), unchanged behaviour.
    const publicMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
    const sigHashType =
      (methodIndex !== undefined ? publicMethods[methodIndex]?.sigHashType : undefined) ?? 0x41;

    return computeOpPushTx(
      tx, inputIndex, subscript, satoshis,
      codeSepIdx,
      sigHashType,
    );
  }

  /**
   * Build the prefix for an unlocking script: optionally _codePart.
   * needsCodePart should be true only when the method constructs continuation outputs
   * (non-terminal stateful calls). Terminal and stateless methods don't use _codePart.
   *
   * Public low-level assembly surface. BUG-100: the OP_PUSH_TX signature is
   * derived on-chain from the preimage (see codegen emitCheckPreimageBinding),
   * so NO signature is pushed here — the stateful unlock layout is
   * `[_codePart?] args... [_changePKH _changeAmount] [_newAmount] txPreimage
   * [selector]` (multi-contract assembly rebuilds it per input). `opSig` is
   * accepted for call-site compatibility but ignored.
   */
  buildStatefulPrefix(_opSig: string, needsCodePart: boolean = false): string {
    let prefix = '';
    if (needsCodePart && this.artifact.codeSeparatorIndex !== undefined) {
      prefix += encodePushData(this.getCodePartHex());
    }
    return prefix;
  }

  // -------------------------------------------------------------------------
  // Reconnection
  // -------------------------------------------------------------------------

  /**
   * Reconnect to an existing deployed contract from a known UTXO.
   *
   * This is the synchronous equivalent of `fromTxId()` — use it when the
   * UTXO data is already available (e.g. from an overlay service or cache)
   * without needing a Provider to fetch the transaction.
   *
   * @param artifact - The compiled artifact describing the contract.
   * @param utxo     - The UTXO containing the contract output.
   * @returns A RunarContract instance connected to the existing UTXO.
   */
  static fromUtxo(
    artifact: RunarArtifact,
    utxo: { txid: string; outputIndex: number; satoshis: number; script: string },
  ): RunarContract {
    const contract = new RunarContract(
      artifact,
      restoreConstructorArgs(artifact, utxo.script),
    );

    if (artifact.stateFields && artifact.stateFields.length > 0) {
      const lastOpReturn = findLastOpReturn(utxo.script);
      contract._codeScript = lastOpReturn !== -1
        ? utxo.script.slice(0, lastOpReturn)
        : utxo.script;
    } else {
      contract._codeScript = utxo.script;
    }

    // Detect inscription envelope in the code portion. Keep it in _codeScript
    // (do NOT strip) so that stateful continuation outputs preserve it.
    if (contract._codeScript) {
      const inscription = parseInscriptionEnvelope(contract._codeScript);
      if (inscription) {
        contract._inscription = inscription;
      }
    }

    contract.currentUtxo = {
      txid: utxo.txid,
      outputIndex: utxo.outputIndex,
      satoshis: utxo.satoshis,
      script: utxo.script,
    };

    if (artifact.stateFields && artifact.stateFields.length > 0) {
      const state = extractStateFromScript(artifact, utxo.script);
      // Deep-review finding C10: `extractStateFromScript` returns null ONLY
      // when the script has no recognisable state section at all (no
      // OP_RETURN found) — i.e. state extraction failed ENTIRELY, distinct
      // from "this one field has no on-chain slot" (issue #119's deliberate
      // zero-fill of unslotted CONSTRUCTOR args in `restoreConstructorArgs`,
      // untouched here). Silently keeping the constructor-initial `_state`
      // set by the `RunarContract` constructor above would present stale
      // deploy-time defaults as if they were live on-chain state. Fail
      // loudly instead of fabricating plausible-looking state.
      if (state === null) {
        throw new Error(
          `RunarContract.fromUtxo: could not extract state for ${artifact.contractName} — ` +
            `no state section (OP_RETURN) found in the UTXO script, but the artifact declares ` +
            `${artifact.stateFields.length} state field(s). Refusing to silently present ` +
            `constructor-initial state as live on-chain state.`,
        );
      }
      contract._state = state;
    }

    return contract;
  }

  /**
   * Reconnect to an existing deployed contract from its deployment transaction.
   *
   * @param artifact     - The compiled artifact describing the contract.
   * @param txid         - The transaction ID containing the contract UTXO.
   * @param outputIndex  - The output index of the contract UTXO.
   * @param provider     - Blockchain provider.
   * @returns A RunarContract instance connected to the existing UTXO.
   */
  static async fromTxId(
    artifact: RunarArtifact,
    txid: string,
    outputIndex: number,
    provider: Provider,
  ): Promise<RunarContract> {
    const tx = await provider.getTransaction(txid);

    if (outputIndex >= tx.outputs.length) {
      throw new Error(
        `RunarContract.fromTxId: output index ${outputIndex} out of range (tx has ${tx.outputs.length} outputs)`,
      );
    }

    const output = tx.outputs[outputIndex]!;
    return RunarContract.fromUtxo(artifact, {
      txid,
      outputIndex,
      satoshis: output.satoshis,
      script: output.script,
    });
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private findMethod(name: string): ABIMethod | undefined {
    return this.artifact.abi.methods.find(
      (m) => m.name === name && m.isPublic,
    );
  }
}

// ---------------------------------------------------------------------------
// JSON BigInt revival
// ---------------------------------------------------------------------------

/**
 * Revive a value that may have been serialized as a BigInt string ("0n")
 * when the artifact JSON was loaded without the bigintReviver (e.g. via
 * Vite's `import artifact from './artifact.json'`).
 */
function reviveJsonValue(value: unknown, type: string): unknown {
  if (typeof value === 'string' && (type === 'bigint' || type === 'int')) {
    if (value.endsWith('n')) return BigInt(value.slice(0, -1));
    return BigInt(value);
  }
  return value;
}

/**
 * Recursively revive a (possibly nested) initialValue tree against its
 * declared type. For `FixedArray<FixedArray<bigint, 2>, 2>` this walks
 * 2 levels deep and reviveJsonValues each leaf as `bigint`.
 */
function reviveNestedValue(value: unknown, type: string): unknown {
  if (!type.startsWith('FixedArray<')) {
    return reviveJsonValue(value, type);
  }
  // Peel one FixedArray<inner, N> layer.
  const inner = type.slice('FixedArray<'.length, -1);
  let depth = 0;
  let splitAt = -1;
  for (let i = inner.length - 1; i >= 0; i--) {
    const ch = inner[i]!;
    if (ch === '>') depth++;
    else if (ch === '<') depth--;
    else if (ch === ',' && depth === 0) {
      splitAt = i;
      break;
    }
  }
  if (splitAt < 0) return value;
  const elemType = inner.slice(0, splitAt).trim();
  if (!Array.isArray(value)) return value;
  return value.map(v => reviveNestedValue(v, elemType));
}

/**
 * Parse a nested `FixedArray<...>` type string into its outer dimensions,
 * returning `[outerLen, innerLen, ...]`. For example:
 *   "FixedArray<bigint, 9>"                        -> [9]
 *   "FixedArray<FixedArray<bigint, 2>, 2>"         -> [2, 2]
 *   "FixedArray<FixedArray<FixedArray<bigint,2>,3>,4>" -> [4, 3, 2]
 * A non-FixedArray type returns `[]`.
 */
function parseFixedArrayDims(type: string): number[] {
  const dims: number[] = [];
  let current = type.trim();
  while (current.startsWith('FixedArray<')) {
    const inner = current.slice('FixedArray<'.length, -1);
    // Find the matching comma that separates the element type from
    // the length — this is the last top-level comma, since the length
    // is always a bare integer and the element type may contain its
    // own `FixedArray<T, N>` commas.
    let depth = 0;
    let splitAt = -1;
    for (let i = inner.length - 1; i >= 0; i--) {
      const ch = inner[i]!;
      if (ch === '>') depth++;
      else if (ch === '<') depth--;
      else if (ch === ',' && depth === 0) {
        splitAt = i;
        break;
      }
    }
    if (splitAt < 0) return dims; // malformed
    const elemType = inner.slice(0, splitAt).trim();
    const lenStr = inner.slice(splitAt + 1).trim();
    const len = Number.parseInt(lenStr, 10);
    if (!Number.isFinite(len) || len <= 0) return dims;
    dims.push(len);
    current = elemType;
  }
  return dims;
}

/**
 * Recursively flatten a nested JS array of depth `dims.length` into a
 * flat list of leaf values in declaration order.
 */
function flattenNested(value: unknown, dims: number[]): unknown[] {
  if (dims.length === 0) return [value];
  const out: unknown[] = [];
  if (!Array.isArray(value)) {
    // Missing or wrong shape — emit `dims.reduce(*,1)` undefineds so
    // the caller can still reach the leaves.
    const total = dims.reduce((a, b) => a * b, 1);
    for (let i = 0; i < total; i++) out.push(undefined);
    return out;
  }
  const [, ...rest] = dims;
  for (const v of value) {
    out.push(...flattenNested(v, rest));
  }
  return out;
}

/**
 * Recursively rebuild a nested JS array of depth `dims.length` from a
 * flat list of leaf values in declaration order.
 */
function regroupNested(flat: unknown[], dims: number[], offset = 0): { value: unknown[]; consumed: number } {
  const [outerLen, ...rest] = dims;
  if (outerLen === undefined) {
    return { value: [], consumed: 0 };
  }
  const value: unknown[] = new Array(outerLen);
  let consumed = 0;
  if (rest.length === 0) {
    for (let i = 0; i < outerLen; i++) {
      value[i] = flat[offset + i];
    }
    consumed = outerLen;
  } else {
    for (let i = 0; i < outerLen; i++) {
      const sub = regroupNested(flat, rest, offset + consumed);
      value[i] = sub.value;
      consumed += sub.consumed;
    }
  }
  return { value, consumed };
}

/**
 * Flatten a state record whose grouped FixedArray entries (`Board`) hold
 * a (possibly nested) JS array of length N into a new record where each
 * leaf element is keyed by its underlying synthetic scalar name
 * (`Board__0`..`Board__8`, `Grid__0__0`..`Grid__1__1`, etc.). The
 * grouped entries are also preserved for callers that read them later.
 *
 * Used at the ANF-interpreter boundary, which knows only the expanded
 * scalar property names.
 */
function flattenFixedArrayState(
  state: Record<string, unknown>,
  stateFields: ReadonlyArray<{
    name: string;
    type: string;
    fixedArray?: { syntheticNames: string[] };
  }> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...state };
  if (!stateFields) return out;
  for (const field of stateFields) {
    if (!field.fixedArray) continue;
    const value = state[field.name];
    if (!Array.isArray(value)) continue;
    const dims = parseFixedArrayDims(field.type);
    const flat = flattenNested(value, dims);
    const syntheticNames = field.fixedArray.syntheticNames;
    for (let i = 0; i < syntheticNames.length; i++) {
      const synth = syntheticNames[i]!;
      // Do not overwrite an explicit scalar in the original state.
      if (!(synth in out)) out[synth] = flat[i];
    }
  }
  return out;
}

/**
 * Re-group a state record's synthetic scalar entries back into arrays
 * (possibly nested) under their grouped names. Non-synthetic scalars
 * are passed through.
 */
function regroupFixedArrayState(
  state: Record<string, unknown>,
  stateFields: ReadonlyArray<{
    name: string;
    type: string;
    fixedArray?: { length: number; syntheticNames: string[] };
  }> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...state };
  if (!stateFields) return out;
  for (const field of stateFields) {
    if (!field.fixedArray) continue;
    const syntheticNames = field.fixedArray.syntheticNames;
    const flat: unknown[] = new Array(syntheticNames.length);
    let sawAny = false;
    for (let i = 0; i < syntheticNames.length; i++) {
      const synth = syntheticNames[i]!;
      if (synth in out) {
        flat[i] = out[synth];
        sawAny = true;
      }
    }
    if (!sawAny) continue;
    // Fall back to the prior grouped value for still-missing leaves
    // by re-flattening it alongside the scalar updates.
    const prior = state[field.name];
    const dims = parseFixedArrayDims(field.type);
    if (Array.isArray(prior)) {
      const priorFlat = flattenNested(prior, dims);
      for (let i = 0; i < flat.length; i++) {
        if (flat[i] === undefined) flat[i] = priorFlat[i];
      }
    }
    const rebuilt = regroupNested(flat, dims);
    out[field.name] = rebuilt.value;
  }
  return out;
}

/**
 * If a constructor arg list uses the grouped FixedArray form
 * (`[someArray, ...]`), expand each (possibly nested) array-valued arg
 * into consecutive positional slots so the ANF interpreter's index-based
 * lookup works.
 */
function flattenFixedArrayArgs(
  args: unknown[],
  abiParams: ReadonlyArray<{ name: string; type: string; fixedArray?: { length: number } }>,
): unknown[] {
  const out: unknown[] = [];
  for (let i = 0; i < args.length; i++) {
    const param = abiParams[i];
    const value = args[i];
    if (param?.fixedArray && Array.isArray(value)) {
      const dims = parseFixedArrayDims(param.type);
      if (dims.length > 0) {
        out.push(...flattenNested(value, dims));
      } else {
        for (const v of value) out.push(v);
      }
    } else {
      out.push(value);
    }
  }
  return out;
}

/**
 * Recover the positional constructor argument list from a deployed locking
 * script, so a restored contract (`fromUtxo` / `fromTxId`) operates on the real
 * baked-in values rather than `0n` placeholders.
 *
 * `extractConstructorArgs` returns a name→value map keyed by ABI param name;
 * `abi.constructor.params` is already ordered by paramIndex, so mapping over it
 * yields the positional `unknown[]` the `RunarContract` constructor expects.
 *
 * Params that carry no constructor slot (mutable state fields — their value
 * lives in the OP_RETURN state section, restored separately) are absent from
 * the extracted map; they fall back to `0n`, matching the prior placeholder
 * behaviour, and are immediately overwritten by `extractStateFromScript`.
 *
 * FixedArray constructor params are rejected by the compiler ("Constructor
 * parameter cannot be a FixedArray"), so no FixedArray grouping arises here.
 */
function restoreConstructorArgs(artifact: RunarArtifact, scriptHex: string): unknown[] {
  const params = artifact.abi.constructor.params;
  if (params.length === 0) return [];
  const extracted = extractConstructorArgs(artifact, scriptHex);
  return params.map((p) => (Object.prototype.hasOwnProperty.call(extracted, p.name) ? extracted[p.name] : 0n));
}

/**
 * Build a named argument map from positional args and user-visible params.
 * Used to feed the ANF interpreter for auto-state computation.
 */
function buildNamedArgs(
  userParams: Array<{ name: string; type: string }>,
  resolvedArgs: unknown[],
): Record<string, unknown> {
  const named: Record<string, unknown> = {};
  for (let i = 0; i < userParams.length; i++) {
    named[userParams[i]!.name] = resolvedArgs[i];
  }
  return named;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/**
 * Compute the BIP-143 sighash digest — `hash256(preimage)` i.e.
 * `sha256(sha256(preimage))` — that is ACTUALLY ECDSA-signed by
 * `OP_CHECKSIG` on-chain.
 *
 * Deep-review finding C19: `PreparedCall.sighash` previously stored only
 * `sha256(preimage)` (a SINGLE hash). That happened to work for the default
 * `call()` path only because `LocalSigner.sign()` hands its OWN independently
 * computed `sha256(preimage)` to `PrivateKey.sign()`, which re-hashes its
 * input once more internally — so the total ends up correct by accident of
 * that one call chain. An external wallet / hardware signer wired to the
 * multi-signer `prepareCall()` / `finalizeCall()` API is handed
 * `PreparedCall.sighash` and is expected to ECDSA-sign it DIRECTLY (no
 * further hashing) — e.g. a BRC-100 `signHash`-style API. Handed the
 * single-hashed value, such a signer signs the wrong digest and the node's
 * real `OP_CHECKSIG` rejects the spend.
 *
 * This is the WIRE-LEVEL digest external signers must sign — the same value
 * the Java SDK already stores in its `PreparedCall`. Port this exact
 * `hash256(preimage)` computation (not `sha256(preimage)`) to every other
 * tier's `PreparedCall.sighash` equivalent (Go/Rust/Python).
 */
function computeBip143Sighash(preimageHex: string): string {
  const preimageBytes = Utils.toArray(preimageHex, 'hex');
  return Utils.toHex(Hash.hash256(preimageBytes));
}

/**
 * Encode an argument value as a Bitcoin Script push data element.
 *
 * Exported as part of the low-level assembly surface: downstream tooling
 * (runar-testing's mock-preimage builders) and multi-contract tx assembly (and
 * any external unlocking-script construction) must encode arguments
 * byte-identically to `buildUnlockingScript` — share this, don't copy it.
 */
export function encodeArg(value: unknown): string {
  if (isEmptySig(value)) {
    return '00'; // OP_0 — empty signature push for the failing OR-CHECKSIG branch (issue #106)
  }
  if (typeof value === 'bigint') {
    return encodeScriptNumber(value);
  }
  if (typeof value === 'number') {
    return encodeScriptNumber(BigInt(value));
  }
  if (typeof value === 'boolean') {
    return value ? '51' : '00';
  }
  if (typeof value === 'string') {
    // Assume hex-encoded data
    return encodePushData(value);
  }
  // Fallback: convert to string
  return encodePushData(String(value));
}

/**
 * Encode a bigint as a minimally-encoded Bitcoin Script number push
 * (OP_0 / OP_1..OP_16 / OP_1NEGATE / sign-magnitude LE push data).
 * Exported as part of the low-level assembly surface.
 */
export function encodeScriptNumber(n: bigint): string {
  if (n === 0n) {
    return '00'; // OP_0
  }
  if (n >= 1n && n <= 16n) {
    // OP_1 through OP_16
    return (0x50 + Number(n)).toString(16);
  }
  if (n === -1n) {
    return '4f'; // OP_1NEGATE
  }

  const negative = n < 0n;
  let absVal = negative ? -n : n;
  const bytes: number[] = [];

  while (absVal > 0n) {
    bytes.push(Number(absVal & 0xffn));
    absVal >>= 8n;
  }

  if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }

  const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  return encodePushData(hex);
}

/**
 * Normalize a witness-value input (hex string or Uint8Array) into a
 * lowercase hex string suitable for `encodePushData`. Hex inputs may
 * optionally carry a `0x` prefix and any casing.
 */
function normalizeWitnessBytes(value: string | Uint8Array): string {
  if (typeof value === 'string') {
    const h = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
    if (h.length % 2 !== 0) {
      throw new Error(`witness value: hex string must have even length (got ${h.length})`);
    }
    if (!/^[0-9a-fA-F]*$/.test(h)) {
      throw new Error('witness value: invalid hex characters');
    }
    return h.toLowerCase();
  }
  // Uint8Array
  let out = '';
  for (let i = 0; i < value.length; i++) {
    out += value[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Encode raw hex bytes as a Bitcoin Script push (direct push / PUSHDATA1/2/4).
 * Exported as part of the low-level assembly surface.
 */
export function encodePushData(dataHex: string): string {
  if (dataHex.length === 0) return '00'; // OP_0
  const len = dataHex.length / 2;

  // MINIMALDATA: single-byte payloads in the OP_N range must use the
  // corresponding minimal opcode (`OP_1..OP_16` / `OP_1NEGATE`) rather than
  // the direct push `01 NN`, which is relay-rejected as "Data push larger
  // than necessary". `encodeScriptNumber` already short-circuits Int args to
  // OP_N; this brings the ByteString push path to the same standard. Kept
  // byte-identical with `encodePushDataState` in state.ts and the shared
  // `encode_push_data` in the other six SDKs.
  //
  // NOTE: 0x00 is deliberately NOT in that set. `OP_0` pushes the EMPTY byte
  // array, not a 1-byte `0x00` — so the minimal encoding of a 1-byte `0x00`
  // payload is the direct push `01 00` (matching the compiler's
  // `encodePushBytesHex` in push-encoding.ts), not `OP_0` (S1).
  if (len === 1) {
    const byte = parseInt(dataHex, 16);
    if (byte >= 0x01 && byte <= 0x10) return (0x50 + byte).toString(16).padStart(2, '0'); // OP_1..OP_16
    if (byte === 0x81) return '4f'; // OP_1NEGATE
  }

  if (len <= 75) {
    return len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xff) {
    return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xffff) {
    const lo = (len & 0xff).toString(16).padStart(2, '0');
    const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + dataHex;
  } else {
    const b0 = (len & 0xff).toString(16).padStart(2, '0');
    const b1 = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
    const b2 = ((len >> 16) & 0xff).toString(16).padStart(2, '0');
    const b3 = ((len >> 24) & 0xff).toString(16).padStart(2, '0');
    return '4e' + b0 + b1 + b2 + b3 + dataHex;
  }
}
