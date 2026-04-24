// ---------------------------------------------------------------------------
// runar-sdk/contract.ts — Main contract runtime wrapper
// ---------------------------------------------------------------------------

import type { RunarArtifact, ABIMethod } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { TransactionData, UTXO, DeployOptions, CallOptions, PreparedCall } from './types.js';
import type { Inscription } from './ordinals/types.js';
import { buildDeployTransaction, selectUtxos } from './deployment.js';
import { buildCallTransaction } from './calling.js';
import { serializeState, extractStateFromScript, findLastOpReturn } from './state.js';
import { computeOpPushTx } from './oppushtx.js';
import { buildP2PKHScript } from './script-utils.js';
import { computeNewStateAndDataOutputs } from './anf-interpreter.js';
import { buildInscriptionEnvelope, parseInscriptionEnvelope } from './ordinals/envelope.js';
import { Utils, Hash, Transaction as BsvTransaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import { WalletProvider } from './providers/wallet-provider.js';

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

    // Sign all inputs — need unsigned hex for signer
    const unsignedHex = tx.toHex();
    for (let i = 0; i < inputCount; i++) {
      const utxo = utxos[i]!;
      const sig = await signer.sign(unsignedHex, i, utxo.script, utxo.satoshis);
      const pubKey = await signer.getPublicKey();
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
      console.warn('Failed to fetch transaction after broadcast:', err);
      return {
        txid,
        version: 1,
        inputs: [],
        outputs: [{ satoshis: deploySatoshis, script: lockingScript }],
        locktime: 0,
        raw: tx.toHex(),
      };
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
    const wallet = (walletProvider as any).wallet;
    const basket = (walletProvider as any).basket;

    const lockingScript = this.getLockingScript();
    const satoshis = options.satoshis ?? 1;

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

    // In stateful contracts, user checkSig executes AFTER OP_CODESEPARATOR
    // (checkPreimage is auto-injected at method entry), so use trimmed script.
    // In stateless contracts, user checkSig is BEFORE OP_CODESEPARATOR, so use full script.
    let mIdx = 0;
    if (prepared._isStateful) {
      const pubMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
      if (pubMethods.length > 1) {
        const idx = pubMethods.findIndex((m) => m.name === methodName);
        if (idx >= 0) mIdx = idx;
      }
    }
    const sigSubscript = prepared._isStateful
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

    const method = this.findMethod(methodName);
    if (!method) {
      throw new Error(
        `RunarContract.prepareCall: method '${methodName}' not found in ${this.artifact.contractName}`,
      );
    }

    const isStateful =
      this.artifact.stateFields !== undefined &&
      this.artifact.stateFields.length > 0;
    const methodNeedsChange = method.params.some((p) => p.name === '_changePKH');
    const methodNeedsNewAmount = method.params.some((p) => p.name === '_newAmount');
    const userParams = isStateful
      ? method.params.filter(
          (p) =>
            p.type !== 'SigHashPreimage' &&
            p.name !== '_changePKH' &&
            p.name !== '_changeAmount' &&
            p.name !== '_newAmount',
        )
      : method.params;

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
        prevoutsIndices.push(i);
        const estimatedInputs = 1 + (options?.additionalContractInputs?.length ?? 0) + 1;
        resolvedArgs[i] = '00'.repeat(36 * estimatedInputs);
      }
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

      const buildTerminalTx = (unlock: string): BsvTransaction => {
        const ttx = new BsvTransaction();
        ttx.addInput({
          sourceTXID: contractUtxo.txid,
          sourceOutputIndex: contractUtxo.outputIndex,
          unlockingScript: UnlockingScript.fromHex(unlock),
          sequence: 0xffffffff,
        });
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
          const unlock = this.buildStatefulPrefix(opSig) + argsHex + changeHex + newAmountHex + encodePushData(preimage) + methodSelectorHex;
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

      // Compute sighash from preimage
      let sighash = '';
      if (finalPreimage) {
        const preimageBytes = Utils.toArray(finalPreimage, 'hex');
        const sighashBytes = Hash.sha256(preimageBytes);
        sighash = Utils.toHex(sighashBytes);
      }

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
        _isTerminal: true,
        _needsOpPushTx: needsOpPushTx,
        _methodNeedsChange: methodNeedsChange,
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
      };
    }

    // -------------------------------------------------------------------
    // Non-terminal path
    // -------------------------------------------------------------------

    // Build the initial unlocking script (with placeholders)
    let unlockingScript: string;
    if (needsOpPushTx) {
      unlockingScript = encodePushData('00'.repeat(72)) +
        this.buildUnlockingScript(methodName, resolvedArgs);
    } else {
      unlockingScript = this.buildUnlockingScript(methodName, resolvedArgs);
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

    if (isStateful && hasMultiOutput) {
      const codeScript = this._codeScript ?? this.buildCodeScript();
      contractOutputs = options!.outputs!.map((out) => {
        const stateHex = serializeState(this.artifact.stateFields!, out.state);
        return { script: codeScript + '6a' + stateHex, satoshis: out.satoshis ?? 1 };
      });
    } else if (isStateful) {
      newSatoshis = options?.satoshis ?? this.currentUtxo.satoshis;
      if (options?.newState) {
        // Explicit newState takes priority (backward compat)
        this._state = { ...this._state, ...options.newState };
      } else if (methodNeedsChange && this.artifact.anf) {
        // Auto-compute new state from ANF IR
        const namedArgs = buildNamedArgs(userParams, resolvedArgs);
        // Flatten FixedArray grouped state entries into their underlying
        // synthetic scalar keys so the ANF interpreter (which only sees
        // expanded scalars) can read them by name.
        const flatState = flattenFixedArrayState(this._state, this.artifact.stateFields);
        const flatCtorArgs = flattenFixedArrayArgs(this.constructorArgs, this.artifact.abi.constructor.params);
        const { state: computed, dataOutputs: anfDataOutputs } = computeNewStateAndDataOutputs(
          this.artifact.anf, methodName, flatState, namedArgs,
          flatCtorArgs,
        );
        if (anfDataOutputs.length > 0 && resolvedDataOutputs.length === 0) {
          resolvedDataOutputs = anfDataOutputs.map((d) => ({
            script: d.script,
            satoshis: Number(d.satoshis),
          }));
        }
        const merged = { ...flatState, ...computed };
        // Re-group synthetic scalars back into array values, then merge
        // into the user-visible state.
        const regrouped = regroupFixedArrayState(merged, this.artifact.stateFields);
        this._state = { ...this._state, ...regrouped };
      }
      newLockingScript = this.getLockingScript();
    }

    const feeRate = await provider.getFeeRate();
    const changeScript = buildP2PKHScript(changeAddress);
    const allFundingUtxos = await provider.getUtxos(address);
    const additionalUtxos = allFundingUtxos.filter(
      (u) => !(u.txid === this.currentUtxo!.txid && u.outputIndex === this.currentUtxo!.outputIndex),
    );

    // Resolve per-input args for additional contract inputs
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

    // Build placeholder unlocking scripts for merge inputs
    const extraUnlockPlaceholders = extraContractUtxos.map((_, i) => {
      const argsForPlaceholder = resolvedPerInputArgs?.[i] ?? resolvedArgs;
      return encodePushData('00'.repeat(72)) + this.buildUnlockingScript(methodName, argsForPlaceholder);
    });

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
      },
    );

    // Sign P2PKH funding inputs
    let txHex = tx.toHex();
    const p2pkhStartIdx = 1 + extraContractUtxos.length;
    for (let i = p2pkhStartIdx; i < inputCount; i++) {
      const utxo = additionalUtxos[i - p2pkhStartIdx];
      if (utxo) {
        const sig = await signer.sign(txHex, i, utxo.script, utxo.satoshis);
        const pubKey = await signer.getPublicKey();
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
        const unlock = this.buildStatefulPrefix(opSig, methodNeedsChange) + argsHex + changeHex + newAmountHex + encodePushData(preimage) + methodSelectorHex;
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

      // Rebuild TX with real unlocking scripts
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

      // Re-sign P2PKH funding inputs
      txHex = tx.toHex();
      for (let i = p2pkhStartIdx; i < inputCount; i++) {
        const utxo = additionalUtxos[i - p2pkhStartIdx];
        if (utxo) {
          const sig = await signer.sign(txHex, i, utxo.script, utxo.satoshis);
          const pubKey = await signer.getPublicKey();
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

    // Compute sighash from preimage
    let sighash = '';
    if (finalPreimage) {
      const preimageBytes = Utils.toArray(finalPreimage, 'hex');
      const sighashBytes = Hash.sha256(preimageBytes);
      sighash = Utils.toHex(sighashBytes);
    }

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
      _isTerminal: false,
      _needsOpPushTx: needsOpPushTx,
      _methodNeedsChange: methodNeedsChange,
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
        this.buildStatefulPrefix(prepared.opPushTxSig, prepared._methodNeedsChange) +
        argsHex +
        changeHex +
        newAmountHex +
        encodePushData(prepared.preimage) +
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
      this.currentUtxo = {
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
      console.warn('Failed to fetch transaction after broadcast:', err);
      return {
        txid,
        version: 1,
        inputs: [],
        outputs: [],
        locktime: 0,
        raw: finalTx.toHex(),
      };
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
   */
  private getCodePartHex(): string {
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
   * Used for BIP-143 sighash computation for user CHECKSIG in stateful contracts
   * (where checkSig executes AFTER OP_CODESEPARATOR).
   */
  private getSubscriptForSigning(fullScript: string, methodIndex?: number): string {
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
   */
  private computeOpPushTxWithCodeSep(
    tx: BsvTransaction,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    methodIndex?: number,
  ): { sigHex: string; preimageHex: string } {
    let codeSepIdx = this.artifact.codeSeparatorIndex;
    const indices = this.artifact.codeSeparatorIndices;
    if (indices && methodIndex !== undefined && methodIndex < indices.length) {
      codeSepIdx = indices[methodIndex];
    }
    if (codeSepIdx !== undefined) {
      codeSepIdx = this.adjustCodeSepOffset(codeSepIdx);
    }
    return computeOpPushTx(
      tx, inputIndex, subscript, satoshis,
      codeSepIdx,
    );
  }

  /**
   * Build the prefix for an unlocking script: optionally _codePart + _opPushTxSig.
   * needsCodePart should be true only when the method constructs continuation outputs
   * (non-terminal stateful calls). Terminal and stateless methods don't use _codePart.
   */
  private buildStatefulPrefix(opSig: string, needsCodePart: boolean = false): string {
    let prefix = '';
    if (needsCodePart && this.artifact.codeSeparatorIndex !== undefined) {
      prefix += encodePushData(this.getCodePartHex());
    }
    prefix += encodePushData(opSig);
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
      new Array(artifact.abi.constructor.params.length).fill(0n) as unknown[],
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
      if (state) {
        contract._state = state;
      }
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
 * Encode an argument value as a Bitcoin Script push data element.
 */
function encodeArg(value: unknown): string {
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

function encodeScriptNumber(n: bigint): string {
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

function encodePushData(dataHex: string): string {
  if (dataHex.length === 0) return '00'; // OP_0
  const len = dataHex.length / 2;

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
