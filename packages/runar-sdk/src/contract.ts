// ---------------------------------------------------------------------------
// runar-sdk/contract.ts — Main contract runtime wrapper
// ---------------------------------------------------------------------------

import type { RunarArtifact, ABIMethod } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { Transaction, UTXO, DeployOptions, CallOptions, PreparedCall } from './types.js';
import { buildDeployTransaction, selectUtxos } from './deployment.js';
import { buildCallTransaction, toLittleEndian32, toLittleEndian64, encodeVarInt, reverseHex } from './calling.js';
import { serializeState, extractStateFromScript, findLastOpReturn } from './state.js';
import { computeOpPushTx } from './oppushtx.js';
import { buildP2PKHScript } from './script-utils.js';
import { Utils, Hash, Transaction as BsvTransaction } from '@bsv/sdk';

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
  async deploy(options: DeployOptions): Promise<{ txid: string; tx: Transaction }>;
  async deploy(
    provider: Provider,
    signer: Signer,
    options: DeployOptions,
  ): Promise<{ txid: string; tx: Transaction }>;
  async deploy(
    providerOrOptions: Provider | DeployOptions,
    maybeSigner?: Signer,
    maybeOptions?: DeployOptions,
  ): Promise<{ txid: string; tx: Transaction }> {
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
      // Explicit: deploy(provider, signer, options) — options in maybeSigner slot shouldn't happen
      // but handle gracefully
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
    const { txHex, inputCount } = buildDeployTransaction(
      lockingScript,
      utxos,
      deploySatoshis,
      changeAddress,
      changeScript,
      feeRate,
    );

    // Sign all inputs
    let signedTx = txHex;
    for (let i = 0; i < inputCount; i++) {
      const utxo = utxos[i]!;
      const sig = await signer.sign(signedTx, i, utxo.script, utxo.satoshis);
      const pubKey = await signer.getPublicKey();
      // Build P2PKH unlocking script: <sig> <pubkey>
      const unlockScript = encodePushData(sig) + encodePushData(pubKey);
      signedTx = insertUnlockingScript(signedTx, i, unlockScript);
    }

    // Broadcast
    const txid = await provider.broadcast(signedTx);

    // Track the deployed UTXO
    this.currentUtxo = {
      txid,
      outputIndex: 0,
      satoshis: deploySatoshis,
      script: lockingScript,
    };

    const tx = await provider.getTransaction(txid).catch((err) => {
      console.warn('Failed to fetch transaction after broadcast:', err);
      return {
        txid,
        version: 1,
        inputs: [],
        outputs: [{ satoshis: deploySatoshis, script: lockingScript }],
        locktime: 0,
        raw: signedTx,
      };
    });

    return { txid, tx };
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
  ): Promise<{ txid: string; tx: Transaction }>;
  async call(
    methodName: string,
    args: unknown[],
    provider: Provider,
    signer: Signer,
    options?: CallOptions,
  ): Promise<{ txid: string; tx: Transaction }>;
  async call(
    methodName: string,
    args: unknown[],
    providerOrOptions?: Provider | CallOptions,
    maybeSigner?: Signer,
    maybeOptions?: CallOptions,
  ): Promise<{ txid: string; tx: Transaction }> {
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
    const signatures: Record<number, string> = {};
    for (const idx of prepared.sigIndices) {
      signatures[idx] = await signer.sign(
        prepared.txHex, 0,
        prepared._contractUtxo.script,
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

    // Compute method selector (needed for both terminal and non-terminal)
    let methodSelectorHex = '';
    if (isStateful) {
      const publicMethods = this.artifact.abi.methods.filter((m) => m.isPublic);
      if (publicMethods.length > 1) {
        const idx = publicMethods.findIndex((m) => m.name === methodName);
        if (idx >= 0) methodSelectorHex = encodeScriptNumber(BigInt(idx));
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

      const buildTerminalTx = (unlock: string): string => {
        let tx = '';
        tx += toLittleEndian32(1);
        tx += encodeVarInt(1);
        tx += reverseHex(contractUtxo.txid);
        tx += toLittleEndian32(contractUtxo.outputIndex);
        tx += encodeVarInt(unlock.length / 2);
        tx += unlock;
        tx += 'ffffffff';
        tx += encodeVarInt(terminalOutputs.length);
        for (const out of terminalOutputs) {
          tx += toLittleEndian64(out.satoshis);
          tx += encodeVarInt(out.scriptHex.length / 2);
          tx += out.scriptHex;
        }
        tx += toLittleEndian32(0);
        return tx;
      };

      let termTx = buildTerminalTx(termUnlockScript);
      let finalOpPushTxSig = '';
      let finalPreimage = '';

      if (isStateful) {
        // Build stateful terminal unlock with PLACEHOLDER user sigs
        const buildUnlock = (tx: string): { unlock: string; opSig: string; preimage: string } => {
          const { sigHex: opSig, preimageHex: preimage } = computeOpPushTx(
            tx, 0, contractUtxo.script, contractUtxo.satoshis,
          );
          let argsHex = '';
          for (const arg of resolvedArgs) argsHex += encodeArg(arg);
          let changeHex = '';
          if (methodNeedsChange && changePKHHex) {
            changeHex = encodePushData(changePKHHex) + encodeArg(0n);
          }
          const unlock = encodePushData(opSig) + argsHex + changeHex + encodePushData(preimage) + methodSelectorHex;
          return { unlock, opSig, preimage };
        };

        // First pass
        const first = buildUnlock(termTx);
        termTx = buildTerminalTx(first.unlock);

        // Second pass
        const second = buildUnlock(termTx);
        termTx = insertUnlockingScript(termTx, 0, second.unlock);
        finalOpPushTxSig = second.opSig;
        finalPreimage = second.preimage;
      } else if (needsOpPushTx || sigIndices.length > 0) {
        // Stateless terminal — keep placeholder sigs
        if (needsOpPushTx) {
          const { sigHex, preimageHex } = computeOpPushTx(
            termTx, 0, contractUtxo.script, contractUtxo.satoshis,
          );
          finalOpPushTxSig = sigHex;
          resolvedArgs[preimageIndex] = preimageHex;
        }
        // Don't sign Sig params — keep 72-byte placeholders
        let realUnlock = this.buildUnlockingScript(methodName, resolvedArgs);
        if (needsOpPushTx && finalOpPushTxSig) {
          realUnlock = encodePushData(finalOpPushTxSig) + realUnlock;
          const tmpTx = insertUnlockingScript(termTx, 0, realUnlock);
          const { sigHex: finalSig, preimageHex: finalPre } = computeOpPushTx(
            tmpTx, 0, contractUtxo.script, contractUtxo.satoshis,
          );
          resolvedArgs[preimageIndex] = finalPre;
          finalOpPushTxSig = finalSig;
          finalPreimage = finalPre;
          realUnlock = encodePushData(finalSig) +
            this.buildUnlockingScript(methodName, resolvedArgs);
        }
        termTx = insertUnlockingScript(termTx, 0, realUnlock);
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
        txHex: termTx,
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

    if (isStateful && hasMultiOutput) {
      const codeScript = this._codeScript ?? this.buildCodeScript();
      contractOutputs = options!.outputs!.map((out) => {
        const stateHex = serializeState(this.artifact.stateFields!, out.state);
        return { script: codeScript + '6a' + stateHex, satoshis: out.satoshis ?? 1 };
      });
    } else if (isStateful) {
      newSatoshis = options?.satoshis ?? this.currentUtxo.satoshis;
      if (options?.newState) {
        this._state = { ...this._state, ...options.newState };
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

    let { txHex, inputCount, changeAmount } = buildCallTransaction(
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
      },
    );

    // Sign P2PKH funding inputs
    let signedTx = txHex;
    const p2pkhStartIdx = 1 + extraContractUtxos.length;
    for (let i = p2pkhStartIdx; i < inputCount; i++) {
      const utxo = additionalUtxos[i - p2pkhStartIdx];
      if (utxo) {
        const sig = await signer.sign(signedTx, i, utxo.script, utxo.satoshis);
        const pubKey = await signer.getPublicKey();
        const unlockScript = encodePushData(sig) + encodePushData(pubKey);
        signedTx = insertUnlockingScript(signedTx, i, unlockScript);
      }
    }

    let finalOpPushTxSig = '';
    let finalPreimage = '';

    if (isStateful) {
      const perInputArgs = options?.additionalContractInputArgs;

      // Helper: build a stateful unlock. For inputIdx===0 (primary), keeps
      // placeholder Sig params. For inputIdx>0 (extra), signs with signer.
      const buildStatefulUnlock = async (
        tx: string, inputIdx: number, subscript: string, sats: number,
        argsOverride?: unknown[], txChangeAmount?: number,
      ): Promise<{ unlock: string; opSig: string; preimage: string }> => {
        const { sigHex: opSig, preimageHex: preimage } = computeOpPushTx(
          tx, inputIdx, subscript, sats,
        );
        const baseArgs = argsOverride ?? resolvedArgs;
        const inputArgs = [...baseArgs];
        // Only sign Sig params for extra inputs, not the primary
        if (inputIdx > 0) {
          for (const idx of sigIndices) {
            inputArgs[idx] = await signer.sign(tx, inputIdx, subscript, sats);
          }
        }
        if (prevoutsIndices.length > 0) {
          const parsedTx = BsvTransaction.fromHex(tx);
          let allPrevoutsHex = '';
          for (const inp of parsedTx.inputs) {
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
        const unlock = encodePushData(opSig) + argsHex + changeHex + newAmountHex + encodePushData(preimage) + methodSelectorHex;
        return { unlock, opSig, preimage };
      };

      // First pass
      const { unlock: input0Unlock } = await buildStatefulUnlock(
        signedTx, 0, contractUtxo.script, contractUtxo.satoshis,
        undefined, changeAmount,
      );
      const extraUnlocks: string[] = [];
      for (let i = 0; i < extraContractUtxos.length; i++) {
        const mu = extraContractUtxos[i]!;
        const extraArgs = perInputArgs?.[i] ? resolvedPerInputArgs?.[i] : undefined;
        const { unlock } = await buildStatefulUnlock(signedTx, i + 1, mu.script, mu.satoshis, extraArgs, changeAmount);
        extraUnlocks.push(unlock);
      }

      // Rebuild TX with real unlocking scripts
      ({ txHex, inputCount, changeAmount } = buildCallTransaction(
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
        },
      ));
      signedTx = txHex;

      // Second pass: recompute with final tx
      const { unlock: finalInput0Unlock, opSig, preimage } = await buildStatefulUnlock(
        signedTx, 0, contractUtxo.script, contractUtxo.satoshis,
        undefined, changeAmount,
      );
      finalOpPushTxSig = opSig;
      finalPreimage = preimage;
      signedTx = insertUnlockingScript(signedTx, 0, finalInput0Unlock);

      for (let i = 0; i < extraContractUtxos.length; i++) {
        const mu = extraContractUtxos[i]!;
        const extraArgs = perInputArgs?.[i] ? resolvedPerInputArgs?.[i] : undefined;
        const { unlock: finalMergeUnlock } = await buildStatefulUnlock(signedTx, i + 1, mu.script, mu.satoshis, extraArgs, changeAmount);
        signedTx = insertUnlockingScript(signedTx, i + 1, finalMergeUnlock);
      }

      // Re-sign P2PKH funding inputs
      for (let i = p2pkhStartIdx; i < inputCount; i++) {
        const utxo = additionalUtxos[i - p2pkhStartIdx];
        if (utxo) {
          const sig = await signer.sign(signedTx, i, utxo.script, utxo.satoshis);
          const pubKey = await signer.getPublicKey();
          const unlockScript = encodePushData(sig) + encodePushData(pubKey);
          signedTx = insertUnlockingScript(signedTx, i, unlockScript);
        }
      }

      // Update resolvedArgs with real prevouts so finalizeCall can
      // rebuild the primary unlock with correct allPrevouts values.
      if (prevoutsIndices.length > 0) {
        const parsedTx = BsvTransaction.fromHex(signedTx);
        let allPrevoutsHex = '';
        for (const inp of parsedTx.inputs) {
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
        const { sigHex, preimageHex } = computeOpPushTx(
          signedTx, 0, contractUtxo.script, contractUtxo.satoshis,
        );
        finalOpPushTxSig = sigHex;
        resolvedArgs[preimageIndex] = preimageHex;
      }
      // Don't sign Sig params — keep placeholders
      let realUnlockingScript = this.buildUnlockingScript(methodName, resolvedArgs);
      if (needsOpPushTx && finalOpPushTxSig) {
        realUnlockingScript = encodePushData(finalOpPushTxSig) + realUnlockingScript;
        const tmpTx = insertUnlockingScript(signedTx, 0, realUnlockingScript);
        const { sigHex: finalSig, preimageHex: finalPre } = computeOpPushTx(
          tmpTx, 0, contractUtxo.script, contractUtxo.satoshis,
        );
        resolvedArgs[preimageIndex] = finalPre;
        finalOpPushTxSig = finalSig;
        finalPreimage = finalPre;
        realUnlockingScript = encodePushData(finalSig) +
          this.buildUnlockingScript(methodName, resolvedArgs);
      }
      signedTx = insertUnlockingScript(signedTx, 0, realUnlockingScript);
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
      txHex: signedTx,
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
  ): Promise<{ txid: string; tx: Transaction }> {
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
        encodePushData(prepared.opPushTxSig) +
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
      primaryUnlock = encodePushData(prepared.opPushTxSig) +
        this.buildUnlockingScript(prepared._methodName, resolvedArgs);
    } else {
      primaryUnlock = this.buildUnlockingScript(prepared._methodName, resolvedArgs);
    }

    // Insert primary unlock into the transaction
    let finalTx = insertUnlockingScript(prepared.txHex, 0, primaryUnlock);

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

    const tx = await provider.getTransaction(txid).catch((err) => {
      console.warn('Failed to fetch transaction after broadcast:', err);
      return {
        txid,
        version: 1,
        inputs: [],
        outputs: [],
        locktime: 0,
        raw: finalTx,
      };
    });

    return { txid, tx };
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
    // Use stored code script from chain if available (reconnected contract)
    let script = this._codeScript ?? this.buildCodeScript();

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

    if (this.artifact.constructorSlots && this.artifact.constructorSlots.length > 0) {
      // Sort by byteOffset descending so splicing doesn't shift later offsets
      const slots = [...this.artifact.constructorSlots].sort(
        (a, b) => b.byteOffset - a.byteOffset,
      );
      for (const slot of slots) {
        const encoded = encodeArg(this.constructorArgs[slot.paramIndex]);
        const hexOffset = slot.byteOffset * 2;
        // Replace the 1-byte OP_0 placeholder (2 hex chars) with the encoded arg
        script = script.slice(0, hexOffset) + encoded + script.slice(hexOffset + 2);
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

  // -------------------------------------------------------------------------
  // Reconnection
  // -------------------------------------------------------------------------

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
    const contract = new RunarContract(
      artifact,
      // Dummy constructor args -- we store the on-chain code script directly
      // so these won't be used in getLockingScript().
      new Array(artifact.abi.constructor.params.length).fill(0n) as unknown[],
    );

    // Store the code portion of the on-chain script so getLockingScript()
    // produces correct output without needing the original constructor args.
    if (artifact.stateFields && artifact.stateFields.length > 0) {
      // Stateful: code is everything before the last OP_RETURN.
      // Use opcode-aware walking to find the real OP_RETURN (not a 0x6a
      // byte inside push data).
      const lastOpReturn = findLastOpReturn(output.script);
      contract._codeScript = lastOpReturn !== -1
        ? output.script.slice(0, lastOpReturn)
        : output.script;
    } else {
      // Stateless: the full on-chain script IS the code
      contract._codeScript = output.script;
    }

    // Set the current UTXO
    contract.currentUtxo = {
      txid,
      outputIndex,
      satoshis: output.satoshis,
      script: output.script,
    };

    // Extract state if this is a stateful contract
    if (artifact.stateFields && artifact.stateFields.length > 0) {
      const state = extractStateFromScript(artifact, output.script);
      if (state) {
        contract._state = state;
      }
    }

    return contract;
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


/**
 * Insert an unlocking script into a raw transaction at a specific input index.
 *
 * Parses the raw transaction hex to locate the target input's scriptSig field,
 * replaces it with the provided unlocking script, and returns the modified
 * transaction hex.
 */
function insertUnlockingScript(
  txHex: string,
  inputIndex: number,
  unlockScript: string,
): string {
  let pos = 0;

  // Skip version (4 bytes = 8 hex chars)
  pos += 8;

  // Read input count
  const { value: inputCount, hexLen: icLen } = readVarIntHex(txHex, pos);
  pos += icLen;

  if (inputIndex >= inputCount) {
    throw new Error(
      `insertUnlockingScript: input index ${inputIndex} out of range (${inputCount} inputs)`,
    );
  }

  for (let i = 0; i < inputCount; i++) {
    // Skip prevTxid (32 bytes = 64 hex chars)
    pos += 64;
    // Skip prevOutputIndex (4 bytes = 8 hex chars)
    pos += 8;

    // Read scriptSig length
    const { value: scriptLen, hexLen: slLen } = readVarIntHex(txHex, pos);

    if (i === inputIndex) {
      // Build the replacement: new varint length + new script data
      const newScriptByteLen = unlockScript.length / 2;
      const newVarInt = writeVarIntHex(newScriptByteLen);

      const before = txHex.slice(0, pos);
      const after = txHex.slice(pos + slLen + scriptLen * 2);
      return before + newVarInt + unlockScript + after;
    }

    // Skip this input's scriptSig + sequence (4 bytes = 8 hex chars)
    pos += slLen + scriptLen * 2 + 8;
  }

  // Should be unreachable due to the range check above
  throw new Error(
    `insertUnlockingScript: input index ${inputIndex} out of range`,
  );
}

/**
 * Read a Bitcoin varint from a hex string at the given position.
 * Returns the decoded value and the number of hex characters consumed.
 */
function readVarIntHex(
  hex: string,
  pos: number,
): { value: number; hexLen: number } {
  const first = parseInt(hex.slice(pos, pos + 2), 16);
  if (first < 0xfd) {
    return { value: first, hexLen: 2 };
  }
  if (first === 0xfd) {
    const lo = parseInt(hex.slice(pos + 2, pos + 4), 16);
    const hi = parseInt(hex.slice(pos + 4, pos + 6), 16);
    return { value: lo | (hi << 8), hexLen: 6 };
  }
  if (first === 0xfe) {
    const b0 = parseInt(hex.slice(pos + 2, pos + 4), 16);
    const b1 = parseInt(hex.slice(pos + 4, pos + 6), 16);
    const b2 = parseInt(hex.slice(pos + 6, pos + 8), 16);
    const b3 = parseInt(hex.slice(pos + 8, pos + 10), 16);
    return {
      value: (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0,
      hexLen: 10,
    };
  }
  // 0xff -- 8-byte varint; handle the low 4 bytes (sufficient for scripts)
  const b0 = parseInt(hex.slice(pos + 2, pos + 4), 16);
  const b1 = parseInt(hex.slice(pos + 4, pos + 6), 16);
  const b2 = parseInt(hex.slice(pos + 6, pos + 8), 16);
  const b3 = parseInt(hex.slice(pos + 8, pos + 10), 16);
  return {
    value: (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0,
    hexLen: 18,
  };
}

/**
 * Encode a number as a Bitcoin varint in hex.
 */
function writeVarIntHex(n: number): string {
  if (n < 0xfd) {
    return n.toString(16).padStart(2, '0');
  }
  if (n <= 0xffff) {
    const lo = (n & 0xff).toString(16).padStart(2, '0');
    const hi = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
    return 'fd' + lo + hi;
  }
  if (n <= 0xffffffff) {
    const b0 = (n & 0xff).toString(16).padStart(2, '0');
    const b1 = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
    const b2 = ((n >> 16) & 0xff).toString(16).padStart(2, '0');
    const b3 = ((n >> 24) & 0xff).toString(16).padStart(2, '0');
    return 'fe' + b0 + b1 + b2 + b3;
  }
  throw new Error('writeVarIntHex: value too large');
}
