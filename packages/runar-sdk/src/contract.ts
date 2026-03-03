// ---------------------------------------------------------------------------
// runar-sdk/contract.ts — Main contract runtime wrapper
// ---------------------------------------------------------------------------

import type { RunarArtifact, ABIMethod } from 'runar-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { Transaction, UTXO, DeployOptions, CallOptions } from './types.js';
import { buildDeployTransaction, selectUtxos } from './deployment.js';
import { buildCallTransaction, type CallOutput } from './calling.js';
import { serializeState, extractStateFromScript, findLastOpReturn } from './state.js';

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
    // State fields are matched to constructor args by their declaration
    // index, not by name, since the constructor param name may differ
    // from the state field name (e.g., `initialHash` -> `rollingHash`).
    if (artifact.stateFields && artifact.stateFields.length > 0) {
      for (const field of artifact.stateFields) {
        if (field.index < constructorArgs.length) {
          this._state[field.name] = constructorArgs[field.index];
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Deployment
  // -------------------------------------------------------------------------

  /**
   * Deploy the contract by creating a UTXO with the locking script.
   *
   * @param provider - Blockchain provider for UTXO lookup and broadcast.
   * @param signer   - Signer for the funding transaction inputs.
   * @param options  - Deployment options (satoshis, change address).
   * @returns The deployment txid and parsed transaction.
   */
  async deploy(
    provider: Provider,
    signer: Signer,
    options: DeployOptions,
  ): Promise<{ txid: string; tx: Transaction }> {
    const address = await signer.getAddress();
    const changeAddress = options.changeAddress ?? address;
    const lockingScript = this.getLockingScript();

    // Fetch funding UTXOs and select the minimum set needed
    const allUtxos = await provider.getUtxos(address);
    if (allUtxos.length === 0) {
      throw new Error(`RunarContract.deploy: no UTXOs found for address ${address}`);
    }
    const utxos = selectUtxos(allUtxos, options.satoshis, lockingScript.length / 2);

    // Build the deploy transaction
    const changeScript = buildP2PKHScriptFromAddress(changeAddress);
    const { txHex, inputCount } = buildDeployTransaction(
      lockingScript,
      utxos,
      options.satoshis,
      changeAddress,
      changeScript,
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
      satoshis: options.satoshis,
      script: lockingScript,
    };

    const tx = await provider.getTransaction(txid).catch((err) => {
      console.warn('Failed to fetch transaction after broadcast:', err);
      return {
        txid,
        version: 1,
        inputs: [],
        outputs: [{ satoshis: options.satoshis, script: lockingScript }],
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
   *
   * @param methodName - Name of the public method to call.
   * @param args       - Arguments matching the method's ABI.
   * @param provider   - Blockchain provider.
   * @param signer     - Signer for the transaction inputs.
   * @param options    - Call options (satoshis for next output, change address).
   * @returns The call txid and parsed transaction.
   */
  async call(
    methodName: string,
    args: unknown[],
    provider: Provider,
    signer: Signer,
    options?: CallOptions,
  ): Promise<{ txid: string; tx: Transaction }> {
    // Validate method exists
    const method = this.findMethod(methodName);
    if (!method) {
      throw new Error(
        `RunarContract.call: method '${methodName}' not found in ${this.artifact.contractName}`,
      );
    }
    if (method.params.length !== args.length) {
      throw new Error(
        `RunarContract.call: method '${methodName}' expects ${method.params.length} args, got ${args.length}`,
      );
    }

    if (!this.currentUtxo) {
      throw new Error(
        'RunarContract.call: contract is not deployed. Call deploy() or fromTxId() first.',
      );
    }

    const address = await signer.getAddress();
    const changeAddress = options?.changeAddress ?? address;
    // For InductiveSmartContract methods, detect if the ABI includes a
    // `parentTx` implicit parameter. If so, fetch the raw parent transaction
    // (the tx that created the current UTXO) and prepend it to the unlocking
    // script before the regular arguments and method selector.
    let parentTxPrefix = '';
    const hasParentTxParam = method.params.some((p) => p.name === 'parentTx');
    if (hasParentTxParam) {
      const parentTx = await provider.getTransaction(this.currentUtxo.txid);
      if (!parentTx.raw) {
        throw new Error(
          'RunarContract.call: provider returned transaction without raw hex, needed for parentTx (InductiveSmartContract)',
        );
      }
      parentTxPrefix = encodePushData(parentTx.raw);
    }

    const unlockingScript = parentTxPrefix + this.buildUnlockingScript(methodName, args);

    // Determine if this is a stateful call
    const isStateful =
      this.artifact.stateFields !== undefined &&
      this.artifact.stateFields.length > 0;

    let newLockingScript: string | undefined;
    let newSatoshis: number | undefined;
    let multiOutputs: CallOutput[] | undefined;

    if (isStateful) {
      if (options?.outputs && options.outputs.length > 0) {
        // Multi-output mode: build a locking script for each output
        const savedState = { ...this._state };
        multiOutputs = [];
        for (const outputSpec of options.outputs) {
          this._state = { ...savedState, ...outputSpec.state };
          multiOutputs.push({
            lockingScript: this.getLockingScript(),
            satoshis: outputSpec.satoshis,
          });
        }
        // Restore state to the continuation output's state (last by default)
        const contIdx = options.continuationOutputIndex ?? (options.outputs.length - 1);
        const contOutput = options.outputs[contIdx];
        if (contOutput) {
          this._state = { ...savedState, ...contOutput.state };
        } else {
          this._state = savedState;
        }
      } else {
        // Single-output mode (existing behavior)
        newSatoshis = options?.satoshis ?? this.currentUtxo.satoshis;
        if (options?.newState) {
          this._state = { ...this._state, ...options.newState };
        }
        newLockingScript = this.getLockingScript();
      }
    }

    const changeScript = buildP2PKHScriptFromAddress(changeAddress);

    // Fetch additional funding UTXOs if needed
    const additionalUtxos = await provider.getUtxos(address);

    const { txHex, inputCount } = buildCallTransaction(
      this.currentUtxo,
      unlockingScript,
      newLockingScript,
      newSatoshis,
      changeAddress,
      changeScript,
      additionalUtxos.length > 0 ? additionalUtxos : undefined,
      multiOutputs,
    );

    // Sign additional inputs (input 0 already has the unlocking script)
    let signedTx = txHex;
    for (let i = 1; i < inputCount; i++) {
      const utxo = additionalUtxos[i - 1];
      if (utxo) {
        const sig = await signer.sign(signedTx, i, utxo.script, utxo.satoshis);
        const pubKey = await signer.getPublicKey();
        const unlockScript = encodePushData(sig) + encodePushData(pubKey);
        signedTx = insertUnlockingScript(signedTx, i, unlockScript);
      }
    }

    // Broadcast
    const txid = await provider.broadcast(signedTx);

    // Update tracked UTXO for stateful contracts
    if (isStateful) {
      if (multiOutputs && multiOutputs.length > 0) {
        // Multi-output: track the continuation output
        const contIdx = options?.continuationOutputIndex ?? (multiOutputs.length - 1);
        const contOutput = multiOutputs[contIdx];
        if (contOutput) {
          this.currentUtxo = {
            txid,
            outputIndex: contIdx,
            satoshis: contOutput.satoshis,
            script: contOutput.lockingScript,
          };
        } else {
          this.currentUtxo = null;
        }
      } else if (newLockingScript) {
        this.currentUtxo = {
          txid,
          outputIndex: 0,
          satoshis: newSatoshis ?? this.currentUtxo.satoshis,
          script: newLockingScript,
        };
      } else {
        this.currentUtxo = null;
      }
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
        raw: signedTx,
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
    } else {
      // Backward compatibility: old artifacts without constructorSlots
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
 * Build a P2PKH locking script from an address string.
 * If the address is 40-char hex, treat as raw pubkey hash.
 * Otherwise, use a deterministic placeholder hash.
 */
function buildP2PKHScriptFromAddress(address: string): string {
  const pubKeyHash = /^[0-9a-fA-F]{40}$/.test(address)
    ? address
    : deterministicHash20(address);
  return '76a914' + pubKeyHash + '88ac';
}

function deterministicHash20(input: string): string {
  const bytes = new Uint8Array(20);
  for (let i = 0; i < input.length; i++) {
    bytes[i % 20] = ((bytes[i % 20]! ^ input.charCodeAt(i)) * 31 + 17) & 0xff;
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
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
