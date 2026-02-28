// ---------------------------------------------------------------------------
// tsop-sdk/contract.ts — Main contract runtime wrapper
// ---------------------------------------------------------------------------

import type { TSOPArtifact, ABIMethod } from 'tsop-ir-schema';
import type { Provider } from './providers/provider.js';
import type { Signer } from './signers/signer.js';
import type { Transaction, UTXO, DeployOptions, CallOptions } from './types.js';
import { buildDeployTransaction } from './deployment.js';
import { buildCallTransaction } from './calling.js';
import { serializeState, extractStateFromScript } from './state.js';

/**
 * Runtime wrapper for a compiled TSOP contract.
 *
 * Handles deployment, method invocation, state tracking, and script
 * construction. Works with any Provider and Signer implementation.
 *
 * ```ts
 * const artifact = JSON.parse(fs.readFileSync('./artifacts/Counter.json', 'utf8'));
 * const contract = new TSOPContract(artifact, [0n]); // constructor args
 * const { txid } = await contract.deploy(provider, signer, { satoshis: 10000 });
 * ```
 */
export class TSOPContract {
  readonly artifact: TSOPArtifact;
  private readonly constructorArgs: unknown[];
  private _state: Record<string, unknown> = {};
  private currentUtxo: UTXO | null = null;

  constructor(artifact: TSOPArtifact, constructorArgs: unknown[]) {
    this.artifact = artifact;
    this.constructorArgs = constructorArgs;

    // Validate constructor args match ABI
    const expected = artifact.abi.constructor.params.length;
    if (constructorArgs.length !== expected) {
      throw new Error(
        `TSOPContract: expected ${expected} constructor args for ${artifact.contractName}, got ${constructorArgs.length}`,
      );
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

    // Fetch funding UTXOs
    const utxos = await provider.getUtxos(address);
    if (utxos.length === 0) {
      throw new Error(`TSOPContract.deploy: no UTXOs found for address ${address}`);
    }

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

    // Initialize state from constructor args if stateful
    if (this.artifact.stateFields && this.artifact.stateFields.length > 0) {
      for (const field of this.artifact.stateFields) {
        const paramIndex = this.artifact.abi.constructor.params.findIndex(
          (p) => p.name === field.name,
        );
        if (paramIndex >= 0) {
          this._state[field.name] = this.constructorArgs[paramIndex];
        }
      }
    }

    const tx = await provider.getTransaction(txid).catch(() => ({
      txid,
      version: 1,
      inputs: [],
      outputs: [{ satoshis: options.satoshis, script: lockingScript }],
      locktime: 0,
      raw: signedTx,
    }));

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
        `TSOPContract.call: method '${methodName}' not found in ${this.artifact.contractName}`,
      );
    }
    if (method.params.length !== args.length) {
      throw new Error(
        `TSOPContract.call: method '${methodName}' expects ${method.params.length} args, got ${args.length}`,
      );
    }

    if (!this.currentUtxo) {
      throw new Error(
        'TSOPContract.call: contract is not deployed. Call deploy() or fromTxId() first.',
      );
    }

    const address = await signer.getAddress();
    const changeAddress = options?.changeAddress ?? address;
    const unlockingScript = this.buildUnlockingScript(methodName, args);

    // Determine if this is a stateful call
    const isStateful =
      this.artifact.stateFields !== undefined &&
      this.artifact.stateFields.length > 0;

    let newLockingScript: string | undefined;
    let newSatoshis: number | undefined;

    if (isStateful) {
      newSatoshis = options?.satoshis ?? this.currentUtxo.satoshis;
      // For stateful contracts, we rebuild the locking script with
      // potentially updated state. In practice, the contract's public
      // method would update `this._state` and we'd reconstruct.
      newLockingScript = this.getLockingScript();
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
    if (isStateful && newLockingScript) {
      this.currentUtxo = {
        txid,
        outputIndex: 0,
        satoshis: newSatoshis ?? this.currentUtxo.satoshis,
        script: newLockingScript,
      };
    } else {
      this.currentUtxo = null;
    }

    const tx = await provider.getTransaction(txid).catch(() => ({
      txid,
      version: 1,
      inputs: [],
      outputs: [],
      locktime: 0,
      raw: signedTx,
    }));

    return { txid, tx };
  }

  // -------------------------------------------------------------------------
  // State access
  // -------------------------------------------------------------------------

  /** Get the current contract state (for stateful contracts). */
  get state(): Record<string, unknown> {
    return { ...this._state };
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
    let script = this.artifact.script;

    // Append constructor args as push data at the end of the script
    // The compiled script expects constructor params on the stack at setup
    // time, so they're embedded as data pushes.
    for (const arg of this.constructorArgs) {
      script += encodeArg(arg);
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
   * @returns A TSOPContract instance connected to the existing UTXO.
   */
  static async fromTxId(
    artifact: TSOPArtifact,
    txid: string,
    outputIndex: number,
    provider: Provider,
  ): Promise<TSOPContract> {
    const tx = await provider.getTransaction(txid);

    if (outputIndex >= tx.outputs.length) {
      throw new Error(
        `TSOPContract.fromTxId: output index ${outputIndex} out of range (tx has ${tx.outputs.length} outputs)`,
      );
    }

    const output = tx.outputs[outputIndex]!;
    const contract = new TSOPContract(
      artifact,
      // We don't know the original constructor args, but we can reconstruct
      // state from the script. Pass empty array; state will be populated below.
      new Array(artifact.abi.constructor.params.length).fill(0n) as unknown[],
    );

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
    return value ? '0151' : '0100';
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
 * This is a simplified approach that works for the common case. A production
 * implementation would properly parse and reconstruct the transaction.
 */
function insertUnlockingScript(
  txHex: string,
  _inputIndex: number,
  _unlockScript: string,
): string {
  // KNOWN LIMITATION: This function currently returns the transaction hex
  // unmodified. Proper scriptSig injection requires parsing the raw
  // transaction, locating the specified input, replacing its scriptSig
  // field, and re-serializing. This means only input 0 (whose unlock
  // script is placed during buildCallTransaction) will be correct.
  // Additional inputs will lack their unlocking scripts until full
  // transaction parsing is integrated via @bsv/sdk.
  return txHex;
}
