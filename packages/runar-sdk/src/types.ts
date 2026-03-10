// ---------------------------------------------------------------------------
// runar-sdk/types.ts — Shared types for on-chain interaction
// ---------------------------------------------------------------------------

export interface Transaction {
  txid: string;
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  raw?: string; // raw hex
}

export interface TxInput {
  txid: string;
  outputIndex: number;
  script: string; // hex
  sequence: number;
}

export interface TxOutput {
  satoshis: number;
  script: string; // hex
}

export interface UTXO {
  txid: string;
  outputIndex: number;
  satoshis: number;
  script: string;
}

export interface DeployOptions {
  /** Satoshis to lock in the contract UTXO. Defaults to 1. */
  satoshis?: number;
  changeAddress?: string;
}

/** Describes one continuation output for multi-output methods. */
export interface OutputSpec {
  satoshis: number;
  state: Record<string, unknown>;
}

/** Result returned from a multi-output call. */
export interface CallResult {
  txid: string;
  tx: Transaction;
  outputs: Array<{ outputIndex: number; satoshis: number; script: string }>;
}

/**
 * Result of `prepareCall()` — contains everything needed for external signing
 * and subsequent `finalizeCall()`.
 *
 * Public fields (`sighash`, `preimage`, `opPushTxSig`, `txHex`, `sigIndices`)
 * are for external signer coordination. Fields prefixed with `_` are opaque
 * internals consumed by `finalizeCall()`.
 */
export interface PreparedCall {
  /** BIP-143 sighash (hex) — what external signers ECDSA-sign. */
  sighash: string;
  /** Full BIP-143 preimage (hex). */
  preimage: string;
  /** OP_PUSH_TX DER signature + sighash byte (hex). Empty if not needed. */
  opPushTxSig: string;
  /** Built transaction hex (P2PKH funding signed, primary contract input uses placeholder sigs). */
  txHex: string;
  /** User-visible arg positions that need external Sig values. */
  sigIndices: number[];

  // Internal fields — consumed by finalizeCall()
  /** @internal */ _methodName: string;
  /** @internal */ _resolvedArgs: unknown[];
  /** @internal */ _methodSelectorHex: string;
  /** @internal */ _isStateful: boolean;
  /** @internal */ _isTerminal: boolean;
  /** @internal */ _needsOpPushTx: boolean;
  /** @internal */ _methodNeedsChange: boolean;
  /** @internal */ _changePKHHex: string;
  /** @internal */ _changeAmount: number;
  /** @internal */ _methodNeedsNewAmount: boolean;
  /** @internal */ _newAmount: number;
  /** @internal */ _preimageIndex: number;
  /** @internal */ _contractUtxo: UTXO;
  /** @internal */ _newLockingScript: string;
  /** @internal */ _newSatoshis: number;
  /** @internal */ _hasMultiOutput: boolean;
  /** @internal */ _contractOutputs: Array<{ script: string; satoshis: number }>;
}

export interface CallOptions {
  satoshis?: number; // for next output (stateful, single-output)
  changeAddress?: string;
  /** Override the public key used for the change output (hex-encoded).
   *  Defaults to the signer's public key. */
  changePubKey?: string;
  /** New state values for the continuation output (stateful contracts). */
  newState?: Record<string, unknown>;
  /**
   * Multiple continuation outputs for multi-output methods (e.g., `transfer`).
   * Each entry specifies the satoshis and state for one output UTXO.
   * When provided, replaces the single continuation output from `newState`.
   */
  outputs?: OutputSpec[];

  /**
   * After a multi-output call, which output index to track as the
   * contract's continuation UTXO. Default: last output (typically the
   * "change" or self-continuation output).
   */
  continuationOutputIndex?: number;

  /**
   * Additional contract UTXOs to include as inputs (e.g., for merge, swap,
   * or any multi-input spending pattern). Each UTXO's unlocking script uses
   * the same method as the primary call, with OP_PUSH_TX and Sig
   * auto-computed per input.
   */
  additionalContractInputs?: UTXO[];

  /**
   * Per-input args for additional contract inputs. When provided,
   * `additionalContractInputArgs[i]` overrides the args for
   * `additionalContractInputs[i]`. Sig params (null) are still
   * auto-computed per input.
   *
   * If not provided, all additional inputs use the same args as the
   * primary call.
   */
  additionalContractInputArgs?: unknown[][];

  /**
   * Terminal outputs for methods that verify exact output structure via
   * extractOutputHash(). When set, the transaction is built with ONLY
   * the contract UTXO as input (no funding inputs, no change output).
   * The fee comes from the contract balance. The contract is considered
   * fully spent after this call (currentUtxo becomes null).
   *
   * Each output specifies the exact locking script hex and satoshis.
   */
  terminalOutputs?: Array<{ scriptHex: string; satoshis: number }>;
}
