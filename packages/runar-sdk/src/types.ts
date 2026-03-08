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

export interface CallOptions {
  satoshis?: number; // for next output (stateful)
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
  outputs?: Array<{ satoshis: number; state: Record<string, unknown> }>;

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
}
