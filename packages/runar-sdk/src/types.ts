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
  satoshis: number;
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

export interface CallOptions {
  satoshis?: number; // for next output (stateful, single-output)
  changeAddress?: string;
  /** New state values for the continuation output (stateful contracts). */
  newState?: Record<string, unknown>;
  /** For multi-output methods: specify multiple continuation outputs. */
  outputs?: OutputSpec[];
  /**
   * After a multi-output call, which output index to track as the
   * contract's continuation UTXO. Default: last output (typically the
   * "change" or self-continuation output).
   */
  continuationOutputIndex?: number;
}
