// ---------------------------------------------------------------------------
// tsop-sdk/types.ts — Shared types for on-chain interaction
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

export interface CallOptions {
  satoshis?: number; // for next output (stateful)
  changeAddress?: string;
}
