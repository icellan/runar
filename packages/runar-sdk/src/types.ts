// ---------------------------------------------------------------------------
// runar-sdk/types.ts — Shared types for on-chain interaction
// ---------------------------------------------------------------------------

import type { Transaction as BsvTransaction } from '@bsv/sdk';
import type { Signer } from './signers/signer.js';

/**
 * Plain data shape returned by Provider.getTransaction().
 * Renamed from `Transaction` to avoid collision with the @bsv/sdk Transaction class
 * which is now the primary transaction type used throughout the SDK.
 */
export interface TransactionData {
  txid: string;
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  raw?: string; // raw hex
}

/** Re-export @bsv/sdk Transaction as the primary transaction type. */
export type { BsvTransaction as Transaction };

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
  /**
   * Signer for the P2PKH funding inputs (issue #134). When the funding UTXOs
   * are owned by a different key than the connected deploy signer, set this so
   * the funding inputs are signed by their real owner. Defaults to the
   * connected signer (zero behaviour change).
   */
  fundingSigner?: Signer;
}

/**
 * Result of `prepareCall()` — contains everything needed for external signing
 * and subsequent `finalizeCall()`.
 *
 * Public fields (`sighash`, `preimage`, `opPushTxSig`, `tx`, `sigIndices`)
 * are for external signer coordination. Fields prefixed with `_` are opaque
 * internals consumed by `finalizeCall()`.
 */
export interface PreparedCall {
  /**
   * BIP-143 sighash (hex) — `hash256(preimage)`, i.e. `sha256(sha256(...))`.
   * External signers ECDSA-sign these 32 bytes DIRECTLY, with no further
   * hashing (see `WalletSigner.signHash`).
   */
  sighash: string;
  /** Full BIP-143 preimage (hex). */
  preimage: string;
  /** OP_PUSH_TX DER signature + sighash byte (hex). Empty if not needed. */
  opPushTxSig: string;
  /** Built transaction (P2PKH funding signed, primary contract input uses placeholder sigs). */
  tx: BsvTransaction;
  /** User-visible arg positions that need external Sig values. */
  sigIndices: number[];

  // Internal fields — consumed by finalizeCall()
  /** @internal */ _methodName: string;
  /** @internal */ _resolvedArgs: unknown[];
  /** @internal */ _methodSelectorHex: string;
  /** @internal */ _isStateful: boolean;
  /**
   * @internal
   * True when the contract extends StatefulSmartContract (from artifact
   * `parentClass`), independent of whether it has mutable state fields.
   * Gates the issue-#42/#44 terminal sighash subscript trim: a stateful
   * contract with ZERO mutable fields still auto-injects checkPreimage at
   * method entry, so its user checkSig runs after the OP_CODESEPARATOR.
   */
  _parentStateful: boolean;
  /** @internal */ _isTerminal: boolean;
  /** @internal */ _needsOpPushTx: boolean;
  /** @internal */ _methodNeedsChange: boolean;
  /** @internal Whether the unlocking script is prefixed with `_codePart` (issue #100). */ _methodUsesCodePart?: boolean;
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
  /**
   * @internal
   * Pre-resolved intent-intrinsic witness hex (PUSHDATA-encoded
   * `_prevOutScript_*` followed by `_serialisedOutputs`, ABI order).
   * Empty when the method has no auto-injected intent params.
   */
  _intentWitnessHex: string;
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

  /**
   * Additional funding UTXOs to include as P2PKH inputs for terminal
   * method calls. Enables terminal methods to receive additional funds
   * when the contract's own balance is insufficient for outputs + fees.
   */
  fundingUtxos?: UTXO[];

  /**
   * A single plain P2PKH UTXO added to a terminal call tx purely to pay the
   * miner fee (issue #118). A true terminal method pays out the full contract
   * balance, so fee would be 0 and ARC rejects; the covenant asserts its exact
   * output set, so no change output can absorb a fee. The fee input is added
   * BEFORE the OP_PUSH_TX preimage is computed (so hashPrevouts covers it) and
   * is consumed entirely as fee — no change output is created. Signed with
   * `fundingSigner ?? signer`. The covenant's output assertions are untouched.
   *
   * IMPORTANT: because there is no change output, the ENTIRE feeUtxo is spent
   * as fee — any amount beyond the actual miner fee is BURNED, not returned.
   * Size the feeUtxo close to the intended fee (a few hundred sats at the BSV
   * standard 0.1 sat/byte is typical for a small terminal tx). The SDK emits a
   * `console.warn` when the supplied feeUtxo dwarfs the terminal tx's estimated
   * fee (> 5x and > ~1000 sats of excess), so an accidental large coin is
   * caught before broadcast.
   */
  feeUtxo?: UTXO;

  /**
   * Optional explicit override for data outputs emitted via
   * `this.addDataOutput(...)` in the method body. When omitted, the SDK
   * resolves data outputs automatically by running the ANF interpreter on
   * the method body (the common case). Pass a non-empty array to bypass
   * the interpreter.
   */
  dataOutputs?: Array<{ script: string; satoshis: number | bigint }>;
  /**
   * Override the call tx's nLockTime field. Defaults to unset → SDK uses 0
   * (legacy behavior, preserves existing contracts). Set for contracts that
   * assert `extractLocktime(preimage) >= deadline` (e.g. auction close/claim).
   * Threaded through both the non-terminal and terminal call-tx build sites.
   */
  locktime?: number;

  /**
   * Override the nSequence written onto EVERY input of the call tx (issue #131).
   * Defaults are zero-config: when `locktime` is set and non-zero, sequence
   * defaults to 0xfffffffe (non-final, so consensus actually enforces
   * nLockTime); otherwise it stays 0xffffffff (final, legacy). Set explicitly
   * only for RBF or custom relative-locktime scenarios. Threaded through the
   * non-terminal and terminal call-tx build sites.
   */
  sequence?: number;

  /**
   * Cap the number of P2PKH funding inputs added to a non-terminal call tx
   * (issue #133). Funding is chosen by smallest-sufficient, largest-first
   * selection (the same `selectUtxos` strategy deploy uses). If covering the
   * outputs + fee would need more than this many inputs, the call throws
   * rather than silently sweeping the wallet. Unset → no cap.
   */
  maxFundingInputs?: number;

  /**
   * Signer for the P2PKH funding (and terminal fee) inputs (issue #134). When
   * the funding/fee UTXOs are owned by a different key than the connected
   * method signer, set this so those inputs are signed by their real owner.
   * The method's own `Sig` args are still signed by the connected signer.
   * Defaults to the connected signer (zero behaviour change).
   */
  fundingSigner?: Signer;
}
