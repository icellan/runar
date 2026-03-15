// ---------------------------------------------------------------------------
// runar-sdk — public API
// ---------------------------------------------------------------------------

// Types
export type {
  TransactionData,
  Transaction,
  TxInput,
  TxOutput,
  UTXO,
  DeployOptions,
  CallOptions,
  PreparedCall,
} from './types.js';

// Providers
export { WhatsOnChainProvider, MockProvider, RPCProvider, WalletProvider } from './providers/index.js';
export type { Provider, RPCProviderOptions, WalletProviderOptions } from './providers/index.js';

// Signers
export { LocalSigner, ExternalSigner, WalletSigner } from './signers/index.js';
export type { Signer, SignCallback, WalletSignerOptions } from './signers/index.js';

// Contract
export { RunarContract } from './contract.js';

// Transaction building
export { buildDeployTransaction, selectUtxos, estimateDeployFee } from './deployment.js';
export { buildCallTransaction, estimateCallFee } from './calling.js';

// State management
export {
  serializeState,
  deserializeState,
  extractStateFromScript,
  findLastOpReturn,
} from './state.js';

// OP_PUSH_TX
export { computeOpPushTx } from './oppushtx.js';

// Script utilities
export { buildP2PKHScript, extractConstructorArgs, matchesArtifact } from './script-utils.js';

// Token management
export { TokenWallet } from './tokens.js';

// ANF interpreter (auto-compute state transitions)
export { computeNewState } from './anf-interpreter.js';

// Code generation
export { generateTypescript } from './codegen/index.js';

// Re-export artifact types from runar-ir-schema for convenience
export type {
  RunarArtifact,
  ABI,
  ABIMethod,
  ABIParam,
  ABIConstructor,
  StateField,
  SourceMap,
  SourceMapping,
} from 'runar-ir-schema';
