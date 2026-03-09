// ---------------------------------------------------------------------------
// runar-sdk — public API
// ---------------------------------------------------------------------------

// Types
export type {
  Transaction,
  TxInput,
  TxOutput,
  UTXO,
  DeployOptions,
  CallOptions,
  PreparedCall,
} from './types.js';

// Providers
export { WhatsOnChainProvider, MockProvider, RPCProvider } from './providers/index.js';
export type { Provider, RPCProviderOptions } from './providers/index.js';

// Signers
export { LocalSigner, ExternalSigner, WalletSigner } from './signers/index.js';
export type { Signer, SignCallback, WalletSignerOptions } from './signers/index.js';

// Contract
export { RunarContract } from './contract.js';

// Transaction building
export { buildDeployTransaction, selectUtxos, estimateDeployFee } from './deployment.js';
export { buildCallTransaction } from './calling.js';

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
export { buildP2PKHScript } from './script-utils.js';

// Token management
export { TokenWallet } from './tokens.js';

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
