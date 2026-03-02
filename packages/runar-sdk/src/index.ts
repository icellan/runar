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
} from './types.js';

// Providers
export type { Provider } from './providers/index.js';
export { WhatsOnChainProvider, MockProvider } from './providers/index.js';

// Signers
export type { Signer } from './signers/index.js';
export type { SignCallback } from './signers/index.js';
export { LocalSigner, ExternalSigner } from './signers/index.js';

// Contract
export { RunarContract } from './contract.js';

// Transaction building
export { buildDeployTransaction } from './deployment.js';
export { buildCallTransaction } from './calling.js';

// State management
export {
  serializeState,
  deserializeState,
  extractStateFromScript,
} from './state.js';

// Token management
export { TokenWallet } from './tokens.js';

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
