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
export { WhatsOnChainProvider, MockProvider, RPCProvider, WalletProvider, GorillaPoolProvider } from './providers/index.js';
export type { Provider, RPCProviderOptions, WalletProviderOptions, InscriptionInfo, InscriptionDetail } from './providers/index.js';

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

// Ordinals (1sat inscriptions, BSV-20/BSV-21 tokens)
export type { Inscription, EnvelopeBounds } from './ordinals/index.js';
export {
  buildInscriptionEnvelope,
  parseInscriptionEnvelope,
  findInscriptionEnvelope,
  stripInscriptionEnvelope,
  BSV20,
  BSV21,
} from './ordinals/index.js';
export type {
  BSV20DeployParams,
  BSV20MintParams,
  BSV20TransferParams,
  BSV21DeployMintParams,
  BSV21TransferParams,
} from './ordinals/index.js';

// ANF interpreter (auto-compute state transitions)
export { computeNewState, computeNewStateAndDataOutputs } from './anf-interpreter.js';
export type { DataOutputEntry } from './anf-interpreter.js';

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
