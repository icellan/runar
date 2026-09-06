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
// The never-validate MockProvider factory in providers/mock.ts (see the
// comment above its declaration) is deliberately NOT re-exported here
// (testing-gap remediation P1-3): it is test-only surface, gated by the
// machine-checked always-ack allowlist (`src/__tests__/always-ack-
// allowlist.test.ts`) — publishing it on the public barrel would let any
// downstream consumer import an unvalidated broadcast provider ungated.
// Tests import it directly from `../providers/mock.js`.
export { WhatsOnChainProvider, MockProvider, RPCProvider, WalletProvider, GorillaPoolProvider } from './providers/index.js';
export type { Provider, RPCProviderOptions, WalletProviderOptions, InscriptionInfo, InscriptionDetail } from './providers/index.js';

// Signers
export { LocalSigner, MockSigner, ExternalSigner, WalletSigner } from './signers/index.js';
export type { Signer, SignCallback, WalletSignerOptions } from './signers/index.js';

// Contract
export {
  RunarContract,
  encodeArg,
  encodePushData,
  encodeScriptNumber,
  EMPTY_SIG,
  isEmptySig,
  isLikelyOrCheckSigMethod,
} from './contract.js';

// Cross-artifact transaction assembly (N different-artifact covenant inputs in one tx)
export { assembleMultiContractCall, dryRunMultiContractInput } from './multi-contract.js';
export type {
  MultiContractCallInput,
  MultiContractCallOutput,
  AssembleMultiContractCallOptions,
  AssembledMultiContractCall,
} from './multi-contract.js';

// Typed SDK errors
export { ScriptSizeExceededError, assertScriptHexUnderLimit } from './errors.js';

// Transaction building
export { buildDeployTransaction, selectUtxos, estimateDeployFee } from './deployment.js';
export { buildCallTransaction, estimateCallFee, estimateFeeForArtifact } from './calling.js';
export type { EstimateFeeForArtifactOpts } from './calling.js';

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
export { buildP2PKHScript, extractConstructorArgs, matchesArtifact, pubkeyToPKH } from './script-utils.js';

// Spend-safety (NEW-005): @bsv/sdk's `Spend` mutates the scripts it executes,
// so any harness that replays a live transaction must detach them first.
export { detachLockingScript, detachUnlockingScript } from './spend-safety.js';

// Verification-descriptor resolution (value-dependent half of the artifact's
// constructorSlots/stateFields/templateDigest descriptors)
export {
  resolveSlotLayout,
  computeTemplateHash,
  buildResolvedCodeHex,
  resolveStateLayout,
} from './slot-layout.js';
export type {
  ResolvedSlot,
  ResolvedSlotLayout,
  ResolvedSlotEncoding,
  ResolvedStateLayout,
} from './slot-layout.js';

// Signed-envelope wire protocol for overlay apps
export { canonicalJson, signEnvelope, verifyEnvelope } from './envelope.js';
export type {
  SignedEnvelope,
  SignEnvelopeOpts,
  EnvelopeSigner,
  VerifyEnvelopeOpts,
  VerifyEnvelopeResult,
  VerifyEnvelopeReason,
} from './envelope.js';

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
export {
  computeNewState,
  computeNewStateAndDataOutputs,
  executeStrict,
  executeOnChainAuthoritative,
  AssertionFailureError,
} from './anf-interpreter.js';
export type { DataOutputEntry, RawOutputEntry, ExecutionResult, OnChainCryptoContext } from './anf-interpreter.js';

// Re-export artifact types from runar-ir-schema for convenience
export type {
  RunarArtifact,
  ABI,
  ABIMethod,
  ABIParam,
  ABIConstructor,
  StateField,
  ConstructorSlot,
  TemplateDigest,
  TemplateDigestPiece,
  SourceMap,
  SourceMapping,
} from 'runar-ir-schema';
