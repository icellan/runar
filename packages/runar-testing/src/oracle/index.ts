export { buildWitness } from './witness.js';
export type { WitnessArg } from './witness.js';
export { runDifferentialExecution, isWitnessSignMarker } from './differential-execution.js';
export type { DiffExecOptions, DiffExecResult, WitnessSignMarker } from './differential-execution.js';
export { runTriModalExecution } from './tri-modal-execution.js';
export type { TriModalExecResult } from './tri-modal-execution.js';
export { runFoldEquivalence } from './fold-equivalence.js';
export type { FoldEqOptions, FoldEqResult, FoldEqDivergence } from './fold-equivalence.js';
export {
  runStatelessSigned,
  runStatefulSpend,
  runPrecompiledHexSpend,
  validateContractInput,
  testKey,
} from './real-crypto-execution.js';
export type {
  RealExecResult,
  SignMarker,
  StatelessArg,
  StatelessSignedOptions,
  StatefulSpendOptions,
  PrecompiledHexOptions,
} from './real-crypto-execution.js';
