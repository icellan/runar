/**
 * Artifact module — re-exports assembler and related types.
 */

export {
  assembleArtifact,
  serializeArtifact,
  deserializeArtifact,
} from './assembler.js';

export type {
  TSOPArtifact,
  ABI,
  ABIConstructor,
  ABIMethod,
  ABIParam,
  SourceMap,
  SourceMapping,
  StateField,
  AssembleOptions,
} from './assembler.js';
