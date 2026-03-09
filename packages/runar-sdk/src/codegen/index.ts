// ---------------------------------------------------------------------------
// codegen — public API
// ---------------------------------------------------------------------------

export { generateTypescript } from './gen-typescript.js';

// Re-export analysis utilities for programmatic use
export {
  classifyParams,
  getUserParams,
  getSdkArgParams,
  isTerminalMethod,
  isStatefulArtifact,
  getPublicMethods,
  safeMethodName,
  mapTypeToTS,
} from './common.js';
