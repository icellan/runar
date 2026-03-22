// ---------------------------------------------------------------------------
// codegen — public API
// ---------------------------------------------------------------------------

export { generateTypescript } from './gen-typescript.js';
export { generateGo, generateRust, generatePython, generateZig, generateTypescriptFromTemplate } from './gen-all.js';

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
  mapTypeToGo,
  mapTypeToRust,
  mapTypeToPython,
  mapTypeToZig,
  buildCodegenContext,
} from './common.js';
export type { TargetLang, CodegenContext } from './common.js';

// Mustache renderer
export { renderMustache } from './mustache.js';
