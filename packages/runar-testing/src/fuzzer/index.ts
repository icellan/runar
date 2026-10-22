/**
 * Fuzzer module re-exports.
 */

// String-based generators (legacy, backward compatible)
export {
  arbContract,
  arbStatelessContract,
  arbArithmeticContract,
  arbCryptoContract,
} from './generator.js';

// IR-based generators (new, language-neutral)
export {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  arbGeneratedContractWideLoops,
  arbGeneratedStatefulContractWideLoops,
} from './generator.js';
export type { GeneratorConfig } from './generator.js';

// Branch / loop SHAPE families reachable from the IR-based generators, plus
// the shape-pinned variants a seeded test uses to PROVE each is produced
// (see `packages/runar-testing/src/__tests__/fuzzer-branch-shapes.test.ts`).
export {
  BRANCH_SHAPES,
  STATEFUL_BRANCH_SHAPES,
  IR_LOOP_SHAPES,
  branchShapeCarriers,
  irLoopShapeCarriers,
  arbGeneratedContractWithShape,
  arbGeneratedStatefulContractWithShape,
} from './generator.js';
export type { BranchShape, IrLoopShape } from './generator.js';

// Tri-modal execution-oracle generator (issue #124): loops + byte-ops +
// post-loop param reads, with concrete inputs for fast-check property shrinking.
export {
  arbExecCase,
  arbExecCaseWithLoopShape,
  arbExecCaseWithBranchShape,
  loopShapeCarriers,
  branchShapeLocals,
  branchShapeMerged,
  EXEC_LOOP_SHAPES,
  EXEC_BRANCH_SHAPES,
} from './generator.js';
export type { ExecCase, ExecArg, ExecLoopShape, ExecBranchShape } from './generator.js';

// Contract IR types
export type {
  GeneratedContract,
  GeneratedProperty,
  GeneratedMethod,
  GeneratedParam,
  Expr,
  Stmt,
  RuinarType,
} from './contract-ir.js';
export { toSnakeCase, toPascalCase, collectUsedFunctions, collectUsedTypes } from './contract-ir.js';

// Multi-format renderers
export {
  renderTypeScript,
  renderGo,
  renderRust,
  renderPython,
  renderZig,
  renderRuby,
  renderJava,
  RENDERERS,
  FORMAT_EXTENSIONS,
} from './renderers.js';
export type { RenderFormat } from './renderers.js';
