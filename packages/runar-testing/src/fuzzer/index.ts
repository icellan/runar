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
} from './generator.js';
export type { GeneratorConfig } from './generator.js';

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
