/**
 * Optimizer — re-exports all optimization passes.
 */

export { optimizeStackIR } from './peephole.js';
export { foldConstants } from './constant-fold.js';
export { eliminateDeadBindings } from './dce.js';
export { optimizeEC } from './anf-ec.js';
