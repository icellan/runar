/**
 * Optimizer — re-exports all optimization passes.
 */

export { optimizeStackIR } from './peephole.js';
export { foldConstants, eliminateDeadBindings } from './constant-fold.js';
export { optimizeEC } from './anf-ec.js';
