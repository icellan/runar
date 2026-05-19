/**
 * CompilerResult-shaped wrappers around the existing pass entry points.
 *
 * Each wrapper takes the same input as the underlying pass and returns a
 * `CompilerResult<T>` with uniform error semantics:
 *
 *   - Passes that natively return `{ errors, warnings? }` are adapted by
 *     splitting the diagnostic lists; the result `value` is the produced
 *     IR (or `null` if any error-severity diagnostic was reported).
 *   - Passes that natively throw on error (anf-lower, stack-lower, emit)
 *     are wrapped in try/catch so an unhandled throw becomes a single
 *     error-severity diagnostic with `severity: 'error'`.
 *
 * The original pass functions remain unchanged and continue to be
 * exported. These wrappers are an opt-in, typed enhancement for callers
 * that want to compose passes monadically.
 */

import { CompilerResult } from '../compiler-result.js';
import type { Diagnostic } from '../compiler-result.js';
import type { ContractNode, ANFProgram, StackProgram } from '../ir/index.js';

import { parse } from './01-parse.js';
import { validate } from './02-validate.js';
import { typecheck } from './03-typecheck.js';
import { expandFixedArrays } from './03b-expand-fixed-arrays.js';
import { lowerToANF } from './04-anf-lower.js';
import { lowerToStack } from './05-stack-lower.js';
import { emit } from './06-emit.js';
import type { EmitResult } from './06-emit.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function splitDiagnostics(diags: Diagnostic[]): {
  errors: Diagnostic[];
  warnings: Diagnostic[];
} {
  const errors: Diagnostic[] = [];
  const warnings: Diagnostic[] = [];
  for (const d of diags) {
    if (d.severity === 'error') errors.push(d);
    else warnings.push(d);
  }
  return { errors, warnings };
}

function throwToDiagnostic(e: unknown): Diagnostic {
  const msg = e instanceof Error ? e.message : String(e);
  return { message: msg, severity: 'error' };
}

// ---------------------------------------------------------------------------
// Per-pass wrappers
// ---------------------------------------------------------------------------

/** Pass 1 — Parse. Source → ContractNode. */
export function parseR(
  source: string,
  fileName?: string,
): CompilerResult<ContractNode> {
  let r: ReturnType<typeof parse>;
  try {
    r = parse(source, fileName);
  } catch (e: unknown) {
    return CompilerResult.fail<ContractNode>([throwToDiagnostic(e)]);
  }
  const { errors, warnings } = splitDiagnostics(r.errors);
  if (errors.length > 0 || r.contract === null) {
    return CompilerResult.fail<ContractNode>(errors, warnings);
  }
  return CompilerResult.ok(r.contract, warnings);
}

/** Pass 2 — Validate. ContractNode → ContractNode (no transform). */
export function validateR(contract: ContractNode): CompilerResult<ContractNode> {
  let r: ReturnType<typeof validate>;
  try {
    r = validate(contract);
  } catch (e: unknown) {
    return CompilerResult.fail<ContractNode>([throwToDiagnostic(e)]);
  }
  if (r.errors.length > 0) {
    return CompilerResult.fail<ContractNode>(r.errors, r.warnings);
  }
  return CompilerResult.ok(contract, r.warnings);
}

/** Pass 3 — Type-check. ContractNode → ContractNode (same AST, types verified). */
export function typecheckR(contract: ContractNode): CompilerResult<ContractNode> {
  let r: ReturnType<typeof typecheck>;
  try {
    r = typecheck(contract);
  } catch (e: unknown) {
    return CompilerResult.fail<ContractNode>([throwToDiagnostic(e)]);
  }
  const { errors, warnings } = splitDiagnostics(r.errors);
  if (errors.length > 0) {
    return CompilerResult.fail<ContractNode>(errors, warnings);
  }
  return CompilerResult.ok(r.typedContract, warnings);
}

/** Pass 3b — Expand fixed-size array properties. ContractNode → ContractNode. */
export function expandFixedArraysR(
  contract: ContractNode,
): CompilerResult<ContractNode> {
  let r: ReturnType<typeof expandFixedArrays>;
  try {
    r = expandFixedArrays(contract);
  } catch (e: unknown) {
    return CompilerResult.fail<ContractNode>([throwToDiagnostic(e)]);
  }
  const { errors, warnings } = splitDiagnostics(r.errors);
  if (errors.length > 0) {
    return CompilerResult.fail<ContractNode>(errors, warnings);
  }
  return CompilerResult.ok(r.contract, warnings);
}

/** Pass 4 — ANF lower. ContractNode → ANFProgram. */
export function lowerToANFR(contract: ContractNode): CompilerResult<ANFProgram> {
  try {
    return CompilerResult.ok(lowerToANF(contract));
  } catch (e: unknown) {
    return CompilerResult.fail<ANFProgram>([throwToDiagnostic(e)]);
  }
}

/** Pass 5 — Stack lower. ANFProgram → StackProgram. */
export function lowerToStackR(program: ANFProgram): CompilerResult<StackProgram> {
  try {
    return CompilerResult.ok(lowerToStack(program));
  } catch (e: unknown) {
    return CompilerResult.fail<StackProgram>([throwToDiagnostic(e)]);
  }
}

/** Pass 6 — Emit. StackProgram → EmitResult (hex + ASM + spans). */
export function emitR(program: StackProgram): CompilerResult<EmitResult> {
  try {
    return CompilerResult.ok(emit(program));
  } catch (e: unknown) {
    return CompilerResult.fail<EmitResult>([throwToDiagnostic(e)]);
  }
}
