/**
 * Rúnar Compiler -- main entry point.
 *
 * Chains the 6-pass nanopass pipeline:
 *   Pass 1: Parse (source -> Rúnar AST)
 *   Pass 2: Validate (Rúnar AST -> validated Rúnar AST)
 *   Pass 3: Type-Check (Rúnar AST -> type-checked Rúnar AST)
 *   Pass 4: ANF Lower (Rúnar AST -> ANF IR)
 *   Pass 5: Stack Lower (ANF IR -> Stack IR) + peephole optimize
 *   Pass 6: Emit (Stack IR -> Bitcoin Script hex) + artifact assembly
 */

export { parse } from './passes/01-parse.js';
export type { ParseResult } from './passes/01-parse.js';
export { parseSolSource } from './passes/01-parse-sol.js';
export { parseMoveSource } from './passes/01-parse-move.js';
export { parsePythonSource } from './passes/01-parse-python.js';
export { parseGoSource } from './passes/01-parse-go.js';
export { parseRustSource } from './passes/01-parse-rust.js';
export { parseRubySource } from './passes/01-parse-ruby.js';

export { validate } from './passes/02-validate.js';
export type { ValidationResult } from './passes/02-validate.js';

export { typecheck } from './passes/03-typecheck.js';
export type { TypeCheckResult } from './passes/03-typecheck.js';

export { lowerToANF } from './passes/04-anf-lower.js';

export type { CompilerDiagnostic, Severity } from './errors.js';
export { CompilerError, ParseError, ValidationError, TypeError, makeDiagnostic } from './errors.js';

export * from './ir/index.js';

import { parse } from './passes/01-parse.js';
import { validate } from './passes/02-validate.js';
import { typecheck } from './passes/03-typecheck.js';
import { lowerToANF } from './passes/04-anf-lower.js';
import { lowerToStack } from './passes/05-stack-lower.js';
import { emit } from './passes/06-emit.js';
import { optimizeStackIR } from './optimizer/peephole.js';
import { optimizeEC } from './optimizer/anf-ec.js';
import { foldConstants } from './optimizer/constant-fold.js';
import { assembleArtifact } from './artifact/assembler.js';
import type { CompilerDiagnostic } from './errors.js';
import type { ContractNode, ANFProgram, RunarArtifact } from './ir/index.js';

// ---------------------------------------------------------------------------
// Compile options and result
// ---------------------------------------------------------------------------

export interface CompileOptions {
  /** Source file name for error messages and parser dispatch. Defaults to "contract.ts". */
  fileName?: string;

  /** If true, stop after parsing (Pass 1). */
  parseOnly?: boolean;

  /** If true, stop after validation (Pass 2). */
  validateOnly?: boolean;

  /** If true, stop after type-checking (Pass 3). */
  typecheckOnly?: boolean;

  /** Bake property values into the locking script (replaces placeholders). */
  constructorArgs?: Record<string, bigint | boolean | string>;

  /** If true, skip the ANF constant folding pass. Default: false (folding enabled). */
  disableConstantFolding?: boolean;
}

export interface CompileResult {
  /** The ANF IR program (null if compilation stopped early or failed). */
  anf: ANFProgram | null;

  /** The parsed contract AST (available after Pass 1). */
  contract: ContractNode | null;

  /** All diagnostics (errors and warnings) from all passes. */
  diagnostics: CompilerDiagnostic[];

  /** True if there are no error-severity diagnostics. */
  success: boolean;

  /** The compiled artifact (available if passes 5-6 succeed). */
  artifact?: RunarArtifact;

  /** Hex-encoded Bitcoin Script (available if passes 5-6 succeed). */
  scriptHex?: string;

  /** Human-readable ASM representation (available if passes 5-6 succeed). */
  scriptAsm?: string;
}

// ---------------------------------------------------------------------------
// Main compile function
// ---------------------------------------------------------------------------

/**
 * Compile a Rúnar source string through all 6 nanopass pipeline stages.
 *
 * The pipeline is:
 *   1. Parse: source -> Rúnar AST (auto-dispatches by file extension)
 *   2. Validate: check language subset constraints
 *   3. Type-check: verify type consistency
 *   4. ANF Lower: flatten to A-Normal Form IR
 *   5. Stack Lower: ANF IR -> Stack IR (+ peephole optimize)
 *   6. Emit: Stack IR -> hex-encoded Bitcoin Script (+ artifact assembly)
 *
 * Each pass is a pure function. If a pass produces errors, subsequent
 * passes are skipped and the partial result is returned.
 *
 * This function never throws. All errors are caught and returned as
 * diagnostics in the `CompileResult`.
 *
 * When `constructorArgs` are provided, the compiler replaces ANF property
 * `initialValue` fields before stack lowering, producing a complete
 * locking script with real values instead of OP_0 placeholders.
 */
export function compile(source: string, options?: CompileOptions): CompileResult {
  const diagnostics: CompilerDiagnostic[] = [];
  const opts = options ?? {};

  // Pass 1: Parse
  // parse() uses asKindOrThrow() in 20+ places and can throw on malformed input.
  let parseResult: ReturnType<typeof parse>;
  try {
    parseResult = parse(source, opts.fileName);
    diagnostics.push(...parseResult.errors);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
    return {
      anf: null,
      contract: null,
      diagnostics,
      success: false,
    };
  }

  if (!parseResult.contract || hasErrors(diagnostics)) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  if (opts.parseOnly) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: !hasErrors(diagnostics),
    };
  }

  // Pass 2: Validate
  let validationResult: ReturnType<typeof validate>;
  try {
    validationResult = validate(parseResult.contract);
    diagnostics.push(...validationResult.errors);
    diagnostics.push(...validationResult.warnings);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  if (hasErrors(diagnostics)) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  if (opts.validateOnly) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: !hasErrors(diagnostics),
    };
  }

  // Pass 3: Type-Check
  let typeCheckResult: ReturnType<typeof typecheck>;
  try {
    typeCheckResult = typecheck(parseResult.contract);
    diagnostics.push(...typeCheckResult.errors);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  if (hasErrors(diagnostics)) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  if (opts.typecheckOnly) {
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: !hasErrors(diagnostics),
    };
  }

  // Pass 4: ANF Lower
  let anf: ANFProgram;
  try {
    anf = lowerToANF(parseResult.contract);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
    return {
      anf: null,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }

  // Bake constructor args into ANF properties so stack lowering emits real
  // values instead of OP_0 placeholders.
  if (opts.constructorArgs) {
    for (const prop of anf.properties) {
      if (prop.name in opts.constructorArgs) {
        prop.initialValue = opts.constructorArgs[prop.name];
      }
    }
  }

  // Pass 4.25: Constant folding (on by default)
  if (!opts.disableConstantFolding) {
    anf = foldConstants(anf);
  }

  // Pass 4.5: ANF EC Optimizer (always-on)
  const optimizedAnf = optimizeEC(anf);

  // Pass 5-6: Stack lower + Peephole optimize + Emit
  try {
    const stackProgram = lowerToStack(optimizedAnf);

    // Apply peephole optimization to each method's ops (runs on Stack IR,
    // after the ANF conformance boundary, so it doesn't affect cross-compiler
    // conformance).
    for (const method of stackProgram.methods) {
      method.ops = optimizeStackIR(method.ops);
    }

    const emitResult = emit(stackProgram);
    const artifact = assembleArtifact(
      parseResult.contract,
      optimizedAnf,
      stackProgram,
      emitResult.scriptHex,
      emitResult.scriptAsm,
      {
        constructorSlots: emitResult.constructorSlots,
        codeSeparatorIndex: emitResult.codeSeparatorIndex,
        codeSeparatorIndices: emitResult.codeSeparatorIndices,
        includeSourceMap: emitResult.sourceMap.length > 0,
        sourceMappings: emitResult.sourceMap,
      },
    );

    return {
      anf: optimizedAnf,
      contract: parseResult.contract,
      diagnostics,
      success: !hasErrors(diagnostics),
      artifact,
      scriptHex: emitResult.scriptHex,
      scriptAsm: emitResult.scriptAsm,
    };
  } catch (e: unknown) {
    // Stack lowering or emit failed — report as a compilation error
    const msg = e instanceof Error ? e.message : String(e);
    diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
    return {
      anf: optimizedAnf,
      contract: parseResult.contract,
      diagnostics,
      success: false,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasErrors(diagnostics: CompilerDiagnostic[]): boolean {
  return diagnostics.some(d => d.severity === 'error');
}
