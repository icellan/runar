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
export { parseZigSource } from './passes/01-parse-zig.js';
export { parseJavaSource } from './passes/01-parse-java.js';

export { validate } from './passes/02-validate.js';
export type { ValidationResult } from './passes/02-validate.js';

export { typecheck } from './passes/03-typecheck.js';
export type { TypeCheckResult } from './passes/03-typecheck.js';

export { expandFixedArrays } from './passes/03b-expand-fixed-arrays.js';
export type { ExpandFixedArraysResult } from './passes/03b-expand-fixed-arrays.js';

export { lowerToANF } from './passes/04-anf-lower.js';
export { lowerToStack } from './passes/05-stack-lower.js';
export { emit, emitMethod } from './passes/06-emit.js';
// EC codegen emitters. Exported so the testing layer can execute a primitive's
// emitted script directly against a real interpreter, rather than only reaching
// it through a whole compiled contract — which is how `ecAdd`'s inability to
// DOUBLE a point went unnoticed.
export {
  emitEcAdd, emitEcMul, emitEcMulGen, emitEcNegate, emitEcOnCurve,
  emitEcModReduce, emitEcEncodeCompressed, emitEcMakePoint,
  emitEcPointX, emitEcPointY,
} from './passes/ec-codegen.js';
// NIST P-256 / P-384 emitters, exported for the same reason: the interpreter
// MOCKED these primitives, so nothing ever executed their emitted script and
// both `pNNNAdd(P, P)` and `pNNNMul(P, 2)` were wrong.
export {
  emitP256Add, emitP256Mul, emitP256MulGen, emitP256Negate, emitP256OnCurve,
  emitP256EncodeCompressed,
  emitP384Add, emitP384Mul, emitP384MulGen, emitP384Negate, emitP384OnCurve,
  emitP384EncodeCompressed,
  // The ECDSA verifiers were the only EC emitters NOT exported here, and
  // consequently the only ones no test had ever executed — which is how
  // `decompressPubKey` shipped without a square-check on the recovered y.
  emitVerifyECDSA_P256, emitVerifyECDSA_P384,
} from './passes/p256-p384-codegen.js';
export {
  emitCheckPreimageBinding,
  emitCheckPreimageBindingRaw,
  checkPreimageBindingBytes,
  CHECK_PREIMAGE_BINDING_HEX,
} from './passes/oppushtx-codegen.js';
export { optimizeStackIR } from './optimizer/peephole.js';
export { optimizeEC } from './optimizer/anf-ec.js';
export { foldConstants } from './optimizer/constant-fold.js';
export { eliminateDeadBindings } from './optimizer/dce.js';
export { assembleArtifact } from './artifact/assembler.js';

// Script-byte cost model + size instrumentation. Read-only: nothing here
// changes compilation output, but `estimateScriptBytes` is the metric any
// size-directed optimizer pass must compare candidates with, and it is
// asserted byte-exact against the emitter over the whole conformance corpus.
export { sizeOfStackOp, sizeOfPushValue, estimateScriptBytes } from './metrics/cost-model.js';
export { analyzeScriptHex, stackOpMetrics } from './metrics/script-metrics.js';
export type { ByteCategory, ConstantUse, ScriptMetrics, StackOpMetrics } from './metrics/script-metrics.js';

export type { CompilerDiagnostic, Severity } from './errors.js';
export { CompilerError, ParseError, ValidationError, TypeError, makeDiagnostic } from './errors.js';

// CompilerResult<T> / DiagnosticList — uniform pass-recovery wrapper.
// Optional, typed enhancement of the existing per-pass return shapes.
export { CompilerResult } from './compiler-result.js';
export type { Diagnostic, DiagnosticList } from './compiler-result.js';
export {
  parseR,
  validateR,
  typecheckR,
  expandFixedArraysR,
  lowerToANFR,
  lowerToStackR,
  emitR,
} from './passes/compiler-result-passes.js';

export * from './ir/index.js';

import { parse } from './passes/01-parse.js';
import { validate } from './passes/02-validate.js';
import { typecheck } from './passes/03-typecheck.js';
import { expandFixedArrays } from './passes/03b-expand-fixed-arrays.js';
import { lowerToANF } from './passes/04-anf-lower.js';
import { lowerToStack } from './passes/05-stack-lower.js';
import { emit } from './passes/06-emit.js';
import { optimizeStackIR } from './optimizer/peephole.js';
import { optimizeEC } from './optimizer/anf-ec.js';
import { foldConstants } from './optimizer/constant-fold.js';
import { eliminateDeadBindings } from './optimizer/dce.js';
import { assembleArtifact } from './artifact/assembler.js';
import type { CompilerDiagnostic } from './errors.js';
import type { ContractNode, ANFProgram, ANFBinding, RunarArtifact } from './ir/index.js';
import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';

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

  /**
   * Names of readonly properties that MUST be verifiable on-chain — i.e.
   * survive compilation baked into the locking script (as deploy-time
   * constructor slots, or as compile-time-baked values).
   *
   * A readonly property that no method references is ELIMINATED from the
   * compiled script entirely — silently. Its value then exists nowhere in
   * the deployed UTXO, so no downstream contract or verifier can extract
   * it: provenance you can check in Script only exists if the contract
   * itself commits to it. Listing such a property here turns that silent
   * elimination into a compile error.
   */
  requireBaked?: string[];

  /** If true, skip the ANF constant folding pass. Default: false (folding enabled). */
  disableConstantFolding?: boolean;

  /**
   * If true, skip the always-on ANF EC algebraic optimizer.
   *
   * Intended for the decompiler's `--strict-roundtrip` mode and similar
   * byte-identity probes — when comparing a candidate against bytes whose
   * production didn't apply the EC optimizer (e.g. older Rúnar versions,
   * hand-rolled scripts), enabling this keeps the re-emit byte-faithful.
   * NOT a stable user-facing option; the default pipeline always optimizes.
   */
  disableEcOptimizer?: boolean;

  /**
   * If true, skip the Stack IR peephole optimizer.
   *
   * Same niche as `disableEcOptimizer` — turn off when round-tripping
   * against bytes that were emitted without peephole rewriting.
   */
  disablePeephole?: boolean;

  /**
   * EXPERIMENTAL. Park each curve's field prime / group order in a stack slot
   * inside the EC codegen modules instead of re-pushing the 33- or 49-byte
   * literal at every modular reduction.
   *
   * Default false, and the emitters take an untouched code path when it is —
   * so the checked-in goldens, `conformance/script-size-baseline.json`, and
   * cross-tier hex parity are all unaffected while this is off. Turning it on
   * changes the emitted bytes and is therefore a TS-tier-only experiment until
   * the transformation is ported to the other six compilers. Measured effect:
   * `verifyECDSA_P256` 974,024 -> 319,693 bytes (-67 %).
   *
   * See `docs/experiments/script-size-optimization-baseline.md`.
   */
  ecConstantPool?: boolean;

  /**
   * EXPERIMENTAL. Operand scheduling strategy for the ANF -> Stack pass.
   *
   * `'current'` (default) ships today's bytes. `'liveness'` parks a result on
   * the alt stack when the next binding does not consume it, so the operands a
   * chain reads repeatedly stay at depth 0/1 instead of sinking one slot per
   * binding. TS-tier-only experiment while it is opt-in; see
   * `docs/experiments/stack-scheduler-design.md`.
   */
  schedulerMode?: 'current' | 'liveness';

  /** Called between compilation passes with the current stage name and progress percentage (0-100). */
  onProgress?: (stage: string, percent: number) => void;
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
  const onProgress = opts.onProgress;

  // Pass 1: Parse
  onProgress?.('Parsing', 0);
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
  onProgress?.('Validating', 10);
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
  onProgress?.('Type checking', 20);
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

  // Pass 3b: Expand fixed-size array properties
  onProgress?.('Expanding fixed arrays', 28);
  let expandedContract: ContractNode;
  try {
    const expandResult = expandFixedArrays(parseResult.contract);
    diagnostics.push(...expandResult.errors);
    expandedContract = expandResult.contract;
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

  // Pass 4: ANF Lower
  onProgress?.('Lowering to ANF', 35);
  let anf: ANFProgram;
  try {
    anf = lowerToANF(expandedContract);
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
    const shapeErrors = validateConstructorArgsShape(anf, opts.constructorArgs);
    if (shapeErrors.length > 0) {
      for (const msg of shapeErrors) {
        diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
      }
      return {
        anf: null,
        contract: parseResult.contract,
        diagnostics,
        success: false,
      };
    }

    for (const prop of anf.properties) {
      if (prop.name in opts.constructorArgs) {
        prop.initialValue = opts.constructorArgs[prop.name];
      }
    }

    const unbakedErrors = findUnbakedReferencedReadonly(anf);
    if (unbakedErrors.length > 0) {
      for (const msg of unbakedErrors) {
        diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
      }
      return {
        anf: null,
        contract: parseResult.contract,
        diagnostics,
        success: false,
      };
    }
  }

  // requireBaked guard: turn silent elimination of a must-be-verifiable
  // readonly property into a compile error. Runs on the pre-fold ANF so
  // `load_prop` references are still intact in both template and baked modes.
  if (opts.requireBaked && opts.requireBaked.length > 0) {
    const requireBakedErrors = validateRequireBaked(anf, opts.requireBaked);
    if (requireBakedErrors.length > 0) {
      for (const msg of requireBakedErrors) {
        diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
      }
      return {
        anf: null,
        contract: parseResult.contract,
        diagnostics,
        success: false,
      };
    }
  }

  // Pass 4.25: Constant folding (on by default)
  if (!opts.disableConstantFolding) {
    onProgress?.('Constant folding', 45);
    anf = foldConstants(anf);
  }

  // Pass 4.5: ANF EC Optimizer (always-on by default; opt-out for strict-roundtrip).
  // Note: DCE is invoked from within the EC optimizer (`optimizer/anf-ec.ts`) and
  // delegates to the discrete `optimizer/dce.ts` module — see "Pass 4.75: DCE" there.
  // Calling DCE unconditionally here would diverge from the checked-in fold-OFF
  // goldens (which were stamped under the EC-optimizer-gated DCE policy).
  onProgress?.('EC optimization', 50);
  const optimizedAnf = opts.disableEcOptimizer ? anf : optimizeEC(anf);

  // Issue #109: warn when DCE strips an un-annotated readonly field. Such a
  // field carries no compile-time value (no initializer) and is referenced by
  // no method, so it is eliminated from the locking script entirely — silently
  // dropping deploy-time metadata an author may intend to recover from the
  // on-chain script later. `@embedAlways` fields were forced back in during
  // ANF lowering, so they are "referenced" here and never warn.
  {
    const referenced = collectReferencedProps(optimizedAnf);
    for (const prop of parseResult.contract.properties) {
      if (
        prop.readonly &&
        !prop.embedAlways &&
        prop.initializer === undefined &&
        !referenced.has(prop.name)
      ) {
        diagnostics.push({
          message:
            `readonly field '${prop.name}' is not referenced in any method body and was ` +
            `eliminated by DCE; annotate it /** @embedAlways */ to preserve it in the ` +
            `on-chain script`,
          severity: 'warning',
          loc: prop.sourceLocation,
        } as CompilerDiagnostic);
      }
    }
  }

  // Pass 5-6: Stack lower + Peephole optimize + Emit
  try {
    onProgress?.('Stack lowering', 60);
    const stackProgram = lowerToStack(optimizedAnf, {
      ecConstantPool: opts.ecConstantPool === true,
      schedulerMode: opts.schedulerMode,
    });

    // Apply peephole optimization to each method's ops (runs on Stack IR,
    // after the ANF conformance boundary, so it doesn't affect cross-compiler
    // conformance).
    if (!opts.disablePeephole) {
      onProgress?.('Peephole optimizing', 75);
      for (const method of stackProgram.methods) {
        method.ops = optimizeStackIR(method.ops);
      }
    }

    onProgress?.('Emitting script', 85);
    const emitResult = emit(stackProgram);

    // requireBaked belt-and-braces: in template mode every required prop
    // without a compile-time value must have produced a constructor slot.
    if (opts.requireBaked && opts.requireBaked.length > 0) {
      const slotErrors = findRequireBakedMissingSlots(
        optimizedAnf,
        opts.requireBaked,
        emitResult.constructorSlots,
      );
      if (slotErrors.length > 0) {
        for (const msg of slotErrors) {
          diagnostics.push({ message: msg, severity: 'error' } as CompilerDiagnostic);
        }
        return {
          anf: optimizedAnf,
          contract: parseResult.contract,
          diagnostics,
          success: false,
        };
      }
    }

    onProgress?.('Assembling artifact', 95);
    const artifact = assembleArtifact(
      expandedContract,
      optimizedAnf,
      stackProgram,
      emitResult.scriptHex,
      emitResult.scriptAsm,
      {
        constructorSlots: emitResult.constructorSlots,
        codeSepIndexSlots: emitResult.codeSepIndexSlots,
        codeSeparatorIndex: emitResult.codeSeparatorIndex,
        codeSeparatorIndices: emitResult.codeSeparatorIndices,
        rawScriptSpans: emitResult.rawScriptSpans,
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
// compileFromANF — IR-input compilation (mirrors Go/Rust/Python `--ir`)
// ---------------------------------------------------------------------------

export interface CompileFromANFOptions {
  /** Bake property values into the locking script (replaces placeholders). */
  constructorArgs?: Record<string, bigint | boolean | string>;
  /** If true, skip the ANF constant folding pass. Default: false (folding enabled). */
  disableConstantFolding?: boolean;
  /** If true, skip the EC algebraic optimizer. See CompileOptions for context. */
  disableEcOptimizer?: boolean;
  /** If true, skip the Stack IR peephole optimizer. See CompileOptions for context. */
  disablePeephole?: boolean;
  /** EXPERIMENTAL. Pool repeated EC curve constants. See CompileOptions. */
  ecConstantPool?: boolean;
  /** EXPERIMENTAL. Operand scheduling strategy. See CompileOptions. */
  schedulerMode?: 'current' | 'liveness';
}

export interface CompileFromANFResult {
  /** Hex-encoded Bitcoin Script. */
  scriptHex: string;
  /** Human-readable ASM representation. */
  scriptAsm: string;
  /** The (possibly post-fold, post-EC-optimize) ANF program. */
  anf: ANFProgram;
  /** Per-method OP_CODESEPARATOR byte offsets. */
  codeSeparatorIndices?: number[];
  /** Constructor parameter placeholder byte offsets. */
  constructorSlots?: { paramIndex: number; byteOffset: number }[];
}

/**
 * Compile a parsed/loaded ANF IR program directly to a Bitcoin Script.
 *
 * Skips passes 1–4 (parse/validate/typecheck/anf-lower) and runs only:
 *   constant-fold (optional) → EC optimize → stack-lower → peephole → emit
 *
 * Mirrors Go's `CompileFromIR`, Rust's `compile_from_ir`, Python's
 * `compile_from_ir_bytes`, and the corresponding entry points on the Zig,
 * Ruby, and Java tiers. Returns the locking-script hex and ASM only —
 * since an IR program does not carry a `ContractNode`, the full ABI /
 * state-fields artifact cannot be reconstructed at this layer; callers
 * that need the full artifact should compile from source.
 */
export function compileFromANF(
  program: ANFProgram,
  options?: CompileFromANFOptions,
): CompileFromANFResult {
  const opts = options ?? {};

  const anf: ANFProgram = program;

  // Bake constructor args into ANF properties so stack lowering emits real
  // values instead of OP_0 placeholders.
  if (opts.constructorArgs) {
    const shapeErrors = validateConstructorArgsShape(anf, opts.constructorArgs);
    if (shapeErrors.length > 0) {
      throw new Error(`compileFromANF: ${shapeErrors.join('; ')}`);
    }

    for (const prop of anf.properties) {
      if (prop.name in opts.constructorArgs) {
        prop.initialValue = opts.constructorArgs[prop.name];
      }
    }

    const unbakedErrors = findUnbakedReferencedReadonly(anf);
    if (unbakedErrors.length > 0) {
      throw new Error(`compileFromANF: ${unbakedErrors.join('; ')}`);
    }
  }

  // Constant folding is a source-pipeline optimization (see compile()); it is
  // intentionally NOT run here on already-lowered ANF IR. Re-folding pre-lowered
  // IR rewrites bin_ops to constants but leaves the now-dead operand bindings in
  // place (foldConstants does no dead-binding elimination), which stack lowering
  // then emits as wasteful push+drop sequences — diverging from both the fold-OFF
  // goldens and the Zig tier, whose compileFromIR never folds IR input
  // (compilers/zig/src/main.zig). The peephole optimizer still folds constants at
  // the stack level, so the IR path stays byte-identical to the goldens.
  // (opts.disableConstantFolding is accepted for CLI symmetry but is a no-op here.)

  // EC optimizer delegates internally to optimizer/dce.ts for dead-binding cleanup.
  const optimizedAnf = opts.disableEcOptimizer ? anf : optimizeEC(anf);

  const stackProgram = lowerToStack(optimizedAnf, {
    ecConstantPool: opts.ecConstantPool === true,
    schedulerMode: opts.schedulerMode,
  });
  if (!opts.disablePeephole) {
    for (const method of stackProgram.methods) {
      method.ops = optimizeStackIR(method.ops);
    }
  }

  const emitResult = emit(stackProgram);
  return {
    scriptHex: emitResult.scriptHex,
    scriptAsm: emitResult.scriptAsm,
    anf: optimizedAnf,
    codeSeparatorIndices: emitResult.codeSeparatorIndices,
    constructorSlots: emitResult.constructorSlots,
  };
}

/**
 * Parse an ANF IR JSON string into an `ANFProgram`.
 *
 * The TS compiler emits `bigint` values as JSON strings of the form
 * `"42n"`. The Go / Rust / Python emitters use plain numbers for safe
 * integer values and decimal strings for big numbers. This loader accepts
 * both shapes so a TS `--from-ir` invocation can consume IR produced by
 * any peer compiler.
 *
 * Throws on malformed JSON. Does NOT perform deep schema validation —
 * downstream stack-lowering will reject malformed IR with an explicit error.
 */
export function loadANFFromJSON(json: string): ANFProgram {
  // Input-bytes guard: reject obviously oversized IR before JSON.parse.
  const inputBytes = Buffer.byteLength(json, 'utf8');
  if (inputBytes > InputLimits.MAX_IR_BYTES) {
    throw new CanonicalJsonError(
      'bytes',
      `loadANFFromJSON: IR JSON exceeds ${InputLimits.MAX_IR_BYTES} bytes (actual ${inputBytes})`,
      { limit: InputLimits.MAX_IR_BYTES, actual: inputBytes },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json, (_key, value) => {
      if (typeof value === 'string' && /^-?\d+n$/.test(value)) {
        return BigInt(value.slice(0, -1));
      }
      return value;
    }) as unknown;
  } catch (e) {
    throw new CanonicalJsonError(
      'invalid',
      `loadANFFromJSON: input is not valid JSON: ${(e as Error).message}`,
    );
  }

  // Iterative depth-walk: cap structural nesting at MAX_NESTING before any
  // recursive consumer (typecheck, stack-lower) touches the tree.
  assertNestingDepth(parsed, InputLimits.MAX_NESTING);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('loadANFFromJSON: top-level value is not an object');
  }
  const program = parsed as Partial<ANFProgram>;
  if (typeof program.contractName !== 'string') {
    throw new Error('loadANFFromJSON: missing string field "contractName"');
  }
  if (!Array.isArray(program.properties)) {
    throw new Error('loadANFFromJSON: missing array field "properties"');
  }
  if (!Array.isArray(program.methods)) {
    throw new Error('loadANFFromJSON: missing array field "methods"');
  }
  return program as ANFProgram;
}

/**
 * Iteratively walk a parsed JSON value and throw CanonicalJsonError('depth')
 * if the structural nesting exceeds `limit`. Iterative form avoids native
 * stack overflow on adversarial inputs whose nesting alone is the attack.
 */
function assertNestingDepth(value: unknown, limit: number): void {
  const stack: Array<{ v: unknown; d: number }> = [{ v: value, d: 0 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop()!;
    if (v === null || typeof v !== 'object') continue;
    if (d > limit) {
      throw new CanonicalJsonError(
        'depth',
        `loadANFFromJSON: IR nesting exceeds ${limit}`,
        { limit, actual: d },
      );
    }
    if (Array.isArray(v)) {
      for (const child of v) stack.push({ v: child, d: d + 1 });
    } else {
      for (const child of Object.values(v as Record<string, unknown>)) {
        stack.push({ v: child, d: d + 1 });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// compileCheck — frontend-only validation wrapper
// ---------------------------------------------------------------------------

export interface CompileCheckOptions {
  /** Source file name for error messages and parser dispatch. Defaults to "contract.runar.ts". */
  fileName?: string;
}

/**
 * Run the Rúnar frontend (parse → validate → typecheck → expandFixedArrays
 * → typecheck) on a source string and throw on any error-severity diagnostic.
 *
 * Returns void on success. Throws an Error whose message lists every
 * frontend diagnostic when validation fails. Mirrors the named API exposed
 * by the Go (`CompileCheck`), Rust (`compile_check`), Python
 * (`compile_check`), Zig, Ruby, and Java tiers, so contract-level tests in
 * TypeScript can write `compileCheck(src, 'X.runar.ts')` instead of having
 * to thread through the full `compile()` result.
 */
export function compileCheck(source: string, fileName?: string, options?: CompileCheckOptions): void {
  const effectiveFileName = options?.fileName ?? fileName ?? 'contract.runar.ts';
  const result = compile(source, {
    fileName: effectiveFileName,
    typecheckOnly: true,
  });

  if (!result.success) {
    const errorDiagnostics = result.diagnostics.filter(d => d.severity === 'error');
    const messages = errorDiagnostics.length > 0
      ? errorDiagnostics.map(d => d.message ?? 'unknown error').join('; ')
      : 'unknown compileCheck failure';
    throw new Error(`compileCheck failed for ${effectiveFileName}: ${messages}`);
  }

  // Run pass 3b (expand fixed arrays) explicitly so callers get the same
  // failure surface as the full compile pipeline (pass 3b runs after the
  // typecheck-only short-circuit above).
  if (!result.contract) {
    throw new Error(`compileCheck failed for ${effectiveFileName}: no contract produced`);
  }
  const expand = expandFixedArrays(result.contract);
  const expandErrors = expand.errors.filter(d => d.severity === 'error');
  if (expandErrors.length > 0) {
    const messages = expandErrors.map(d => d.message ?? 'unknown error').join('; ');
    throw new Error(`compileCheck failed for ${effectiveFileName}: ${messages}`);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasErrors(diagnostics: CompilerDiagnostic[]): boolean {
  return diagnostics.some(d => d.severity === 'error');
}

/**
 * Validate the shape of `constructorArgs` against the contract's properties
 * BEFORE baking. Returns a list of error messages (empty when valid).
 *
 * Rejects:
 *  (a) positional arrays — `constructorArgs` must be a named record keyed by
 *      property name. A positional array matches no property names, so
 *      nothing would be baked and the script would silently keep its OP_0
 *      placeholders (failing opaquely at runtime).
 *  (b) keys that do not match any contract property name (typos would
 *      otherwise silently bake nothing for that key).
 */
function validateConstructorArgsShape(
  anf: ANFProgram,
  constructorArgs: Record<string, bigint | boolean | string>,
): string[] {
  const errors: string[] = [];

  if (Array.isArray(constructorArgs)) {
    const propNames = anf.properties.map(p => p.name).join(', ');
    errors.push(
      `constructorArgs must be a record keyed by property name, not a positional array. ` +
        `Contract '${anf.contractName}' properties: [${propNames}]. ` +
        `Example: { ${anf.properties[0]?.name ?? 'propName'}: <value> }`,
    );
    return errors;
  }

  const propNameSet = new Set(anf.properties.map(p => p.name));
  for (const key of Object.keys(constructorArgs)) {
    if (!propNameSet.has(key)) {
      const propNames = anf.properties.map(p => p.name).join(', ');
      errors.push(
        `constructorArgs key '${key}' does not match any property of contract ` +
          `'${anf.contractName}' (properties: [${propNames}]). ` +
          `Nothing would be baked for this key.`,
      );
    }
  }

  return errors;
}

/**
 * After baking `constructorArgs`, find readonly properties that are
 * REFERENCED by at least one method body but still have no baked
 * `initialValue`. Such properties would be emitted as OP_0 placeholders,
 * making the compiled script fail opaquely at runtime (e.g.
 * `OP_EQUALVERIFY failed` with no hint as to why).
 *
 * Only applies when the caller asked for baking — unbaked placeholder
 * compilation (no `constructorArgs`) is the normal deploy-artifact path
 * where the SDK substitutes values via `constructorSlots`.
 */
function findUnbakedReferencedReadonly(anf: ANFProgram): string[] {
  const referenced = collectReferencedProps(anf);

  const errors: string[] = [];
  for (const prop of anf.properties) {
    if (prop.readonly && prop.initialValue === undefined && referenced.has(prop.name)) {
      errors.push(
        `readonly property '${prop.name}' is referenced by a method but has no value ` +
          `after baking constructorArgs — the emitted script would carry an OP_0 ` +
          `placeholder that fails at runtime. Provide '${prop.name}' in constructorArgs ` +
          `(or give the property an initializer).`,
      );
    }
  }
  return errors;
}

/**
 * Validate `requireBaked` names against the (post-bake, pre-fold) ANF:
 *  (a) every name must be a contract property;
 *  (b) it must be readonly — mutable state lives in the OP_RETURN state
 *      tail, not a baked code slot;
 *  (c) it must be REFERENCED by at least one method body — an unreferenced
 *      readonly property is eliminated from the compiled script entirely,
 *      so its value would not be verifiable on-chain by anyone.
 */
function validateRequireBaked(anf: ANFProgram, names: string[]): string[] {
  const errors: string[] = [];
  const referenced = collectReferencedProps(anf);
  for (const name of names) {
    const prop = anf.properties.find(p => p.name === name);
    if (!prop) {
      const propNames = anf.properties.map(p => p.name).join(', ');
      errors.push(
        `requireBaked: '${name}' is not a property of contract '${anf.contractName}' ` +
          `(properties: [${propNames}]).`,
      );
      continue;
    }
    if (!prop.readonly) {
      errors.push(
        `requireBaked: property '${name}' is mutable state — it is serialized into the ` +
          `OP_RETURN state tail, not baked into the code part. requireBaked applies to ` +
          `readonly properties only.`,
      );
      continue;
    }
    if (!referenced.has(name)) {
      errors.push(
        `requireBaked: readonly property '${name}' is not referenced by any method body, ` +
          `so the compiler ELIMINATES it — its value would exist nowhere in the deployed ` +
          `locking script and could not be verified on-chain by any downstream contract. ` +
          `Reference it in a method (e.g. checkSig(sig, this.${name}) or ` +
          `assert(this.${name} >= 1n)) to force it into a constructor slot.`,
      );
    }
  }
  return errors;
}

/**
 * Post-emit requireBaked cross-check (template mode): every required prop
 * that has no compile-time value must map to at least one emitted
 * constructor slot. Guards against any optimizer pass dropping a reference
 * AFTER the ANF-level check.
 *
 * SCOPE / KNOWN LIMITATION: this belt-and-braces check covers TEMPLATE mode
 * only — baked props (`initialValue !== undefined`) are skipped because they
 * carry no constructor slot. In baked mode the guarantee rests solely on the
 * pre-fold `validateRequireBaked` reference check. A baked required prop whose
 * ONLY reference constant-folds to a tautology (e.g. `assert(this.source >= 1n)`
 * with `source` baked to `1n` → `assert(true)`, then eliminated) can therefore
 * be dropped from the emitted code with no diagnostic, because folding runs
 * after the reference check and the folded literal is indistinguishable from an
 * eliminated one. A robust baked-mode check would require tracking the baked
 * value's survival through fold+emit; until then, authors relying on
 * requireBaked in baked mode should confirm the value is present in the emitted
 * artifact. Template mode (the documented deploy path) is fully covered.
 */
function findRequireBakedMissingSlots(
  anf: ANFProgram,
  names: string[],
  constructorSlots: { paramIndex: number; byteOffset: number }[],
): string[] {
  const ctorProps = anf.properties.filter(p => p.initialValue === undefined);
  const slotNames = new Set(
    constructorSlots.map(s => ctorProps[s.paramIndex]?.name).filter(n => n !== undefined),
  );
  const errors: string[] = [];
  for (const name of names) {
    const prop = anf.properties.find(p => p.name === name);
    if (!prop || !prop.readonly) continue; // reported by validateRequireBaked
    if (prop.initialValue !== undefined) continue; // baked at compile time
    if (!slotNames.has(name)) {
      errors.push(
        `requireBaked: readonly property '${name}' produced no constructor slot in the ` +
          `emitted script (optimized away after ANF lowering) — its value would not be ` +
          `verifiable on-chain.`,
      );
    }
  }
  return errors;
}

/**
 * Collect the property names actually referenced by method bodies.
 *
 * The raw ANF from pass 4 loads every property at method entry; only after
 * dead-binding elimination do the surviving `load_prop` nodes reflect real
 * references. DCE is a pure function, so running it here on a probe copy
 * does not perturb the main pipeline.
 */
function collectReferencedProps(anf: ANFProgram): Set<string> {
  const probe = eliminateDeadBindings(anf);
  const referenced = new Set<string>();
  for (const method of probe.methods) {
    // The constructor's super(...) call references every property but is
    // never emitted as script code — only real method bodies count.
    if (method.name === 'constructor') continue;
    collectLoadPropRefs(method.body, referenced);
  }
  return referenced;
}

/** Recursively collect `load_prop` property names from ANF bindings. */
function collectLoadPropRefs(bindings: ANFBinding[], out: Set<string>): void {
  for (const binding of bindings) {
    const v = binding.value;
    switch (v.kind) {
      case 'load_prop':
        out.add(v.name);
        break;
      case 'if':
        collectLoadPropRefs(v.then, out);
        collectLoadPropRefs(v.else, out);
        break;
      case 'loop':
        collectLoadPropRefs(v.body, out);
        break;
      default:
        break;
    }
  }
}
