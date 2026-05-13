/**
 * Types for the Bitcoin Script static analyzer.
 *
 * The analyzer reads compiled Bitcoin Script hex and checks for stack safety,
 * spending path correctness, signature verification hygiene, and opcode
 * concerns — independent of which compiler produced the script.
 */

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type FindingSeverity = 'error' | 'warning' | 'info';

/**
 * Finding codes emitted by the analyzer.
 *
 * Errors indicate definite correctness problems.
 * Warnings indicate likely problems or suspicious patterns.
 * Info findings are suggestions or observations.
 */
export type FindingCode =
  // Stack safety
  | 'STACK_UNDERFLOW'
  | 'INVALID_TERMINAL_STACK'
  | 'INCONSISTENT_BRANCH_DEPTH'
  | 'UNREACHABLE_AFTER_RETURN'
  // Control flow
  | 'UNBALANCED_IF_ENDIF'
  // Spending paths
  | 'UNCONDITIONALLY_SUCCEEDS'
  // Signature hygiene
  | 'NO_SIG_CHECK'
  | 'CHECKSIG_RESULT_DROPPED'
  // Opcode concerns
  | 'CODESEPARATOR_PRESENT'
  | 'INEFFICIENT_PUSH'
  | 'LARGE_SCRIPT'
  // Analyzer capacity limits
  | 'PATHS_TRUNCATED';

export interface AnalysisFinding {
  /** Severity: error (definite bug), warning (likely problem), info (suggestion). */
  severity: FindingSeverity;
  /** Machine-readable finding code. */
  code: FindingCode;
  /** Human-readable description. */
  message: string;
  /** Byte offset in the script where the issue occurs. */
  offset?: number;
  /** Opcode name at that offset (e.g., 'OP_ADD', 'OP_CHECKSIG'). */
  opcode?: string;
  /** Execution path descriptor (e.g., "IF[true] at 5 -> ELSE at 12"). */
  path?: string;
}

// ---------------------------------------------------------------------------
// Execution paths
// ---------------------------------------------------------------------------

export interface ExecutionPath {
  /** Sequential path identifier. */
  id: number;
  /** Human-readable description of the path through IF/ELSE branches. */
  description: string;
  /** Sequence of boolean choices for each OP_IF/OP_NOTIF encountered. */
  branchChoices: boolean[];
  /** Whether this path is reachable (not behind always-false conditions). */
  reachable: boolean;
  /** Whether this path contains OP_CHECKSIG/OP_CHECKMULTISIG or *VERIFY variants. */
  hasCheckSig: boolean;
  /** Symbolic stack depth at the end of this path. */
  stackDepthAtEnd: number;
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export interface AnalysisSummary {
  totalPaths: number;
  reachablePaths: number;
  pathsWithCheckSig: number;
  pathsWithoutCheckSig: number;
  maxStackDepth: number;
  scriptSizeBytes: number;
}

// ---------------------------------------------------------------------------
// Raw script spans
// ---------------------------------------------------------------------------

/**
 * Byte range in the locking script produced by a `raw_script` ANF node
 * (surfaced in source as `asm({ body, in_arity, out_arity })`).
 *
 * The analyzer treats these spans as opaque — it does not walk the opcodes
 * inside, since `raw_bytes` is a peephole barrier and the contents may not
 * form a well-formed opcode stream. The declared `inArity` / `outArity`
 * carry the stack-effect contract so depth tracking remains sound across
 * the span without inspecting it.
 *
 * Compilers emit these into the `rawScriptSpans` artifact field. Callers
 * that load an artifact JSON should forward the field to
 * `analyzeScript(hex, { rawScriptSpans })`.
 */
export interface RawScriptSpan {
  /** Byte offset of the span start in the locking script. */
  offset: number;
  /** Total length of the span, in bytes. */
  length: number;
  /** Number of stack values consumed before the span executes. */
  inArity: number;
  /** Number of stack values left on the stack after the span executes. */
  outArity: number;
}

/**
 * Options for `analyzeScript`.
 */
export interface AnalyzeOptions {
  /**
   * Byte ranges produced by `raw_script` ANF nodes. When supplied, the
   * analyzer collapses each span into a single opaque step whose stack
   * effect is `(-inArity, +outArity)` and skips opcode-level concerns
   * (CODESEPARATOR / INEFFICIENT_PUSH / CHECKSIG / IF-ELSE) for the
   * contents of the span.
   */
  rawScriptSpans?: RawScriptSpan[];
}

// ---------------------------------------------------------------------------
// Top-level result
// ---------------------------------------------------------------------------

export interface AnalysisResult {
  /** The input hex script. */
  script: string;
  /** Script size in bytes. */
  scriptSize: number;
  /** All findings, sorted by severity (error first) then offset. */
  findings: AnalysisFinding[];
  /** All enumerated execution paths. */
  paths: ExecutionPath[];
  /** Aggregate summary. */
  summary: AnalysisSummary;
}
