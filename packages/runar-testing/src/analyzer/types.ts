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
