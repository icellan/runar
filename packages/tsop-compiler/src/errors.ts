import type { SourceLocation } from './ir/index.js';

/**
 * Severity levels for compiler diagnostics.
 */
export type Severity = 'error' | 'warning';

/**
 * A single compiler diagnostic (error or warning).
 */
export interface CompilerDiagnostic {
  message: string;
  loc?: SourceLocation;
  severity: Severity;
}

/**
 * Base error class for the TSOP compiler.
 */
export class CompilerError extends Error {
  public readonly loc?: SourceLocation;

  constructor(message: string, loc?: SourceLocation) {
    const prefix = loc
      ? `${loc.file}:${loc.line}:${loc.column}`
      : '<unknown>';
    super(`${prefix}: ${message}`);
    this.name = 'CompilerError';
    this.loc = loc;
  }
}

/**
 * Thrown during Pass 1 (parse) when the TypeScript source cannot be
 * translated into a TSOP AST.
 */
export class ParseError extends CompilerError {
  constructor(message: string, loc?: SourceLocation) {
    super(message, loc);
    this.name = 'ParseError';
  }
}

/**
 * Thrown during Pass 2 (validate) when the TSOP AST violates subset
 * constraints.
 */
export class ValidationError extends CompilerError {
  constructor(message: string, loc?: SourceLocation) {
    super(message, loc);
    this.name = 'ValidationError';
  }
}

/**
 * Thrown during Pass 3 (typecheck) when expressions have incompatible types.
 */
export class TypeError extends CompilerError {
  constructor(message: string, loc?: SourceLocation) {
    super(message, loc);
    this.name = 'TypeError';
  }
}

/**
 * Helper: create a diagnostic object without throwing.
 */
export function makeDiagnostic(
  message: string,
  severity: Severity,
  loc?: SourceLocation,
): CompilerDiagnostic {
  return { message, severity, loc };
}
