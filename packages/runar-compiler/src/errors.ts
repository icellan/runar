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
 * Base error class for the Rúnar compiler.
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
 * translated into a Rúnar AST.
 */
export class ParseError extends CompilerError {
  constructor(message: string, loc?: SourceLocation) {
    super(message, loc);
    this.name = 'ParseError';
  }
}

/**
 * Thrown during Pass 2 (validate) when the Rúnar AST violates subset
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
 * F-011: the one diagnostic every tier's hand-written tokenizers emit, at the
 * opening quote, for a quoted literal that reaches a line break or end of file
 * before its closing quote. On `.runar.rs`, for Python triple-quoted strings
 * and for `.runar.go` backtick raw strings, which may span lines, only end of
 * file counts.
 */
export const UNTERMINATED_STRING_LITERAL = 'unterminated string literal';

/**
 * F-026: a .runar.zig call argument list or array literal whose elements are
 * not separated by commas. Zig requires the comma (a trailing one is allowed).
 */
export const ZIG_LIST_COMMA = "expected ',' between list elements";

/**
 * F-026: a .runar.py statement (or class-level field) followed by more code on
 * the same line. Rúnar's Python surface has no `;`, so a statement must end at
 * the line break.
 */
export const PY_STATEMENT_LINE_BREAK = 'expected a line break between statements';

/** F-026: prefix of a TypeScript syntactic diagnostic surfaced on .runar.ts. */
export const TS_SYNTAX_ERROR_PREFIX = 'TypeScript syntax error: ';

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
