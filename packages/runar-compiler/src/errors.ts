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
 * N-121 (user decision R85): optional chaining is disallowed (spec/grammar.md).
 * Every tier refuses a `.runar.ts` `?.` with this diagnostic, at the `?`.
 * Only the first `?.` in a file is reported.
 */
export const OPTIONAL_CHAINING = "optional chaining '?.' is not supported";

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

/**
 * N-053: a .runar.rb / .runar.py statement whose first token can begin neither
 * a statement nor an expression. The dispatchers used to skip such a token and
 * carry on, which dropped keywords, `!` and parentheses out of a statement
 * (inverting a Ruby helper's implicit return). Every tier refuses it with this
 * diagnostic; `token` is the token's source text.
 */
export function unsupportedStatementMessage(token: string): string {
  return `Unsupported statement starting with '${token}'`;
}

/**
 * N-004: a .runar.rb class-body token that is not `prop`, `runar_public`,
 * `params`, `def` or a bare `private` / `public` marker, and the first token
 * after the class's `end`. The parser used to skip both silently, so an
 * indented `=begin` (lexed as `=`, `begin`) let a "commented-out" method
 * become the only spend path. Every tier refuses with these texts; `token`
 * is the token's source text.
 */
export function unexpectedClassBodyTokenMessage(token: string): string {
  return `Unexpected token in class body: '${token}'`;
}

export function unexpectedTokenAfterClassMessage(token: string): string {
  return `Unexpected token after class end: '${token}'`;
}

/**
 * N-050: a static or class-level method is not a contract method, and must
 * never become a spending entry point. Every tier refuses each surface's
 * spelling of one (`static`, `@staticmethod` / `@classmethod`, `def self.m`,
 * a `.rs` / `.zig` `pub fn` without a self receiver) with this diagnostic.
 * `name` is the method name as written in the source.
 */
export function staticMethodMessage(name: string): string {
  return `static methods are not allowed in Rúnar contracts; method '${name}' is declared static`;
}

/**
 * N-023 (R49): on the .runar.java surface a bare name that no local or
 * parameter shadows refers to the field, so `count = ...` (or `count += ...`,
 * `count++`, `--count`) is a state write in Java. Rúnar requires the explicit
 * `this.count = ...` form; every tier's Java parser refuses the bare form with
 * this diagnostic. `name` is the property name.
 */
export function bareJavaPropertyAssignmentMessage(name: string): string {
  return `bare assignment to property '${name}' is not allowed; write \`this.${name} = ...\``;
}

/**
 * F-203: a .runar.py string or bytes literal escape that CPython does not
 * define for that literal kind (`\q`; `\N`, `\u`, `\U` in bytes), a `\x` not
 * followed by two hex digits, an octal escape above 0o377, or (in a plain
 * string) a `\N{..}` / `\u` / `\U` escape the surface does not support.
 * CPython keeps an unknown escape as a literal backslash with a warning; every
 * tier refuses it instead. `escape` is the backslash plus the escape letter
 * (`\q`, `\x`), or the whole octal escape (`\400`).
 */
export function invalidEscapeSequenceMessage(escape: string): string {
  return `invalid escape sequence '${escape}'`;
}

/** F-203: CPython's refusal of a non-ASCII character inside b'..' / b"..". */
export const PY_BYTES_NON_ASCII = 'bytes can only contain ASCII literal characters';

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
