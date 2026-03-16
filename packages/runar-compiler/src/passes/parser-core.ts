/**
 * ParserCore — shared base class for hand-written recursive-descent parsers.
 *
 * Provides parser state management and a full precedence-climbing expression
 * parser for C-like operator syntax. Sol, Move, Go, and Rust parsers can
 * extend this class instead of duplicating the expression chain.
 *
 * Subclasses must implement:
 *   - parseUnary()   — language-specific unary operators, then postfix/primary
 *   - parsePrimary() — language-specific literals and identifiers
 *
 * The binary expression chain handles:
 *   ||  &&  |  ^  &  ==  !=  <  <=  >  >=  <<  >>  +  -  *  /  %
 *
 * Equality operators are mapped: == → === and != → !== (Rúnar AST convention).
 */

import type { Expression, BinaryOp, SourceLocation } from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';

// ---------------------------------------------------------------------------
// Token interface
// ---------------------------------------------------------------------------

export interface Token {
  type: string;
  value: string;
  line: number;
  column: number;
}

// ---------------------------------------------------------------------------
// ParserCore base class
// ---------------------------------------------------------------------------

export abstract class ParserCore<T extends Token = Token> {
  protected tokens: T[];
  protected pos = 0;
  protected file: string;
  protected errors: CompilerDiagnostic[] = [];

  constructor(tokens: T[], file: string) {
    this.tokens = tokens;
    this.file = file;
  }

  // -----------------------------------------------------------------------
  // Parser state
  // -----------------------------------------------------------------------

  protected current(): T {
    return this.tokens[this.pos] ?? this.tokens[this.tokens.length - 1]!;
  }

  protected advance(): T {
    const t = this.current();
    this.pos++;
    return t;
  }

  protected expect(type: string): T {
    const t = this.current();
    if (t.type !== type) {
      this.errors.push(makeDiagnostic(
        `Expected '${type}', got '${t.value || t.type}'`,
        'error',
        { file: this.file, line: t.line, column: t.column },
      ));
    }
    return this.advance();
  }

  protected match(type: string): boolean {
    if (this.current().type === type) {
      this.advance();
      return true;
    }
    return false;
  }

  protected loc(): SourceLocation {
    const t = this.current();
    return { file: this.file, line: t.line, column: t.column };
  }

  // -----------------------------------------------------------------------
  // Expression parsing — precedence climbing
  // -----------------------------------------------------------------------
  //
  // Full chain (highest to lowest precedence, bottom-up):
  //   MulDiv → AddSub → Shift → Comparison → Equality
  //   → BitAnd → BitXor → BitOr → And → Or
  //
  // Subclasses must implement parseUnary() which is called by parseMulDiv().

  protected parseExpression(): Expression {
    return this.parseOr();
  }

  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.current().type === '||') {
      this.advance();
      left = { kind: 'binary_expr', op: '||', left, right: this.parseAnd() };
    }
    return left;
  }

  private parseAnd(): Expression {
    let left = this.parseBitOr();
    while (this.current().type === '&&') {
      this.advance();
      left = { kind: 'binary_expr', op: '&&', left, right: this.parseBitOr() };
    }
    return left;
  }

  private parseBitOr(): Expression {
    let left = this.parseBitXor();
    while (this.current().type === '|' && this.tokens[this.pos + 1]?.type !== '|') {
      this.advance();
      left = { kind: 'binary_expr', op: '|', left, right: this.parseBitXor() };
    }
    return left;
  }

  private parseBitXor(): Expression {
    let left = this.parseBitAnd();
    while (this.current().type === '^') {
      this.advance();
      left = { kind: 'binary_expr', op: '^', left, right: this.parseBitAnd() };
    }
    return left;
  }

  private parseBitAnd(): Expression {
    let left = this.parseEquality();
    while (this.current().type === '&' && this.tokens[this.pos + 1]?.type !== '&') {
      this.advance();
      left = { kind: 'binary_expr', op: '&', left, right: this.parseEquality() };
    }
    return left;
  }

  private parseEquality(): Expression {
    let left = this.parseComparison();
    while (this.current().type === '==' || this.current().type === '!=') {
      const op: BinaryOp = this.advance().type === '==' ? '===' : '!==';
      left = { kind: 'binary_expr', op, left, right: this.parseComparison() };
    }
    return left;
  }

  private parseComparison(): Expression {
    let left = this.parseShift();
    while (['<', '<=', '>', '>='].includes(this.current().type)) {
      const op = this.advance().value as BinaryOp;
      left = { kind: 'binary_expr', op, left, right: this.parseShift() };
    }
    return left;
  }

  private parseShift(): Expression {
    let left = this.parseAddSub();
    while (this.current().type === '<<' || this.current().type === '>>') {
      const op = this.advance().value as BinaryOp;
      left = { kind: 'binary_expr', op, left, right: this.parseAddSub() };
    }
    return left;
  }

  private parseAddSub(): Expression {
    let left = this.parseMulDiv();
    while (this.current().type === '+' || this.current().type === '-') {
      const op = this.advance().value as BinaryOp;
      left = { kind: 'binary_expr', op, left, right: this.parseMulDiv() };
    }
    return left;
  }

  private parseMulDiv(): Expression {
    let left = this.parseUnary();
    while (this.current().type === '*' || this.current().type === '/' || this.current().type === '%') {
      const op = this.advance().value as BinaryOp;
      left = { kind: 'binary_expr', op, left, right: this.parseUnary() };
    }
    return left;
  }

  // -----------------------------------------------------------------------
  // Abstract — must be implemented by subclasses
  // -----------------------------------------------------------------------

  /**
   * Parse unary expressions (!, -, ~, ++, --, etc.) then delegate to
   * postfix/primary parsing. Called by the precedence chain at the
   * highest-precedence level.
   */
  protected abstract parseUnary(): Expression;

  /**
   * Parse primary expressions: literals, identifiers, parenthesized
   * expressions. Called by parseUnary() or parsePostfix() implementations.
   */
  protected abstract parsePrimary(): Expression;

  // -----------------------------------------------------------------------
  // Helpers for subclasses
  // -----------------------------------------------------------------------

  /**
   * Standard postfix chain: function calls `(...)`, member access `.x`,
   * and index access `[i]`. Subclasses can call this from their
   * parseUnary() implementation after parsing a primary expression.
   *
   * The `selfNames` set contains identifiers that should be treated as
   * `this` (e.g., 'self', 'contract', or a receiver variable name).
   * When the object of `.property` is one of these, the result is a
   * `property_access` node instead of a `member_expr`.
   */
  protected parsePostfixChain(expr: Expression, selfNames: Set<string>): Expression {
    while (true) {
      if (this.current().type === '(') {
        // Function call
        this.advance();
        const args: Expression[] = [];
        while (this.current().type !== ')' && this.current().type !== 'eof') {
          args.push(this.parseExpression());
          if (this.current().type === ',') this.advance();
        }
        this.expect(')');
        expr = { kind: 'call_expr', callee: expr, args };
      } else if (this.current().type === '.') {
        this.advance();
        const prop = this.current().value;
        this.advance();
        // self.property -> PropertyAccessExpr
        if (expr.kind === 'identifier' && selfNames.has(expr.name)) {
          expr = { kind: 'property_access', property: prop };
        } else {
          expr = { kind: 'member_expr', object: expr, property: prop };
        }
      } else if (this.current().type === '[') {
        this.advance();
        const index = this.parseExpression();
        this.expect(']');
        expr = { kind: 'index_access', object: expr, index };
      } else {
        break;
      }
    }
    return expr;
  }
}
