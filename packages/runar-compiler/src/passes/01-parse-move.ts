/**
 * Move-style parser for Rúnar contracts.
 *
 * Parses `.runar.move` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses hand-written recursive descent.
 */

import type {
  ContractNode,
  PropertyNode,
  MethodNode,
  ParamNode,
  TypeNode,
  PrimitiveTypeName,
  Statement,
  Expression,
  SourceLocation,
  BinaryOp,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import type { ParseResult } from './01-parse.js';

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokenType =
  | 'module' | 'use' | 'resource' | 'struct' | 'public' | 'fun'
  | 'let' | 'mut' | 'if' | 'else' | 'loop' | 'while' | 'return'
  | 'assert!' | 'assert_eq!' | 'true' | 'false' | 'has'
  | 'ident' | 'number' | 'hexstring'
  | '(' | ')' | '{' | '}' | '[' | ']' | ';' | ',' | '.' | ':' | '::' | '->'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-='
  | 'eof';

interface Token {
  type: TokenType;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS: Record<string, TokenType> = {
  module: 'module', use: 'use', resource: 'resource', struct: 'struct',
  public: 'public', fun: 'fun', let: 'let', mut: 'mut',
  if: 'if', else: 'else', loop: 'loop', while: 'while', return: 'return',
  true: 'true', false: 'false', has: 'has',
};

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let pos = 0;
  let line = 1;
  let column = 1;

  function advance(): string {
    const ch = source[pos++]!;
    if (ch === '\n') { line++; column = 1; } else { column++; }
    return ch;
  }
  function peek(): string { return source[pos] || ''; }
  function peekN(n: number): string { return source[pos + n] || ''; }
  function add(type: TokenType, value: string, l: number, c: number) {
    tokens.push({ type, value, line: l, column: c });
  }

  while (pos < source.length) {
    const ch = peek();
    const l = line;
    const c = column;

    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') { advance(); continue; }

    // Comments
    if (ch === '/' && peekN(1) === '/') {
      while (pos < source.length && peek() !== '\n') advance();
      continue;
    }
    if (ch === '/' && peekN(1) === '*') {
      advance(); advance();
      while (pos < source.length - 1) {
        if (peek() === '*' && peekN(1) === '/') { advance(); advance(); break; }
        advance();
      }
      continue;
    }

    // Two-char ops
    if (ch === ':' && peekN(1) === ':') { advance(); advance(); add('::', '::', l, c); continue; }
    if (ch === '-' && peekN(1) === '>') { advance(); advance(); add('->', '->', l, c); continue; }
    if (ch === '=' && peekN(1) === '=') { advance(); advance(); add('==', '==', l, c); continue; }
    if (ch === '!' && peekN(1) === '=') { advance(); advance(); add('!=', '!=', l, c); continue; }
    if (ch === '<' && peekN(1) === '=') { advance(); advance(); add('<=', '<=', l, c); continue; }
    if (ch === '>' && peekN(1) === '=') { advance(); advance(); add('>=', '>=', l, c); continue; }
    if (ch === '&' && peekN(1) === '&') { advance(); advance(); add('&&', '&&', l, c); continue; }
    if (ch === '|' && peekN(1) === '|') { advance(); advance(); add('||', '||', l, c); continue; }
    if (ch === '+' && peekN(1) === '=') { advance(); advance(); add('+=', '+=', l, c); continue; }
    if (ch === '-' && peekN(1) === '=') { advance(); advance(); add('-=', '-=', l, c); continue; }

    const singles = '(){}[];,.:+-*/%<>=&|^~!';
    if (singles.includes(ch as string)) { advance(); add(ch as TokenType, ch, l, c); continue; }

    // Hex literal: 0x...
    if (ch === '0' && peekN(1) === 'x') {
      let val = '';
      advance(); advance();
      while (pos < source.length && /[0-9a-fA-F]/.test(peek())) val += advance();
      add('hexstring', val, l, c);
      continue;
    }

    // Number
    if (/[0-9]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[0-9_]/.test(peek())) val += advance();
      add('number', val.replace(/_/g, ''), l, c);
      continue;
    }

    // Identifier / keyword / assert!/assert_eq!
    if (/[a-zA-Z_]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[a-zA-Z0-9_]/.test(peek())) val += advance();
      // Check for assert!/assert_eq!
      if ((val === 'assert' || val === 'assert_eq') && peek() === '!') {
        val += advance(); // consume '!'
        const kwType = KEYWORDS[val] || (val === 'assert!' ? 'assert!' : val === 'assert_eq!' ? 'assert_eq!' : 'ident');
        add(kwType as TokenType, val, l, c);
        continue;
      }
      add(KEYWORDS[val] || 'ident', val, l, c);
      continue;
    }

    advance();
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

// ---------------------------------------------------------------------------
// Type mapping: Move snake_case → Rúnar camelCase
// ---------------------------------------------------------------------------

function mapMoveType(name: string): string {
  const map: Record<string, string> = {
    Int: 'bigint', u64: 'bigint', u128: 'bigint', u256: 'bigint',
    Bool: 'boolean', bool: 'boolean',
    vector: 'ByteString',
    address: 'Addr',
  };
  return map[name] || name;
}

function snakeToCamel(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class MoveParser {
  private tokens: Token[];
  private pos = 0;
  private file: string;
  private errors: CompilerDiagnostic[] = [];

  constructor(tokens: Token[], file: string) {
    this.tokens = tokens;
    this.file = file;
  }

  private current(): Token { return this.tokens[this.pos] ?? this.tokens[this.tokens.length - 1]!; }
  private advance(): Token { const t = this.current(); this.pos++; return t; }
  private expect(type: TokenType): Token {
    const t = this.current();
    if (t.type !== type) {
      this.errors.push(makeDiagnostic(
        `Expected '${type}', got '${t.value || t.type}'`,
        'error',
        { file: this.file, line: t.line, column: t.column }));
    }
    return this.advance();
  }
  private match(type: TokenType): boolean {
    if (this.current().type === type) { this.advance(); return true; }
    return false;
  }
  private loc(): SourceLocation {
    const t = this.current();
    return { file: this.file, line: t.line, column: t.column };
  }

  parse(): ParseResult {
    // module ContractName { ... }
    this.expect('module');
    const contractName = this.expect('ident').value;
    this.expect('{');

    // Skip use declarations
    while (this.current().type === 'use') {
      while (this.current().type !== ';' && this.current().type !== 'eof') this.advance();
      if (this.current().type === ';') this.advance();
    }

    let parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      if (this.current().type === 'resource' || this.current().type === 'struct') {
        const isResource = this.current().type === 'resource';
        this.advance();
        if (this.current().type === 'struct') this.advance(); // "resource struct"

        // Struct name (skip, should match module name)
        if (this.current().type === 'ident') this.advance();

        // Optional "has key, store" abilities
        if (this.current().type === 'has') {
          this.advance();
          while (this.current().type !== '{' && this.current().type !== 'eof') this.advance();
        }

        this.expect('{');
        let hasMutableField = false;
        while (this.current().type !== '}' && this.current().type !== 'eof') {
          const propLoc = this.loc();
          const propName = snakeToCamel(this.expect('ident').value);
          this.expect(':');

          // Check for &mut (mutable reference)
          let readonly = true;
          if (this.current().type === '&') {
            this.advance();
            if (this.current().type === 'mut') {
              this.advance();
              readonly = false;
            }
          }

          const typeName = this.parseMoveType();
          if (!readonly) hasMutableField = true;

          // Optional initializer: = value
          let initializer: Expression | undefined;
          if (this.current().type === '=') {
            this.advance();
            initializer = this.parseExpression();
          }

          properties.push({
            kind: 'property',
            name: propName,
            type: typeName,
            readonly,
            initializer,
            sourceLocation: propLoc,
          });

          this.match(',');
        }
        this.expect('}');

        // If the struct is not marked resource, check for "stateful" marker
        if (isResource || hasMutableField) {
          parentClass = 'StatefulSmartContract';
        }
      } else if (this.current().type === 'public' || this.current().type === 'fun') {
        methods.push(this.parseFunction());
      } else {
        this.advance(); // skip unknown
      }
    }
    this.expect('}');

    // Determine parent class from property mutability
    const hasMutable = properties.some(p => !p.readonly);
    if (hasMutable) parentClass = 'StatefulSmartContract';

    // Build constructor — only non-initialized properties become params
    const loc = { file: this.file, line: 1, column: 1 };
    const uninitProps = properties.filter(p => !p.initializer);
    const constructorNode: MethodNode = {
      kind: 'method',
      name: 'constructor',
      params: uninitProps.map(p => ({ kind: 'param' as const, name: p.name, type: p.type })),
      body: [
        // super(...) as first statement
        {
          kind: 'expression_statement' as const,
          expression: {
            kind: 'call_expr' as const,
            callee: { kind: 'identifier' as const, name: 'super' },
            args: uninitProps.map(p => ({ kind: 'identifier' as const, name: p.name })),
          },
          sourceLocation: loc,
        },
        ...uninitProps.map(p => ({
          kind: 'assignment' as const,
          target: { kind: 'property_access' as const, property: p.name },
          value: { kind: 'identifier' as const, name: p.name },
          sourceLocation: loc,
        })),
      ],
      visibility: 'public',
      sourceLocation: loc,
    };

    const contract: ContractNode = {
      kind: 'contract',
      name: contractName,
      parentClass,
      properties,
      constructor: constructorNode,
      methods,
      sourceFile: this.file,
    };

    return { contract, errors: this.errors };
  }

  private parseMoveType(): TypeNode {
    const name = this.expect('ident').value;
    const mapped = mapMoveType(name);

    // vector<T> => FixedArray<T, N> (we treat it as ByteString for now)
    if (name === 'vector' && this.current().type === '<') {
      this.advance();
      const innerType = this.parseMoveType();
      this.expect('>');
      return innerType; // Simplify: vector<u8> -> ByteString
    }

    const primitives = new Set([
      'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
      'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point', 'void',
    ]);
    if (primitives.has(mapped)) {
      return { kind: 'primitive_type', name: mapped as PrimitiveTypeName };
    }
    return { kind: 'custom_type', name: mapped };
  }

  private parseFunction(): MethodNode {
    const location = this.loc();
    let visibility: 'public' | 'private' = 'private';
    if (this.current().type === 'public') {
      this.advance();
      visibility = 'public';
    }

    // Optional "entry" or "friend" keyword
    if (this.current().type === 'ident' && (this.current().value === 'entry' || this.current().value === 'friend')) {
      this.advance();
    }

    this.expect('fun');
    const rawName = this.expect('ident').value;
    const name = snakeToCamel(rawName);

    this.expect('(');
    const params: ParamNode[] = [];
    while (this.current().type !== ')' && this.current().type !== 'eof') {
      // Skip &self, &mut self, contract: &ContractName
      if (this.current().type === '&') {
        this.advance();
        if (this.current().type === 'mut') this.advance();
        if (this.current().type === 'ident' && this.current().value === 'self') {
          this.advance();
          if (this.current().type === ',') this.advance();
          continue;
        }
      }
      if (this.current().type === 'ident' && this.current().value === 'self') {
        this.advance();
        if (this.current().type === ',') this.advance();
        continue;
      }

      const pNameRaw = this.expect('ident').value;

      // Check if this is "contract: &Type" pattern (skip it)
      if (this.current().type === ':') {
        this.advance();
        // Skip reference markers
        if (this.current().type === '&') {
          this.advance();
          if (this.current().type === 'mut') this.advance();
        }
        const pType = this.parseMoveType();

        // If param name is 'contract' or 'self', skip it
        if (pNameRaw === 'contract' || pNameRaw === 'self') {
          if (this.current().type === ',') this.advance();
          continue;
        }

        params.push({
          kind: 'param',
          name: snakeToCamel(pNameRaw),
          type: pType,
        });
      }

      if (this.current().type === ',') this.advance();
    }
    this.expect(')');

    // Optional return type
    if (this.current().type === ':') {
      this.advance();
      this.parseMoveType();
    }

    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    return { kind: 'method', name, params, body, visibility, sourceLocation: location };
  }

  private parseStatement(): Statement {
    const location = this.loc();

    // assert!(expr, code) -> assert(expr)
    if (this.current().type === 'assert!' as TokenType) {
      this.advance();
      this.expect('(');
      const expr = this.parseExpression();
      // Skip optional error code
      if (this.current().type === ',') {
        this.advance();
        this.parseExpression(); // skip error code
      }
      this.expect(')');
      this.match(';');
      return {
        kind: 'expression_statement',
        expression: {
          kind: 'call_expr',
          callee: { kind: 'identifier', name: 'assert' },
          args: [expr],
        },
        sourceLocation: location,
      };
    }

    // assert_eq!(a, b) -> assert(a === b)
    if (this.current().type === 'assert_eq!' as TokenType) {
      this.advance();
      this.expect('(');
      const left = this.parseExpression();
      this.expect(',');
      const right = this.parseExpression();
      this.expect(')');
      this.match(';');
      return {
        kind: 'expression_statement',
        expression: {
          kind: 'call_expr',
          callee: { kind: 'identifier', name: 'assert' },
          args: [{
            kind: 'binary_expr',
            op: '===',
            left,
            right,
          }],
        },
        sourceLocation: location,
      };
    }

    // let [mut] name [: type] = expr;
    if (this.current().type === 'let') {
      this.advance();
      let mutable = false;
      if (this.current().type === 'mut') {
        this.advance();
        mutable = true;
      }
      const varName = snakeToCamel(this.expect('ident').value);
      let varType: TypeNode | undefined;
      if (this.current().type === ':') {
        this.advance();
        varType = this.parseMoveType();
      }
      this.expect('=');
      const init = this.parseExpression();
      this.match(';');
      return { kind: 'variable_decl', name: varName, type: varType, mutable, init, sourceLocation: location };
    }

    // if
    if (this.current().type === 'if') {
      return this.parseIfStatement();
    }

    // return
    if (this.current().type === 'return') {
      this.advance();
      const value = this.current().type !== ';' && this.current().type !== '}' ? this.parseExpression() : undefined;
      this.match(';');
      return { kind: 'return_statement', value, sourceLocation: location };
    }

    // Expression statement
    const expr = this.parseExpression();

    // Assignment
    if (this.current().type === '=') {
      this.advance();
      const value = this.parseExpression();
      this.match(';');
      return { kind: 'assignment', target: this.convertMoveExpr(expr), value, sourceLocation: location };
    }

    // Compound assignments
    if (this.current().type === '+=') {
      this.advance();
      const rhs = this.parseExpression();
      this.match(';');
      const target = this.convertMoveExpr(expr);
      return { kind: 'assignment', target, value: { kind: 'binary_expr', op: '+', left: target, right: rhs }, sourceLocation: location };
    }
    if (this.current().type === '-=') {
      this.advance();
      const rhs = this.parseExpression();
      this.match(';');
      const target = this.convertMoveExpr(expr);
      return { kind: 'assignment', target, value: { kind: 'binary_expr', op: '-', left: target, right: rhs }, sourceLocation: location };
    }

    this.match(';');
    return { kind: 'expression_statement', expression: expr, sourceLocation: location };
  }

  private convertMoveExpr(expr: Expression): Expression {
    // Convert Move-style &contract.field to this.field
    if (expr.kind === 'member_expr' && expr.object.kind === 'identifier' && expr.object.name === 'contract') {
      return { kind: 'property_access', property: snakeToCamel(expr.property) };
    }
    return expr;
  }

  private parseIfStatement(): Statement {
    const location = this.loc();
    this.expect('if');
    this.expect('(');
    const condition = this.parseExpression();
    this.expect(')');
    this.expect('{');
    const thenBranch: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      thenBranch.push(this.parseStatement());
    }
    this.expect('}');

    let elseBranch: Statement[] | undefined;
    if (this.current().type === 'else') {
      this.advance();
      this.expect('{');
      elseBranch = [];
      while (this.current().type !== '}' && this.current().type !== 'eof') {
        elseBranch.push(this.parseStatement());
      }
      this.expect('}');
    }

    return { kind: 'if_statement', condition, then: thenBranch, else: elseBranch, sourceLocation: location };
  }

  // Expression parsing (same precedence climbing as Solidity parser)
  private parseExpression(): Expression { return this.parseOr(); }

  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.current().type === '||') { this.advance(); left = { kind: 'binary_expr', op: '||', left, right: this.parseAnd() }; }
    return left;
  }
  private parseAnd(): Expression {
    let left = this.parseBitOr();
    while (this.current().type === '&&') { this.advance(); left = { kind: 'binary_expr', op: '&&', left, right: this.parseBitOr() }; }
    return left;
  }
  private parseBitOr(): Expression {
    let left = this.parseBitXor();
    while (this.current().type === '|' && this.tokens[this.pos + 1]?.type !== '|') { this.advance(); left = { kind: 'binary_expr', op: '|', left, right: this.parseBitXor() }; }
    return left;
  }
  private parseBitXor(): Expression {
    let left = this.parseBitAnd();
    while (this.current().type === '^') { this.advance(); left = { kind: 'binary_expr', op: '^', left, right: this.parseBitAnd() }; }
    return left;
  }
  private parseBitAnd(): Expression {
    let left = this.parseEquality();
    while (this.current().type === '&' && this.tokens[this.pos + 1]?.type !== '&') { this.advance(); left = { kind: 'binary_expr', op: '&', left, right: this.parseEquality() }; }
    return left;
  }
  private parseEquality(): Expression {
    let left = this.parseComparison();
    while (this.current().type === '==' || this.current().type === '!=') {
      const op = this.advance().type === '==' ? '===' : '!==';
      left = { kind: 'binary_expr', op: op as BinaryOp, left, right: this.parseComparison() };
    }
    return left;
  }
  private parseComparison(): Expression {
    let left = this.parseAddSub();
    while (['<', '<=', '>', '>='].includes(this.current().type)) {
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

  private parseUnary(): Expression {
    if (this.current().type === '!') { this.advance(); return { kind: 'unary_expr', op: '!', operand: this.parseUnary() }; }
    if (this.current().type === '-') { this.advance(); return { kind: 'unary_expr', op: '-', operand: this.parseUnary() }; }
    if (this.current().type === '~') { this.advance(); return { kind: 'unary_expr', op: '~', operand: this.parseUnary() }; }
    // Dereference & — skip
    if (this.current().type === '&') {
      this.advance();
      if (this.current().type === 'mut') this.advance();
      return this.parsePostfix();
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expression {
    let expr = this.parsePrimary();
    while (true) {
      if (this.current().type === '(') {
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
        const prop = snakeToCamel(this.expect('ident').value);
        if (expr.kind === 'identifier' && (expr.name === 'self' || expr.name === 'contract')) {
          expr = { kind: 'property_access', property: prop };
        } else {
          expr = { kind: 'member_expr', object: expr, property: prop };
        }
      } else if (this.current().type === '::') {
        this.advance();
        const member = this.expect('ident').value;
        // module::function -> just function name
        expr = { kind: 'identifier', name: snakeToCamel(member) };
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

  private parsePrimary(): Expression {
    const t = this.current();
    if (t.type === 'number') { this.advance(); return { kind: 'bigint_literal', value: BigInt(t.value) }; }
    if (t.type === 'hexstring') { this.advance(); return { kind: 'bytestring_literal', value: t.value }; }
    if (t.type === 'true') { this.advance(); return { kind: 'bool_literal', value: true }; }
    if (t.type === 'false') { this.advance(); return { kind: 'bool_literal', value: false }; }
    if (t.type === '(') {
      this.advance();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }
    if (t.type === '[') {
      this.advance();
      const elements: Expression[] = [];
      while (this.current().type !== ']' && this.current().type !== 'eof') {
        elements.push(this.parseExpression());
        if (this.current().type === ',') this.advance();
      }
      this.expect(']');
      return { kind: 'array_literal', elements };
    }
    if (t.type === 'ident') {
      this.advance();
      const name = snakeToCamel(t.value);
      // Map Move builtins to Rúnar builtins.
      // After snakeToCamel, most names already match (e.g. check_sig → checkSig).
      // Explicit entries are needed for:
      //   1. Names where snakeToCamel produces wrong casing (num_2_bin → num2Bin, not num2bin)
      //   2. Names where the Move convention differs from the Rúnar name
      //      (reverse_byte_string → reverseByteString, but Rúnar uses reverseBytes)
      //   3. Builtins whose names pass through snakeToCamel unchanged and need anchoring
      const builtinMap: Record<string, string> = {
        // Hashing
        hash160: 'hash160', hash256: 'hash256', sha256: 'sha256', ripemd160: 'ripemd160',
        // Signature verification
        checkSig: 'checkSig', checkMultiSig: 'checkMultiSig',
        checkPreimage: 'checkPreimage', verifyRabinSig: 'verifyRabinSig',
        // Post-quantum signature verification
        verifyWOTS: 'verifyWOTS', verifyWots: 'verifyWOTS',
        // verify_slhdsa_sha2_128s → verifySlhdsaSha2128s, verify_slh_dsa_sha2_128s → verifySlhDsaSha2128s
        verifySlhdsaSha2128s: 'verifySLHDSA_SHA2_128s', verifySlhDsaSha2128s: 'verifySLHDSA_SHA2_128s',
        verifySlhdsaSha2128f: 'verifySLHDSA_SHA2_128f', verifySlhDsaSha2128f: 'verifySLHDSA_SHA2_128f',
        verifySlhdsaSha2192s: 'verifySLHDSA_SHA2_192s', verifySlhDsaSha2192s: 'verifySLHDSA_SHA2_192s',
        verifySlhdsaSha2192f: 'verifySLHDSA_SHA2_192f', verifySlhDsaSha2192f: 'verifySLHDSA_SHA2_192f',
        verifySlhdsaSha2256s: 'verifySLHDSA_SHA2_256s', verifySlhDsaSha2256s: 'verifySLHDSA_SHA2_256s',
        verifySlhdsaSha2256f: 'verifySLHDSA_SHA2_256f', verifySlhDsaSha2256f: 'verifySLHDSA_SHA2_256f',
        // Byte operations — fixups for digit-containing names
        num2bin: 'num2bin', num2Bin: 'num2bin',
        bin2num: 'bin2num', bin2Num: 'bin2num',
        int2str: 'int2str', int2Str: 'int2str',
        // Byte operations — name divergence fixups
        reverseByteString: 'reverseBytes', reverseBytes: 'reverseBytes',
        toByteString: 'toByteString',
        cat: 'cat', substr: 'substr', split: 'split', left: 'left', right: 'right',
        len: 'len', pack: 'pack', unpack: 'unpack', bool: 'bool',
        // Preimage extractors
        extractVersion: 'extractVersion',
        extractHashPrevouts: 'extractHashPrevouts',
        extractHashSequence: 'extractHashSequence',
        extractOutpoint: 'extractOutpoint',
        extractScriptCode: 'extractScriptCode',
        extractSequence: 'extractSequence',
        extractSigHashType: 'extractSigHashType',
        extractInputIndex: 'extractInputIndex',
        extractOutputs: 'extractOutputs',
        extractAmount: 'extractAmount',
        extractLocktime: 'extractLocktime',
        extractOutputHash: 'extractOutputHash',
        // Output construction
        addOutput: 'addOutput',
        // Math builtins
        abs: 'abs', min: 'min', max: 'max', within: 'within',
        safediv: 'safediv', safemod: 'safemod', clamp: 'clamp', sign: 'sign',
        pow: 'pow', mulDiv: 'mulDiv', percentOf: 'percentOf', sqrt: 'sqrt',
        gcd: 'gcd', divmod: 'divmod', log2: 'log2',
        // EC builtins
        ecAdd: 'ecAdd', ecMul: 'ecMul', ecMulGen: 'ecMulGen',
        ecNegate: 'ecNegate', ecOnCurve: 'ecOnCurve', ecModReduce: 'ecModReduce',
        ecEncodeCompressed: 'ecEncodeCompressed', ecMakePoint: 'ecMakePoint',
        ecPointX: 'ecPointX', ecPointY: 'ecPointY',
      };
      return { kind: 'identifier', name: builtinMap[name] || name };
    }
    this.advance();
    return { kind: 'identifier', name: t.value };
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseMoveSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.move';
  const tokens = tokenize(source);
  const parser = new MoveParser(tokens, file);
  return parser.parse();
}
