/**
 * Solidity-like parser for Rúnar contracts.
 *
 * Parses `.runar.sol` files into the same Rúnar AST that the TypeScript
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
  | 'pragma' | 'contract' | 'is' | 'function' | 'constructor'
  | 'public' | 'private' | 'immutable' | 'require' | 'if' | 'else'
  | 'for' | 'return' | 'true' | 'false' | 'let' | 'stateful'
  | 'ident' | 'number' | 'hexstring'
  | '(' | ')' | '{' | '}' | '[' | ']' | ';' | ',' | '.' | ':'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-='
  | '++' | '--'
  | 'eof';

interface Token {
  type: TokenType;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['pragma', 'pragma'], ['contract', 'contract'], ['is', 'is'],
  ['function', 'function'], ['constructor', 'constructor'],
  ['public', 'public'], ['private', 'private'], ['immutable', 'immutable'],
  ['require', 'require'], ['if', 'if'], ['else', 'else'],
  ['for', 'for'], ['return', 'return'], ['true', 'true'], ['false', 'false'],
  ['let', 'let'], ['stateful', 'stateful'],
]);

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

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      advance();
      continue;
    }

    // Line comments
    if (ch === '/' && peekN(1) === '/') {
      while (pos < source.length && peek() !== '\n') advance();
      continue;
    }

    // Block comments
    if (ch === '/' && peekN(1) === '*') {
      advance(); advance();
      while (pos < source.length - 1) {
        if (peek() === '*' && peekN(1) === '/') { advance(); advance(); break; }
        advance();
      }
      continue;
    }

    // Two-char operators
    if (ch === '=' && peekN(1) === '=') { advance(); advance(); add('==', '==', l, c); continue; }
    if (ch === '!' && peekN(1) === '=') { advance(); advance(); add('!=', '!=', l, c); continue; }
    if (ch === '<' && peekN(1) === '=') { advance(); advance(); add('<=', '<=', l, c); continue; }
    if (ch === '>' && peekN(1) === '=') { advance(); advance(); add('>=', '>=', l, c); continue; }
    if (ch === '&' && peekN(1) === '&') { advance(); advance(); add('&&', '&&', l, c); continue; }
    if (ch === '|' && peekN(1) === '|') { advance(); advance(); add('||', '||', l, c); continue; }
    if (ch === '+' && peekN(1) === '+') { advance(); advance(); add('++', '++', l, c); continue; }
    if (ch === '-' && peekN(1) === '-') { advance(); advance(); add('--', '--', l, c); continue; }
    if (ch === '+' && peekN(1) === '=') { advance(); advance(); add('+=', '+=', l, c); continue; }
    if (ch === '-' && peekN(1) === '=') { advance(); advance(); add('-=', '-=', l, c); continue; }

    // Single-char operators & punctuation
    const singles = '(){}[];,.:+-*/%<>=&|^~!';
    if (singles.includes(ch as string)) {
      advance();
      add(ch as TokenType, ch, l, c);
      continue;
    }

    // Hex string literal
    if (ch === '0' && peekN(1) === 'x') {
      let val = '';
      advance(); advance();
      while (pos < source.length && /[0-9a-fA-F]/.test(peek())) {
        val += advance();
      }
      add('hexstring', val, l, c);
      continue;
    }

    // Number
    if (/[0-9]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[0-9]/.test(peek())) {
        val += advance();
      }
      add('number', val, l, c);
      continue;
    }

    // Identifier or keyword
    if (/[a-zA-Z_]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[a-zA-Z0-9_]/.test(peek())) {
        val += advance();
      }
      const kwType = KEYWORDS.get(val);
      add(kwType || 'ident', val, l, c);
      continue;
    }

    // Skip unknown
    advance();
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// Solidity type → Rúnar type mapping
function mapSolType(name: string): string {
  const typeMap: Record<string, string> = {
    int: 'bigint', uint: 'bigint',
    int256: 'bigint', uint256: 'bigint',
    address: 'Addr', bytes: 'ByteString', bool: 'boolean',
  };
  return typeMap[name] || name;
}

class SolParser {
  private tokens: Token[];
  private pos = 0;
  private file: string;
  private errors: CompilerDiagnostic[] = [];

  constructor(tokens: Token[], file: string) {
    this.tokens = tokens;
    this.file = file;
  }

  private current(): Token { return this.tokens[this.pos] ?? this.tokens[this.tokens.length - 1]!; }
  private peek(): Token { return this.current(); }
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
    // Skip pragma
    if (this.peek().type === 'pragma') {
      while (this.current().type !== ';' && this.current().type !== 'eof') this.advance();
      if (this.current().type === ';') this.advance();
    }

    // Parse contract
    this.expect('contract');
    const nameToken = this.expect('ident');
    const contractName = nameToken.value;

    // Optional: is SmartContract / StatefulSmartContract
    let parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
    if (this.match('is')) {
      const parent = this.expect('ident').value;
      if (parent === 'StatefulSmartContract') parentClass = 'StatefulSmartContract';
    }

    this.expect('{');

    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];
    let constructorNode: MethodNode | null = null;

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      if (this.current().type === 'constructor') {
        constructorNode = this.parseConstructor(properties);
      } else if (this.current().type === 'function') {
        methods.push(this.parseFunction());
      } else {
        // Property declaration: Type [immutable] name;
        properties.push(this.parseProperty());
      }
    }
    this.expect('}');

    // Build constructor if not explicitly defined
    if (!constructorNode) {
      const loc = { file: this.file, line: 1, column: 1 };
      // Only non-initialized properties become constructor params
      const uninitProps = properties.filter(p => !p.initializer);
      constructorNode = {
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
    }

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

  private parseProperty(): PropertyNode {
    const location = this.loc();
    // Type [immutable] name [= value];
    const typeName = this.parseType();
    let readonly = false;
    if (this.current().type === 'immutable') {
      this.advance();
      readonly = true;
    }
    const name = this.expect('ident').value;

    // Optional initializer: = value
    let initializer: Expression | undefined;
    if (this.current().type === '=') {
      this.advance();
      initializer = this.parseExpression();
    }

    this.expect(';');
    return {
      kind: 'property',
      name,
      type: typeName,
      readonly,
      initializer,
      sourceLocation: location,
    };
  }

  private parseType(): TypeNode {
    const name = this.expect('ident').value;
    const mapped = mapSolType(name);
    // Check for FixedArray<T, N> — would be Type[N] in Solidity style
    if (this.current().type === '[') {
      this.advance();
      const length = parseInt(this.expect('number').value, 10);
      this.expect(']');
      return {
        kind: 'fixed_array_type',
        element: this.makePrimitiveOrCustom(mapped),
        length,
      };
    }
    return this.makePrimitiveOrCustom(mapped);
  }

  private makePrimitiveOrCustom(name: string): TypeNode {
    const primitives = new Set([
      'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
      'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point', 'void',
    ]);
    if (primitives.has(name)) {
      return { kind: 'primitive_type', name: name as PrimitiveTypeName };
    }
    return { kind: 'custom_type', name };
  }

  private parseConstructor(_properties: PropertyNode[]): MethodNode {
    const location = this.loc();
    this.expect('constructor');
    this.expect('(');
    const params: ParamNode[] = [];
    while (this.current().type !== ')' && this.current().type !== 'eof') {
      const pType = this.parseType();
      // Param names in Solidity can start with _
      const pName = this.expect('ident').value.replace(/^_/, '');
      params.push({ kind: 'param', name: pName, type: pType });
      if (this.current().type === ',') this.advance();
    }
    this.expect(')');
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    // Inject super(...) as first statement
    const superCall: Statement = {
      kind: 'expression_statement',
      expression: {
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'super' },
        args: params.map(p => ({ kind: 'identifier' as const, name: p.name })),
      },
      sourceLocation: location,
    };

    // Build a rename map for _-prefixed param names (e.g., _count → count)
    const renameMap = new Map<string, string>();
    for (const p of params) {
      const original = '_' + p.name;
      if (original !== p.name) renameMap.set(original, p.name);
    }

    // Convert bare identifier assignments (e.g., `pubKeyHash = _pk`) to
    // property access (this.pubKeyHash = pk) to match validator expectations,
    // and rename _-prefixed identifiers to their stripped versions
    const propNames = new Set(_properties.map(p => p.name));
    const fixedBody = body.map(stmt => {
      const renamed = renameMap.size > 0 ? renameIdentifiers(stmt, renameMap) : stmt;
      if (renamed.kind === 'assignment' && renamed.target.kind === 'identifier' && propNames.has(renamed.target.name)) {
        return { ...renamed, target: { kind: 'property_access' as const, property: renamed.target.name } };
      }
      return renamed;
    });

    return {
      kind: 'method',
      name: 'constructor',
      params,
      body: [superCall, ...fixedBody],
      visibility: 'public',
      sourceLocation: location,
    };
  }

  private parseFunction(): MethodNode {
    const location = this.loc();
    this.expect('function');
    const name = this.expect('ident').value;
    this.expect('(');
    const params: ParamNode[] = [];
    while (this.current().type !== ')' && this.current().type !== 'eof') {
      const pType = this.parseType();
      const pName = this.expect('ident').value;
      params.push({ kind: 'param', name: pName, type: pType });
      if (this.current().type === ',') this.advance();
    }
    this.expect(')');

    // Visibility modifier
    let visibility: 'public' | 'private' = 'private';
    if (this.current().type === 'public') { this.advance(); visibility = 'public'; }
    else if (this.current().type === 'private') { this.advance(); }

    // Return type (skip)
    if (this.current().type === 'ident' && this.current().value === 'returns') {
      this.advance();
      this.expect('(');
      while (this.current().type !== ')' && this.current().type !== 'eof') this.advance();
      this.expect(')');
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

    // require(expr); -> assert(expr)
    if (this.current().type === 'require') {
      this.advance();
      this.expect('(');
      const expr = this.parseExpression();
      this.expect(')');
      this.expect(';');
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

    // Variable declaration: let Type name = expr;
    if (this.current().type === 'let') {
      this.advance();
      const varType = this.parseType();
      const varName = this.expect('ident').value;
      this.expect('=');
      const init = this.parseExpression();
      this.expect(';');
      return {
        kind: 'variable_decl',
        name: varName,
        type: varType,
        mutable: true,
        init,
        sourceLocation: location,
      };
    }

    // Type name = expr; (const-like)
    if (this.current().type === 'ident' && this.tokens[this.pos + 1]?.type === 'ident'
        && this.tokens[this.pos + 2]?.type === '=') {
      const varType = this.parseType();
      const varName = this.expect('ident').value;
      this.expect('=');
      const init = this.parseExpression();
      this.expect(';');
      return {
        kind: 'variable_decl',
        name: varName,
        type: varType,
        mutable: false,
        init,
        sourceLocation: location,
      };
    }

    // if
    if (this.current().type === 'if') {
      return this.parseIfStatement();
    }

    // for
    if (this.current().type === 'for') {
      return this.parseForStatement();
    }

    // return
    if (this.current().type === 'return') {
      this.advance();
      const value = this.current().type !== ';' ? this.parseExpression() : undefined;
      this.expect(';');
      return { kind: 'return_statement', value, sourceLocation: location };
    }

    // Expression statement
    const expr = this.parseExpression();

    // Check for assignment
    if (this.current().type === '=') {
      this.advance();
      const value = this.parseExpression();
      this.expect(';');
      return { kind: 'assignment', target: expr, value, sourceLocation: location };
    }

    // Check for ++/--
    if (this.current().type === '++') {
      this.advance();
      this.expect(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }
    if (this.current().type === '--') {
      this.advance();
      this.expect(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }

    // Compound assignments
    if (this.current().type === '+=') {
      this.advance();
      const rhs = this.parseExpression();
      this.expect(';');
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '+', left: expr, right: rhs },
        sourceLocation: location,
      };
    }
    if (this.current().type === '-=') {
      this.advance();
      const rhs = this.parseExpression();
      this.expect(';');
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '-', left: expr, right: rhs },
        sourceLocation: location,
      };
    }

    this.expect(';');
    return { kind: 'expression_statement', expression: expr, sourceLocation: location };
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

  private parseForStatement(): Statement {
    const location = this.loc();
    this.expect('for');
    this.expect('(');

    // Init: Type name = expr
    const initType = this.parseType();
    const initName = this.expect('ident').value;
    this.expect('=');
    const initValue = this.parseExpression();
    this.expect(';');

    const condition = this.parseExpression();
    this.expect(';');

    // Update
    const updateExpr = this.parseExpression();
    let update: Statement;
    if (this.current().type === '++') {
      this.advance();
      update = {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand: updateExpr, prefix: false },
        sourceLocation: location,
      };
    } else if (this.current().type === '--') {
      this.advance();
      update = {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand: updateExpr, prefix: false },
        sourceLocation: location,
      };
    } else {
      update = { kind: 'expression_statement', expression: updateExpr, sourceLocation: location };
    }

    this.expect(')');
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    return {
      kind: 'for_statement',
      init: {
        kind: 'variable_decl',
        name: initName,
        type: initType,
        mutable: true,
        init: initValue,
        sourceLocation: location,
      },
      condition,
      update,
      body,
      sourceLocation: location,
    };
  }

  // Expression parsing with precedence climbing
  private parseExpression(): Expression {
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
    if (this.current().type === '!') {
      this.advance();
      return { kind: 'unary_expr', op: '!', operand: this.parseUnary() };
    }
    if (this.current().type === '-') {
      this.advance();
      return { kind: 'unary_expr', op: '-', operand: this.parseUnary() };
    }
    if (this.current().type === '~') {
      this.advance();
      return { kind: 'unary_expr', op: '~', operand: this.parseUnary() };
    }
    if (this.current().type === '++') {
      this.advance();
      return { kind: 'increment_expr', operand: this.parsePostfix(), prefix: true };
    }
    if (this.current().type === '--') {
      this.advance();
      return { kind: 'decrement_expr', operand: this.parsePostfix(), prefix: true };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expression {
    let expr = this.parsePrimary();
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
        const prop = this.expect('ident').value;
        // this.property -> PropertyAccessExpr
        if (expr.kind === 'identifier' && expr.name === 'this') {
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

  private parsePrimary(): Expression {
    const t = this.current();

    if (t.type === 'number') {
      this.advance();
      return { kind: 'bigint_literal', value: BigInt(t.value) };
    }
    if (t.type === 'hexstring') {
      this.advance();
      return { kind: 'bytestring_literal', value: t.value };
    }
    if (t.type === 'true') {
      this.advance();
      return { kind: 'bool_literal', value: true };
    }
    if (t.type === 'false') {
      this.advance();
      return { kind: 'bool_literal', value: false };
    }
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
      return { kind: 'identifier', name: t.value };
    }

    this.advance();
    return { kind: 'identifier', name: t.value };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Recursively rename identifiers in a statement tree.
 * Used to fix _-prefixed constructor params in the body.
 */
function renameIdentifiers(stmt: Statement, map: Map<string, string>): Statement {
  function renameExpr(expr: Expression): Expression {
    switch (expr.kind) {
      case 'identifier': {
        const renamed = map.get(expr.name);
        return renamed ? { ...expr, name: renamed } : expr;
      }
      case 'binary_expr':
        return { ...expr, left: renameExpr(expr.left), right: renameExpr(expr.right) };
      case 'unary_expr':
        return { ...expr, operand: renameExpr(expr.operand) };
      case 'call_expr':
        return { ...expr, callee: renameExpr(expr.callee), args: expr.args.map(renameExpr) };
      case 'member_expr':
        return { ...expr, object: renameExpr(expr.object) };
      case 'ternary_expr':
        return { ...expr, condition: renameExpr(expr.condition), consequent: renameExpr(expr.consequent), alternate: renameExpr(expr.alternate) };
      case 'index_access':
        return { ...expr, object: renameExpr(expr.object), index: renameExpr(expr.index) };
      case 'increment_expr':
      case 'decrement_expr':
        return { ...expr, operand: renameExpr(expr.operand) };
      default:
        return expr;
    }
  }

  switch (stmt.kind) {
    case 'variable_decl':
      return { ...stmt, init: renameExpr(stmt.init) };
    case 'assignment':
      return { ...stmt, target: renameExpr(stmt.target), value: renameExpr(stmt.value) };
    case 'expression_statement':
      return { ...stmt, expression: renameExpr(stmt.expression) };
    case 'if_statement':
      return {
        ...stmt,
        condition: renameExpr(stmt.condition),
        then: stmt.then.map(s => renameIdentifiers(s, map)),
        else: stmt.else?.map(s => renameIdentifiers(s, map)),
      };
    case 'for_statement':
      return {
        ...stmt,
        init: renameIdentifiers(stmt.init, map) as typeof stmt.init,
        condition: renameExpr(stmt.condition),
        update: renameIdentifiers(stmt.update, map),
        body: stmt.body.map(s => renameIdentifiers(s, map)),
      };
    case 'return_statement':
      return stmt.value ? { ...stmt, value: renameExpr(stmt.value) } : stmt;
    default:
      return stmt;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseSolSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.sol';
  const tokens = tokenize(source);
  const parser = new SolParser(tokens, file);
  return parser.parse();
}
