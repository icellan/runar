/**
 * Zig contract parser for Rúnar contracts.
 *
 * Parses `.runar.zig` files into the standard Rúnar AST using a hand-written
 * tokenizer and recursive descent parser. The supported contract shape follows
 * the Zig examples in this repository:
 *   - `const runar = @import("runar");`
 *   - `pub const Name = struct { ... };`
 *   - `pub const Contract = runar.SmartContract;`
 *   - `pub const Contract = runar.StatefulSmartContract;`
 *   - Zig struct fields and `pub fn init(...)`
 *   - `pub fn method(self, ...)` and private `fn helper(self, ...)`
 *   - `runar.foo(...)` builtin calls lowered to bare builtin identifiers
 */

import type {
  ContractNode,
  PropertyNode,
  MethodNode,
  ParamNode,
  TypeNode,
  PrimitiveTypeName,
  Statement,
  ForStatement,
  Expression,
  SourceLocation,
  BinaryOp,
} from '../ir/index.js';
import type { ParseResult } from './01-parse.js';
import { ParserCore } from './parser-core.js';
import type { Token } from './parser-core.js';
import { makeDiagnostic } from '../errors.js';

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokenType =
  | 'pub' | 'const' | 'var' | 'fn' | 'struct'
  | 'if' | 'else' | 'for' | 'while' | 'return'
  | 'true' | 'false' | 'void'
  | 'ident' | 'number' | 'string'
  | '(' | ')' | '{' | '}' | '[' | ']'
  | ';' | ',' | '.' | ':' | '@'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '<<' | '>>'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%='
  | 'eof';

interface ZigToken extends Token {
  type: string;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['pub', 'pub'],
  ['const', 'const'],
  ['var', 'var'],
  ['fn', 'fn'],
  ['struct', 'struct'],
  ['if', 'if'],
  ['else', 'else'],
  ['for', 'for'],
  ['while', 'while'],
  ['return', 'return'],
  ['true', 'true'],
  ['false', 'false'],
  ['void', 'void'],
  ['and', '&&'],
  ['or', '||'],
]);

function tokenize(source: string): ZigToken[] {
  const tokens: ZigToken[] = [];
  let pos = 0;
  let line = 1;
  let column = 1;

  function advance(): string {
    const ch = source[pos++]!;
    if (ch === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
    return ch;
  }

  function peek(): string {
    return source[pos] || '';
  }

  function peekN(n: number): string {
    return source[pos + n] || '';
  }

  function add(type: TokenType, value: string, tokenLine: number, tokenColumn: number): void {
    tokens.push({ type, value, line: tokenLine, column: tokenColumn });
  }

  while (pos < source.length) {
    const ch = peek();
    const tokenLine = line;
    const tokenColumn = column;

    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      advance();
      continue;
    }

    if (ch === '/' && peekN(1) === '/') {
      while (pos < source.length && peek() !== '\n') advance();
      continue;
    }

    if (ch === '/' && peekN(1) === '*') {
      advance();
      advance();
      while (pos < source.length - 1) {
        if (peek() === '*' && peekN(1) === '/') {
          advance();
          advance();
          break;
        }
        advance();
      }
      continue;
    }

    if (ch === '=' && peekN(1) === '=') { advance(); advance(); add('==', '==', tokenLine, tokenColumn); continue; }
    if (ch === '!' && peekN(1) === '=') { advance(); advance(); add('!=', '!=', tokenLine, tokenColumn); continue; }
    if (ch === '<' && peekN(1) === '=') { advance(); advance(); add('<=', '<=', tokenLine, tokenColumn); continue; }
    if (ch === '>' && peekN(1) === '=') { advance(); advance(); add('>=', '>=', tokenLine, tokenColumn); continue; }
    if (ch === '<' && peekN(1) === '<') { advance(); advance(); add('<<', '<<', tokenLine, tokenColumn); continue; }
    if (ch === '>' && peekN(1) === '>') { advance(); advance(); add('>>', '>>', tokenLine, tokenColumn); continue; }
    if (ch === '&' && peekN(1) === '&') { advance(); advance(); add('&&', '&&', tokenLine, tokenColumn); continue; }
    if (ch === '|' && peekN(1) === '|') { advance(); advance(); add('||', '||', tokenLine, tokenColumn); continue; }
    if (ch === '+' && peekN(1) === '=') { advance(); advance(); add('+=', '+=', tokenLine, tokenColumn); continue; }
    if (ch === '-' && peekN(1) === '=') { advance(); advance(); add('-=', '-=', tokenLine, tokenColumn); continue; }
    if (ch === '*' && peekN(1) === '=') { advance(); advance(); add('*=', '*=', tokenLine, tokenColumn); continue; }
    if (ch === '/' && peekN(1) === '=') { advance(); advance(); add('/=', '/=', tokenLine, tokenColumn); continue; }
    if (ch === '%' && peekN(1) === '=') { advance(); advance(); add('%=', '%=', tokenLine, tokenColumn); continue; }

    const singles = '(){}[];,.:@+-*/%<>=&|^~!';
    if (singles.includes(ch)) {
      advance();
      add(ch as TokenType, ch, tokenLine, tokenColumn);
      continue;
    }

    if (ch === '"') {
      let value = '';
      advance();
      while (pos < source.length && peek() !== '"') {
        if (peek() === '\\') {
          advance();
          value += advance();
        } else {
          value += advance();
        }
      }
      if (pos < source.length) advance();
      add('string', value, tokenLine, tokenColumn);
      continue;
    }

    if (/[0-9]/.test(ch)) {
      let value = '';
      while (pos < source.length && /[0-9_]/.test(peek())) {
        value += advance();
      }
      add('number', value.replace(/_/g, ''), tokenLine, tokenColumn);
      continue;
    }

    if (/[A-Za-z_]/.test(ch)) {
      let value = '';
      while (pos < source.length && /[A-Za-z0-9_]/.test(peek())) {
        value += advance();
      }
      add(KEYWORDS.get(value) || 'ident', value, tokenLine, tokenColumn);
      continue;
    }

    advance();
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

const ZIG_TYPE_MAP: Record<string, string> = {
  i8: 'bigint',
  i16: 'bigint',
  i32: 'bigint',
  i64: 'bigint',
  i128: 'bigint',
  isize: 'bigint',
  u8: 'bigint',
  u16: 'bigint',
  u32: 'bigint',
  u64: 'bigint',
  u128: 'bigint',
  usize: 'bigint',
  comptime_int: 'bigint',
  bool: 'boolean',
  void: 'void',
  Bigint: 'bigint',
  ByteString: 'ByteString',
  PubKey: 'PubKey',
  Sig: 'Sig',
  Sha256: 'Sha256',
  Ripemd160: 'Ripemd160',
  Addr: 'Addr',
  SigHashPreimage: 'SigHashPreimage',
  RabinSig: 'RabinSig',
  RabinPubKey: 'RabinPubKey',
  Point: 'Point',
};

const PRIMITIVE_TYPES = new Set<PrimitiveTypeName>([
  'bigint',
  'boolean',
  'ByteString',
  'PubKey',
  'Sig',
  'Sha256',
  'Ripemd160',
  'Addr',
  'SigHashPreimage',
  'RabinSig',
  'RabinPubKey',
  'Point',
  'void',
]);

function mapZigType(name: string): string {
  return ZIG_TYPE_MAP[name] || name;
}

function makePrimitiveOrCustom(name: string): TypeNode {
  if (PRIMITIVE_TYPES.has(name as PrimitiveTypeName)) {
    return { kind: 'primitive_type', name: name as PrimitiveTypeName };
  }
  return { kind: 'custom_type', name };
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

interface ParsedType {
  type: TypeNode;
  rawName: string;
  readonly?: boolean;
}

class ZigParser extends ParserCore<ZigToken> {
  private contractName = 'UnnamedContract';
  private parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
  private properties: PropertyNode[] = [];
  private methods: MethodNode[] = [];
  private constructorNode: MethodNode | null = null;
  private selfNames = new Set<string>();
  private statefulContextNames = new Set<string>();

  parse(): ParseResult {
    this.skipRunarImport();

    while (this.current().type !== 'eof') {
      if (this.current().type === 'pub' &&
          this.tokens[this.pos + 1]?.type === 'const' &&
          this.tokens[this.pos + 3]?.type === '=') {
        const maybeContract = this.tryParseContractDecl();
        if (maybeContract) {
          return { contract: maybeContract, errors: this.errors };
        }
      }
      this.advance();
    }

    this.errors.push(makeDiagnostic(
      'Expected Zig contract declaration `pub const Name = struct { ... };`',
      'error',
      { file: this.file, line: 1, column: 1 },
    ));

    return {
      contract: {
        kind: 'contract',
        name: this.contractName,
        parentClass: this.parentClass,
        properties: this.properties,
        constructor: this.createFallbackConstructor(),
        methods: this.methods,
        sourceFile: this.file,
      },
      errors: this.errors,
    };
  }

  private skipRunarImport(): void {
    const start = this.pos;
    if (this.current().type === 'const') {
      this.advance();
      if (this.current().type === 'ident' && this.current().value === 'runar') {
        this.advance();
        if (this.match('=')) {
          if (this.match('@') &&
              this.current().type === 'ident' &&
              this.current().value === 'import') {
            this.advance();
            this.expect('(');
            if (this.current().type === 'string') this.advance();
            this.expect(')');
            if (this.current().type === ';') this.advance();
            return;
          }
        }
      }
    }

    this.pos = start;
    this.errors.push(makeDiagnostic(
      'Expected `const runar = @import("runar");` at the top of the file',
      'error',
      { file: this.file, line: 1, column: 1 },
    ));
  }

  private tryParseContractDecl(): ContractNode | null {
    const start = this.pos;

    this.expect('pub');
    this.expect('const');
    const nameToken = this.expect('ident');
    if (this.current().type !== '=') {
      this.pos = start;
      return null;
    }

    this.expect('=');
    if (this.current().type !== 'struct') {
      this.pos = start;
      return null;
    }

    this.contractName = nameToken.value;
    this.parentClass = 'SmartContract';
    this.properties = [];
    this.methods = [];
    this.constructorNode = null;

    this.expect('struct');
    this.expect('{');

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      if (this.current().type === 'pub' &&
          this.tokens[this.pos + 1]?.type === 'const' &&
          this.tokens[this.pos + 2]?.type === 'ident' &&
          this.tokens[this.pos + 2]?.value === 'Contract') {
        this.parseContractMarker();
        continue;
      }

      if (this.current().type === 'pub' && this.tokens[this.pos + 1]?.type === 'fn') {
        const method = this.parseMethod(true);
        if (method) this.methods.push(method);
        continue;
      }

      if (this.current().type === 'fn') {
        const method = this.parseMethod(false);
        if (method) this.methods.push(method);
        continue;
      }

      if (this.current().type === 'ident') {
        this.properties.push(this.parseField());
        continue;
      }

      this.advance();
    }

    this.expect('}');
    if (this.current().type === ';') this.advance();

    this.properties = this.properties.map((property) => ({
      ...property,
      readonly: this.parentClass === 'SmartContract' || property.readonly || property.initializer === undefined,
    }));

    const methodNames = new Set(this.methods.map(method => method.name));
    this.methods = this.methods.map(method => this.rewriteBareMethodCalls(method, methodNames));
    if (this.constructorNode) {
      this.constructorNode = this.rewriteBareMethodCalls(this.constructorNode, methodNames);
    }

    const contract: ContractNode = {
      kind: 'contract',
      name: this.contractName,
      parentClass: this.parentClass,
      properties: this.properties,
      constructor: this.constructorNode ?? this.createFallbackConstructor(),
      methods: this.methods,
      sourceFile: this.file,
    };

    return contract;
  }

  private parseContractMarker(): void {
    this.expect('pub');
    this.expect('const');
    this.expect('ident');
    this.expect('=');

    if (this.current().type === 'ident' && this.current().value === 'runar') {
      this.advance();
      this.expect('.');
      const parent = this.expect('ident').value;
      this.parentClass = parent === 'StatefulSmartContract'
        ? 'StatefulSmartContract'
        : 'SmartContract';
    }

    if (this.current().type === ';') this.advance();
  }

  private parseField(): PropertyNode {
    const sourceLocation = this.loc();
    const name = this.expect('ident').value;
    this.expect(':');
    const parsedType = this.parseType();
    let initializer: Expression | undefined;

    if (this.current().type === '=') {
      this.advance();
      initializer = this.parseExpression();
    }

    if (this.current().type === ',') this.advance();

    return {
      kind: 'property',
      name,
      type: parsedType.type,
      readonly: parsedType.readonly ?? false,
      initializer,
      sourceLocation,
    };
  }

  private parseMethod(isPublic: boolean): MethodNode | null {
    const sourceLocation = this.loc();
    if (isPublic) this.expect('pub');
    this.expect('fn');
    const name = this.expect('ident').value;
    const { params, receiverName, statefulContextNames } = this.parseParamList();

    if (this.current().type !== '{') {
      this.parseType();
    }

    const previousSelfNames = this.selfNames;
    const previousStatefulContextNames = this.statefulContextNames;
    this.selfNames = receiverName ? new Set([receiverName]) : new Set();
    this.statefulContextNames = new Set(statefulContextNames);

    if (name === 'init') {
      this.constructorNode = this.parseConstructor(sourceLocation, params);
      this.selfNames = previousSelfNames;
      this.statefulContextNames = previousStatefulContextNames;
      return null;
    }

    const body = this.parseBlockStatements();
    this.selfNames = previousSelfNames;
    this.statefulContextNames = previousStatefulContextNames;

    return {
      kind: 'method',
      name,
      params,
      body,
      visibility: isPublic ? 'public' : 'private',
      sourceLocation,
    };
  }

  private parseConstructor(sourceLocation: SourceLocation, params: ParamNode[]): MethodNode {
    const body = this.parseConstructorBody(params);
    return {
      kind: 'method',
      name: 'constructor',
      params,
      body,
      visibility: 'public',
      sourceLocation,
    };
  }

  private parseParamList(): {
    params: ParamNode[];
    receiverName: string | null;
    statefulContextNames: Set<string>;
  } {
    this.expect('(');
    const params: ParamNode[] = [];
    let receiverName: string | null = null;
    const statefulContextNames = new Set<string>();
    let index = 0;

    while (this.current().type !== ')' && this.current().type !== 'eof') {
      const paramName = this.expect('ident').value;
      this.expect(':');
      const parsedType = this.parseParamType();
      const isReceiver = index === 0 && parsedType.rawName === this.contractName;

      if (isReceiver) {
        receiverName = paramName;
      } else {
        if (parsedType.rawName === 'StatefulContext') {
          statefulContextNames.add(paramName);
        }
        params.push({
          kind: 'param',
          name: paramName,
          type: parsedType.type,
        });
      }

      index++;
      if (this.current().type === ',') this.advance();
    }

    this.expect(')');
    return { params, receiverName, statefulContextNames };
  }

  private parseParamType(): ParsedType {
    while (this.current().type === '*' || this.current().type === '&') {
      this.advance();
    }
    if (this.current().type === 'const') this.advance();
    return this.parseType();
  }

  private parseType(): ParsedType {
    if (this.current().type === '[') {
      this.advance();
      const lengthToken = this.expect('number');
      const length = Number.parseInt(lengthToken.value, 10);
      this.expect(']');
      const element = this.parseType();
      return {
        type: { kind: 'fixed_array_type', element: element.type, length: Number.isFinite(length) ? length : 0 },
        rawName: element.rawName,
      };
    }

    if (this.current().type === 'ident' && this.current().value === 'runar' &&
        this.tokens[this.pos + 1]?.type === '.') {
      this.advance();
      this.expect('.');
      const name = this.expect('ident').value;
      if (name === 'Readonly' && this.current().type === '(') {
        this.expect('(');
        const inner = this.parseType();
        this.expect(')');
        return { ...inner, readonly: true };
      }
      const mapped = mapZigType(name);
      return { type: makePrimitiveOrCustom(mapped), rawName: name };
    }

    if (this.current().type === 'void') {
      this.advance();
      return { type: { kind: 'primitive_type', name: 'void' }, rawName: 'void' };
    }

    if (this.current().type === 'ident') {
      const name = this.advance().value;
      const mapped = mapZigType(name);
      return { type: makePrimitiveOrCustom(mapped), rawName: name };
    }

    const fallback = this.advance();
    return { type: { kind: 'custom_type', name: 'unknown' }, rawName: fallback.value || 'unknown' };
  }

  private parseBlockStatements(): Statement[] {
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      const statement = this.parseStatement();
      if (statement) {
        // Merge `var i = 0; while (i < N) : (i += 1) { ... }` into a single ForStatement
        const lastStmt = body.length > 0 ? body[body.length - 1] : undefined;
        const loopInitName = statement.kind === 'for_statement'
          ? this.getLoopUpdateTargetName(statement)
          : null;
        if (statement.kind === 'for_statement' &&
            (statement as ForStatement).init.name === '__while_no_init' &&
            lastStmt?.kind === 'variable_decl' &&
            loopInitName === lastStmt.name) {
          body.pop();
          (statement as ForStatement).init = lastStmt as any;
        }
        body.push(statement);
      }
    }
    this.expect('}');
    return body;
  }

  private getLoopUpdateTargetName(stmt: ForStatement): string | null {
    if (stmt.update.kind === 'assignment' && stmt.update.target.kind === 'identifier') {
      return stmt.update.target.name;
    }
    if (stmt.update.kind === 'expression_statement' && stmt.update.expression.kind === 'identifier') {
      return stmt.update.expression.name;
    }
    return null;
  }

  private parseConstructorBody(params: ParamNode[]): Statement[] {
    this.expect('{');
    const body: Statement[] = [this.createSuperCall(params)];
    let foundReturnStruct = false;

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      if (this.current().type === 'return' &&
          this.tokens[this.pos + 1]?.type === '.' &&
          this.tokens[this.pos + 2]?.type === '{') {
        this.advance();
        body.push(...this.parseStructReturnAssignments());
        foundReturnStruct = true;
        if (this.current().type === ';') this.advance();
        continue;
      }

      const statement = this.parseStatement();
      if (statement) body.push(statement);
    }

    this.expect('}');

    if (!foundReturnStruct) {
      for (const property of this.properties) {
        if (params.some(param => param.name === property.name)) {
          body.push(this.createPropertyAssignment(property.name, { kind: 'identifier', name: property.name }));
        }
      }
    }

    return body;
  }

  private parseStructReturnAssignments(): Statement[] {
    const assignments: Statement[] = [];
    this.expect('.');
    this.expect('{');

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      if (this.current().type === '.') this.advance();
      const field = this.expect('ident').value;
      this.expect('=');
      const value = this.parseExpression();
      assignments.push(this.createPropertyAssignment(field, value));
      if (this.current().type === ',') this.advance();
    }

    this.expect('}');
    return assignments;
  }

  private parseStatement(): Statement | null {
    const sourceLocation = this.loc();

    if (this.current().type === 'return') {
      this.advance();
      let value: Expression | undefined;
      if (this.current().type !== ';') {
        value = this.parseExpression();
      }
      if (this.current().type === ';') this.advance();
      return { kind: 'return_statement', value, sourceLocation };
    }

    if (this.current().type === 'if') {
      return this.parseIfStatement();
    }

    if (this.current().type === 'const' || this.current().type === 'var') {
      return this.parseVariableDecl();
    }

    if (this.current().type === 'ident' &&
        this.current().value === '_' &&
        this.tokens[this.pos + 1]?.type === '=') {
      this.advance();
      this.advance();
      this.parseExpression();
      if (this.current().type === ';') this.advance();
      return null;
    }

    if (this.current().type === 'while') {
      return this.parseWhileStatement();
    }

    if (this.current().type === 'for') {
      this.errors.push(makeDiagnostic(
        `Unsupported Zig 'for' syntax — use 'while' loops instead`,
        'error',
        sourceLocation,
      ));
      this.skipUnsupportedBlock();
      return null;
    }

    const target = this.parseExpression();

    if (this.current().type === '=') {
      this.advance();
      const value = this.parseExpression();
      if (this.current().type === ';') this.advance();
      return { kind: 'assignment', target, value, sourceLocation };
    }

    const compoundOp = this.parseCompoundAssignmentOperator();
    if (compoundOp) {
      const rhs = this.parseExpression();
      if (this.current().type === ';') this.advance();
      return {
        kind: 'assignment',
        target,
        value: { kind: 'binary_expr', op: compoundOp, left: target, right: rhs },
        sourceLocation,
      };
    }

    if (this.current().type === ';') this.advance();
    return { kind: 'expression_statement', expression: target, sourceLocation };
  }

  private parseVariableDecl(): Statement {
    const sourceLocation = this.loc();
    const mutable = this.current().type === 'var';
    this.advance();
    const name = this.expect('ident').value;
    let type: TypeNode | undefined;

    if (this.current().type === ':') {
      this.advance();
      type = this.parseType().type;
    }

    this.expect('=');
    const init = this.parseExpression();
    if (this.current().type === ';') this.advance();

    return {
      kind: 'variable_decl',
      name,
      type,
      mutable,
      init,
      sourceLocation,
    };
  }

  private parseIfStatement(): Statement {
    const sourceLocation = this.loc();
    this.expect('if');
    if (this.current().type === '(') this.advance();
    const condition = this.parseExpression();
    if (this.current().type === ')') this.advance();
    const thenBranch = this.parseBlockStatements();

    let elseBranch: Statement[] | undefined;
    if (this.current().type === 'else') {
      this.advance();
      if (this.current().type === 'if') {
        elseBranch = [this.parseIfStatement()];
      } else {
        elseBranch = this.parseBlockStatements();
      }
    }

    return {
      kind: 'if_statement',
      condition,
      then: thenBranch,
      else: elseBranch,
      sourceLocation,
    };
  }

  /**
   * Parse Zig while loop: `while (condition) : (continue_expr) { body }`
   *
   * Emits a ForStatement. The init is synthesized as `var _while_dummy: i64 = 0`
   * unless `parseBlockStatements` merges the preceding variable decl (see below).
   * The continue expression becomes the update.
   */
  private parseWhileStatement(): Statement {
    const sourceLocation = this.loc();
    this.expect('while');

    // Condition: while (i < 5)
    if (this.current().type === '(') this.advance();
    const condition = this.parseExpression();
    if (this.current().type === ')') this.advance();

    // Continue expression: : (i += 1)
    let update: Statement;
    if (this.current().type === ':') {
      this.advance();
      if (this.current().type === '(') this.advance();
      const updateTarget = this.parseExpression();
      const compoundOp = this.parseCompoundAssignmentOperator();
      if (compoundOp) {
        const rhs = this.parseExpression();
        update = {
          kind: 'assignment',
          target: updateTarget,
          value: { kind: 'binary_expr', op: compoundOp, left: updateTarget, right: rhs },
          sourceLocation,
        };
      } else {
        update = { kind: 'expression_statement', expression: updateTarget, sourceLocation };
      }
      if (this.current().type === ')') this.advance();
    } else {
      // No continue expression — synthesize a no-op
      update = {
        kind: 'expression_statement',
        expression: { kind: 'bigint_literal', value: 0n },
        sourceLocation,
      };
    }

    const body = this.parseBlockStatements();

    // Emit a for_statement. The init will be patched by parseBlockStatements
    // if the preceding statement was a variable_decl for the loop variable.
    return {
      kind: 'for_statement',
      init: {
        kind: 'variable_decl',
        name: '__while_no_init',
        mutable: true,
        init: { kind: 'bigint_literal', value: 0n },
        sourceLocation,
      },
      condition,
      update,
      body,
      sourceLocation,
    } as ForStatement;
  }

  private parseCompoundAssignmentOperator(): BinaryOp | null {
    if (this.current().type === '+=') { this.advance(); return '+'; }
    if (this.current().type === '-=') { this.advance(); return '-'; }
    if (this.current().type === '*=') { this.advance(); return '*'; }
    if (this.current().type === '/=') { this.advance(); return '/'; }
    if (this.current().type === '%=') { this.advance(); return '%'; }
    return null;
  }

  private createSuperCall(params: ParamNode[]): Statement {
    return {
      kind: 'expression_statement',
      expression: {
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'super' },
        args: params.map(param => ({ kind: 'identifier', name: param.name })),
      },
      sourceLocation: { file: this.file, line: 1, column: 1 },
    };
  }

  private createPropertyAssignment(name: string, value: Expression): Statement {
    return {
      kind: 'assignment',
      target: { kind: 'property_access', property: name },
      value,
      sourceLocation: { file: this.file, line: 1, column: 1 },
    };
  }

  private createFallbackConstructor(): MethodNode {
    const params = this.properties
      .filter(property => property.initializer === undefined)
      .map<ParamNode>(property => ({
        kind: 'param',
        name: property.name,
        type: property.type,
      }));

    return {
      kind: 'method',
      name: 'constructor',
      params,
      body: [
        this.createSuperCall(params),
        ...params.map(param => this.createPropertyAssignment(param.name, { kind: 'identifier', name: param.name })),
      ],
      visibility: 'public',
      sourceLocation: { file: this.file, line: 1, column: 1 },
    };
  }

  private skipUnsupportedBlock(): void {
    while (this.current().type !== '{' && this.current().type !== ';' && this.current().type !== 'eof') {
      this.advance();
    }

    if (this.current().type === ';') {
      this.advance();
      return;
    }

    if (this.current().type !== '{') return;

    let depth = 0;
    while (this.current().type !== 'eof') {
      if (this.current().type === '{') depth++;
      if (this.current().type === '}') {
        depth--;
        this.advance();
        if (depth <= 0) break;
        continue;
      }
      this.advance();
    }
  }

  protected parseUnary(): Expression {
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

    let expr = this.parsePrimary();
    expr = this.parsePostfixChain(expr, this.selfNames);
    return expr;
  }

  protected parsePrimary(): Expression {
    const token = this.current();

    if (token.type === '.' && this.tokens[this.pos + 1]?.type === '{') {
      this.advance();
      this.advance();
      const elements: Expression[] = [];
      while (this.current().type !== '}' && this.current().type !== 'eof') {
        elements.push(this.parseExpression());
        if (this.current().type === ',') this.advance();
      }
      this.expect('}');
      return { kind: 'array_literal', elements };
    }

    if (token.type === 'number') {
      this.advance();
      return { kind: 'bigint_literal', value: BigInt(token.value) };
    }

    if (token.type === 'string') {
      this.advance();
      return { kind: 'bytestring_literal', value: token.value };
    }

    if (token.type === 'true') {
      this.advance();
      return { kind: 'bool_literal', value: true };
    }

    if (token.type === 'false') {
      this.advance();
      return { kind: 'bool_literal', value: false };
    }

    if (token.type === '(') {
      this.advance();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }

    if (token.type === '[') {
      this.advance();
      const elements: Expression[] = [];
      while (this.current().type !== ']' && this.current().type !== 'eof') {
        elements.push(this.parseExpression());
        if (this.current().type === ',') this.advance();
      }
      this.expect(']');
      return { kind: 'array_literal', elements };
    }

    // Zig @builtins: @divTrunc(a, b), @mod(a, b), @shlExact(a, b), @shrExact(a, b), @intCast(expr), @truncate(expr)
    if (token.type === '@') {
      this.advance();
      const builtinName = this.expect('ident').value;

      if (
        builtinName === 'divTrunc' ||
        builtinName === 'mod' ||
        builtinName === 'shlExact' ||
        builtinName === 'shrExact'
      ) {
        this.expect('(');
        const left = this.parseExpression();
        this.expect(',');
        const right = this.parseExpression();
        this.expect(')');
        const op: BinaryOp = builtinName === 'divTrunc'
          ? '/'
          : builtinName === 'mod'
            ? '%'
            : builtinName === 'shlExact'
              ? '<<'
              : '>>';
        return { kind: 'binary_expr', op, left, right };
      }

      // @intCast, @truncate, @as — parse and return the inner expression
      if (builtinName === 'intCast' || builtinName === 'truncate' || builtinName === 'as') {
        this.expect('(');
        // @as has a type argument first: @as(i64, expr)
        if (builtinName === 'as') {
          this.parseType(); // skip type
          this.expect(',');
        }
        const inner = this.parseExpression();
        this.expect(')');
        return inner;
      }

      // @import — skip (already handled at top-level)
      if (builtinName === 'import') {
        this.expect('(');
        this.parseExpression();
        this.expect(')');
        return { kind: 'identifier', name: '__import' };
      }

      // @embedFile — treat as a string literal placeholder
      if (builtinName === 'embedFile') {
        this.expect('(');
        const arg = this.parseExpression();
        this.expect(')');
        return arg;
      }

      // Unknown @builtin — preserve call shape but reject it explicitly.
      if (this.current().type === '(') {
        this.advance();
        const args: Expression[] = [];
        args.push(this.parseExpression());
        while (this.current().type === ',') {
          this.advance();
          args.push(this.parseExpression());
        }
        this.expect(')');
        this.errors.push(makeDiagnostic(
          `Unsupported Zig builtin '@${builtinName}'`,
          'error',
          { file: this.file, line: token.line, column: token.column },
        ));
        return {
          kind: 'call_expr',
          callee: { kind: 'identifier', name: builtinName },
          args,
        };
      }

      this.errors.push(makeDiagnostic(
        `Unsupported Zig builtin '@${builtinName}'`,
        'error',
        { file: this.file, line: token.line, column: token.column },
      ));
      return { kind: 'identifier', name: builtinName };
    }

    if (token.type === 'ident') {
      this.advance();

      if (token.value === 'runar' && this.current().type === '.') {
        this.advance();
        const builtin = this.expect('ident').value;
        if (builtin === 'bytesEq' && this.current().type === '(') {
          this.advance();
          const left = this.parseExpression();
          this.expect(',');
          const right = this.parseExpression();
          this.expect(')');
          return { kind: 'binary_expr', op: '===', left, right };
        }
        return { kind: 'identifier', name: builtin };
      }

      return { kind: 'identifier', name: token.value };
    }

    this.advance();
    return { kind: 'identifier', name: token.value || 'unknown' };
  }

  private rewriteBareMethodCalls(method: MethodNode, methodNames: Set<string>): MethodNode {
    const scope = new Set(method.params.map(param => param.name));
    return {
      ...method,
      body: this.rewriteStatements(method.body, methodNames, scope),
    };
  }

  private rewriteStatements(
    statements: Statement[],
    methodNames: Set<string>,
    scope: Set<string>,
  ): Statement[] {
    const rewritten: Statement[] = [];
    const currentScope = new Set(scope);

    for (const statement of statements) {
      const next = this.rewriteStatement(statement, methodNames, currentScope);
      rewritten.push(next);
      if (next.kind === 'variable_decl') {
        currentScope.add(next.name);
      }
    }

    return rewritten;
  }

  private rewriteStatement(
    statement: Statement,
    methodNames: Set<string>,
    scope: Set<string>,
  ): Statement {
    switch (statement.kind) {
      case 'variable_decl':
        return {
          ...statement,
          init: this.rewriteExpression(statement.init, methodNames, scope),
        };
      case 'assignment':
        return {
          ...statement,
          target: this.rewriteExpression(statement.target, methodNames, scope),
          value: this.rewriteExpression(statement.value, methodNames, scope),
        };
      case 'if_statement':
        return {
          ...statement,
          condition: this.rewriteExpression(statement.condition, methodNames, scope),
          then: this.rewriteStatements(statement.then, methodNames, new Set(scope)),
          else: statement.else
            ? this.rewriteStatements(statement.else, methodNames, new Set(scope))
            : undefined,
        };
      case 'for_statement': {
        const loopScope = new Set(scope);
        const init = this.rewriteStatement(statement.init, methodNames, loopScope) as Extract<Statement, { kind: 'variable_decl' }>;
        loopScope.add(init.name);
        return {
          ...statement,
          init,
          condition: this.rewriteExpression(statement.condition, methodNames, loopScope),
          update: this.rewriteStatement(statement.update, methodNames, loopScope),
          body: this.rewriteStatements(statement.body, methodNames, loopScope),
        };
      }
      case 'return_statement':
        return {
          ...statement,
          value: statement.value
            ? this.rewriteExpression(statement.value, methodNames, scope)
            : undefined,
        };
      case 'expression_statement':
        return {
          ...statement,
          expression: this.rewriteExpression(statement.expression, methodNames, scope),
        };
    }
  }

  private rewriteExpression(
    expression: Expression,
    methodNames: Set<string>,
    scope: Set<string>,
  ): Expression {
    switch (expression.kind) {
      case 'call_expr': {
        const callee = expression.callee.kind === 'identifier' &&
            methodNames.has(expression.callee.name) &&
            !scope.has(expression.callee.name)
          ? { kind: 'property_access', property: expression.callee.name } as const
          : this.rewriteExpression(expression.callee, methodNames, scope);
        return {
          ...expression,
          callee,
          args: expression.args.map(arg => this.rewriteExpression(arg, methodNames, scope)),
        };
      }
      case 'binary_expr':
        return {
          ...expression,
          left: this.rewriteExpression(expression.left, methodNames, scope),
          right: this.rewriteExpression(expression.right, methodNames, scope),
        };
      case 'unary_expr':
        return {
          ...expression,
          operand: this.rewriteExpression(expression.operand, methodNames, scope),
        };
      case 'ternary_expr':
        return {
          ...expression,
          condition: this.rewriteExpression(expression.condition, methodNames, scope),
          consequent: this.rewriteExpression(expression.consequent, methodNames, scope),
          alternate: this.rewriteExpression(expression.alternate, methodNames, scope),
        };
      case 'member_expr':
        return {
          ...expression,
          object: this.rewriteExpression(expression.object, methodNames, scope),
        };
      case 'index_access':
        return {
          ...expression,
          object: this.rewriteExpression(expression.object, methodNames, scope),
          index: this.rewriteExpression(expression.index, methodNames, scope),
        };
      case 'increment_expr':
      case 'decrement_expr':
        return {
          ...expression,
          operand: this.rewriteExpression(expression.operand, methodNames, scope),
        };
      case 'array_literal':
        return {
          ...expression,
          elements: expression.elements.map(element => this.rewriteExpression(element, methodNames, scope)),
        };
      case 'identifier':
      case 'property_access':
      case 'bigint_literal':
      case 'bool_literal':
      case 'bytestring_literal':
        return expression;
    }
  }

  protected parsePostfixChain(expr: Expression, selfNames: Set<string>): Expression {
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
        const prop = this.current().value;
        this.advance();
        if (expr.kind === 'identifier' && selfNames.has(expr.name)) {
          expr = { kind: 'property_access', property: prop };
        } else if (
          expr.kind === 'identifier' &&
          this.statefulContextNames.has(expr.name) &&
          (prop === 'txPreimage' || prop === 'getStateScript' || prop === 'addOutput' || prop === 'addRawOutput')
        ) {
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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseZigSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.zig';
  const tokens = tokenize(source);
  const parser = new ZigParser(tokens, file);
  return parser.parse();
}
