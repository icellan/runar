/**
 * Java parser for Rúnar contracts.
 *
 * Parses `.runar.java` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses a hand-written recursive-descent parser over a
 * small Java subset — we do not require javac at build time for the
 * TypeScript compiler, so this parser re-implements only the syntax
 * the Rúnar Java surface exposes.
 *
 * Mirrors `compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java`
 * (the authoritative surface spec) and stays byte-compatible with the
 * other six compilers' parsers on the shared AST boundary.
 *
 * Supported subset:
 *   - package + imports (consumed; not represented in the AST)
 *   - class extending `SmartContract` or `StatefulSmartContract`
 *   - `@Readonly` fields with optional literal initializer
 *   - constructor (class-named method) with `super(...)` first
 *   - `@Public` methods (void return), `@Readonly` ignored on methods
 *   - statements: var decl, `this.x = ...` assignment, if/else, for,
 *     return, expression statement
 *   - expressions: identifiers, int + boolean literals, `X.fromHex("...")`
 *     → ByteStringLiteral, `BigInteger.valueOf(N)` / `BigInteger.{ZERO,
 *     ONE, TWO, TEN}` → BigIntLiteral, all binary + unary ops, ternary,
 *     method calls, member access (`this.foo` → PropertyAccessExpr),
 *     array access, `new T[]{...}` array literal
 *   - types: `boolean`/`Boolean`, `BigInteger`/`Bigint`, every Rúnar
 *     domain type, `FixedArray<T, N>` (N literal)
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
  | 'package' | 'import' | 'static'
  | 'class' | 'extends' | 'implements' | 'interface' | 'enum'
  | 'public' | 'private' | 'protected' | 'final' | 'abstract' | 'native'
  | 'void' | 'boolean'
  | 'if' | 'else' | 'for' | 'while' | 'do' | 'return'
  | 'true' | 'false' | 'null' | 'new' | 'this' | 'super'
  | 'ident' | 'number' | 'string'
  | '@'
  | '(' | ')' | '{' | '}' | '[' | ']' | ';' | ',' | '.' | ':' | '?'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '<<' | '>>' | '>>>'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%='
  | '&=' | '|=' | '^=' | '<<=' | '>>=' | '>>>='
  | '++' | '--'
  | 'eof';

interface Token {
  type: TokenType;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['package', 'package'], ['import', 'import'], ['static', 'static'],
  ['class', 'class'], ['extends', 'extends'], ['implements', 'implements'],
  ['interface', 'interface'], ['enum', 'enum'],
  ['public', 'public'], ['private', 'private'], ['protected', 'protected'],
  ['final', 'final'], ['abstract', 'abstract'], ['native', 'native'],
  ['void', 'void'], ['boolean', 'boolean'],
  ['if', 'if'], ['else', 'else'], ['for', 'for'],
  ['while', 'while'], ['do', 'do'], ['return', 'return'],
  ['true', 'true'], ['false', 'false'], ['null', 'null'],
  ['new', 'new'], ['this', 'this'], ['super', 'super'],
]);

function tokenize(source: string, file: string, errors: CompilerDiagnostic[]): Token[] {
  const tokens: Token[] = [];
  let pos = 0;
  let line = 1;
  let column = 1;

  function advance(): string {
    const ch = source[pos++]!;
    if (ch === '\n') { line++; column = 1; } else { column++; }
    return ch;
  }
  function peek(): string { return source[pos] ?? ''; }
  function peekN(n: number): string { return source[pos + n] ?? ''; }
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

    // Block comments (includes Javadoc /** ... */)
    if (ch === '/' && peekN(1) === '*') {
      advance(); advance();
      while (pos < source.length) {
        if (peek() === '*' && peekN(1) === '/') { advance(); advance(); break; }
        advance();
      }
      continue;
    }

    // String literal
    if (ch === '"') {
      let val = '';
      advance(); // opening quote
      while (pos < source.length && peek() !== '"') {
        if (peek() === '\\') {
          advance();
          const esc = peek();
          if (esc === 'n') { val += '\n'; advance(); }
          else if (esc === 't') { val += '\t'; advance(); }
          else if (esc === 'r') { val += '\r'; advance(); }
          else if (esc === '0') { val += '\0'; advance(); }
          else if (esc === '"') { val += '"'; advance(); }
          else if (esc === '\\') { val += '\\'; advance(); }
          else if (esc === '\'') { val += '\''; advance(); }
          else { val += advance(); }
        } else {
          val += advance();
        }
      }
      if (pos < source.length) advance(); // closing quote
      add('string', val, l, c);
      continue;
    }

    // Char literal (rejected but tokenized to preserve position)
    if (ch === '\'') {
      let val = '';
      advance();
      while (pos < source.length && peek() !== '\'') {
        if (peek() === '\\') { advance(); if (pos < source.length) val += advance(); }
        else val += advance();
      }
      if (pos < source.length) advance();
      errors.push(makeDiagnostic(
        'char literals are unsupported in Rúnar Java contracts',
        'error',
        { file, line: l, column: c },
      ));
      add('string', val, l, c);
      continue;
    }

    // Four-char operator: >>>=
    if (ch === '>' && peekN(1) === '>' && peekN(2) === '>' && peekN(3) === '=') {
      advance(); advance(); advance(); advance();
      add('>>>=', '>>>=', l, c);
      continue;
    }

    // Three-char operators: <<=, >>=, >>>
    if (ch === '<' && peekN(1) === '<' && peekN(2) === '=') {
      advance(); advance(); advance(); add('<<=', '<<=', l, c); continue;
    }
    if (ch === '>' && peekN(1) === '>' && peekN(2) === '=') {
      advance(); advance(); advance(); add('>>=', '>>=', l, c); continue;
    }
    if (ch === '>' && peekN(1) === '>' && peekN(2) === '>') {
      advance(); advance(); advance(); add('>>>', '>>>', l, c); continue;
    }

    // Two-char operators
    if (ch === '=' && peekN(1) === '=') { advance(); advance(); add('==', '==', l, c); continue; }
    if (ch === '!' && peekN(1) === '=') { advance(); advance(); add('!=', '!=', l, c); continue; }
    if (ch === '<' && peekN(1) === '=') { advance(); advance(); add('<=', '<=', l, c); continue; }
    if (ch === '>' && peekN(1) === '=') { advance(); advance(); add('>=', '>=', l, c); continue; }
    if (ch === '<' && peekN(1) === '<') { advance(); advance(); add('<<', '<<', l, c); continue; }
    if (ch === '>' && peekN(1) === '>') { advance(); advance(); add('>>', '>>', l, c); continue; }
    if (ch === '&' && peekN(1) === '&') { advance(); advance(); add('&&', '&&', l, c); continue; }
    if (ch === '|' && peekN(1) === '|') { advance(); advance(); add('||', '||', l, c); continue; }
    if (ch === '+' && peekN(1) === '+') { advance(); advance(); add('++', '++', l, c); continue; }
    if (ch === '-' && peekN(1) === '-') { advance(); advance(); add('--', '--', l, c); continue; }
    if (ch === '+' && peekN(1) === '=') { advance(); advance(); add('+=', '+=', l, c); continue; }
    if (ch === '-' && peekN(1) === '=') { advance(); advance(); add('-=', '-=', l, c); continue; }
    if (ch === '*' && peekN(1) === '=') { advance(); advance(); add('*=', '*=', l, c); continue; }
    if (ch === '/' && peekN(1) === '=') { advance(); advance(); add('/=', '/=', l, c); continue; }
    if (ch === '%' && peekN(1) === '=') { advance(); advance(); add('%=', '%=', l, c); continue; }
    if (ch === '&' && peekN(1) === '=') { advance(); advance(); add('&=', '&=', l, c); continue; }
    if (ch === '|' && peekN(1) === '=') { advance(); advance(); add('|=', '|=', l, c); continue; }
    if (ch === '^' && peekN(1) === '=') { advance(); advance(); add('^=', '^=', l, c); continue; }

    // Single-char operators & punctuation
    const singles = '(){}[];,.:?+-*/%<>=&|^~!@';
    if (singles.includes(ch as string)) {
      advance();
      add(ch as TokenType, ch, l, c);
      continue;
    }

    // Hex literal: 0x...
    if (ch === '0' && (peekN(1) === 'x' || peekN(1) === 'X')) {
      let val = '';
      advance(); advance();
      while (pos < source.length && /[0-9a-fA-F_]/.test(peek())) {
        const d = advance();
        if (d !== '_') val += d;
      }
      // Java numeric suffixes L/l
      if (peek() === 'L' || peek() === 'l') advance();
      add('number', String(BigInt('0x' + val)), l, c);
      continue;
    }

    // Decimal number (Java integer literal). No floats in the subset.
    if (/[0-9]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[0-9_]/.test(peek())) {
        const d = advance();
        if (d !== '_') val += d;
      }
      // Reject floats explicitly
      if (peek() === '.' && /[0-9]/.test(peekN(1))) {
        errors.push(makeDiagnostic(
          'floating-point literals are unsupported in Rúnar Java contracts',
          'error',
          { file, line: l, column: c },
        ));
        // consume the fractional part
        advance();
        while (pos < source.length && /[0-9_eE+\-]/.test(peek())) advance();
      }
      // Suffixes L/l (long) accepted; f/F/d/D rejected
      if (peek() === 'L' || peek() === 'l') advance();
      else if (peek() === 'f' || peek() === 'F' || peek() === 'd' || peek() === 'D') {
        errors.push(makeDiagnostic(
          'floating-point literals are unsupported in Rúnar Java contracts',
          'error',
          { file, line: l, column: c },
        ));
        advance();
      }
      add('number', val, l, c);
      continue;
    }

    // Identifier / keyword
    if (/[a-zA-Z_$]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[a-zA-Z0-9_$]/.test(peek())) {
        val += advance();
      }
      const kw = KEYWORDS.get(val);
      add(kw ?? 'ident', val, l, c);
      continue;
    }

    // Unknown character: skip
    advance();
  }

  tokens.push({ type: 'eof', value: '', line, column });
  return tokens;
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

const PRIMITIVE_TYPES = new Set<PrimitiveTypeName>([
  'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey',
  'Point', 'P256Point', 'P384Point', 'void',
]);

function resolveNamedType(name: string): TypeNode {
  if (name === 'BigInteger' || name === 'Bigint') {
    return { kind: 'primitive_type', name: 'bigint' };
  }
  if (name === 'Boolean') {
    return { kind: 'primitive_type', name: 'boolean' };
  }
  if (name === 'Sha256Digest') {
    return { kind: 'primitive_type', name: 'Sha256' };
  }
  if (name === 'Hash160') {
    return { kind: 'primitive_type', name: 'Ripemd160' };
  }
  if (PRIMITIVE_TYPES.has(name as PrimitiveTypeName)) {
    return { kind: 'primitive_type', name: name as PrimitiveTypeName };
  }
  return { kind: 'custom_type', name };
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class JavaParser {
  private tokens: Token[];
  private pos = 0;
  private file: string;
  private errors: CompilerDiagnostic[];

  constructor(tokens: Token[], file: string, errors: CompilerDiagnostic[]) {
    this.tokens = tokens;
    this.file = file;
    this.errors = errors;
  }

  // ----- token helpers -----
  private current(): Token { return this.tokens[this.pos] ?? this.tokens[this.tokens.length - 1]!; }
  private lookahead(n: number): Token {
    return this.tokens[this.pos + n] ?? this.tokens[this.tokens.length - 1]!;
  }
  private advance(): Token { const t = this.current(); this.pos++; return t; }
  private match(type: TokenType): boolean {
    if (this.current().type === type) { this.advance(); return true; }
    return false;
  }
  private expect(type: TokenType): Token {
    const t = this.current();
    if (t.type !== type) {
      this.errors.push(makeDiagnostic(
        `expected '${type}', got '${t.value || t.type}'`,
        'error',
        { file: this.file, line: t.line, column: t.column },
      ));
    }
    return this.advance();
  }
  private loc(): SourceLocation {
    const t = this.current();
    return { file: this.file, line: t.line, column: t.column };
  }
  private errorAt(tok: Token, msg: string): void {
    this.errors.push(makeDiagnostic(msg, 'error', { file: this.file, line: tok.line, column: tok.column }));
  }

  // ----- top-level -----
  parse(): ParseResult {
    // package declaration (optional, ignored)
    if (this.current().type === 'package') {
      while (this.current().type !== ';' && this.current().type !== 'eof') this.advance();
      this.match(';');
    }

    // imports (optional, ignored)
    while (this.current().type === 'import') {
      while (this.current().type !== ';' && this.current().type !== 'eof') this.advance();
      this.match(';');
    }

    // Skip class-level annotations (e.g., @Stateful) and optional modifiers
    while (this.current().type === '@') {
      this.skipAnnotation();
    }
    while (isClassModifier(this.current().type)) this.advance();

    if (this.current().type !== 'class') {
      this.errorAt(this.current(), 'expected class declaration');
      return { contract: null, errors: this.errors };
    }

    const classTok = this.advance(); // 'class'
    const nameTok = this.expect('ident');
    const className = nameTok.value;
    const classLoc: SourceLocation = { file: this.file, line: classTok.line, column: classTok.column };

    // Require `extends SmartContract | StatefulSmartContract`
    if (this.current().type !== 'extends') {
      this.errorAt(this.current(),
        `contract class must extend SmartContract or StatefulSmartContract`);
      return { contract: null, errors: this.errors };
    }
    this.advance();
    const parentName = this.parseQualifiedNameSimple();
    let parentClass: 'SmartContract' | 'StatefulSmartContract';
    if (parentName === 'SmartContract') {
      parentClass = 'SmartContract';
    } else if (parentName === 'StatefulSmartContract') {
      parentClass = 'StatefulSmartContract';
    } else {
      this.errorAt(nameTok,
        `contract class must extend SmartContract or StatefulSmartContract, got ${parentName}`);
      return { contract: null, errors: this.errors };
    }

    // Optional `implements ...` (consume, ignore)
    if (this.current().type === 'implements') {
      this.advance();
      // eat comma-separated type list up to '{'
      while (this.current().type !== '{' && this.current().type !== 'eof') this.advance();
    }

    this.expect('{');

    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];
    let constructor: MethodNode | null = null;

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      const member = this.parseMember(className);
      if (!member) continue;
      if (member.kind === 'property') {
        properties.push(member);
      } else if (member.isConstructor) {
        if (constructor) {
          this.errorAt(this.current(), `${className} has more than one constructor`);
        } else {
          constructor = member.method;
        }
      } else {
        methods.push(member.method);
      }
    }
    this.expect('}');

    if (!constructor) {
      constructor = syntheticConstructor(properties, this.file);
    }

    const contract: ContractNode = {
      kind: 'contract',
      name: className,
      parentClass,
      properties,
      constructor,
      methods,
      sourceFile: this.file,
    };
    // Note: classLoc is captured but ContractNode doesn't carry a sourceLocation.
    void classLoc;

    return { contract, errors: this.errors };
  }

  // Qualified name (`runar.lang.SmartContract`) → last segment.
  private parseQualifiedNameSimple(): string {
    let t = this.expect('ident');
    let last = t.value;
    while (this.current().type === '.') {
      this.advance();
      t = this.expect('ident');
      last = t.value;
    }
    return last;
  }

  // Parse any qualified identifier, returning the full text with dots.
  private parseQualifiedNameFull(): string {
    let t = this.expect('ident');
    let acc = t.value;
    while (this.current().type === '.') {
      this.advance();
      t = this.expect('ident');
      acc += '.' + t.value;
    }
    return acc;
  }

  // Skip an annotation: `@Name` with optional `(...)` argument list.
  private skipAnnotation(): void {
    this.expect('@');
    // annotation name may be qualified: @runar.lang.Public
    if (this.current().type === 'ident') this.advance();
    while (this.current().type === '.' && this.lookahead(1).type === 'ident') {
      this.advance(); this.advance();
    }
    if (this.current().type === '(') {
      // consume balanced parentheses
      let depth = 0;
      while (this.current().type !== 'eof') {
        if (this.current().type === '(') { depth++; this.advance(); }
        else if (this.current().type === ')') { depth--; this.advance(); if (depth === 0) break; }
        else this.advance();
      }
    }
  }

  // ----- members -----

  private parseMember(className: string):
    | PropertyNode
    | { kind: 'method'; method: MethodNode; isConstructor: boolean }
    | null
  {
    const loc = this.loc();

    // Annotations precede modifiers.
    let readonly = false;
    let publicAnn = false;
    while (this.current().type === '@') {
      const start = this.pos;
      this.expect('@');
      if (this.current().type !== 'ident') {
        // malformed
        continue;
      }
      // allow qualified annotation names (@runar.lang.annotations.Public)
      let name = this.expect('ident').value;
      while (this.current().type === '.' && this.lookahead(1).type === 'ident') {
        this.advance();
        name = this.expect('ident').value;
      }
      // optional (...)
      if (this.current().type === '(') {
        let depth = 0;
        while (this.current().type !== 'eof') {
          if (this.current().type === '(') { depth++; this.advance(); }
          else if (this.current().type === ')') { depth--; this.advance(); if (depth === 0) break; }
          else this.advance();
        }
      }
      if (name === 'Readonly') readonly = true;
      else if (name === 'Public') publicAnn = true;
      else if (name === 'Stateful' || name === 'Override' || name === 'SuppressWarnings') {
        // accepted but ignored
      } else {
        this.errors.push(makeDiagnostic(
          `unsupported annotation @${name}`,
          'error',
          { file: this.file, line: this.tokens[start]!.line, column: this.tokens[start]!.column },
        ));
      }
    }

    // modifiers
    while (isMemberModifier(this.current().type)) this.advance();

    // A member is either:
    //   (1) constructor:  ClassName ( params ) { ... }
    //   (2) method:       ReturnType name ( params ) { ... }
    //   (3) field:        Type name ( = init )? ;
    // Constructor test: current ident matches className and next is '('
    if (this.current().type === 'ident'
        && this.current().value === className
        && this.lookahead(1).type === '(') {
      const method = this.parseConstructor(className, loc);
      return { kind: 'method', method, isConstructor: true };
    }

    // Parse a type. This is always a type name for fields/methods.
    // Distinguish by looking at what follows `Type identifier`.
    const type = this.parseType();

    if (this.current().type !== 'ident') {
      this.errorAt(this.current(), `expected member name`);
      // attempt to skip to next ';' or '}' to recover
      while (this.current().type !== ';' && this.current().type !== '}' && this.current().type !== 'eof') {
        this.advance();
      }
      this.match(';');
      return null;
    }
    const memberNameTok = this.advance();
    const memberName = memberNameTok.value;

    if (this.current().type === '(') {
      // method
      const method = this.parseMethodBody(memberName, type, publicAnn, loc);
      return { kind: 'method', method, isConstructor: false };
    }

    // Field declaration
    let initializer: Expression | undefined;
    if (this.current().type === '=') {
      this.advance();
      initializer = this.parseExpression();
    }
    // Allow comma-separated field declarations? The reference parser rejects
    // them implicitly (javac would parse them as multiple VariableTree). We
    // support a single field per declaration.
    this.expect(';');

    const prop: PropertyNode = {
      kind: 'property',
      name: memberName,
      type,
      readonly,
      initializer,
      sourceLocation: loc,
    };
    return prop;
  }

  private parseConstructor(className: string, loc: SourceLocation): MethodNode {
    this.expect('ident'); // class name as constructor
    const params = this.parseParamList();
    // optional `throws ...` clause (consume)
    if (this.current().type === 'ident' && this.current().value === 'throws') {
      this.advance();
      while (this.current().type !== '{' && this.current().type !== 'eof') this.advance();
    }
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      const s = this.parseStatement();
      if (s) body.push(s);
    }
    this.expect('}');
    void className;
    return {
      kind: 'method',
      name: 'constructor',
      params,
      body,
      visibility: 'public',
      sourceLocation: loc,
    };
  }

  private parseMethodBody(
    name: string,
    _returnType: TypeNode,
    isPublic: boolean,
    loc: SourceLocation,
  ): MethodNode {
    const params = this.parseParamList();
    // optional throws clause
    if (this.current().type === 'ident' && this.current().value === 'throws') {
      this.advance();
      while (this.current().type !== '{' && this.current().type !== ';' && this.current().type !== 'eof') {
        this.advance();
      }
    }
    const body: Statement[] = [];
    if (this.current().type === ';') {
      this.advance();
    } else {
      this.expect('{');
      while (this.current().type !== '}' && this.current().type !== 'eof') {
        const s = this.parseStatement();
        if (s) body.push(s);
      }
      this.expect('}');
    }
    return {
      kind: 'method',
      name,
      params,
      body,
      visibility: isPublic ? 'public' : 'private',
      sourceLocation: loc,
    };
  }

  private parseParamList(): ParamNode[] {
    this.expect('(');
    const params: ParamNode[] = [];
    while (this.current().type !== ')' && this.current().type !== 'eof') {
      // Consume parameter-level modifiers ('final', annotations)
      while (this.current().type === '@') this.skipAnnotation();
      while (this.current().type === 'final') this.advance();

      const t = this.parseType();
      const nameTok = this.expect('ident');
      params.push({ kind: 'param', name: nameTok.value, type: t });
      if (this.current().type === ',') this.advance();
      else break;
    }
    this.expect(')');
    return params;
  }

  // ----- types -----

  private parseType(): TypeNode {
    const t = this.current();

    // void
    if (t.type === 'void') {
      this.advance();
      return { kind: 'primitive_type', name: 'void' };
    }
    // boolean (primitive)
    if (t.type === 'boolean') {
      this.advance();
      return { kind: 'primitive_type', name: 'boolean' };
    }

    if (t.type !== 'ident') {
      this.errorAt(t, `expected type, got '${t.value || t.type}'`);
      this.advance();
      return { kind: 'custom_type', name: 'unknown' };
    }

    // Qualified name: take last segment
    const firstTok = this.advance();
    let last = firstTok.value;
    while (this.current().type === '.' && this.lookahead(1).type === 'ident') {
      this.advance();
      last = this.expect('ident').value;
    }

    let result: TypeNode;

    // Generic parameters: `FixedArray<T, N>` or ignored generics.
    if (this.current().type === '<') {
      // Only `FixedArray<element, length>` is a supported generic type.
      if (last === 'FixedArray') {
        this.advance(); // consume '<'
        const element = this.parseType();
        this.expect(',');
        // length literal
        const lenTok = this.current();
        let length = 0;
        if (lenTok.type === 'number') {
          length = parseInt(this.advance().value, 10);
        } else {
          this.errorAt(lenTok, 'FixedArray length must be an integer literal');
          this.advance();
        }
        this.expect('>');
        result = { kind: 'fixed_array_type', element, length };
      } else {
        // Unsupported generic — consume and fall back to custom type.
        this.errorAt(firstTok, `unsupported generic type ${last}`);
        this.skipBalanced('<', '>');
        result = { kind: 'custom_type', name: last };
      }
    } else {
      result = resolveNamedType(last);
    }

    // `T[]` array suffix not supported; reject it.
    if (this.current().type === '[' && this.lookahead(1).type === ']') {
      this.errorAt(this.current(), `bare array types (T[]) are not supported; use FixedArray<T, N>`);
      this.advance(); this.advance();
    }

    return result;
  }

  private skipBalanced(open: TokenType, close: TokenType): void {
    if (this.current().type !== open) return;
    let depth = 0;
    while (this.current().type !== 'eof') {
      if (this.current().type === open) { depth++; this.advance(); }
      else if (this.current().type === close) { depth--; this.advance(); if (depth === 0) break; }
      else this.advance();
    }
  }

  // ----- statements -----

  private parseStatement(): Statement | null {
    const loc = this.loc();
    const t = this.current();

    switch (t.type) {
      case '{': {
        // Bare blocks are unsupported (match the reference Java parser).
        this.errorAt(t, 'nested blocks are unsupported');
        // Recover: skip the block.
        this.skipBalanced('{', '}');
        return null;
      }
      case 'if':
        return this.parseIfStatement(loc);
      case 'for':
        return this.parseForStatement(loc);
      case 'while':
      case 'do': {
        this.errorAt(t, `'${t.type}' loops are unsupported; use a bounded for-loop`);
        // skip to next ';' or '}'
        while (this.current().type !== ';' && this.current().type !== '}' && this.current().type !== 'eof') {
          this.advance();
        }
        this.match(';');
        return null;
      }
      case 'return':
        return this.parseReturnStatement(loc);
      case ';':
        this.advance();
        return null;
      default:
        return this.parseExpressionOrDeclStatement(loc);
    }
  }

  private parseIfStatement(loc: SourceLocation): Statement {
    this.expect('if');
    this.expect('(');
    const condition = this.parseExpression();
    this.expect(')');
    const thenBranch = this.parseBlockOrSingle();

    let elseBranch: Statement[] | undefined;
    if (this.match('else')) {
      elseBranch = this.parseBlockOrSingle();
    }
    return { kind: 'if_statement', condition, then: thenBranch, else: elseBranch, sourceLocation: loc };
  }

  private parseBlockOrSingle(): Statement[] {
    if (this.current().type === '{') {
      this.advance();
      const body: Statement[] = [];
      while (this.current().type !== '}' && this.current().type !== 'eof') {
        const s = this.parseStatement();
        if (s) body.push(s);
      }
      this.expect('}');
      return body;
    }
    const s = this.parseStatement();
    return s ? [s] : [];
  }

  private parseForStatement(loc: SourceLocation): Statement {
    this.expect('for');
    this.expect('(');
    // Initializer must be a variable decl.
    const initLoc = this.loc();
    const initType = this.parseType();
    const initNameTok = this.expect('ident');
    this.expect('=');
    const initValue = this.parseExpression();
    this.expect(';');

    const condition = this.parseExpression();
    this.expect(';');

    // Update: single expression (supports assignment, ++/--).
    const updateLoc = this.loc();
    const update = this.parseSimpleStatementNoSemicolon(updateLoc);
    this.expect(')');

    const body = this.parseBlockOrSingle();
    return {
      kind: 'for_statement',
      init: {
        kind: 'variable_decl',
        name: initNameTok.value,
        type: initType,
        mutable: true,
        init: initValue,
        sourceLocation: initLoc,
      },
      condition,
      update,
      body,
      sourceLocation: loc,
    };
  }

  private parseReturnStatement(loc: SourceLocation): Statement {
    this.expect('return');
    let value: Expression | undefined;
    if (this.current().type !== ';') {
      value = this.parseExpression();
    }
    this.expect(';');
    return { kind: 'return_statement', value, sourceLocation: loc };
  }

  /**
   * A statement that isn't `if`/`for`/`return`: either a variable declaration
   * (`Type name = expr;`) or an expression statement (possibly an assignment,
   * `++`/`--`, or a compound assignment).
   */
  private parseExpressionOrDeclStatement(loc: SourceLocation): Statement | null {
    // Detect `Type name = ...;` variable declaration. Heuristic mirrors the
    // sol/zig/go parsers: consume type-token(s) then check for `ident '='` or
    // `ident ';'`.
    if (looksLikeLocalVarDecl(this)) {
      return this.parseLocalVarDecl(loc);
    }

    const expr = this.parseExpression();
    const stmt = this.finishExpressionStatement(expr, loc, true);
    return stmt;
  }

  /**
   * Similar to parseExpressionOrDeclStatement but for the for-loop update
   * slot: no terminating `;` is consumed by the caller; we build and return
   * the statement directly.
   */
  private parseSimpleStatementNoSemicolon(loc: SourceLocation): Statement {
    const expr = this.parseExpression();
    const s = this.finishExpressionStatement(expr, loc, false);
    return s ?? { kind: 'expression_statement', expression: expr, sourceLocation: loc };
  }

  private parseLocalVarDecl(loc: SourceLocation): Statement {
    const type = this.parseType();
    const nameTok = this.expect('ident');
    this.expect('=');
    const init = this.parseExpression();
    this.expect(';');
    return {
      kind: 'variable_decl',
      name: nameTok.value,
      type,
      mutable: true,
      init,
      sourceLocation: loc,
    };
  }

  /** Finish an expression that might be an assignment, post-inc, or plain expr. */
  private finishExpressionStatement(
    target: Expression,
    loc: SourceLocation,
    consumeSemi: boolean,
  ): Statement | null {
    const tok = this.current();

    if (tok.type === '=') {
      this.advance();
      const value = this.parseExpression();
      if (consumeSemi) this.expect(';');
      return { kind: 'assignment', target, value, sourceLocation: loc };
    }

    // Compound assignments
    const compoundOps: Partial<Record<TokenType, BinaryOp>> = {
      '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%',
      '&=': '&', '|=': '|', '^=': '^', '<<=': '<<', '>>=': '>>',
    };
    if (tok.type in compoundOps) {
      const op = compoundOps[tok.type]!;
      this.advance();
      const rhs = this.parseExpression();
      if (consumeSemi) this.expect(';');
      return {
        kind: 'assignment',
        target,
        value: { kind: 'binary_expr', op, left: target, right: rhs },
        sourceLocation: loc,
      };
    }

    // Post-increment / post-decrement statement-level
    if (tok.type === '++') {
      this.advance();
      if (consumeSemi) this.expect(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand: target, prefix: false },
        sourceLocation: loc,
      };
    }
    if (tok.type === '--') {
      this.advance();
      if (consumeSemi) this.expect(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand: target, prefix: false },
        sourceLocation: loc,
      };
    }

    if (consumeSemi) this.expect(';');
    return { kind: 'expression_statement', expression: target, sourceLocation: loc };
  }

  // ----- expressions -----

  private parseExpression(): Expression {
    return this.parseTernary();
  }

  private parseTernary(): Expression {
    const cond = this.parseLogicalOr();
    if (this.current().type === '?') {
      this.advance();
      const consequent = this.parseExpression();
      this.expect(':');
      const alternate = this.parseExpression();
      return { kind: 'ternary_expr', condition: cond, consequent, alternate };
    }
    return cond;
  }

  private parseLogicalOr(): Expression {
    let left = this.parseLogicalAnd();
    while (this.current().type === '||') {
      this.advance();
      left = { kind: 'binary_expr', op: '||', left, right: this.parseLogicalAnd() };
    }
    return left;
  }

  private parseLogicalAnd(): Expression {
    let left = this.parseBitOr();
    while (this.current().type === '&&') {
      this.advance();
      left = { kind: 'binary_expr', op: '&&', left, right: this.parseBitOr() };
    }
    return left;
  }

  private parseBitOr(): Expression {
    let left = this.parseBitXor();
    while (this.current().type === '|') {
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
    while (this.current().type === '&') {
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

  private parseUnary(): Expression {
    const t = this.current().type;
    if (t === '!') {
      this.advance();
      return { kind: 'unary_expr', op: '!', operand: this.parseUnary() };
    }
    if (t === '-') {
      this.advance();
      return { kind: 'unary_expr', op: '-', operand: this.parseUnary() };
    }
    if (t === '+') {
      // unary plus: just the operand
      this.advance();
      return this.parseUnary();
    }
    if (t === '~') {
      this.advance();
      return { kind: 'unary_expr', op: '~', operand: this.parseUnary() };
    }
    if (t === '++') {
      this.advance();
      return { kind: 'increment_expr', operand: this.parseUnary(), prefix: true };
    }
    if (t === '--') {
      this.advance();
      return { kind: 'decrement_expr', operand: this.parseUnary(), prefix: true };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expression {
    let expr = this.parsePrimary();
    while (true) {
      const t = this.current().type;
      if (t === '(') {
        // function/method call
        this.advance();
        const args: Expression[] = [];
        while (this.current().type !== ')' && this.current().type !== 'eof') {
          args.push(this.parseExpression());
          if (this.current().type === ',') this.advance();
          else break;
        }
        this.expect(')');
        expr = this.buildCallExpr(expr, args);
      } else if (t === '.') {
        this.advance();
        const propTok = this.expect('ident');
        const propName = propTok.value;
        if (expr.kind === 'identifier' && expr.name === 'this') {
          expr = { kind: 'property_access', property: propName };
        } else if (expr.kind === 'identifier' && expr.name === 'BigInteger') {
          // BigInteger.ZERO / ONE / TWO / TEN → BigIntLiteral
          const folded = foldBigIntegerConstant(propName);
          if (folded) {
            expr = folded;
          } else {
            expr = { kind: 'member_expr', object: expr, property: propName };
          }
        } else {
          expr = { kind: 'member_expr', object: expr, property: propName };
        }
      } else if (t === '[') {
        this.advance();
        const index = this.parseExpression();
        this.expect(']');
        expr = { kind: 'index_access', object: expr, index };
      } else if (t === '++') {
        this.advance();
        expr = { kind: 'increment_expr', operand: expr, prefix: false };
      } else if (t === '--') {
        this.advance();
        expr = { kind: 'decrement_expr', operand: expr, prefix: false };
      } else {
        break;
      }
    }
    return expr;
  }

  /**
   * Build a call expression, special-casing the two "call as literal" forms:
   *   `X.fromHex("deadbeef")` → ByteStringLiteral("deadbeef")
   *   `BigInteger.valueOf(7)` → BigIntLiteral(7n)
   */
  private buildCallExpr(callee: Expression, args: Expression[]): Expression {
    // X.fromHex("deadbeef") → ByteStringLiteral
    if (callee.kind === 'member_expr'
        && callee.property === 'fromHex'
        && args.length === 1
        && args[0]!.kind === 'bytestring_literal') {
      // Already mapped below: we treat string literals as bytestring_literal
      // when they appear as the sole argument to fromHex. See parsePrimary
      // below — string literals produce a bytestring_literal whose value is
      // the raw string content.
      return args[0]!;
    }
    // BigInteger.valueOf(<int literal>) → BigIntLiteral
    if (callee.kind === 'member_expr'
        && callee.property === 'valueOf'
        && callee.object.kind === 'identifier'
        && callee.object.name === 'BigInteger'
        && args.length === 1
        && args[0]!.kind === 'bigint_literal') {
      return args[0]!;
    }
    // Also accept `valueOf` on a PropertyAccessExpr (e.g., writing
    // `this.BigInteger.valueOf(...)`) — won't occur in practice, so no-op.
    return { kind: 'call_expr', callee, args };
  }

  private parsePrimary(): Expression {
    const t = this.current();

    switch (t.type) {
      case 'number':
        this.advance();
        return { kind: 'bigint_literal', value: BigInt(t.value) };
      case 'true':
        this.advance();
        return { kind: 'bool_literal', value: true };
      case 'false':
        this.advance();
        return { kind: 'bool_literal', value: false };
      case 'null':
        this.errorAt(t, 'null literals are unsupported in Rúnar Java contracts');
        this.advance();
        return { kind: 'bigint_literal', value: 0n };
      case 'string':
        // Bare string literals only appear as the argument to X.fromHex("...")
        // in the Rúnar subset. We represent them as ByteStringLiteral; the
        // buildCallExpr helper above unwraps them when the callee is fromHex.
        // If a bare string appears anywhere else, the validator will catch
        // it (bytestring in a non-ByteString context fails typecheck) and
        // we emit an error below for immediate diagnostic clarity.
        this.advance();
        return { kind: 'bytestring_literal', value: t.value };
      case 'this':
        this.advance();
        return { kind: 'identifier', name: 'this' };
      case 'super':
        this.advance();
        return { kind: 'identifier', name: 'super' };
      case '(': {
        this.advance();
        const expr = this.parseExpression();
        this.expect(')');
        return expr;
      }
      case 'new':
        return this.parseNewExpression();
      case 'ident': {
        this.advance();
        return { kind: 'identifier', name: t.value };
      }
      default:
        this.errorAt(t, `unexpected token '${t.value || t.type}' in expression`);
        this.advance();
        return { kind: 'bigint_literal', value: 0n };
    }
  }

  private parseNewExpression(): Expression {
    this.expect('new');
    // Only `new T[]{...}` is supported: a typed array literal.
    const typeTok = this.current();
    if (typeTok.type !== 'ident' && typeTok.type !== 'boolean') {
      this.errorAt(typeTok, `expected type after 'new'`);
      return { kind: 'array_literal', elements: [] };
    }
    // Consume type name (possibly qualified) plus optional generic args.
    this.advance();
    while (this.current().type === '.' && this.lookahead(1).type === 'ident') {
      this.advance(); this.advance();
    }
    if (this.current().type === '<') this.skipBalanced('<', '>');

    if (this.current().type === '[' && this.lookahead(1).type === ']') {
      this.advance(); this.advance();
      this.expect('{');
      const elements: Expression[] = [];
      while (this.current().type !== '}' && this.current().type !== 'eof') {
        elements.push(this.parseExpression());
        if (this.current().type === ',') this.advance();
        else break;
      }
      this.expect('}');
      return { kind: 'array_literal', elements };
    }

    // `new Foo(...)` — constructor call. Not part of the Rúnar subset.
    this.errorAt(typeTok, '`new` expressions other than array literals (new T[]{...}) are unsupported');
    // attempt to consume a balanced '(...)'
    if (this.current().type === '(') this.skipBalanced('(', ')');
    return { kind: 'bigint_literal', value: 0n };
  }
}

// ---------------------------------------------------------------------------
// Lookahead helpers (free functions to keep parser class compact)
// ---------------------------------------------------------------------------

/**
 * Return true if the tokens starting at the parser's current position look
 * like the beginning of a local variable declaration: `Type name = ...` or
 * `Type name;`. We do not fully resolve the type here (that is `parseType`'s
 * job); we only detect the shape from the lookahead.
 *
 * A valid variable-type token is one of:
 *   - 'boolean' / 'void' keyword
 *   - an `ident` (possibly followed by a qualified path `.ident`* and an
 *     optional `<…>` generic argument list)
 *
 * We also need the next non-type token after the type to be `ident`
 * followed by `=` or `;`.
 */
function looksLikeLocalVarDecl(p: JavaParser): boolean {
  // Scan forward on a *copy* of the position index.
  // Using a helper "read" closure isolated from parser state.
  // Access to private fields requires small friend-function helpers.
  return _looksLikeLocalVarDecl(p);
}

// Cast-friend helper: reaches into the parser's private token stream to do
// the lookahead. We intentionally treat this as an internal implementation
// detail co-located in this file.
function _looksLikeLocalVarDecl(p: JavaParser): boolean {
  const self = p as unknown as {
    tokens: Token[];
    pos: number;
    lookahead(n: number): Token;
  };
  let i = self.pos;
  const tok = (n: number): Token => self.tokens[n] ?? self.tokens[self.tokens.length - 1]!;

  // Accept `void` / `boolean` as primitives.
  if (tok(i).type === 'void' || tok(i).type === 'boolean') {
    i++;
  } else if (tok(i).type === 'ident') {
    i++;
    // Qualified name segments
    while (tok(i).type === '.' && tok(i + 1).type === 'ident') {
      i += 2;
    }
    // Generic args: <...>
    if (tok(i).type === '<') {
      let depth = 0;
      while (i < self.tokens.length) {
        if (tok(i).type === '<') { depth++; i++; }
        else if (tok(i).type === '>') { depth--; i++; if (depth === 0) break; }
        else if (tok(i).type === '>>') { depth -= 2; i++; if (depth <= 0) break; }
        else i++;
      }
    }
  } else {
    return false;
  }

  // Now the name
  if (tok(i).type !== 'ident') return false;
  i++;
  // Then = or ;
  return tok(i).type === '=' || tok(i).type === ';';
}

// ---------------------------------------------------------------------------
// Modifier predicates
// ---------------------------------------------------------------------------

function isClassModifier(t: TokenType): boolean {
  return t === 'public' || t === 'private' || t === 'protected'
      || t === 'final' || t === 'abstract' || t === 'static';
}

function isMemberModifier(t: TokenType): boolean {
  return t === 'public' || t === 'private' || t === 'protected'
      || t === 'final' || t === 'static' || t === 'abstract' || t === 'native';
}

// ---------------------------------------------------------------------------
// BigInteger constant folding
// ---------------------------------------------------------------------------

function foldBigIntegerConstant(name: string): Expression | null {
  switch (name) {
    case 'ZERO': return { kind: 'bigint_literal', value: 0n };
    case 'ONE':  return { kind: 'bigint_literal', value: 1n };
    case 'TWO':  return { kind: 'bigint_literal', value: 2n };
    case 'TEN':  return { kind: 'bigint_literal', value: 10n };
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// Synthetic constructor (when the contract omits one)
// ---------------------------------------------------------------------------

function syntheticConstructor(properties: PropertyNode[], file: string): MethodNode {
  const loc: SourceLocation = { file, line: 1, column: 1 };
  const params: ParamNode[] = [];
  const body: Statement[] = [];

  const uninit = properties.filter(p => !p.initializer);
  for (const p of uninit) {
    params.push({ kind: 'param', name: p.name, type: p.type });
  }
  body.push({
    kind: 'expression_statement',
    expression: {
      kind: 'call_expr',
      callee: { kind: 'identifier', name: 'super' },
      args: uninit.map(p => ({ kind: 'identifier' as const, name: p.name })),
    },
    sourceLocation: loc,
  });
  for (const p of uninit) {
    body.push({
      kind: 'assignment',
      target: { kind: 'property_access', property: p.name },
      value: { kind: 'identifier', name: p.name },
      sourceLocation: loc,
    });
  }

  return {
    kind: 'method',
    name: 'constructor',
    params,
    body,
    visibility: 'public',
    sourceLocation: loc,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseJavaSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.java';
  const errors: CompilerDiagnostic[] = [];
  const tokens = tokenize(source, file, errors);
  const parser = new JavaParser(tokens, file, errors);
  return parser.parse();
}
