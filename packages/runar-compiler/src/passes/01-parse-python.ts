/**
 * Python parser for Rúnar contracts.
 *
 * Parses `.runar.py` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses hand-written tokenizer with INDENT/DEDENT tokens
 * (for significant whitespace) plus recursive descent.
 *
 * Python syntax conventions:
 *   - `class Foo(SmartContract):` / `class Foo(StatefulSmartContract):`
 *   - `@public` decorator for public methods
 *   - `self.prop` for property access (maps to `this.prop`)
 *   - `assert_(expr)` or `assert expr` for assertions
 *   - `snake_case` names converted to `camelCase` in AST
 *   - `//` integer division maps to `/` in AST (OP_DIV)
 *   - `and`/`or`/`not` for boolean operators
 *   - `Readonly[T]` for readonly properties in stateful contracts
 *   - `for i in range(n):` for bounded loops
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
  | 'class' | 'def' | 'if' | 'elif' | 'else' | 'for' | 'in' | 'range'
  | 'return' | 'pass' | 'True' | 'False' | 'None'
  | 'and' | 'or' | 'not' | 'self' | 'super'
  | 'from' | 'import' | 'assert'
  | 'ident' | 'number' | 'hexstring' | 'string'
  | '(' | ')' | '[' | ']' | ':' | ',' | '.' | '->' | '@'
  | '+' | '-' | '*' | '/' | '//' | '%' | '**'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '<<' | '>>'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '//=' | '%='
  | 'INDENT' | 'DEDENT' | 'NEWLINE'
  | 'eof';

interface Token {
  type: TokenType;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['class', 'class'], ['def', 'def'], ['if', 'if'], ['elif', 'elif'],
  ['else', 'else'], ['for', 'for'], ['in', 'in'], ['range', 'range'],
  ['return', 'return'], ['pass', 'pass'], ['True', 'True'], ['False', 'False'],
  ['None', 'None'], ['and', 'and'], ['or', 'or'], ['not', 'not'],
  ['self', 'self'], ['super', 'super'], ['from', 'from'], ['import', 'import'],
  ['assert', 'assert'],
]);

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const lines = source.split('\n');
  const indentStack: number[] = [0];

  // Track state for multi-line expressions (parentheses nesting)
  let parenDepth = 0;

  function add(type: TokenType, value: string, line: number, col: number) {
    tokens.push({ type, value, line, column: col });
  }

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const rawLine = lines[lineIdx]!;
    const lineNum = lineIdx + 1;

    // Strip trailing \r
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;

    // Skip blank lines and comment-only lines (they don't affect indentation)
    const stripped = line.trimStart();
    if (stripped === '' || stripped.startsWith('#')) {
      continue;
    }

    // Compute indent level (only at paren depth 0)
    if (parenDepth === 0) {
      let indent = 0;
      for (let i = 0; i < line.length; i++) {
        if (line[i] === ' ') indent++;
        else if (line[i] === '\t') indent += 4;
        else break;
      }

      if (indent > indentStack[indentStack.length - 1]!) {
        indentStack.push(indent);
        add('INDENT', '', lineNum, 1);
      } else if (indent < indentStack[indentStack.length - 1]!) {
        while (indentStack.length > 1 && indentStack[indentStack.length - 1]! > indent) {
          indentStack.pop();
          add('DEDENT', '', lineNum, 1);
        }
      }
    }

    // Tokenize the content of this line
    let pos = stripped.length < line.length ? line.length - stripped.length : 0;

    while (pos < line.length) {
      const ch = line[pos]!;
      const col = pos + 1;

      // Whitespace within line
      if (ch === ' ' || ch === '\t') {
        pos++;
        continue;
      }

      // Comment
      if (ch === '#') {
        break; // rest of line is comment
      }

      // Decorators
      if (ch === '@') {
        pos++;
        add('@', '@', lineNum, col);
        continue;
      }

      // Three-char operators: //= **
      if (ch === '/' && pos + 2 < line.length && line[pos + 1] === '/' && line[pos + 2] === '=') {
        add('//=', '//=', lineNum, col);
        pos += 3;
        continue;
      }
      if (ch === '*' && pos + 1 < line.length && line[pos + 1] === '*') {
        add('**', '**', lineNum, col);
        pos += 2;
        continue;
      }

      // Two-char operators
      if (ch === '/' && pos + 1 < line.length && line[pos + 1] === '/') {
        add('//', '//', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '=' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('==', '==', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '!' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('!=', '!=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '<' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('<=', '<=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '>' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('>=', '>=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '<' && pos + 1 < line.length && line[pos + 1] === '<') {
        add('<<', '<<', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '>' && pos + 1 < line.length && line[pos + 1] === '>') {
        add('>>', '>>', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '+' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('+=', '+=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '-' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('-=', '-=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '*' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('*=', '*=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '/' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('/=', '/=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '%' && pos + 1 < line.length && line[pos + 1] === '=') {
        add('%=', '%=', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '-' && pos + 1 < line.length && line[pos + 1] === '>') {
        add('->', '->', lineNum, col);
        pos += 2;
        continue;
      }

      // Parentheses (track depth for multi-line expressions)
      if (ch === '(') { parenDepth++; add('(', '(', lineNum, col); pos++; continue; }
      if (ch === ')') { parenDepth = Math.max(0, parenDepth - 1); add(')', ')', lineNum, col); pos++; continue; }
      if (ch === '[') { parenDepth++; add('[', '[', lineNum, col); pos++; continue; }
      if (ch === ']') { parenDepth = Math.max(0, parenDepth - 1); add(']', ']', lineNum, col); pos++; continue; }

      // Single-char operators & delimiters
      if (',:+-%&|^~!'.includes(ch)) {
        add(ch as TokenType, ch, lineNum, col);
        pos++;
        continue;
      }
      if (ch === '.') {
        add('.', '.', lineNum, col);
        pos++;
        continue;
      }
      if (ch === '<') { add('<', '<', lineNum, col); pos++; continue; }
      if (ch === '>') { add('>', '>', lineNum, col); pos++; continue; }
      if (ch === '=') { add('=', '=', lineNum, col); pos++; continue; }
      if (ch === '*') { add('*', '*', lineNum, col); pos++; continue; }
      if (ch === '/') { add('/', '/', lineNum, col); pos++; continue; }

      // Hex byte string: b'\xde\xad' or b"\xde\xad"
      if (ch === 'b' && pos + 1 < line.length && (line[pos + 1] === '\'' || line[pos + 1] === '"')) {
        const quote = line[pos + 1]!;
        pos += 2; // skip b and opening quote
        let hex = '';
        while (pos < line.length && line[pos] !== quote) {
          if (line[pos] === '\\' && pos + 1 < line.length && line[pos + 1] === 'x') {
            // \xHH
            hex += line.substring(pos + 2, pos + 4);
            pos += 4;
          } else {
            // Non-hex byte — encode as hex
            hex += line.charCodeAt(pos).toString(16).padStart(2, '0');
            pos++;
          }
        }
        if (pos < line.length) pos++; // skip closing quote
        add('hexstring', hex, lineNum, col);
        continue;
      }

      // String literals (single or double quoted)
      if (ch === '\'' || ch === '"') {
        const quote = ch;
        pos++;
        let val = '';
        while (pos < line.length && line[pos] !== quote) {
          if (line[pos] === '\\' && pos + 1 < line.length) {
            pos++; // skip backslash
            val += line[pos];
            pos++;
          } else {
            val += line[pos];
            pos++;
          }
        }
        if (pos < line.length) pos++; // skip closing quote
        add('string', val, lineNum, col);
        continue;
      }

      // Numbers (decimal and hex)
      if (ch >= '0' && ch <= '9') {
        let num = '';
        if (ch === '0' && pos + 1 < line.length && (line[pos + 1] === 'x' || line[pos + 1] === 'X')) {
          num = '0x';
          pos += 2;
          while (pos < line.length && /[0-9a-fA-F_]/.test(line[pos]!)) {
            if (line[pos] !== '_') num += line[pos];
            pos++;
          }
        } else {
          while (pos < line.length && /[0-9_]/.test(line[pos]!)) {
            if (line[pos] !== '_') num += line[pos];
            pos++;
          }
        }
        add('number', num, lineNum, col);
        continue;
      }

      // Identifiers and keywords
      if (/[a-zA-Z_]/.test(ch)) {
        let val = '';
        while (pos < line.length && /[a-zA-Z0-9_]/.test(line[pos]!)) {
          val += line[pos];
          pos++;
        }
        const kw = KEYWORDS.get(val);
        add(kw || 'ident', val, lineNum, col);
        continue;
      }

      // Skip unknown characters
      pos++;
    }

    // Emit NEWLINE at end of significant line (only if not inside parens)
    if (parenDepth === 0) {
      add('NEWLINE', '', lineNum, line.length + 1);
    }
  }

  // Emit remaining DEDENTs
  while (indentStack.length > 1) {
    indentStack.pop();
    add('DEDENT', '', lines.length, 1);
  }

  add('eof', '', lines.length + 1, 1);
  return tokens;
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/** Convert snake_case to camelCase. Single words pass through unchanged. */
function snakeToCamel(name: string): string {
  // Strip trailing underscore (e.g. assert_ -> assert)
  let n = name.endsWith('_') && name !== '_' ? name.slice(0, -1) : name;

  return n.replace(/_([a-z0-9])/g, (_, ch: string) => ch.toUpperCase());
}

/** Map Python built-in function names to AST callee names. */
function mapBuiltinName(name: string): string {
  // Exact-match special cases (names that don't follow simple snake_case → camelCase)
  const SPECIAL: Record<string, string> = {
    'assert_': 'assert',
    'verify_wots': 'verifyWOTS',
    'verify_slh_dsa_sha2_128s': 'verifySLHDSA_SHA2_128s',
    'verify_slh_dsa_sha2_128f': 'verifySLHDSA_SHA2_128f',
    'verify_slh_dsa_sha2_192s': 'verifySLHDSA_SHA2_192s',
    'verify_slh_dsa_sha2_192f': 'verifySLHDSA_SHA2_192f',
    'verify_slh_dsa_sha2_256s': 'verifySLHDSA_SHA2_256s',
    'verify_slh_dsa_sha2_256f': 'verifySLHDSA_SHA2_256f',
    'verify_rabin_sig': 'verifyRabinSig',
    'check_sig': 'checkSig',
    'check_multi_sig': 'checkMultiSig',
    'check_preimage': 'checkPreimage',
    'hash160': 'hash160',
    'hash256': 'hash256',
    'sha256': 'sha256',
    'ripemd160': 'ripemd160',
    'num2bin': 'num2bin',
    'reverse_bytes': 'reverseBytes',
    'extract_locktime': 'extractLocktime',
    'extract_output_hash': 'extractOutputHash',
    'extract_amount': 'extractAmount',
    'extract_version': 'extractVersion',
    'extract_sequence': 'extractSequence',
    'ec_add': 'ecAdd',
    'ec_mul': 'ecMul',
    'ec_mul_gen': 'ecMulGen',
    'ec_negate': 'ecNegate',
    'ec_on_curve': 'ecOnCurve',
    'ec_mod_reduce': 'ecModReduce',
    'ec_encode_compressed': 'ecEncodeCompressed',
    'ec_make_point': 'ecMakePoint',
    'ec_point_x': 'ecPointX',
    'ec_point_y': 'ecPointY',
    'mul_div': 'mulDiv',
    'percent_of': 'percentOf',
    'add_output': 'addOutput',
    'get_state_script': 'getStateScript',
  };
  const special = SPECIAL[name];
  if (special) return special;

  // Names that pass through unchanged
  if (['bool', 'abs', 'min', 'max', 'len', 'pow', 'cat', 'within',
       'safediv', 'safemod', 'clamp', 'sign', 'sqrt', 'gcd', 'divmod',
       'log2', 'substr'].includes(name)) {
    return name;
  }

  // Default: snake_case -> camelCase
  return snakeToCamel(name);
}

/** Map Python type names to Rúnar AST types. */
function mapPyType(name: string): string {
  switch (name) {
    case 'Bigint': case 'int': return 'bigint';
    case 'bool': return 'boolean';
    case 'ByteString': case 'bytes': return 'ByteString';
    case 'PubKey': return 'PubKey';
    case 'Sig': return 'Sig';
    case 'Addr': return 'Addr';
    case 'Sha256': return 'Sha256';
    case 'Ripemd160': return 'Ripemd160';
    case 'SigHashPreimage': return 'SigHashPreimage';
    case 'RabinSig': return 'RabinSig';
    case 'RabinPubKey': return 'RabinPubKey';
    case 'Point': return 'Point';
    default: return name;
  }
}

const PRIMITIVE_TYPES = new Set<string>([
  'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point', 'void',
]);

function makePrimitiveOrCustom(name: string): TypeNode {
  if (PRIMITIVE_TYPES.has(name)) {
    return { kind: 'primitive_type', name: name as PrimitiveTypeName };
  }
  return { kind: 'custom_type', name };
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class PyParser {
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

  private advance(): Token {
    const t = this.current();
    if (this.pos < this.tokens.length - 1) this.pos++;
    return t;
  }

  private expect(type: TokenType): Token {
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

  private match(type: TokenType): boolean {
    if (this.current().type === type) { this.advance(); return true; }
    return false;
  }

  private checkIdent(name: string): boolean {
    const t = this.current();
    return t.type === 'ident' && t.value === name;
  }

  private loc(): SourceLocation {
    const t = this.current();
    return { file: this.file, line: t.line, column: t.column };
  }

  // Skip NEWLINE tokens
  private skipNewlines(): void {
    while (this.peek().type === 'NEWLINE') this.advance();
  }

  // ---------------------------------------------------------------------------
  // Top-level parsing
  // ---------------------------------------------------------------------------

  parse(): ParseResult {
    this.skipNewlines();

    // Skip `from runar import ...` lines
    while (this.peek().type === 'from') {
      this.parseImportLine();
      this.skipNewlines();
    }

    // Parse class
    const contract = this.parseClass();
    if (!contract) {
      return { contract: null, errors: this.errors };
    }

    return { contract, errors: this.errors };
  }

  private parseImportLine(): void {
    // from X import Y, Z, ...
    // or: import X
    if (this.peek().type === 'from') {
      this.advance(); // 'from'
      // consume module path
      while (this.peek().type !== 'import' && this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
        this.advance();
      }
      if (this.match('import')) {
        // consume imported names
        while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
          this.advance();
        }
      }
    } else if (this.peek().type === 'import') {
      this.advance();
      while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
        this.advance();
      }
    }
    this.skipNewlines();
  }

  private parseClass(): ContractNode | null {
    this.skipNewlines();

    if (this.peek().type !== 'class') {
      this.errors.push(makeDiagnostic(
        'Expected class declaration',
        'error',
        this.loc(),
      ));
      return null;
    }
    this.advance(); // 'class'

    const nameToken = this.expect('ident');
    const contractName = nameToken.value;

    this.expect('(');
    const parentToken = this.expect('ident');
    const parentClass = parentToken.value;
    this.expect(')');
    this.expect(':');
    this.skipNewlines();
    this.expect('INDENT');
    this.skipNewlines();

    if (parentClass !== 'SmartContract' && parentClass !== 'StatefulSmartContract') {
      this.errors.push(makeDiagnostic(
        `Unknown parent class: ${parentClass}`,
        'error',
        { file: this.file, line: parentToken.line, column: parentToken.column },
      ));
      return null;
    }

    // Parse class body: properties, constructor, methods
    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];
    let constructor: MethodNode | null = null;

    while (this.peek().type !== 'DEDENT' && this.peek().type !== 'eof') {
      this.skipNewlines();
      if (this.peek().type === 'DEDENT' || this.peek().type === 'eof') break;

      // Decorators
      const decorators: string[] = [];
      while (this.peek().type === '@') {
        this.advance(); // '@'
        const decName = this.advance().value;
        decorators.push(decName);
        this.skipNewlines();
      }

      // Method definition
      if (this.peek().type === 'def') {
        const method = this.parseMethodDef(decorators);
        if (method.name === 'constructor') {
          constructor = method;
        } else {
          methods.push(method);
        }
        this.skipNewlines();
        continue;
      }

      // Property: name: Type
      if (this.peek().type === 'ident') {
        const prop = this.parseProperty(parentClass);
        if (prop) {
          properties.push(prop);
        }
        this.skipNewlines();
        continue;
      }

      // Skip unknown tokens
      this.advance();
    }

    this.match('DEDENT');

    // Auto-generate constructor if not provided
    if (!constructor) {
      constructor = this.autoGenerateConstructor(properties);
    }

    return {
      kind: 'contract',
      name: contractName,
      parentClass: parentClass as 'SmartContract' | 'StatefulSmartContract',
      properties,
      constructor,
      methods,
      sourceFile: this.file,
    };
  }

  private parseProperty(parentClass: string): PropertyNode | null {
    const loc = this.loc();
    const nameTok = this.advance(); // ident
    const rawName = nameTok.value;

    if (this.peek().type !== ':') {
      // Not a property — might be a stray identifier; skip the line
      while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') this.advance();
      return null;
    }
    this.advance(); // ':'

    // Parse type (possibly Readonly[T])
    let isReadonly = false;
    let typeNode: TypeNode;

    if (this.checkIdent('Readonly')) {
      isReadonly = true;
      this.advance(); // 'Readonly'
      this.expect('[');
      typeNode = this.parseType();
      this.expect(']');
    } else {
      typeNode = this.parseType();
    }

    // In stateless contracts, all properties are readonly
    if (parentClass === 'SmartContract') {
      isReadonly = true;
    }

    // Check for initializer: = value
    let initializer: Expression | undefined;
    if (this.peek().type === '=') {
      this.advance(); // '='
      initializer = this.parseExpression();
    }

    // Skip rest of line
    while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof' && this.peek().type !== 'DEDENT') {
      this.advance();
    }

    return {
      kind: 'property',
      name: snakeToCamel(rawName),
      type: typeNode,
      readonly: isReadonly,
      initializer,
      sourceLocation: loc,
    };
  }

  private parseType(): TypeNode {
    const tok = this.advance();
    const rawName = tok.value;

    // Check for FixedArray-like generic types (not common in Python DSL but support it)
    if (this.peek().type === '[' && rawName !== 'Readonly') {
      // E.g., FixedArray[T, N]
      if (rawName === 'FixedArray') {
        this.advance(); // '['
        const elemType = this.parseType();
        this.expect(',');
        const sizeTok = this.expect('number');
        const size = parseInt(sizeTok.value, 10);
        this.expect(']');
        return { kind: 'fixed_array_type', element: elemType, length: size };
      }
    }

    const mapped = mapPyType(rawName);
    return makePrimitiveOrCustom(mapped);
  }

  private parseMethodDef(decorators: string[]): MethodNode {
    const loc = this.loc();
    this.expect('def');

    const nameTok = this.advance();
    const rawName = nameTok.value;

    this.expect('(');
    const params = this.parseParams();
    this.expect(')');

    // Optional return type annotation: -> Type
    if (this.match('->')) {
      this.parseType(); // consume and discard return type
    }

    this.expect(':');
    this.skipNewlines();
    this.expect('INDENT');

    const body = this.parseStatements();

    this.match('DEDENT');

    // Determine if this is the constructor
    if (rawName === '__init__') {
      return {
        kind: 'method',
        name: 'constructor',
        params,
        body,
        visibility: 'public',
        sourceLocation: loc,
      };
    }

    const isPublic = decorators.includes('public');
    const methodName = snakeToCamel(rawName);

    return {
      kind: 'method',
      name: methodName,
      params,
      body,
      visibility: isPublic ? 'public' : 'private',
      sourceLocation: loc,
    };
  }

  private parseParams(): ParamNode[] {
    const params: ParamNode[] = [];

    while (this.peek().type !== ')' && this.peek().type !== 'eof') {
      // Skip 'self' parameter
      if (this.peek().type === 'self') {
        this.advance();
        if (this.peek().type === ',') this.advance();
        continue;
      }

      const nameTok = this.advance();
      const rawName = nameTok.value;

      let typeNode: TypeNode | undefined;
      if (this.match(':')) {
        typeNode = this.parseType();
      }

      params.push({
        kind: 'param',
        name: snakeToCamel(rawName),
        type: typeNode ?? { kind: 'custom_type', name: 'unknown' },
      });

      if (!this.match(',')) break;
    }

    return params;
  }

  private autoGenerateConstructor(properties: PropertyNode[]): MethodNode {
    // Only non-initialized properties become constructor params
    const uninitProps = properties.filter(p => !p.initializer);
    const params: ParamNode[] = uninitProps.map(p => ({
      kind: 'param' as const,
      name: p.name,
      type: p.type,
    }));

    const superArgs: Expression[] = params.map(p => ({
      kind: 'identifier' as const,
      name: p.name,
    }));

    const superCall: Statement = {
      kind: 'expression_statement',
      expression: {
        kind: 'call_expr',
        callee: { kind: 'member_expr', object: { kind: 'identifier', name: 'super' }, property: '' },
        args: superArgs,
      },
      sourceLocation: { file: this.file, line: 1, column: 0 },
    };

    const assignments: Statement[] = uninitProps.map(p => ({
      kind: 'assignment' as const,
      target: { kind: 'property_access' as const, property: p.name },
      value: { kind: 'identifier' as const, name: p.name },
      sourceLocation: { file: this.file, line: 1, column: 0 },
    }));

    return {
      kind: 'method',
      name: 'constructor',
      params,
      body: [superCall, ...assignments],
      visibility: 'public',
      sourceLocation: { file: this.file, line: 1, column: 0 },
    };
  }

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  private parseStatements(): Statement[] {
    const stmts: Statement[] = [];

    while (this.peek().type !== 'DEDENT' && this.peek().type !== 'eof') {
      this.skipNewlines();
      if (this.peek().type === 'DEDENT' || this.peek().type === 'eof') break;

      const stmt = this.parseStatement();
      if (stmt) stmts.push(stmt);
      this.skipNewlines();
    }

    return stmts;
  }

  private parseStatement(): Statement | null {
    const loc = this.loc();

    // assert statement: assert expr or assert_(expr)
    if (this.peek().type === 'assert') {
      return this.parseAssertStatement(loc);
    }

    // if statement
    if (this.peek().type === 'if') {
      return this.parseIfStatement(loc);
    }

    // for statement
    if (this.peek().type === 'for') {
      return this.parseForStatement(loc);
    }

    // return statement
    if (this.peek().type === 'return') {
      return this.parseReturnStatement(loc);
    }

    // pass statement
    if (this.peek().type === 'pass') {
      this.advance();
      return null;
    }

    // super().__init__(...) — parse as part of constructor
    if (this.peek().type === 'super') {
      return this.parseSuperCall(loc);
    }

    // self.prop = expr (assignment to property)
    if (this.peek().type === 'self') {
      return this.parseSelfStatement(loc);
    }

    // Variable declaration or expression statement
    // Check for: ident : Type = expr or ident = expr
    if (this.peek().type === 'ident') {
      return this.parseIdentStatement(loc);
    }

    // Skip unknown
    this.advance();
    return null;
  }

  private parseAssertStatement(loc: SourceLocation): Statement {
    this.advance(); // 'assert'
    const expr = this.parseExpression();
    return {
      kind: 'expression_statement',
      expression: {
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'assert' },
        args: [expr],
      },
      sourceLocation: loc,
    };
  }

  private parseIfStatement(loc: SourceLocation): Statement {
    this.advance(); // 'if'
    const condition = this.parseExpression();
    this.expect(':');
    this.skipNewlines();
    this.expect('INDENT');
    const thenBranch = this.parseStatements();
    this.match('DEDENT');
    this.skipNewlines();

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elif') {
      // elif -> else { if ... }
      const elifLoc = this.loc();
      elseBranch = [this.parseElifStatement(elifLoc)];
    } else if (this.peek().type === 'else') {
      this.advance(); // 'else'
      this.expect(':');
      this.skipNewlines();
      this.expect('INDENT');
      elseBranch = this.parseStatements();
      this.match('DEDENT');
    }

    return {
      kind: 'if_statement',
      condition,
      then: thenBranch,
      else: elseBranch,
      sourceLocation: loc,
    };
  }

  private parseElifStatement(loc: SourceLocation): Statement {
    this.advance(); // 'elif'
    const condition = this.parseExpression();
    this.expect(':');
    this.skipNewlines();
    this.expect('INDENT');
    const thenBranch = this.parseStatements();
    this.match('DEDENT');
    this.skipNewlines();

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elif') {
      const elifLoc = this.loc();
      elseBranch = [this.parseElifStatement(elifLoc)];
    } else if (this.peek().type === 'else') {
      this.advance();
      this.expect(':');
      this.skipNewlines();
      this.expect('INDENT');
      elseBranch = this.parseStatements();
      this.match('DEDENT');
    }

    return {
      kind: 'if_statement',
      condition,
      then: thenBranch,
      else: elseBranch,
      sourceLocation: loc,
    };
  }

  private parseForStatement(loc: SourceLocation): Statement {
    this.advance(); // 'for'

    const iterVar = this.advance(); // loop variable
    const varName = snakeToCamel(iterVar.value);

    this.expect('in');
    this.expect('range');
    this.expect('(');

    // range(n) or range(a, b)
    const firstArg = this.parseExpression();
    let startExpr: Expression;
    let endExpr: Expression;

    if (this.match(',')) {
      startExpr = firstArg;
      endExpr = this.parseExpression();
    } else {
      startExpr = { kind: 'bigint_literal', value: 0n };
      endExpr = firstArg;
    }

    this.expect(')');
    this.expect(':');
    this.skipNewlines();
    this.expect('INDENT');
    const body = this.parseStatements();
    this.match('DEDENT');

    // Construct a C-style for loop AST node:
    // for (let varName = startExpr; varName < endExpr; varName++)
    const init = {
      kind: 'variable_decl' as const,
      name: varName,
      type: { kind: 'primitive_type' as const, name: 'bigint' as PrimitiveTypeName },
      mutable: true,
      init: startExpr,
      sourceLocation: loc,
    };

    const condition: Expression = {
      kind: 'binary_expr',
      op: '<' as BinaryOp,
      left: { kind: 'identifier', name: varName },
      right: endExpr,
    };

    const update: Statement = {
      kind: 'expression_statement',
      expression: { kind: 'increment_expr', operand: { kind: 'identifier', name: varName }, prefix: false },
      sourceLocation: loc,
    };

    return {
      kind: 'for_statement',
      init,
      condition,
      update,
      body,
      sourceLocation: loc,
    };
  }

  private parseReturnStatement(loc: SourceLocation): Statement {
    this.advance(); // 'return'
    let value: Expression | undefined;
    if (this.peek().type !== 'NEWLINE' && this.peek().type !== 'DEDENT' && this.peek().type !== 'eof') {
      value = this.parseExpression();
    }
    return { kind: 'return_statement', value, sourceLocation: loc };
  }

  private parseSuperCall(loc: SourceLocation): Statement {
    // super().__init__(...) or super().__init__(args)
    // In Python: super().__init__(a, b, c) -> super(a, b, c) in AST
    this.advance(); // 'super'
    this.expect('(');
    this.expect(')');
    this.expect('.');

    const methodTok = this.advance(); // __init__
    if (methodTok.value !== '__init__') {
      this.errors.push(makeDiagnostic(
        `Expected __init__ after super(), got '${methodTok.value}'`,
        'error',
        loc,
      ));
    }

    this.expect('(');
    const args: Expression[] = [];
    while (this.peek().type !== ')' && this.peek().type !== 'eof') {
      args.push(this.parseExpression());
      if (!this.match(',')) break;
    }
    this.expect(')');

    return {
      kind: 'expression_statement',
      expression: {
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'super' },
        args,
      },
      sourceLocation: loc,
    };
  }

  private parseSelfStatement(loc: SourceLocation): Statement {
    // self.prop = expr  or  self.prop += expr  or  self.method(...)
    const expr = this.parseExpression();

    // Assignment: self.x = expr
    if (this.match('=')) {
      const value = this.parseExpression();
      return { kind: 'assignment', target: expr, value, sourceLocation: loc };
    }

    // Compound assignment: self.x += expr, etc.
    const compoundOps: Record<string, BinaryOp> = {
      '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%', '//=': '/',
    };

    for (const [tok, binOp] of Object.entries(compoundOps)) {
      if (this.peek().type === tok) {
        this.advance();
        const right = this.parseExpression();
        const value: Expression = { kind: 'binary_expr', op: binOp, left: expr, right };
        return { kind: 'assignment', target: expr, value, sourceLocation: loc };
      }
    }

    // Expression statement (method call)
    return { kind: 'expression_statement', expression: expr, sourceLocation: loc };
  }

  private parseIdentStatement(loc: SourceLocation): Statement | null {
    // Could be:
    // 1. name: Type = expr  (variable declaration with type annotation)
    // 2. name = expr  (variable declaration without type, or assignment)
    // 3. name(...)  (expression statement / function call)
    // 4. name += expr (compound assignment)

    const nameTok = this.peek();
    const rawName = nameTok.value;

    // Look ahead: if next token after ident is ':', it's a typed variable decl
    if (this.tokens[this.pos + 1]?.type === ':') {
      // Variable declaration: name: Type = expr
      this.advance(); // ident
      this.advance(); // ':'
      const typeNode = this.parseType();
      let init: Expression;
      if (this.match('=')) {
        init = this.parseExpression();
      } else {
        init = { kind: 'bigint_literal', value: 0n };
      }
      return {
        kind: 'variable_decl',
        name: snakeToCamel(rawName),
        type: typeNode,
        mutable: true,
        init,
        sourceLocation: loc,
      };
    }

    // Check for simple name = expr pattern (no type annotation)
    // In Python, `x = expr` on its own is a variable declaration if x is a plain identifier.
    // This is distinct from `self.x = expr` which is an assignment.
    if (this.tokens[this.pos + 1]?.type === '=') {
      this.advance(); // consume ident
      this.advance(); // consume '='
      const value = this.parseExpression();
      return {
        kind: 'variable_decl',
        name: snakeToCamel(rawName),
        mutable: true,
        init: value,
        sourceLocation: loc,
      };
    }

    // Parse as expression first
    const expr = this.parseExpression();

    // Simple assignment: name = expr (shouldn't normally reach here for plain idents,
    // but handles cases like a.b = expr)
    if (this.match('=')) {
      const value = this.parseExpression();
      return { kind: 'assignment', target: expr, value, sourceLocation: loc };
    }

    // Compound assignment
    const compoundOps: Record<string, BinaryOp> = {
      '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%', '//=': '/',
    };

    for (const [tok, binOp] of Object.entries(compoundOps)) {
      if (this.peek().type === tok) {
        this.advance();
        const right = this.parseExpression();
        const value: Expression = { kind: 'binary_expr', op: binOp, left: expr, right };
        return { kind: 'assignment', target: expr, value, sourceLocation: loc };
      }
    }

    // Expression statement
    return { kind: 'expression_statement', expression: expr, sourceLocation: loc };
  }

  // ---------------------------------------------------------------------------
  // Expressions (precedence climbing)
  // ---------------------------------------------------------------------------

  private parseExpression(): Expression {
    return this.parseTernary();
  }

  // Python conditional expression: x if cond else y
  // We handle this as postfix: parse or-expr first, then check for 'if'
  private parseTernary(): Expression {
    const expr = this.parseOr();

    if (this.peek().type === 'if') {
      this.advance(); // 'if'
      const condition = this.parseOr();
      this.expect('else');
      const alternate = this.parseTernary();
      return { kind: 'ternary_expr', condition, consequent: expr, alternate };
    }

    return expr;
  }

  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.peek().type === 'or') {
      this.advance();
      const right = this.parseAnd();
      left = { kind: 'binary_expr', op: '||', left, right };
    }
    return left;
  }

  private parseAnd(): Expression {
    let left = this.parseNot();
    while (this.peek().type === 'and') {
      this.advance();
      const right = this.parseNot();
      left = { kind: 'binary_expr', op: '&&', left, right };
    }
    return left;
  }

  private parseNot(): Expression {
    if (this.peek().type === 'not') {
      this.advance();
      const operand = this.parseNot();
      return { kind: 'unary_expr', op: '!', operand };
    }
    return this.parseBitwiseOr();
  }

  private parseBitwiseOr(): Expression {
    let left = this.parseBitwiseXor();
    while (this.peek().type === '|') {
      this.advance();
      const right = this.parseBitwiseXor();
      left = { kind: 'binary_expr', op: '|', left, right };
    }
    return left;
  }

  private parseBitwiseXor(): Expression {
    let left = this.parseBitwiseAnd();
    while (this.peek().type === '^') {
      this.advance();
      const right = this.parseBitwiseAnd();
      left = { kind: 'binary_expr', op: '^', left, right };
    }
    return left;
  }

  private parseBitwiseAnd(): Expression {
    let left = this.parseEquality();
    while (this.peek().type === '&') {
      this.advance();
      const right = this.parseEquality();
      left = { kind: 'binary_expr', op: '&', left, right };
    }
    return left;
  }

  private parseEquality(): Expression {
    let left = this.parseComparison();
    while (true) {
      if (this.peek().type === '==') {
        this.advance();
        const right = this.parseComparison();
        left = { kind: 'binary_expr', op: '===', left, right };
      } else if (this.peek().type === '!=') {
        this.advance();
        const right = this.parseComparison();
        left = { kind: 'binary_expr', op: '!==', left, right };
      } else {
        break;
      }
    }
    return left;
  }

  private parseComparison(): Expression {
    let left = this.parseShift();
    while (true) {
      const t = this.peek().type;
      if (t === '<' || t === '<=' || t === '>' || t === '>=') {
        const op = this.advance().type as BinaryOp;
        const right = this.parseShift();
        left = { kind: 'binary_expr', op, left, right };
      } else {
        break;
      }
    }
    return left;
  }

  private parseShift(): Expression {
    let left = this.parseAddSub();
    while (true) {
      if (this.peek().type === '<<') {
        this.advance();
        const right = this.parseAddSub();
        left = { kind: 'binary_expr', op: '<<', left, right };
      } else if (this.peek().type === '>>') {
        this.advance();
        const right = this.parseAddSub();
        left = { kind: 'binary_expr', op: '>>', left, right };
      } else {
        break;
      }
    }
    return left;
  }

  private parseAddSub(): Expression {
    let left = this.parseMulDiv();
    while (true) {
      if (this.peek().type === '+') {
        this.advance();
        const right = this.parseMulDiv();
        left = { kind: 'binary_expr', op: '+', left, right };
      } else if (this.peek().type === '-') {
        this.advance();
        const right = this.parseMulDiv();
        left = { kind: 'binary_expr', op: '-', left, right };
      } else {
        break;
      }
    }
    return left;
  }

  private parseMulDiv(): Expression {
    let left = this.parseUnary();
    while (true) {
      if (this.peek().type === '*') {
        this.advance();
        const right = this.parseUnary();
        left = { kind: 'binary_expr', op: '*', left, right };
      } else if (this.peek().type === '//') {
        // Python integer division // maps to / in AST (OP_DIV)
        this.advance();
        const right = this.parseUnary();
        left = { kind: 'binary_expr', op: '/', left, right };
      } else if (this.peek().type === '/') {
        this.advance();
        const right = this.parseUnary();
        left = { kind: 'binary_expr', op: '/', left, right };
      } else if (this.peek().type === '%') {
        this.advance();
        const right = this.parseUnary();
        left = { kind: 'binary_expr', op: '%', left, right };
      } else {
        break;
      }
    }
    return left;
  }

  private parseUnary(): Expression {
    if (this.peek().type === '-') {
      this.advance();
      const operand = this.parseUnary();
      return { kind: 'unary_expr', op: '-', operand };
    }
    if (this.peek().type === '~') {
      this.advance();
      const operand = this.parseUnary();
      return { kind: 'unary_expr', op: '~', operand };
    }
    if (this.peek().type === '!') {
      this.advance();
      const operand = this.parseUnary();
      return { kind: 'unary_expr', op: '!', operand };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expression {
    let expr = this.parsePrimary();

    while (true) {
      // Method call or property access: expr.name or expr.name(...)
      if (this.peek().type === '.') {
        this.advance(); // '.'
        const propTok = this.advance();
        const propName = snakeToCamel(propTok.value);

        // Check if it's a method call
        if (this.peek().type === '(') {
          const args = this.parseCallArgs();
          // Handle self.method(...) → this.method(...)
          if (expr.kind === 'identifier' && (expr as { name: string }).name === 'this') {
            expr = {
              kind: 'call_expr',
              callee: { kind: 'member_expr', object: { kind: 'identifier', name: 'this' }, property: propName },
              args,
            };
          } else {
            expr = {
              kind: 'call_expr',
              callee: { kind: 'member_expr', object: expr, property: propName },
              args,
            };
          }
        } else {
          // Property access
          if (expr.kind === 'identifier' && (expr as { name: string }).name === 'this') {
            expr = { kind: 'property_access', property: propName };
          } else {
            expr = { kind: 'member_expr', object: expr, property: propName };
          }
        }
        continue;
      }

      // Function call: expr(...)
      if (this.peek().type === '(') {
        const args = this.parseCallArgs();
        expr = { kind: 'call_expr', callee: expr, args };
        continue;
      }

      // Index access: expr[index]
      if (this.peek().type === '[') {
        this.advance();
        const index = this.parseExpression();
        this.expect(']');
        expr = { kind: 'index_access', object: expr, index };
        continue;
      }

      break;
    }

    return expr;
  }

  private parsePrimary(): Expression {
    const tok = this.peek();

    // Number literal
    if (tok.type === 'number') {
      this.advance();
      const val = tok.value.startsWith('0x') || tok.value.startsWith('0X')
        ? BigInt(tok.value)
        : BigInt(tok.value);
      return { kind: 'bigint_literal', value: val };
    }

    // Boolean literals
    if (tok.type === 'True') {
      this.advance();
      return { kind: 'bool_literal', value: true };
    }
    if (tok.type === 'False') {
      this.advance();
      return { kind: 'bool_literal', value: false };
    }

    // Hex string literal (already parsed by tokenizer)
    if (tok.type === 'hexstring') {
      this.advance();
      return { kind: 'bytestring_literal', value: tok.value };
    }

    // String literal
    if (tok.type === 'string') {
      this.advance();
      return { kind: 'bytestring_literal', value: tok.value };
    }

    // Array literal: [expr, expr, ...]
    if (tok.type === '[') {
      this.advance();
      const elements: Expression[] = [];
      while (this.peek().type !== ']' && this.peek().type !== 'eof') {
        elements.push(this.parseExpression());
        if (this.peek().type === ',') this.advance();
      }
      this.expect(']');
      return { kind: 'array_literal', elements };
    }

    // bytes.fromhex("...")
    if (tok.type === 'ident' && tok.value === 'bytes') {
      // Check for bytes.fromhex("...")
      if (this.tokens[this.pos + 1]?.type === '.' && this.tokens[this.pos + 2]?.value === 'fromhex') {
        this.advance(); // 'bytes'
        this.advance(); // '.'
        this.advance(); // 'fromhex'
        this.expect('(');
        const strTok = this.advance(); // string literal
        this.expect(')');
        return { kind: 'bytestring_literal', value: strTok.value };
      }
    }

    // self -> this
    if (tok.type === 'self') {
      this.advance();
      return { kind: 'identifier', name: 'this' };
    }

    // Parenthesized expression
    if (tok.type === '(') {
      this.advance();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }

    // Identifier or function call
    if (tok.type === 'ident' || tok.type === 'assert') {
      this.advance();
      const rawName = tok.value;
      const name = mapBuiltinName(rawName);
      return { kind: 'identifier', name };
    }

    // None -> 0
    if (tok.type === 'None') {
      this.advance();
      return { kind: 'bigint_literal', value: 0n };
    }

    this.errors.push(makeDiagnostic(
      `Unexpected token in expression: '${tok.value || tok.type}'`,
      'error',
      this.loc(),
    ));
    this.advance();
    return { kind: 'bigint_literal', value: 0n };
  }

  private parseCallArgs(): Expression[] {
    this.expect('(');
    const args: Expression[] = [];
    while (this.peek().type !== ')' && this.peek().type !== 'eof') {
      args.push(this.parseExpression());
      if (!this.match(',')) break;
    }
    this.expect(')');
    return args;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parsePythonSource(source: string, fileName: string): ParseResult {
  const tokens = tokenize(source);
  const parser = new PyParser(tokens, fileName);
  return parser.parse();
}
