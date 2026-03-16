/**
 * Go contract parser for Rúnar contracts.
 *
 * Parses `.runar.go` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses hand-written recursive descent, extending ParserCore
 * for expression parsing.
 *
 * Go contract syntax conventions:
 *   - `type Foo struct { runar.SmartContract; ... }` / `runar.StatefulSmartContract`
 *   - `func (c *Foo) Method(...)` for methods (capitalized = public)
 *   - `func helper(...)` for standalone private helpers
 *   - `c.Field` for property access (maps to `this.Field`)
 *   - `runar.Assert(...)` for assertions
 *   - `runar.X(args)` for builtins (PascalCase → camelCase)
 *   - ``runar:"readonly"`` struct tags for immutable properties
 *   - `init()` method for property initializers
 *   - PascalCase names → camelCase in AST (PubKeyHash → pubKeyHash, Unlock → unlock)
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
} from '../ir/index.js';
import type { ParseResult } from './01-parse.js';
import { ParserCore } from './parser-core.js';
import type { Token } from './parser-core.js';

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type TokenType =
  | 'package' | 'import' | 'type' | 'struct' | 'func'
  | 'if' | 'else' | 'for' | 'return' | 'var'
  | 'true' | 'false'
  | 'ident' | 'number' | 'hexstring' | 'string'
  | '(' | ')' | '{' | '}' | '[' | ']'
  | ';' | ',' | '.' | ':'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '<<' | '>>'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%=' | ':='
  | '++' | '--'
  | 'backtick'
  | 'eof';

interface GoToken extends Token {
  type: string; // TokenType (widened for ParserCore compatibility)
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['package', 'package'], ['import', 'import'], ['type', 'type'],
  ['struct', 'struct'], ['func', 'func'],
  ['if', 'if'], ['else', 'else'], ['for', 'for'],
  ['return', 'return'], ['var', 'var'],
  ['true', 'true'], ['false', 'false'],
]);

function tokenize(source: string): GoToken[] {
  const tokens: GoToken[] = [];
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

    // Backtick-delimited struct tags
    if (ch === '`') {
      let val = '';
      advance(); // consume opening backtick
      while (pos < source.length && peek() !== '`') {
        val += advance();
      }
      if (pos < source.length) advance(); // consume closing backtick
      add('backtick', val, l, c);
      continue;
    }

    // Three-char operators: <<=, >>= (not needed, but :=)
    if (ch === ':' && peekN(1) === '=') { advance(); advance(); add(':=', ':=', l, c); continue; }

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

    // Single-char operators & punctuation
    const singles = '(){}[];,.:+-*/%<>=&|^~!';
    if (singles.includes(ch as string)) {
      advance();
      add(ch as TokenType, ch, l, c);
      continue;
    }

    // String literal
    if (ch === '"') {
      let val = '';
      advance(); // consume opening quote
      while (pos < source.length && peek() !== '"') {
        if (peek() === '\\') {
          advance(); // skip backslash
          val += advance(); // take escaped char
        } else {
          val += advance();
        }
      }
      if (pos < source.length) advance(); // consume closing quote
      add('string', val, l, c);
      continue;
    }

    // Hex literal: 0x...
    if (ch === '0' && peekN(1) === 'x') {
      let val = '';
      advance(); advance(); // consume 0x
      while (pos < source.length && /[0-9a-fA-F]/.test(peek())) {
        val += advance();
      }
      add('hexstring', val, l, c);
      continue;
    }

    // Number
    if (/[0-9]/.test(ch)) {
      let val = '';
      while (pos < source.length && /[0-9_]/.test(peek())) {
        val += advance();
      }
      add('number', val.replace(/_/g, ''), l, c);
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
// Name conversion: Go PascalCase → camelCase
// ---------------------------------------------------------------------------

/**
 * Convert a Go-style exported name to camelCase for the Rúnar AST.
 * e.g., "PubKeyHash" -> "pubKeyHash", "AddOutput" -> "addOutput"
 * Lowercase names pass through unchanged.
 */
function goToCamel(name: string): string {
  if (name.length === 0) return name;
  const first = name[0]!;
  if (first !== first.toUpperCase() || first === first.toLowerCase()) {
    // Already starts with lowercase (or non-letter)
    return name;
  }
  return first.toLowerCase() + name.slice(1);
}

// ---------------------------------------------------------------------------
// Type mapping: Go types → Rúnar types
// ---------------------------------------------------------------------------

const GO_TYPE_MAP: Record<string, string> = {
  Int: 'bigint', Bigint: 'bigint',
  Bool: 'boolean', bool: 'boolean', int: 'bigint',
  ByteString: 'ByteString',
  PubKey: 'PubKey', Sig: 'Sig', Sha256: 'Sha256',
  Ripemd160: 'Ripemd160', Addr: 'Addr',
  SigHashPreimage: 'SigHashPreimage',
  RabinSig: 'RabinSig', RabinPubKey: 'RabinPubKey',
  Point: 'Point',
};

function mapGoType(name: string): string {
  return GO_TYPE_MAP[name] || name;
}

const PRIMITIVE_TYPES = new Set([
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
// Builtin mapping: Go PascalCase → Rúnar camelCase
// ---------------------------------------------------------------------------

const GO_BUILTIN_MAP: Record<string, string> = {
  // Assertions
  Assert: 'assert',
  // Hashing
  Hash160: 'hash160', Hash256: 'hash256', Sha256: 'sha256', Ripemd160: 'ripemd160',
  // Signature verification
  CheckSig: 'checkSig', CheckMultiSig: 'checkMultiSig',
  CheckPreimage: 'checkPreimage', VerifyRabinSig: 'verifyRabinSig',
  // Post-quantum signature verification
  VerifyWOTS: 'verifyWOTS',
  VerifySLHDSA_SHA2_128s: 'verifySLHDSA_SHA2_128s',
  VerifySLHDSA_SHA2_128f: 'verifySLHDSA_SHA2_128f',
  VerifySLHDSA_SHA2_192s: 'verifySLHDSA_SHA2_192s',
  VerifySLHDSA_SHA2_192f: 'verifySLHDSA_SHA2_192f',
  VerifySLHDSA_SHA2_256s: 'verifySLHDSA_SHA2_256s',
  VerifySLHDSA_SHA2_256f: 'verifySLHDSA_SHA2_256f',
  // Byte operations
  Num2Bin: 'num2bin', Bin2Num: 'bin2num', Int2Str: 'int2str',
  Cat: 'cat', Substr: 'substr', Split: 'split',
  Left: 'left', Right: 'right',
  Len: 'len', Pack: 'pack', Unpack: 'unpack',
  ReverseBytes: 'reverseBytes', ToByteString: 'toByteString',
  ToBool: 'bool',
  // Preimage extractors
  ExtractVersion: 'extractVersion',
  ExtractHashPrevouts: 'extractHashPrevouts',
  ExtractHashSequence: 'extractHashSequence',
  ExtractOutpoint: 'extractOutpoint',
  ExtractScriptCode: 'extractScriptCode',
  ExtractSequence: 'extractSequence',
  ExtractSigHashType: 'extractSigHashType',
  ExtractInputIndex: 'extractInputIndex',
  ExtractOutputs: 'extractOutputs',
  ExtractOutputHash: 'extractOutputHash',
  ExtractAmount: 'extractAmount',
  ExtractLocktime: 'extractLocktime',
  // Output construction
  AddOutput: 'addOutput', AddRawOutput: 'addRawOutput',
  GetStateScript: 'getStateScript',
  // Math builtins
  Abs: 'abs', Min: 'min', Max: 'max', Within: 'within',
  Safediv: 'safediv', Safemod: 'safemod', Clamp: 'clamp', Sign: 'sign',
  Pow: 'pow', MulDiv: 'mulDiv', PercentOf: 'percentOf', Sqrt: 'sqrt',
  Gcd: 'gcd', Divmod: 'divmod', Log2: 'log2',
  // EC builtins
  EcAdd: 'ecAdd', EcMul: 'ecMul', EcMulGen: 'ecMulGen',
  EcNegate: 'ecNegate', EcOnCurve: 'ecOnCurve', EcModReduce: 'ecModReduce',
  EcEncodeCompressed: 'ecEncodeCompressed', EcMakePoint: 'ecMakePoint',
  EcPointX: 'ecPointX', EcPointY: 'ecPointY',
  // SHA-256 partial
  Sha256Compress: 'sha256Compress', Sha256Finalize: 'sha256Finalize',
};

/** Known type names used for type cast detection. */
const GO_CAST_TYPES = new Set([
  'Int', 'Bigint', 'Bool', 'ByteString', 'PubKey', 'Sig', 'Sha256',
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point',
]);

function mapGoBuiltin(name: string): string {
  if (GO_BUILTIN_MAP[name]) return GO_BUILTIN_MAP[name]!;
  // Default: lowercase first letter
  if (name.length === 0) return name;
  return name[0]!.toLowerCase() + name.slice(1);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class GoParser extends ParserCore<GoToken> {
  /**
   * The self-names set used by parsePostfixChain. Contains the current
   * receiver name so `c.Field` maps to `property_access`.
   */
  private selfNames = new Set<string>();

  /**
   * Name of the contract struct, used to verify receiver types.
   */
  private contractName = '';

  parse(): ParseResult {
    // Skip `package contract`
    if (this.current().type === 'package') {
      this.advance();
      if (this.current().type === 'ident') this.advance();
    }

    // Skip `import runar "..."`
    this.skipImports();

    let parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];

    // Parse top-level declarations
    while (this.current().type !== 'eof') {
      if (this.current().type === 'type') {
        // struct declaration
        const result = this.parseStructDecl();
        if (result) {
          this.contractName = result.name;
          parentClass = result.parentClass;
          properties.push(...result.properties);
        }
      } else if (this.current().type === 'func') {
        const method = this.parseFuncDecl();
        if (method) {
          methods.push(method);
        }
      } else {
        this.advance(); // skip unknown top-level tokens
      }
    }

    // Process init() method: extract property initializers
    const finalMethods: MethodNode[] = [];
    for (const m of methods) {
      if (m.name === 'init' && m.params.length === 0) {
        // Extract property assignments as initializers
        for (const stmt of m.body) {
          if (stmt.kind === 'assignment' && stmt.target.kind === 'property_access') {
            const propName = stmt.target.property;
            for (let i = 0; i < properties.length; i++) {
              if (properties[i]!.name === propName) {
                properties[i] = { ...properties[i]!, initializer: stmt.value };
                break;
              }
            }
          }
        }
      } else {
        finalMethods.push(m);
      }
    }

    // Build auto-generated constructor
    const loc: SourceLocation = { file: this.file, line: 1, column: 1 };
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
      name: this.contractName || 'UnnamedContract',
      parentClass,
      properties,
      constructor: constructorNode,
      methods: finalMethods,
      sourceFile: this.file,
    };

    return { contract, errors: this.errors };
  }

  // -----------------------------------------------------------------------
  // Import skipping
  // -----------------------------------------------------------------------

  private skipImports(): void {
    while (this.current().type === 'import') {
      this.advance();
      if (this.current().type === '(') {
        // import ( ... )
        this.advance();
        while (this.current().type !== ')' && this.current().type !== 'eof') {
          this.advance();
        }
        if (this.current().type === ')') this.advance();
      } else {
        // import runar "..."
        // Could be: import ident "string"
        while (this.current().type !== 'eof') {
          const t = this.current().type;
          if (t === 'type' || t === 'func' || t === 'import' || t === 'package' || t === 'var') break;
          this.advance();
        }
      }
    }
  }

  // -----------------------------------------------------------------------
  // Struct declaration
  // -----------------------------------------------------------------------

  private parseStructDecl(): {
    name: string;
    parentClass: 'SmartContract' | 'StatefulSmartContract';
    properties: PropertyNode[];
  } | null {
    this.expect('type');
    const nameToken = this.expect('ident');
    const name = nameToken.value;
    this.expect('struct');
    this.expect('{');

    let parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
    const properties: PropertyNode[] = [];

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      const propLoc = this.loc();

      // Check for embedded type: runar.SmartContract / runar.StatefulSmartContract
      if (this.current().type === 'ident' && this.current().value === 'runar' &&
          this.tokens[this.pos + 1]?.type === '.') {
        this.advance(); // skip 'runar'
        this.advance(); // skip '.'
        const embedName = this.expect('ident').value;
        if (embedName === 'StatefulSmartContract') {
          parentClass = 'StatefulSmartContract';
        }
        continue;
      }

      // Property: Name Type [`runar:"readonly"`]
      // Handle comma-separated field names: X, Y runar.Bigint
      const fieldNames: string[] = [];
      fieldNames.push(this.expect('ident').value);

      while (this.current().type === ',') {
        this.advance();
        fieldNames.push(this.expect('ident').value);
      }

      // Parse type
      const propType = this.parseGoType();

      // Check for struct tag
      let readonly = false;
      if (this.current().type === 'backtick') {
        const tagValue = this.current().value;
        if (tagValue.includes('runar:"readonly"')) {
          readonly = true;
        }
        this.advance();
      }

      for (const fieldName of fieldNames) {
        properties.push({
          kind: 'property',
          name: goToCamel(fieldName),
          type: propType,
          readonly,
          sourceLocation: propLoc,
        });
      }
    }
    this.expect('}');

    return { name, parentClass, properties };
  }

  // -----------------------------------------------------------------------
  // Type parsing
  // -----------------------------------------------------------------------

  private parseGoType(): TypeNode {
    // Handle runar.TypeName
    if (this.current().type === 'ident' && this.current().value === 'runar' &&
        this.tokens[this.pos + 1]?.type === '.') {
      this.advance(); // skip 'runar'
      this.advance(); // skip '.'
      const typeName = this.expect('ident').value;
      const mapped = mapGoType(typeName);
      return makePrimitiveOrCustom(mapped);
    }

    // Handle bare types: bool, int, etc.
    if (this.current().type === 'ident') {
      const typeName = this.advance().value;
      const mapped = mapGoType(typeName);
      return makePrimitiveOrCustom(mapped);
    }

    // Handle array types: [N]Type
    if (this.current().type === '[') {
      this.advance();
      const length = parseInt(this.expect('number').value, 10);
      this.expect(']');
      const element = this.parseGoType();
      return { kind: 'fixed_array_type', element, length };
    }

    // Fallback
    this.advance();
    return { kind: 'custom_type', name: 'unknown' };
  }

  // -----------------------------------------------------------------------
  // Function/method declaration
  // -----------------------------------------------------------------------

  private parseFuncDecl(): MethodNode | null {
    const location = this.loc();
    this.expect('func');

    // Check for receiver: (c *Type)
    let hasReceiver = false;
    let recvName = '';

    if (this.current().type === '(') {
      // This is a method with a receiver
      this.advance(); // '('
      recvName = this.expect('ident').value;
      // Skip '*'
      if (this.current().type === '*') this.advance();
      // Skip type name
      if (this.current().type === 'ident') this.advance();
      this.expect(')');
      hasReceiver = true;
    }

    // Method/function name
    const funcName = this.expect('ident').value;

    // Set receiver name for this method
    if (hasReceiver) {
      this.selfNames = new Set([recvName]);
    } else {
      this.selfNames = new Set();
    }

    // Parameters
    this.expect('(');
    const params: ParamNode[] = [];
    while (this.current().type !== ')' && this.current().type !== 'eof') {
      // Handle grouped params: x, y runar.Bigint
      const paramNames: string[] = [];
      paramNames.push(this.expect('ident').value);

      while (this.current().type === ',') {
        // Peek ahead: is this another param name followed by a type, or a new param group?
        // If next token after comma is an ident and the one after that is a comma or ')' or runar, it's still names.
        // If next token after comma is an ident and then '.', it's a new param group (runar.Type).
        const savedPos = this.pos;
        this.advance(); // skip ','

        // Check if this looks like a type (runar.X or bare type)
        if (this.current().type === 'ident') {
          const lookahead1 = this.tokens[this.pos + 1];
          if (lookahead1 && lookahead1.type === '.') {
            // This could be runar.Type for a new param, or more names followed by runar.Type
            // Look further: if after runar.Type there's a comma or ), it's a type for the group
            // If the current ident is 'runar', this is a type
            if (this.current().value === 'runar') {
              // This is the type for the current group - don't consume
              this.pos = savedPos;
              break;
            }
            // Otherwise it's another param name
            paramNames.push(this.expect('ident').value);
          } else if (lookahead1 && (lookahead1.type === ',' || lookahead1.type === ')')) {
            // identifier followed by comma or ) — could be more names without type yet
            // but in Go, this means it's another name in the same group
            paramNames.push(this.expect('ident').value);
          } else {
            // identifier followed by something else — could be a name with a following type
            // Check if after this ident, the next token is runar/type-ish or comma
            // Since we're looking at simple patterns, assume it's another name if followed by a known Go keyword type
            paramNames.push(this.expect('ident').value);
          }
        } else {
          // Not an ident after comma — restore and break
          this.pos = savedPos;
          break;
        }
      }

      // Parse type
      const pType = this.parseGoType();

      for (const pName of paramNames) {
        params.push({ kind: 'param', name: goToCamel(pName), type: pType });
      }

      if (this.current().type === ',') this.advance();
    }
    this.expect(')');

    // Optional return type
    if (this.current().type !== '{') {
      // Skip return type: could be runar.Bigint, bool, etc.
      this.parseGoType();
    }

    // Body
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    // Determine visibility: capitalized = public, lowercase = private
    const isExported = funcName.length > 0 && funcName[0]! === funcName[0]!.toUpperCase() &&
                       funcName[0]! !== funcName[0]!.toLowerCase();
    let visibility: 'public' | 'private' = isExported ? 'public' : 'private';

    // Standalone functions are always private
    if (!hasReceiver) {
      visibility = 'private';
    }

    // Convert method name from Go PascalCase to Rúnar camelCase
    const name = goToCamel(funcName);

    return {
      kind: 'method',
      name,
      params,
      body,
      visibility,
      sourceLocation: location,
    };
  }

  // -----------------------------------------------------------------------
  // Statement parsing
  // -----------------------------------------------------------------------

  private parseStatement(): Statement {
    const location = this.loc();

    // return
    if (this.current().type === 'return') {
      this.advance();
      // Return value is optional; if the next token is '}' there's no value
      const value = this.current().type !== '}' ? this.parseExpression() : undefined;
      return { kind: 'return_statement', value, sourceLocation: location };
    }

    // if
    if (this.current().type === 'if') {
      return this.parseIfStatement();
    }

    // for
    if (this.current().type === 'for') {
      return this.parseForStatement();
    }

    // var declaration: var name Type = expr
    if (this.current().type === 'var') {
      this.advance();
      const varName = goToCamel(this.expect('ident').value);
      const varType = this.parseGoType();
      this.expect('=');
      const init = this.parseExpression();
      return {
        kind: 'variable_decl',
        name: varName,
        type: varType,
        mutable: true,
        init,
        sourceLocation: location,
      };
    }

    // Short variable declaration: name := expr
    // We need to distinguish: ident := expr  vs  expr (which starts with ident)
    if (this.current().type === 'ident' && this.tokens[this.pos + 1]?.type === ':=') {
      const varName = goToCamel(this.advance().value);
      this.advance(); // skip ':='
      const init = this.parseExpression();
      return {
        kind: 'variable_decl',
        name: varName,
        mutable: true,
        init,
        sourceLocation: location,
      };
    }

    // Expression statement (including assignments, inc/dec, calls)
    const expr = this.parseExpression();

    // Assignment: expr = expr
    if (this.current().type === '=') {
      this.advance();
      const value = this.parseExpression();
      return { kind: 'assignment', target: expr, value, sourceLocation: location };
    }

    // Compound assignments: +=, -=, *=, /=, %=
    if (this.current().type === '+=') {
      this.advance();
      const rhs = this.parseExpression();
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
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '-', left: expr, right: rhs },
        sourceLocation: location,
      };
    }
    if (this.current().type === '*=') {
      this.advance();
      const rhs = this.parseExpression();
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '*', left: expr, right: rhs },
        sourceLocation: location,
      };
    }
    if (this.current().type === '/=') {
      this.advance();
      const rhs = this.parseExpression();
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '/', left: expr, right: rhs },
        sourceLocation: location,
      };
    }
    if (this.current().type === '%=') {
      this.advance();
      const rhs = this.parseExpression();
      return {
        kind: 'assignment',
        target: expr,
        value: { kind: 'binary_expr', op: '%', left: expr, right: rhs },
        sourceLocation: location,
      };
    }

    // Postfix ++ / -- as statements
    if (this.current().type === '++') {
      this.advance();
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }
    if (this.current().type === '--') {
      this.advance();
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }

    return { kind: 'expression_statement', expression: expr, sourceLocation: location };
  }

  private parseIfStatement(): Statement {
    const location = this.loc();
    this.expect('if');

    // Go if condition has no parentheses
    const condition = this.parseExpression();
    this.expect('{');
    const thenBranch: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      thenBranch.push(this.parseStatement());
    }
    this.expect('}');

    let elseBranch: Statement[] | undefined;
    if (this.current().type === 'else') {
      this.advance();
      if (this.current().type === 'if') {
        // else if — parse as nested if_statement in the else branch
        elseBranch = [this.parseIfStatement()];
      } else {
        this.expect('{');
        elseBranch = [];
        while (this.current().type !== '}' && this.current().type !== 'eof') {
          elseBranch.push(this.parseStatement());
        }
        this.expect('}');
      }
    }

    return { kind: 'if_statement', condition, then: thenBranch, else: elseBranch, sourceLocation: location };
  }

  private parseForStatement(): Statement {
    const location = this.loc();
    this.expect('for');

    // Init: i := 0 (or var i int = 0)
    let initStmt: Statement;
    if (this.current().type === 'var') {
      initStmt = this.parseStatement();
    } else {
      // Short variable declaration: name := expr
      const initName = goToCamel(this.expect('ident').value);
      this.expect(':=');
      const initValue = this.parseExpression();
      initStmt = {
        kind: 'variable_decl',
        name: initName,
        mutable: true,
        init: initValue,
        sourceLocation: location,
      };
    }

    this.expect(';');

    // Condition
    const condition = this.parseExpression();
    this.expect(';');

    // Update: i++ or i-- or expr
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
    } else if (this.current().type === '+=') {
      this.advance();
      const rhs = this.parseExpression();
      update = {
        kind: 'assignment',
        target: updateExpr,
        value: { kind: 'binary_expr', op: '+', left: updateExpr, right: rhs },
        sourceLocation: location,
      };
    } else if (this.current().type === '-=') {
      this.advance();
      const rhs = this.parseExpression();
      update = {
        kind: 'assignment',
        target: updateExpr,
        value: { kind: 'binary_expr', op: '-', left: updateExpr, right: rhs },
        sourceLocation: location,
      };
    } else {
      update = { kind: 'expression_statement', expression: updateExpr, sourceLocation: location };
    }

    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    return {
      kind: 'for_statement',
      init: initStmt as any, // VariableDeclStatement
      condition,
      update,
      body,
      sourceLocation: location,
    };
  }

  // -----------------------------------------------------------------------
  // Expression parsing — ParserCore abstract methods
  // -----------------------------------------------------------------------

  /**
   * Override parsePostfixChain to apply goToCamel conversion on member
   * access properties. When the object is the receiver (self), the
   * property name is converted from PascalCase to camelCase to match the
   * Rúnar AST convention (e.g., c.PubKeyHash → this.pubKeyHash).
   * Non-self member accesses also get camelCase conversion.
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
        const rawProp = this.current().value;
        this.advance();
        const prop = goToCamel(rawProp);
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
    if (this.current().type === '^') {
      // Go uses ^ as bitwise NOT (complement) when used as unary prefix
      this.advance();
      return { kind: 'unary_expr', op: '~', operand: this.parseUnary() };
    }

    let expr = this.parsePrimary();
    expr = this.parsePostfixChain(expr, this.selfNames);
    return expr;
  }

  protected parsePrimary(): Expression {
    const t = this.current();

    // Number literal
    if (t.type === 'number') {
      this.advance();
      return { kind: 'bigint_literal', value: BigInt(t.value) };
    }

    // Hex string literal
    if (t.type === 'hexstring') {
      this.advance();
      return { kind: 'bytestring_literal', value: t.value };
    }

    // String literal — used for hex-encoded ByteString values in Go contracts
    if (t.type === 'string') {
      this.advance();
      return { kind: 'bytestring_literal', value: t.value };
    }

    // Boolean literals
    if (t.type === 'true') {
      this.advance();
      return { kind: 'bool_literal', value: true };
    }
    if (t.type === 'false') {
      this.advance();
      return { kind: 'bool_literal', value: false };
    }

    // Parenthesized expression
    if (t.type === '(') {
      this.advance();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }

    // Array literal: [expr, expr, ...]
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

    // Identifier — handles runar.X, receiver.Field, plain idents
    if (t.type === 'ident') {
      this.advance();

      // Check for runar.X(args) — builtin call or type cast
      if (t.value === 'runar' && this.current().type === '.') {
        this.advance(); // skip '.'
        const memberName = this.expect('ident').value;

        // Check for type cast: runar.Bigint(expr), runar.Bool(expr), etc.
        if (GO_CAST_TYPES.has(memberName) && this.current().type === '(') {
          this.advance(); // '('
          const inner = this.parseExpression();
          this.expect(')');
          return inner; // unwrap type cast
        }

        // Map to builtin name
        const builtinName = mapGoBuiltin(memberName);
        return { kind: 'identifier', name: builtinName };
      }

      // Receiver access: c (or whatever the receiver name is) — will be
      // resolved to property_access by parsePostfixChain when followed by '.'
      // Non-receiver identifiers get camelCase conversion (e.g., function names)
      if (this.selfNames.has(t.value)) {
        return { kind: 'identifier', name: t.value };
      }
      return { kind: 'identifier', name: goToCamel(t.value) };
    }

    // Fallback
    this.advance();
    return { kind: 'identifier', name: t.value };
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseGoSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.go';
  const tokens = tokenize(source);
  const parser = new GoParser(tokens, file);
  return parser.parse();
}
