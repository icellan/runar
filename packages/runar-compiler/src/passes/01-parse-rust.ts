/**
 * Rust contract parser for Rúnar contracts.
 *
 * Parses `.runar.rs` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses hand-written recursive descent, extending ParserCore
 * for expression parsing.
 *
 * Rust contract syntax conventions:
 *   - `#[runar::contract]` attribute on struct
 *   - `#[runar::methods(Name)]` attribute on impl block
 *   - `#[public]` attribute on public methods
 *   - `#[readonly]` attribute on readonly fields
 *   - `&self` / `&mut self` method receivers (stripped)
 *   - `&Type` reference parameters (stripped)
 *   - `.clone()` calls (stripped)
 *   - `assert!(expr)` macro → assert(expr)
 *   - `snake_case` names → camelCase in AST
 *   - `init()` method for property initializers
 *   - `for i in 0..n { }` range loops
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
  | 'use' | 'pub' | 'struct' | 'impl' | 'fn' | 'let' | 'mut'
  | 'if' | 'else' | 'for' | 'in' | 'return'
  | 'true' | 'false' | 'self'
  | 'ident' | 'number' | 'hexstring' | 'string'
  | '(' | ')' | '{' | '}' | '[' | ']'
  | ';' | ',' | '.' | ':' | '::' | '->' | '#'
  | '+' | '-' | '*' | '/' | '%'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '&&' | '||'
  | '<<' | '>>'
  | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%='
  | '++' | '--'
  | '..'
  | 'eof';

interface RustToken extends Token {
  type: string; // TokenType (widened for ParserCore compatibility)
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['use', 'use'], ['pub', 'pub'], ['struct', 'struct'], ['impl', 'impl'],
  ['fn', 'fn'], ['let', 'let'], ['mut', 'mut'],
  ['if', 'if'], ['else', 'else'], ['for', 'for'], ['in', 'in'],
  ['return', 'return'],
  ['true', 'true'], ['false', 'false'],
  ['self', 'self'],
]);

function tokenize(source: string): RustToken[] {
  const tokens: RustToken[] = [];
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

    // Line comments (including doc comments ///)
    if (ch === '/' && peekN(1) === '/') {
      while (pos < source.length && peek() !== '\n') advance();
      continue;
    }

    // Block comments /* ... */
    if (ch === '/' && peekN(1) === '*') {
      advance(); advance();
      while (pos < source.length - 1) {
        if (peek() === '*' && peekN(1) === '/') { advance(); advance(); break; }
        advance();
      }
      continue;
    }

    // Two-char operators (order matters: check longer tokens first)
    if (ch === ':' && peekN(1) === ':') { advance(); advance(); add('::', '::', l, c); continue; }
    if (ch === '-' && peekN(1) === '>') { advance(); advance(); add('->', '->', l, c); continue; }
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
    if (ch === '.' && peekN(1) === '.') { advance(); advance(); add('..', '..', l, c); continue; }

    // Single-char operators & punctuation
    const singles = '(){}[];,.:+-*/%<>=&|^~!#';
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
// Name conversion: Rust snake_case → camelCase
// ---------------------------------------------------------------------------

function snakeToCamel(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Builtin name mapping (same as Move parser)
// ---------------------------------------------------------------------------

const RUST_BUILTIN_MAP: Record<string, string> = {
  // Hashing
  hash160: 'hash160', hash256: 'hash256', sha256: 'sha256', ripemd160: 'ripemd160',
  // Signature verification
  checkSig: 'checkSig', checkMultiSig: 'checkMultiSig',
  checkPreimage: 'checkPreimage', verifyRabinSig: 'verifyRabinSig',
  // Post-quantum signature verification
  verifyWOTS: 'verifyWOTS', verifyWots: 'verifyWOTS',
  // SLH-DSA: snake_to_camel may produce various forms; map all of them
  verifySlhDsaSha2128s: 'verifySLHDSA_SHA2_128s', verifySlhdsaSha2128s: 'verifySLHDSA_SHA2_128s',
  verifySlhDsaSha2128f: 'verifySLHDSA_SHA2_128f', verifySlhdsaSha2128f: 'verifySLHDSA_SHA2_128f',
  verifySlhDsaSha2192s: 'verifySLHDSA_SHA2_192s', verifySlhdsaSha2192s: 'verifySLHDSA_SHA2_192s',
  verifySlhDsaSha2192f: 'verifySLHDSA_SHA2_192f', verifySlhdsaSha2192f: 'verifySLHDSA_SHA2_192f',
  verifySlhDsaSha2256s: 'verifySLHDSA_SHA2_256s', verifySlhdsaSha2256s: 'verifySLHDSA_SHA2_256s',
  verifySlhDsaSha2256f: 'verifySLHDSA_SHA2_256f', verifySlhdsaSha2256f: 'verifySLHDSA_SHA2_256f',
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
  addOutput: 'addOutput', addRawOutput: 'addRawOutput',
  getStateScript: 'getStateScript',
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
  // SHA-256 partial
  sha256Compress: 'sha256Compress', sha256Finalize: 'sha256Finalize',
  // BLAKE3
  blake3Compress: 'blake3Compress', blake3Hash: 'blake3Hash',
};

/**
 * Map a Rust identifier (after snakeToCamel) to its Rúnar builtin name.
 * Falls through to the camelCase name if no explicit mapping exists.
 */
function mapRustBuiltin(name: string): string {
  return RUST_BUILTIN_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Type mapping: Rust types → Rúnar types
// ---------------------------------------------------------------------------

const RUST_TYPE_MAP: Record<string, string> = {
  Bigint: 'bigint', Int: 'bigint', i64: 'bigint', u64: 'bigint',
  i128: 'bigint', u128: 'bigint', i256: 'bigint', u256: 'bigint',
  Bool: 'boolean', bool: 'boolean',
  ByteString: 'ByteString',
  PubKey: 'PubKey', Sig: 'Sig', Sha256: 'Sha256',
  Ripemd160: 'Ripemd160', Addr: 'Addr',
  SigHashPreimage: 'SigHashPreimage',
  RabinSig: 'RabinSig', RabinPubKey: 'RabinPubKey',
  Point: 'Point',
};

function mapRustType(name: string): string {
  return RUST_TYPE_MAP[name] || name;
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
// Parser
// ---------------------------------------------------------------------------

class RustParser extends ParserCore<RustToken> {
  /** Self-names set for parsePostfixChain. Always contains 'self'. */
  private selfNames = new Set<string>(['self']);

  /** Name of the contract struct. */
  private contractName = '';

  parse(): ParseResult {
    // Skip `use runar::prelude::*;` and other use declarations
    this.skipUseDecls();

    let parentClass: 'SmartContract' | 'StatefulSmartContract' = 'SmartContract';
    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];

    // Parse top-level declarations
    while (this.current().type !== 'eof') {
      // Skip attributes at top level (handled within struct/impl parsing)
      if (this.current().type === '#') {
        const attr = this.parseAttribute();
        // Check for #[runar::contract] -> next should be struct
        if (attr === 'runar::contract') {
          // Optional pub keyword before struct
          if (this.current().type === 'pub') this.advance();
          if (this.current().type === 'struct') {
            const result = this.parseStructDecl();
            if (result) {
              this.contractName = result.name;
              parentClass = result.parentClass;
              properties.push(...result.properties);
            }
          }
          continue;
        }
        // Check for #[runar::methods(Name)] -> next should be impl
        if (attr.startsWith('runar::methods')) {
          if (this.current().type === 'impl') {
            const implMethods = this.parseImplBlock();
            methods.push(...implMethods);
          }
          continue;
        }
        // Other top-level attributes — skip
        continue;
      }

      if (this.current().type === 'pub' || this.current().type === 'struct') {
        // Struct without #[runar::contract] — still parse it
        if (this.current().type === 'pub') this.advance();
        if (this.current().type === 'struct') {
          const result = this.parseStructDecl();
          if (result) {
            this.contractName = result.name;
            parentClass = result.parentClass;
            properties.push(...result.properties);
          }
          continue;
        }
      }

      if (this.current().type === 'impl') {
        const implMethods = this.parseImplBlock();
        methods.push(...implMethods);
        continue;
      }

      // Skip unknown top-level tokens
      this.advance();
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
  // Use declaration skipping
  // -----------------------------------------------------------------------

  private skipUseDecls(): void {
    while (this.current().type === 'use') {
      while (this.current().type !== ';' && this.current().type !== 'eof') {
        this.advance();
      }
      if (this.current().type === ';') this.advance();
    }
  }

  // -----------------------------------------------------------------------
  // Attribute parsing: #[...] -> returns the attribute content as a string
  // -----------------------------------------------------------------------

  private parseAttribute(): string {
    this.expect('#');
    this.expect('[');
    let content = '';
    let depth = 1;
    while (depth > 0 && this.current().type !== 'eof') {
      if (this.current().type === '[') depth++;
      if (this.current().type === ']') {
        depth--;
        if (depth === 0) break;
      }
      if (content.length > 0 &&
          this.current().type !== '(' && this.current().type !== ')' &&
          this.current().type !== '::' &&
          content[content.length - 1] !== '(' && content[content.length - 1] !== ':') {
        // Intentionally don't add spaces between attribute tokens to keep it compact
      }
      content += this.current().value;
      this.advance();
    }
    this.expect(']');
    return content;
  }

  // -----------------------------------------------------------------------
  // Struct declaration
  // -----------------------------------------------------------------------

  private parseStructDecl(): {
    name: string;
    parentClass: 'SmartContract' | 'StatefulSmartContract';
    properties: PropertyNode[];
  } | null {
    this.expect('struct');
    const nameToken = this.expect('ident');
    const name = nameToken.value;
    this.expect('{');

    const properties: PropertyNode[] = [];
    let hasMutableField = false;

    while (this.current().type !== '}' && this.current().type !== 'eof') {
      const propLoc = this.loc();
      let readonly = false;

      // Check for #[readonly] attribute
      if (this.current().type === '#') {
        const attr = this.parseAttribute();
        if (attr === 'readonly') {
          readonly = true;
        }
      }

      // Skip optional `pub` keyword
      if (this.current().type === 'pub') this.advance();

      // Field name
      const fieldNameRaw = this.expect('ident').value;
      const fieldName = snakeToCamel(fieldNameRaw);

      // Colon + type
      this.expect(':');
      const propType = this.parseRustType();

      if (!readonly) hasMutableField = true;

      properties.push({
        kind: 'property',
        name: fieldName,
        type: propType,
        readonly,
        sourceLocation: propLoc,
      });

      // Skip trailing comma
      this.match(',');
    }
    this.expect('}');

    const parentClass = hasMutableField ? 'StatefulSmartContract' : 'SmartContract';

    return { name, parentClass, properties };
  }

  // -----------------------------------------------------------------------
  // Type parsing
  // -----------------------------------------------------------------------

  private parseRustType(): TypeNode {
    // Handle reference types: &Type, &mut Type
    if (this.current().type === '&') {
      this.advance();
      if (this.current().type === 'mut') this.advance();
      return this.parseRustType();
    }

    // Handle array types: [Type; N]
    if (this.current().type === '[') {
      this.advance();
      const element = this.parseRustType();
      this.expect(';');
      const length = parseInt(this.expect('number').value, 10);
      this.expect(']');
      return { kind: 'fixed_array_type', element, length };
    }

    if (this.current().type === 'ident' || this.current().type === 'self') {
      const typeName = this.advance().value;
      const mapped = mapRustType(typeName);
      return makePrimitiveOrCustom(mapped);
    }

    // bool keyword
    if (this.current().type === 'true' || this.current().type === 'false') {
      // This shouldn't happen in type position but handle it gracefully
      this.advance();
      return makePrimitiveOrCustom('boolean');
    }

    // Fallback
    this.advance();
    return { kind: 'custom_type', name: 'unknown' };
  }

  // -----------------------------------------------------------------------
  // Impl block: impl Name { methods... }
  // -----------------------------------------------------------------------

  private parseImplBlock(): MethodNode[] {
    this.expect('impl');
    // Skip struct name
    if (this.current().type === 'ident') this.advance();
    this.expect('{');

    const methods: MethodNode[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      // Check for attributes (#[public])
      let isPublic = false;
      while (this.current().type === '#') {
        const attr = this.parseAttribute();
        if (attr === 'public') {
          isPublic = true;
        }
      }

      // Doc comments are already handled by the tokenizer (skipped)

      // Skip optional `pub` keyword
      if (this.current().type === 'pub') this.advance();

      if (this.current().type === 'fn') {
        const method = this.parseFnDecl(isPublic);
        if (method) methods.push(method);
      } else {
        this.advance(); // skip unknown tokens in impl block
      }
    }
    this.expect('}');

    return methods;
  }

  // -----------------------------------------------------------------------
  // Function/method declaration
  // -----------------------------------------------------------------------

  private parseFnDecl(isPublic: boolean): MethodNode | null {
    const location = this.loc();
    this.expect('fn');

    // Method name
    const rawName = this.expect('ident').value;
    const name = snakeToCamel(rawName);

    // Parameters
    this.expect('(');
    const params: ParamNode[] = [];

    while (this.current().type !== ')' && this.current().type !== 'eof') {
      // Handle &self, &mut self, self
      if (this.current().type === '&') {
        this.advance();
        if (this.current().type === 'mut') this.advance();
        if (this.current().type === 'self') {
          this.advance();
          if (this.current().type === ',') this.advance();
          continue;
        }
        // If not self after &, this is a reference type parameter without name —
        // shouldn't happen in method signature, but handle gracefully
      }
      if (this.current().type === 'self') {
        this.advance();
        if (this.current().type === ',') this.advance();
        continue;
      }
      if (this.current().type === 'mut' &&
          this.tokens[this.pos + 1]?.type === 'self' as string) {
        this.advance(); // skip mut
        this.advance(); // skip self
        if (this.current().type === ',') this.advance();
        continue;
      }

      // Normal parameter: name: Type
      const paramNameRaw = this.expect('ident').value;
      this.expect(':');
      const paramType = this.parseRustType();

      params.push({
        kind: 'param',
        name: snakeToCamel(paramNameRaw),
        type: paramType,
      });

      if (this.current().type === ',') this.advance();
    }
    this.expect(')');

    // Optional return type: -> Type
    if (this.current().type === '->') {
      this.advance();
      this.parseRustType(); // consume and discard
    }

    // Body
    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    const visibility: 'public' | 'private' = isPublic ? 'public' : 'private';

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

    // return [expr];
    if (this.current().type === 'return') {
      this.advance();
      const value = (this.current().type !== ';' && this.current().type !== '}')
        ? this.parseExpression()
        : undefined;
      this.match(';');
      return { kind: 'return_statement', value, sourceLocation: location };
    }

    // if
    if (this.current().type === 'if') {
      return this.parseIfStatement();
    }

    // for i in 0..n { }
    if (this.current().type === 'for') {
      return this.parseForStatement();
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
        varType = this.parseRustType();
      }
      this.expect('=');
      const init = this.parseExpression();
      this.match(';');
      return { kind: 'variable_decl', name: varName, type: varType, mutable, init, sourceLocation: location };
    }

    // assert!(expr)
    if (this.current().type === 'ident' && this.current().value === 'assert' &&
        this.tokens[this.pos + 1]?.type === '!') {
      this.advance(); // skip 'assert'
      this.advance(); // skip '!'
      this.expect('(');
      const expr = this.parseExpression();
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

    // Expression statement (including assignments, calls, etc.)
    const expr = this.parseExpression();

    // Assignment: expr = expr
    if (this.current().type === '=') {
      this.advance();
      const value = this.parseExpression();
      this.match(';');
      return { kind: 'assignment', target: expr, value, sourceLocation: location };
    }

    // Compound assignments: +=, -=, *=, /=, %=
    if (this.current().type === '+=') {
      this.advance();
      const rhs = this.parseExpression();
      this.match(';');
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
      this.match(';');
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
      this.match(';');
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
      this.match(';');
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
      this.match(';');
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
      this.match(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'increment_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }
    if (this.current().type === '--') {
      this.advance();
      this.match(';');
      return {
        kind: 'expression_statement',
        expression: { kind: 'decrement_expr', operand: expr, prefix: false },
        sourceLocation: location,
      };
    }

    this.match(';');
    return { kind: 'expression_statement', expression: expr, sourceLocation: location };
  }

  private parseIfStatement(): Statement {
    const location = this.loc();
    this.expect('if');

    // Rust if has no parentheses around the condition
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
        // else if -> nested if_statement in the else branch
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

    // for i in 0..n { body }
    // Parse loop variable
    const loopVarRaw = this.expect('ident').value;
    const loopVar = snakeToCamel(loopVarRaw);
    this.expect('in');

    // Parse range: start..end
    const startExpr = this.parseExpression();

    // The '..' should have been consumed inside the expression parser if the
    // start is a literal, OR it might be the next token. We already lex '..'
    // as a single token. The expression parser does NOT handle '..', so it
    // will stop before consuming it.
    this.expect('..');
    const endExpr = this.parseExpression();

    this.expect('{');
    const body: Statement[] = [];
    while (this.current().type !== '}' && this.current().type !== 'eof') {
      body.push(this.parseStatement());
    }
    this.expect('}');

    // Translate to C-style for: init=let i=start, cond=i<end, update=i++
    const init = {
      kind: 'variable_decl' as const,
      name: loopVar,
      mutable: true,
      init: startExpr,
      sourceLocation: location,
    };
    const condition = {
      kind: 'binary_expr' as const,
      op: '<' as const,
      left: { kind: 'identifier' as const, name: loopVar },
      right: endExpr,
    };
    const update: Statement = {
      kind: 'expression_statement' as const,
      expression: {
        kind: 'increment_expr' as const,
        operand: { kind: 'identifier' as const, name: loopVar },
        prefix: false,
      },
      sourceLocation: location,
    };

    return {
      kind: 'for_statement',
      init,
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
   * Override parsePostfixChain to apply snakeToCamel conversion on member
   * access properties and handle .clone() stripping.
   *
   * When the object is 'self', the property name is converted from snake_case
   * to camelCase and a `property_access` node is generated.
   *
   * `.clone()` calls are stripped — the expression becomes just the object.
   */
  protected parsePostfixChain(expr: Expression, selfNames: Set<string>): Expression {
    while (true) {
      if (this.current().type === '(') {
        // Function call
        this.advance();
        const args: Expression[] = [];
        while (this.current().type !== ')' && this.current().type !== 'eof') {
          // Strip leading & in arguments (reference operator)
          if (this.current().type === '&') {
            this.advance();
            // Skip 'mut' after &
            if (this.current().type === 'mut') this.advance();
          }
          args.push(this.parseExpression());
          if (this.current().type === ',') this.advance();
        }
        this.expect(')');
        expr = { kind: 'call_expr', callee: expr, args };
      } else if (this.current().type === '.') {
        this.advance();
        const rawProp = this.current().value;
        this.advance();
        const prop = snakeToCamel(rawProp);

        // Check for .clone() — strip it
        if (prop === 'clone' && this.current().type === '(') {
          this.advance(); // '('
          this.expect(')');
          // expr stays unchanged — clone is stripped
          continue;
        }

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
    // Skip reference operator & in expression context
    if (this.current().type === '&') {
      this.advance();
      if (this.current().type === 'mut') this.advance();
      return this.parseUnary();
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

    // String literal — used for hex-encoded ByteString values
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

    // self keyword
    if (t.type === 'self') {
      this.advance();
      return { kind: 'identifier', name: 'self' };
    }

    // Identifier
    if (t.type === 'ident') {
      this.advance();
      const camelName = snakeToCamel(t.value);
      const name = mapRustBuiltin(camelName);
      return { kind: 'identifier', name };
    }

    // Fallback
    this.advance();
    return { kind: 'identifier', name: t.value };
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseRustSource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.rs';
  const tokens = tokenize(source);
  const parser = new RustParser(tokens, file);
  return parser.parse();
}
