/**
 * Ruby parser for Rúnar contracts.
 *
 * Parses `.runar.rb` files into the same Rúnar AST that the TypeScript
 * parser produces. Uses a hand-written tokenizer plus recursive descent.
 *
 * Ruby syntax conventions:
 *   - `class Foo < Runar::SmartContract` / `class Foo < Runar::StatefulSmartContract`
 *   - `runar_public` marker for public methods (with optional param types)
 *   - `@instance_var` for property access (maps to `this.prop`)
 *   - `prop :name, Type [, readonly: true]` for typed property declarations
 *   - `assert expr` for assertions
 *   - `snake_case` names converted to `camelCase` in AST
 *   - `and`/`or`/`not` for boolean operators (alongside `&&`/`||`/`!`)
 *   - `end` keyword terminates blocks (no significant whitespace)
 *   - `unless` maps to if with negated condition
 *   - `for i in 0...n` / `for i in 0..n` for bounded loops
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
  | 'class' | 'def' | 'if' | 'elsif' | 'else' | 'unless' | 'for' | 'in'
  | 'end' | 'return' | 'true' | 'false' | 'nil'
  | 'and' | 'or' | 'not' | 'super' | 'require' | 'assert' | 'do'
  | 'ident' | 'number' | 'hexstring' | 'string' | 'symbol' | 'ivar'
  | '(' | ')' | '[' | ']' | ':' | ',' | '.' | '::' | '@'
  | '+' | '-' | '*' | '/' | '%' | '**'
  | '==' | '!=' | '<' | '<=' | '>' | '>=' | '<<' | '>>'
  | '&&' | '||' | '&' | '|' | '^' | '~' | '!'
  | '=' | '+=' | '-=' | '*=' | '/=' | '%='
  | '...' | '..'
  | '?' | 'NEWLINE'
  | 'eof';

interface Token {
  type: TokenType;
  value: string;
  line: number;
  column: number;
}

const KEYWORDS = new Map<string, TokenType>([
  ['class', 'class'], ['def', 'def'], ['if', 'if'], ['elsif', 'elsif'],
  ['else', 'else'], ['unless', 'unless'], ['for', 'for'], ['in', 'in'],
  ['end', 'end'], ['return', 'return'], ['true', 'true'], ['false', 'false'],
  ['nil', 'nil'], ['and', 'and'], ['or', 'or'], ['not', 'not'],
  ['super', 'super'], ['require', 'require'], ['assert', 'assert'], ['do', 'do'],
]);

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const lines = source.split('\n');

  // Track parenthesis depth for multi-line expressions
  let parenDepth = 0;

  function add(type: TokenType, value: string, line: number, col: number) {
    tokens.push({ type, value, line, column: col });
  }

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const rawLine = lines[lineIdx]!;
    const lineNum = lineIdx + 1;

    // Strip trailing \r
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;

    // Skip blank lines and comment-only lines
    const stripped = line.trimStart();
    if (stripped === '' || stripped.startsWith('#')) {
      continue;
    }

    // Tokenise the content of this line
    let pos = line.length - stripped.length;

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

      // Instance variable: @name
      if (ch === '@') {
        pos++;
        let name = '';
        while (pos < line.length && /[a-zA-Z0-9_]/.test(line[pos]!)) {
          name += line[pos];
          pos++;
        }
        if (name.length > 0) {
          add('ivar', name, lineNum, col);
        } else {
          add('@', '@', lineNum, col);
        }
        continue;
      }

      // Three-dot range operator
      if (ch === '.' && pos + 2 < line.length && line[pos + 1] === '.' && line[pos + 2] === '.') {
        add('...', '...', lineNum, col);
        pos += 3;
        continue;
      }

      // Two-dot range operator
      if (ch === '.' && pos + 1 < line.length && line[pos + 1] === '.') {
        add('..', '..', lineNum, col);
        pos += 2;
        continue;
      }

      // Two-char operators: **, ::, ==, !=, <=, >=, <<, >>, &&, ||, +=, -=, *=, /=, %=
      if (ch === '*' && pos + 1 < line.length && line[pos + 1] === '*') {
        add('**', '**', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === ':' && pos + 1 < line.length && line[pos + 1] === ':') {
        add('::', '::', lineNum, col);
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
      if (ch === '&' && pos + 1 < line.length && line[pos + 1] === '&') {
        add('&&', '&&', lineNum, col);
        pos += 2;
        continue;
      }
      if (ch === '|' && pos + 1 < line.length && line[pos + 1] === '|') {
        add('||', '||', lineNum, col);
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

      // Parentheses (track depth for multi-line expressions)
      if (ch === '(') { parenDepth++; add('(', '(', lineNum, col); pos++; continue; }
      if (ch === ')') { parenDepth = Math.max(0, parenDepth - 1); add(')', ')', lineNum, col); pos++; continue; }
      if (ch === '[') { parenDepth++; add('[', '[', lineNum, col); pos++; continue; }
      if (ch === ']') { parenDepth = Math.max(0, parenDepth - 1); add(']', ']', lineNum, col); pos++; continue; }

      // Symbol: :name (but not ::)
      if (ch === ':' && pos + 1 < line.length && /[a-zA-Z_]/.test(line[pos + 1]!)) {
        pos++; // skip ':'
        let name = '';
        while (pos < line.length && /[a-zA-Z0-9_]/.test(line[pos]!)) {
          name += line[pos];
          pos++;
        }
        add('symbol', name, lineNum, col);
        continue;
      }

      // Single-char operators & delimiters
      if (',:+-%&|^~!?'.includes(ch)) {
        add(ch as TokenType, ch, lineNum, col);
        pos++;
        continue;
      }
      if (ch === '.') { add('.', '.', lineNum, col); pos++; continue; }
      if (ch === '<') { add('<', '<', lineNum, col); pos++; continue; }
      if (ch === '>') { add('>', '>', lineNum, col); pos++; continue; }
      if (ch === '=') { add('=', '=', lineNum, col); pos++; continue; }
      if (ch === '*') { add('*', '*', lineNum, col); pos++; continue; }
      if (ch === '/') { add('/', '/', lineNum, col); pos++; continue; }

      // Single-quoted string literals: hex ByteStrings
      if (ch === '\'') {
        pos++;
        let val = '';
        while (pos < line.length && line[pos] !== '\'') {
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
        add('hexstring', val, lineNum, col);
        continue;
      }

      // Double-quoted string literals
      if (ch === '"') {
        pos++;
        let val = '';
        while (pos < line.length && line[pos] !== '"') {
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
        // Check for trailing ? or ! (Ruby convention)
        if (pos < line.length && (line[pos] === '?' || line[pos] === '!')) {
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

  add('eof', '', lines.length + 1, 1);
  return tokens;
}

// ---------------------------------------------------------------------------
// Name conversion helpers
// ---------------------------------------------------------------------------

/** Convert snake_case to camelCase. Single words pass through unchanged. */
function snakeToCamel(name: string): string {
  // Strip leading underscores before conversion.
  // Without this, `_require_owner` would become `RequireOwner` instead of `requireOwner`.
  const match = name.match(/^(_+)(.*)/);
  if (match) {
    const converted = match[2]!.replace(/_([a-z0-9])/g, (_, ch: string) => ch.toUpperCase());
    return converted;
  }
  return name.replace(/_([a-z0-9])/g, (_, ch: string) => ch.toUpperCase());
}

/** Map Ruby built-in function names to AST callee names. */
function mapBuiltinName(name: string): string {
  // Exact-match special cases (names that don't follow simple snake_case -> camelCase)
  const SPECIAL: Record<string, string> = {
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
    'safe_div': 'safediv',
    'safe_mod': 'safemod',
    'div_mod': 'divmod',
    'add_output': 'addOutput',
    'add_raw_output': 'addRawOutput',
    'get_state_script': 'getStateScript',
    // SHA-256 partial verification
    'sha256_compress': 'sha256Compress',
    'sha256_finalize': 'sha256Finalize',
    // Transaction intrinsics
    'extract_nsequence': 'extractNSequence',
    'extract_hash_prevouts': 'extractHashPrevouts',
    'extract_hash_sequence': 'extractHashSequence',
    'extract_outpoint': 'extractOutpoint',
    'extract_script_code': 'extractScriptCode',
    'extract_input_index': 'extractInputIndex',
    'extract_sig_hash_type': 'extractSigHashType',
    'extract_outputs': 'extractOutputs',
    // EC constants
    'EC_P': 'EC_P',
    'EC_N': 'EC_N',
    'EC_G': 'EC_G',
    // Additional hash builtins
    'bin2num': 'bin2num',
    // Trailing-underscore variants (avoid Ruby Kernel method clashes)
    'sign_': 'sign',
    'pow_': 'pow',
    'sqrt_': 'sqrt',
    'gcd_': 'gcd',
    'log2_': 'log2',
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

/** Map Ruby type names to Rúnar AST types. */
function mapRbType(name: string): string {
  switch (name) {
    case 'Bigint': case 'Integer': case 'Int': return 'bigint';
    case 'Boolean': return 'boolean';
    case 'ByteString': return 'ByteString';
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

/**
 * Rewrite bare function calls to declared contract methods as this.method() calls.
 * In Ruby, `compute_threshold(a, b)` inside a contract is equivalent to
 * `self.compute_threshold(a, b)`, which should produce the same AST as
 * `this.computeThreshold(a, b)` in TypeScript.
 */
function rewriteBareMethodCalls(stmts: Statement[], methodNames: Set<string>): void {
  function rewriteExpr(expr: Expression): Expression {
    if (expr.kind === 'call_expr') {
      const call = expr as { kind: 'call_expr'; callee: Expression; args: Expression[] };
      call.args = call.args.map(rewriteExpr);
      if (call.callee.kind === 'identifier') {
        const name = (call.callee as { name: string }).name;
        if (methodNames.has(name)) {
          call.callee = { kind: 'property_access', property: name } as Expression;
        }
      } else {
        call.callee = rewriteExpr(call.callee);
      }
      return call as Expression;
    }
    if (expr.kind === 'binary_expr') {
      const bin = expr as { kind: 'binary_expr'; left: Expression; right: Expression; op: BinaryOp };
      bin.left = rewriteExpr(bin.left);
      bin.right = rewriteExpr(bin.right);
      return bin as Expression;
    }
    if (expr.kind === 'unary_expr') {
      const un = expr as { kind: 'unary_expr'; operand: Expression; op: string };
      un.operand = rewriteExpr(un.operand);
      return un as Expression;
    }
    if (expr.kind === 'ternary_expr') {
      const tern = expr as { kind: 'ternary_expr'; condition: Expression; consequent: Expression; alternate: Expression };
      tern.condition = rewriteExpr(tern.condition);
      tern.consequent = rewriteExpr(tern.consequent);
      tern.alternate = rewriteExpr(tern.alternate);
      return tern as Expression;
    }
    return expr;
  }

  function rewriteStmt(stmt: Statement): void {
    if (stmt.kind === 'expression_statement') {
      const es = stmt as { expression: Expression };
      es.expression = rewriteExpr(es.expression);
    } else if (stmt.kind === 'variable_decl') {
      const vd = stmt as { init: Expression };
      vd.init = rewriteExpr(vd.init);
    } else if (stmt.kind === 'assignment') {
      const a = stmt as { value: Expression };
      a.value = rewriteExpr(a.value);
    } else if (stmt.kind === 'return_statement') {
      const rs = stmt as { value?: Expression };
      if (rs.value) rs.value = rewriteExpr(rs.value);
    } else if (stmt.kind === 'if_statement') {
      const ifs = stmt as { condition: Expression; then: Statement[]; else?: Statement[] };
      ifs.condition = rewriteExpr(ifs.condition);
      rewriteBareMethodCalls(ifs.then, methodNames);
      if (ifs.else) rewriteBareMethodCalls(ifs.else, methodNames);
    } else if (stmt.kind === 'for_statement') {
      const fs = stmt as { body: Statement[] };
      rewriteBareMethodCalls(fs.body, methodNames);
    }
  }

  for (const stmt of stmts) {
    rewriteStmt(stmt);
  }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class RbParser {
  private tokens: Token[];
  private pos = 0;
  private file: string;
  private errors: CompilerDiagnostic[] = [];

  /** Track locally declared variables per method scope to distinguish decl from assignment. */
  private declaredLocals: Set<string> = new Set();

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

    // Skip `require 'runar'` lines
    while (this.peek().type === 'require') {
      this.parseRequireLine();
      this.skipNewlines();
    }

    // Parse class
    const contract = this.parseClass();
    if (!contract) {
      return { contract: null, errors: this.errors };
    }

    return { contract, errors: this.errors };
  }

  private parseRequireLine(): void {
    this.advance(); // 'require'
    // consume the rest of the line
    while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
      this.advance();
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

    // Expect `< Runar::SmartContract` or `< Runar::StatefulSmartContract`
    this.expect('<');

    // Parse parent class: could be `Runar::SmartContract` or just `SmartContract`
    let parentClass = '';
    const firstPart = this.advance(); // ident (either 'Runar' or the class name directly)
    if (this.peek().type === '::') {
      // Runar::SmartContract
      this.advance(); // '::'
      const classPart = this.advance();
      parentClass = classPart.value;
    } else {
      parentClass = firstPart.value;
    }

    this.skipNewlines();

    if (parentClass !== 'SmartContract' && parentClass !== 'StatefulSmartContract') {
      this.errors.push(makeDiagnostic(
        `Unknown parent class: ${parentClass}`,
        'error',
        { file: this.file, line: firstPart.line, column: firstPart.column },
      ));
      return null;
    }

    // Parse class body until `end`
    const properties: PropertyNode[] = [];
    const methods: MethodNode[] = [];
    let constructor: MethodNode | null = null;

    // Pending visibility/param types for the next method
    let pendingVisibility: 'public' | 'private' | null = null;
    let pendingParamTypes: Map<string, TypeNode> | null = null;

    while (this.peek().type !== 'end' && this.peek().type !== 'eof') {
      this.skipNewlines();
      if (this.peek().type === 'end' || this.peek().type === 'eof') break;

      // `prop :name, Type [, readonly: true]`
      if (this.checkIdent('prop')) {
        const prop = this.parseProp(parentClass);
        if (prop) properties.push(prop);
        this.skipNewlines();
        continue;
      }

      // `runar_public [key: Type, ...]`
      if (this.checkIdent('runar_public')) {
        this.advance(); // 'runar_public'
        pendingVisibility = 'public';
        pendingParamTypes = this.parseOptionalParamTypes();
        this.skipNewlines();
        continue;
      }

      // `params key: Type, ...`
      if (this.checkIdent('params')) {
        this.advance(); // 'params'
        pendingParamTypes = this.parseOptionalParamTypes();
        this.skipNewlines();
        continue;
      }

      // Method definition
      if (this.peek().type === 'def') {
        const method = this.parseMethod(pendingVisibility, pendingParamTypes);
        if (method.name === 'constructor') {
          constructor = method;
        } else {
          methods.push(method);
        }
        pendingVisibility = null;
        pendingParamTypes = null;
        this.skipNewlines();
        continue;
      }

      // Skip unknown tokens
      this.advance();
    }

    this.match('end'); // end of class

    // Auto-generate constructor if not provided
    if (!constructor) {
      constructor = this.autoGenerateConstructor(properties);
    }

    // Back-fill constructor param types from prop declarations.
    // In Ruby, `def initialize(pub_key_hash)` has no type annotations —
    // we infer them from the matching `prop :pub_key_hash, Addr` declarations.
    if (constructor) {
      const propTypeMap = new Map(properties.map(p => [p.name, p.type]));
      for (const param of constructor.params) {
        if (param.type.kind === 'custom_type' && (param.type as any).name === 'unknown') {
          const propType = propTypeMap.get(param.name);
          if (propType) {
            param.type = propType;
          }
        }
      }
    }

    // Convert bare calls to declared methods into this.method() calls.
    // In Ruby, `compute_threshold(a, b)` is equivalent to `self.compute_threshold(a, b)`.
    const methodNames = new Set(methods.map(m => m.name));
    for (const method of methods) {
      rewriteBareMethodCalls(method.body, methodNames);
    }

    // Convert implicit returns in private methods: in Ruby, the last
    // expression in a method body is its return value.  The Runar AST
    // requires explicit return_statement nodes for this.
    for (const method of methods) {
      if (method.visibility === 'private' && method.body.length > 0) {
        const last = method.body[method.body.length - 1]!;
        if (last.kind === 'expression_statement') {
          const exprStmt = last as { kind: string; expression: Expression; sourceLocation?: SourceLocation };
          method.body[method.body.length - 1] = {
            kind: 'return_statement',
            value: exprStmt.expression,
            sourceLocation: exprStmt.sourceLocation,
          } as Statement;
        }
      }
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

  /**
   * Parse optional key: Type pairs after `runar_public` or `params`.
   * Returns null if there are no pairs (just a bare keyword).
   */
  private parseOptionalParamTypes(): Map<string, TypeNode> | null {
    // If the next token is NEWLINE or eof or def, there are no param types
    if (this.peek().type === 'NEWLINE' || this.peek().type === 'eof' || this.peek().type === 'def') {
      return null;
    }

    const paramTypes = new Map<string, TypeNode>();

    // Parse key: Type pairs
    while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
      // Expect ident (param name)
      const nameTok = this.advance();
      const rawName = nameTok.value;

      // Expect ':'
      this.expect(':');

      // Parse type
      const typeNode = this.parseType();

      paramTypes.set(rawName, typeNode);

      // Optional comma
      if (!this.match(',')) break;
    }

    return paramTypes.size > 0 ? paramTypes : null;
  }

  private parseProp(parentClass: string): PropertyNode | null {
    const loc = this.loc();
    this.advance(); // 'prop'

    // Expect symbol :name
    if (this.peek().type !== 'symbol') {
      this.errors.push(makeDiagnostic(
        `Expected symbol after 'prop', got '${this.peek().value || this.peek().type}'`,
        'error',
        this.loc(),
      ));
      // Skip to end of line
      while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') this.advance();
      return null;
    }

    const rawName = this.advance().value; // symbol value (without colon)
    this.expect(',');

    // Parse type
    const typeNode = this.parseType();

    // Check for optional trailing options: readonly: true/false, default: <literal>
    // Multiple options are comma-separated and may appear in any order.
    let isReadonly = false;
    let initializer: Expression | undefined;
    while (this.peek().type === ',') {
      this.advance(); // ','
      if (this.checkIdent('readonly')) {
        this.advance(); // 'readonly'
        this.expect(':');
        if (this.peek().type === 'true') {
          this.advance();
          isReadonly = true;
        } else if (this.peek().type === 'false') {
          this.advance();
          isReadonly = false;
        }
      } else if (this.checkIdent('default')) {
        this.advance(); // 'default'
        this.expect(':');
        initializer = this.parseUnary();
      } else {
        // Unknown trailing option -- stop parsing options
        break;
      }
    }

    // In stateless contracts, all properties are readonly
    if (parentClass === 'SmartContract') {
      isReadonly = true;
    }

    // Skip rest of line
    while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
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

    // Check for FixedArray[T, N] style generic
    if (this.peek().type === '[' && rawName === 'FixedArray') {
      this.advance(); // '['
      const elemType = this.parseType();
      this.expect(',');
      const sizeTok = this.expect('number');
      const size = parseInt(sizeTok.value, 10);
      this.expect(']');
      return { kind: 'fixed_array_type', element: elemType, length: size };
    }

    const mapped = mapRbType(rawName);
    return makePrimitiveOrCustom(mapped);
  }

  private parseMethod(
    pendingVisibility: 'public' | 'private' | null,
    pendingParamTypes: Map<string, TypeNode> | null,
  ): MethodNode {
    const loc = this.loc();
    this.expect('def');

    const nameTok = this.advance();
    const rawName = nameTok.value;

    // Reset local variable tracking for this method scope
    this.declaredLocals = new Set();

    // Parse parameters (optional parentheses for no-arg methods)
    let params: ParamNode[];
    if (this.peek().type === '(') {
      this.expect('(');
      params = this.parseParams(pendingParamTypes);
      this.expect(')');
    } else {
      params = [];
    }

    this.skipNewlines();

    // Parse body until 'end'
    const body = this.parseStatements();

    this.expect('end');

    // Determine if this is the constructor
    if (rawName === 'initialize') {
      return {
        kind: 'method',
        name: 'constructor',
        params,
        body,
        visibility: 'public',
        sourceLocation: loc,
      };
    }

    const isPublic = pendingVisibility === 'public';
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

  private parseParams(paramTypes: Map<string, TypeNode> | null): ParamNode[] {
    const params: ParamNode[] = [];

    while (this.peek().type !== ')' && this.peek().type !== 'eof') {
      const nameTok = this.advance();
      const rawName = nameTok.value;
      const camelName = snakeToCamel(rawName);

      // Look up the type from the preceding runar_public/params declaration
      let typeNode: TypeNode | undefined;
      if (paramTypes) {
        typeNode = paramTypes.get(rawName);
      }

      params.push({
        kind: 'param',
        name: camelName,
        type: typeNode ?? { kind: 'custom_type', name: 'unknown' },
      });

      if (!this.match(',')) break;
    }

    return params;
  }

  private autoGenerateConstructor(properties: PropertyNode[]): MethodNode {
    // Properties with initializers do not need constructor parameters.
    const requiredProps = properties.filter(p => p.initializer === undefined);

    const params: ParamNode[] = requiredProps.map(p => ({
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
        callee: { kind: 'identifier', name: 'super' },
        args: superArgs,
      },
      sourceLocation: { file: this.file, line: 1, column: 0 },
    };

    const assignments: Statement[] = requiredProps.map(p => ({
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

    while (this.peek().type !== 'end' && this.peek().type !== 'elsif'
           && this.peek().type !== 'else' && this.peek().type !== 'eof') {
      this.skipNewlines();
      if (this.peek().type === 'end' || this.peek().type === 'elsif'
          || this.peek().type === 'else' || this.peek().type === 'eof') break;

      const stmt = this.parseStatement();
      if (stmt) stmts.push(stmt);
      this.skipNewlines();
    }

    return stmts;
  }

  private parseStatement(): Statement | null {
    const loc = this.loc();

    // assert statement: assert expr
    if (this.peek().type === 'assert') {
      return this.parseAssertStatement(loc);
    }

    // if statement
    if (this.peek().type === 'if') {
      return this.parseIfStatement(loc);
    }

    // unless statement (maps to if with negated condition)
    if (this.peek().type === 'unless') {
      return this.parseUnlessStatement(loc);
    }

    // for statement
    if (this.peek().type === 'for') {
      return this.parseForStatement(loc);
    }

    // return statement
    if (this.peek().type === 'return') {
      return this.parseReturnStatement(loc);
    }

    // super(args...) — parse as part of constructor
    if (this.peek().type === 'super') {
      return this.parseSuperCall(loc);
    }

    // Instance variable assignment: @var = expr, @var += expr
    if (this.peek().type === 'ivar') {
      return this.parseIvarStatement(loc);
    }

    // Variable declaration or expression statement starting with ident
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
    // Optional 'then' keyword (Ruby allows `if cond then ... end`)
    this.match('NEWLINE');
    this.skipNewlines();

    const thenBranch = this.parseStatements();

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elsif') {
      const elifLoc = this.loc();
      elseBranch = [this.parseElsifStatement(elifLoc)];
    } else if (this.peek().type === 'else') {
      this.advance(); // 'else'
      this.skipNewlines();
      elseBranch = this.parseStatements();
    }

    this.expect('end');

    return {
      kind: 'if_statement',
      condition,
      then: thenBranch,
      else: elseBranch,
      sourceLocation: loc,
    };
  }

  private parseElsifStatement(loc: SourceLocation): Statement {
    this.advance(); // 'elsif'
    const condition = this.parseExpression();
    this.skipNewlines();

    const thenBranch = this.parseStatements();

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elsif') {
      const elifLoc = this.loc();
      elseBranch = [this.parseElsifStatement(elifLoc)];
    } else if (this.peek().type === 'else') {
      this.advance(); // 'else'
      this.skipNewlines();
      elseBranch = this.parseStatements();
    }

    // Note: the outer `end` is consumed by the parent parseIfStatement
    // elsif branches do not consume their own `end`

    return {
      kind: 'if_statement',
      condition,
      then: thenBranch,
      else: elseBranch,
      sourceLocation: loc,
    };
  }

  private parseUnlessStatement(loc: SourceLocation): Statement {
    this.advance(); // 'unless'
    const rawCondition = this.parseExpression();
    this.skipNewlines();

    const body = this.parseStatements();

    this.expect('end');

    // Unless is if with negated condition
    const condition: Expression = { kind: 'unary_expr', op: '!', operand: rawCondition };

    return {
      kind: 'if_statement',
      condition,
      then: body,
      sourceLocation: loc,
    };
  }

  private parseForStatement(loc: SourceLocation): Statement {
    this.advance(); // 'for'

    const iterVar = this.advance(); // loop variable
    const varName = snakeToCamel(iterVar.value);

    this.expect('in');

    // Parse start expression
    const startExpr = this.parseExpression();

    // Expect range operator: .. (inclusive) or ... (exclusive)
    let isExclusive = false;
    if (this.peek().type === '...') {
      isExclusive = true;
      this.advance();
    } else if (this.peek().type === '..') {
      isExclusive = false;
      this.advance();
    } else {
      this.errors.push(makeDiagnostic(
        `Expected range operator '..' or '...' in for loop`,
        'error',
        this.loc(),
      ));
    }

    const endExpr = this.parseExpression();

    // Optional 'do' keyword
    this.match('do');
    this.skipNewlines();

    const body = this.parseStatements();
    this.expect('end');

    // Construct a C-style for loop AST node
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
      op: (isExclusive ? '<' : '<=') as BinaryOp,
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
    if (this.peek().type !== 'NEWLINE' && this.peek().type !== 'end' && this.peek().type !== 'eof') {
      value = this.parseExpression();
    }
    return { kind: 'return_statement', value, sourceLocation: loc };
  }

  private parseSuperCall(loc: SourceLocation): Statement {
    // super(args...) in Ruby constructor
    this.advance(); // 'super'
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

  private parseIvarStatement(loc: SourceLocation): Statement {
    // @var = expr or @var += expr or @var as expression
    const ivarTok = this.advance(); // ivar token
    const rawName = ivarTok.value;
    const propName = snakeToCamel(rawName);
    const target: Expression = { kind: 'property_access', property: propName };

    // Simple assignment: @var = expr
    if (this.match('=')) {
      const value = this.parseExpression();
      return { kind: 'assignment', target, value, sourceLocation: loc };
    }

    // Compound assignment: @var += expr, etc.
    const compoundOps: Record<string, BinaryOp> = {
      '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%',
    };

    for (const [tok, binOp] of Object.entries(compoundOps)) {
      if (this.peek().type === tok) {
        this.advance();
        const right = this.parseExpression();
        const value: Expression = { kind: 'binary_expr', op: binOp, left: target, right };
        return { kind: 'assignment', target, value, sourceLocation: loc };
      }
    }

    // Expression statement (rare: just @var on its own line, or @var.method(...))
    // Re-parse from ivar as an expression — but we already consumed the ivar token,
    // so build the expression and parse any postfix operations
    let expr: Expression = target;
    expr = this.parsePostfixFrom(expr);

    return { kind: 'expression_statement', expression: expr, sourceLocation: loc };
  }

  private parseIdentStatement(loc: SourceLocation): Statement | null {
    const nameTok = this.peek();
    const rawName = nameTok.value;

    // Check for simple name = expr pattern (variable declaration or assignment)
    if (this.tokens[this.pos + 1]?.type === '=') {
      this.advance(); // consume ident
      this.advance(); // consume '='
      const value = this.parseExpression();
      const camelName = snakeToCamel(rawName);

      if (this.declaredLocals.has(camelName)) {
        // Already declared: this is an assignment
        return {
          kind: 'assignment',
          target: { kind: 'identifier', name: camelName },
          value,
          sourceLocation: loc,
        };
      } else {
        // First assignment: variable declaration
        this.declaredLocals.add(camelName);
        return {
          kind: 'variable_decl',
          name: camelName,
          mutable: true,
          init: value,
          sourceLocation: loc,
        };
      }
    }

    // Parse as expression first
    const expr = this.parseExpression();

    // Simple assignment (e.g. a.b = expr)
    if (this.match('=')) {
      const value = this.parseExpression();
      return { kind: 'assignment', target: expr, value, sourceLocation: loc };
    }

    // Compound assignment
    const compoundOps: Record<string, BinaryOp> = {
      '+=': '+', '-=': '-', '*=': '*', '/=': '/', '%=': '%',
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

  // Ruby ternary: condition ? consequent : alternate
  private parseTernary(): Expression {
    const expr = this.parseOr();

    if (this.peek().type === '?') {
      this.advance(); // '?'
      const consequent = this.parseExpression();
      this.expect(':');
      const alternate = this.parseExpression();
      return { kind: 'ternary_expr', condition: expr, consequent, alternate };
    }

    return expr;
  }

  private parseOr(): Expression {
    let left = this.parseAnd();
    while (this.peek().type === 'or' || this.peek().type === '||') {
      this.advance();
      const right = this.parseAnd();
      left = { kind: 'binary_expr', op: '||', left, right };
    }
    return left;
  }

  private parseAnd(): Expression {
    let left = this.parseNot();
    while (this.peek().type === 'and' || this.peek().type === '&&') {
      this.advance();
      const right = this.parseNot();
      left = { kind: 'binary_expr', op: '&&', left, right };
    }
    return left;
  }

  private parseNot(): Expression {
    if (this.peek().type === 'not' || this.peek().type === '!') {
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
    return this.parsePower();
  }

  private parsePower(): Expression {
    const base = this.parsePostfix();

    // ** is right-associative
    if (this.peek().type === '**') {
      this.advance();
      const exp = this.parsePower(); // right-recursive for right-associativity
      // ** maps to pow() call
      return {
        kind: 'call_expr',
        callee: { kind: 'identifier', name: 'pow' },
        args: [base, exp],
      };
    }

    return base;
  }

  private parsePostfix(): Expression {
    let expr = this.parsePrimary();
    return this.parsePostfixFrom(expr);
  }

  /** Parse postfix operations (method calls, property access, indexing) from a given expression. */
  private parsePostfixFrom(expr: Expression): Expression {
    while (true) {
      // Method call or property access: expr.name or expr.name(...)
      if (this.peek().type === '.') {
        this.advance(); // '.'
        const propTok = this.advance();
        const propName = mapBuiltinName(propTok.value);

        // Check if it's a method call
        if (this.peek().type === '(') {
          const args = this.parseCallArgs();
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
      const val = BigInt(tok.value);
      return { kind: 'bigint_literal', value: val };
    }

    // Boolean literals
    if (tok.type === 'true') {
      this.advance();
      return { kind: 'bool_literal', value: true };
    }
    if (tok.type === 'false') {
      this.advance();
      return { kind: 'bool_literal', value: false };
    }

    // Hex string literal (single-quoted)
    if (tok.type === 'hexstring') {
      this.advance();
      return { kind: 'bytestring_literal', value: tok.value };
    }

    // String literal (double-quoted)
    if (tok.type === 'string') {
      this.advance();
      return { kind: 'bytestring_literal', value: tok.value };
    }

    // nil -> 0
    if (tok.type === 'nil') {
      this.advance();
      return { kind: 'bigint_literal', value: 0n };
    }

    // Instance variable: @var -> property access
    if (tok.type === 'ivar') {
      this.advance();
      const propName = snakeToCamel(tok.value);
      return { kind: 'property_access', property: propName };
    }

    // Parenthesised expression
    if (tok.type === '(') {
      this.advance();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }

    // Array literal: [elem, ...]
    if (tok.type === '[') {
      this.advance();
      const elements: Expression[] = [];
      while (this.peek().type !== ']' && this.peek().type !== 'eof') {
        elements.push(this.parseExpression());
        if (!this.match(',')) break;
      }
      this.expect(']');
      return { kind: 'array_literal', elements };
    }

    // Identifier or function call
    if (tok.type === 'ident' || tok.type === 'assert') {
      this.advance();
      const rawName = tok.value;
      const name = mapBuiltinName(rawName);
      return { kind: 'identifier', name };
    }

    // super keyword (as expression, e.g., in super.method)
    if (tok.type === 'super') {
      this.advance();
      return { kind: 'identifier', name: 'super' };
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

export function parseRubySource(source: string, fileName?: string): ParseResult {
  const file = fileName ?? 'contract.runar.rb';
  const tokens = tokenize(source);
  const parser = new RbParser(tokens, file);
  return parser.parse();
}
