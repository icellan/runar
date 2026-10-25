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
import { identifierCollisionMessage, snakeToCamelCore } from './snake-to-camel.js';
import {
  makeDiagnostic,
  staticMethodMessage,
  unexpectedClassBodyTokenMessage,
  unexpectedTokenAfterClassMessage,
  unsupportedStatementMessage,
  UNTERMINATED_STRING_LITERAL,
} from '../errors.js';
import type { ParseResult } from './01-parse.js';
import { assertSourceWithinLimits, NestingCounter, withNestingLimit } from './source-limits.js';
import { invalidIntegerLiteral, parseIntLiteral, scanNumberEnd } from './int-literal.js';
import { lostDirectiveMessage, resolveNativeSighash } from './sighash-directive.js';

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

/**
 * N-053: the tokens that can begin an expression and are not already a
 * statement form of their own. A statement starting with one of these is an
 * expression statement; a statement starting with anything else is refused.
 */
const RB_EXPRESSION_START: ReadonlySet<TokenType> = new Set<TokenType>([
  'number', 'string', 'hexstring', 'true', 'false', 'nil',
  '(', '[', '-', '~', '!', 'not',
]);

function tokenize(source: string, file: string, errors: CompilerDiagnostic[]): Token[] {
  const tokens: Token[] = [];
  const lines = source.split('\n');

  // Track parenthesis depth for multi-line expressions
  let parenDepth = 0;
  // Line number of an open `=begin` embedded document, or 0.
  let blockCommentStart = 0;

  function add(type: TokenType, value: string, line: number, col: number) {
    tokens.push({ type, value, line, column: col });
  }

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const rawLine = lines[lineIdx]!;
    const lineNum = lineIdx + 1;

    // Strip trailing \r
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;

    // N-021: Ruby embedded documents, the Ruby tier's F-018 rule (Ruby's
    // own). `=begin` / `=end` open and close a block comment only at column 0
    // and only as a whole word (followed by whitespace or end of line). Every
    // line from `=begin` through `=end` is a comment. Before this, a method
    // "commented out" this way compiled as a live spend path and the `end` of
    // `=end` closed the class early.
    if (blockCommentStart !== 0) {
      if (isEmbeddedDocMarker(line, '=end')) blockCommentStart = 0;
      continue;
    }
    if (isEmbeddedDocMarker(line, '=begin')) {
      blockCommentStart = lineNum;
      continue;
    }

    // Skip blank lines and comment-only lines
    const stripped = line.trimStart();
    if (stripped === '' || stripped.startsWith('#')) {
      continue;
    }

    // Tokenise the content of this line
    let pos = line.length - stripped.length;

    while (pos < line.length) {
      const ch = line[pos]!;
      const col = pos;

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
        // F-011: the tokenizer is line-based, so a literal that reaches the
        // line break is unterminated; refuse it rather than end it silently.
        else errors.push(makeDiagnostic(UNTERMINATED_STRING_LITERAL, 'error', { file, line: lineNum, column: col }));
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
        else errors.push(makeDiagnostic(UNTERMINATED_STRING_LITERAL, 'error', { file, line: lineNum, column: col }));
        add('string', val, lineNum, col);
        continue;
      }

      // Numbers (F-026): the whole glued [0-9A-Za-z_] run is one literal.
      if (ch >= '0' && ch <= '9') {
        const end = scanNumberEnd(line, pos);
        const text = line.slice(pos, end);
        pos = end;
        const lit = parseIntLiteral('rb', text);
        if (!lit) errors.push(makeDiagnostic(invalidIntegerLiteral('rb', text), 'error', { file, line: lineNum, column: col }));
        add('number', lit ? lit.value.toString() : '0', lineNum, col);
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

      // Unrecognized character — reject it rather than dropping it silently.
      errors.push(makeDiagnostic(
        `Unexpected character '${ch}'`,
        'error',
        { file, line: lineNum, column: col },
      ));
      pos++;
    }

    // Emit NEWLINE at end of significant line (only if not inside parens)
    if (parenDepth === 0) {
      add('NEWLINE', '', lineNum, line.length);
    }
  }

  if (blockCommentStart !== 0) {
    errors.push(makeDiagnostic(
      `unterminated '=begin' block comment starting at line ${blockCommentStart}: missing '=end'`,
      'error',
      { file, line: blockCommentStart, column: 0 },
    ));
  }

  add('eof', '', lines.length + 1, 0);
  return tokens;
}

/** Whether `line` starts at column 0 with `marker` (`=begin` or `=end`) as a
 *  whole word: followed by ASCII whitespace (Ruby's `\s`) or end of line. */
function isEmbeddedDocMarker(line: string, marker: string): boolean {
  if (!line.startsWith(marker)) return false;
  return line.length === marker.length || ' \t\n\v\f\r'.includes(line[marker.length]!);
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
    return snakeToCamelCore(match[2]!);
  }
  return snakeToCamelCore(name);
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
    // NIST EC curves -- snake_case forms used in Ruby contracts.
    'verify_ecdsa_p256': 'verifyECDSA_P256',
    'verify_ecdsa_p384': 'verifyECDSA_P384',
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
    'bb_field_add': 'bbFieldAdd',
    'bb_field_sub': 'bbFieldSub',
    'bb_field_mul': 'bbFieldMul',
    'bb_field_inv': 'bbFieldInv',
    'merkle_root_sha256': 'merkleRootSha256',
    'merkle_root_hash256': 'merkleRootHash256',
    'mul_div': 'mulDiv',
    'percent_of': 'percentOf',
    'safe_div': 'safediv',
    'safe_mod': 'safemod',
    'div_mod': 'divmod',
    'add_output': 'addOutput',
    'add_raw_output': 'addRawOutput',
    'add_data_output': 'addDataOutput',
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
    case 'Boolean': case 'Bool': return 'boolean';
    case 'ByteString': return 'ByteString';
    case 'PubKey': return 'PubKey';
    case 'Sig': return 'Sig';
    case 'Addr': return 'Addr';
    case 'Sha256':
    case 'Sha256Digest':
      return 'Sha256';
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
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point',
  'P256Point', 'P384Point', 'void',
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
  private errors: CompilerDiagnostic[];
  /** F-213 measure (A): parse nesting. */
  private readonly nest = new NestingCounter();

  /** Track locally declared variables per method scope to distinguish decl from assignment. */
  private declaredLocals: Set<string> = new Set();

  /** F-017: (source spelling, Rúnar name) of every declared identifier. */
  private declared: Array<[string, string]> = [];

  /** Convert a DECLARED identifier and record it for the F-017 collision rule
   *  (see `identifierCollisionMessage` in ./snake-to-camel.ts). */
  private declare(raw: string): string {
    const name = snakeToCamel(raw);
    this.declared.push([raw, name]);
    return name;
  }

  constructor(tokens: Token[], file: string, errors: CompilerDiagnostic[] = []) {
    this.tokens = tokens;
    this.file = file;
    this.errors = errors;
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

    // N-004: nothing may follow the class's `end`.
    this.skipNewlines();
    const trailing = this.peek();
    if (trailing.type !== 'eof') {
      this.errors.push(makeDiagnostic(
        unexpectedTokenAfterClassMessage(trailing.value || trailing.type),
        'error',
        { file: this.file, line: trailing.line, column: trailing.column },
      ));
    }

    const collision = identifierCollisionMessage(this.declared);
    if (collision !== null) {
      this.errors.push(makeDiagnostic(collision, 'error'));
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

    if (
      parentClass !== 'SmartContract' &&
      parentClass !== 'StatefulSmartContract' &&
      parentClass !== 'UnsafeSmartContract'
    ) {
      this.errors.push(makeDiagnostic(
        `unknown parent class: '${parentClass}', expected SmartContract, StatefulSmartContract, or UnsafeSmartContract`,
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
    let pendingSighash: Array<{ spec: string | null; loc: SourceLocation }> = [];

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

      // N-093: `runar_sighash 'FLAGS'` is the native spelling of the
      // `@sighash` directive; it applies to the next `def`.
      if (this.checkIdent('runar_sighash')) {
        const sighashLoc = this.loc();
        this.advance(); // 'runar_sighash'
        const arg = this.peek();
        let count = 0;
        while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
          this.advance();
          count++;
        }
        const isStr = arg.type === 'string' || arg.type === 'hexstring';
        pendingSighash.push({ spec: count === 1 && isStr ? arg.value : null, loc: sighashLoc });
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
          // N-093: the constructor is not a spending entry point.
          for (const p of pendingSighash) {
            this.errors.push(makeDiagnostic(lostDirectiveMessage('@sighash'), 'error', p.loc));
          }
          constructor = method;
        } else {
          const sighash = resolveNativeSighash(
            method.name,
            method.visibility === 'public',
            pendingSighash.map((p) => p.spec),
          );
          if (sighash && 'error' in sighash) {
            this.errors.push(makeDiagnostic(sighash.error, 'error', method.sourceLocation));
          } else if (sighash) {
            method.sighashType = sighash.value;
          }
          methods.push(method);
        }
        pendingVisibility = null;
        pendingParamTypes = null;
        pendingSighash = [];
        this.skipNewlines();
        continue;
      }

      // Ruby's bare visibility markers are no-ops here (visibility comes from
      // `runar_public`); examples/ruby uses them.
      if (this.checkIdent('private') || this.checkIdent('public')) {
        this.advance();
        continue;
      }

      // N-004: refuse anything else (an indented `=begin` lexes as `=`).
      const stray = this.advance();
      this.errors.push(makeDiagnostic(
        unexpectedClassBodyTokenMessage(stray.value || stray.type),
        'error',
        { file: this.file, line: stray.line, column: stray.column },
      ));
    }

    // N-093: a `runar_sighash` with no `def` after it annotates nothing.
    for (const p of pendingSighash) {
      this.errors.push(makeDiagnostic(lostDirectiveMessage('@sighash'), 'error', p.loc));
    }

    // N-319: the class `end` is required; EOF here means it is missing.
    if (!this.match('end')) {
      const eofTok = this.current();
      this.errors.push(makeDiagnostic(
        "unterminated class: missing closing 'end'",
        'error',
        { file: this.file, line: eofTok.line, column: eofTok.column },
      ));
    }

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

    // Convert bare calls to declared methods and intrinsics into this.method() calls.
    // In Ruby, bare calls like `add_output(...)` are equivalent to
    // `self.add_output(...)` / `this.addOutput(...)`.
    const intrinsicMethods = ['addOutput', 'addRawOutput', 'addDataOutput', 'getStateScript'];
    const methodNames = new Set([...methods.map(m => m.name), ...intrinsicMethods]);
    for (const method of methods) {
      rewriteBareMethodCalls(method.body, methodNames);
    }

    // Implicit return conversion for private methods.
    //
    // Ruby methods implicitly return the value of their last expression.
    // Private helper methods that return computed values (e.g. a fee
    // calculation) rely on this — without conversion, the calling method
    // would receive no return value and the type checker would reject the
    // call.  We detect ExpressionStatement as the final statement and
    // promote it to a ReturnStatement so the Runar AST has an explicit
    // return node for ANF lowering and type checking to consume.
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
      parentClass: parentClass as 'SmartContract' | 'StatefulSmartContract' | 'UnsafeSmartContract',
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
    let embedAlways = false;
    let initializer: Expression | undefined;
    let optionError = false;
    while (this.peek().type === ',') {
      this.advance(); // ','
      if (this.checkIdent('embed_always')) {
        // N-093: the native spelling of the `@embedAlways` directive.
        this.advance(); // 'embed_always'
        this.expect(':');
        if (this.peek().type === 'true') {
          this.advance();
          embedAlways = true;
        } else if (this.peek().type === 'false') {
          this.advance();
          embedAlways = false;
        } else {
          this.badBooleanPropOption('embed_always');
          optionError = true;
          break;
        }
      } else if (this.checkIdent('readonly')) {
        this.advance(); // 'readonly'
        this.expect(':');
        if (this.peek().type === 'true') {
          this.advance();
          isReadonly = true;
        } else if (this.peek().type === 'false') {
          this.advance();
          isReadonly = false;
        } else {
          this.badBooleanPropOption('readonly');
          optionError = true;
          break;
        }
      } else if (this.checkIdent('default')) {
        this.advance(); // 'default'
        this.expect(':');
        if (this.peek().type === 'nil') {
          // N-414: `nil` is not a Rúnar literal; refused, never read as 0.
          this.errors.push(makeDiagnostic(
            "prop default 'nil' is not a literal (expected a number, true, false or a hex string)",
            'error',
            this.loc(),
          ));
          this.advance(); // 'nil'
        } else {
          initializer = this.parseUnary();
        }
      } else {
        // N-301: an unknown option (e.g. a typo of `embed_always`) is refused,
        // never silently dropped. Same text in all seven tiers.
        this.errors.push(makeDiagnostic(
          `unknown prop option '${this.peek().value || this.peek().type}' (expected readonly, embed_always or default)`,
          'error',
          this.loc(),
        ));
        optionError = true;
        break;
      }
    }

    // N-413: nothing may follow the type or an option value except `,` (the
    // next option) or end of line. `default:` takes one literal, so
    // `default: 1 + 2` or `default: '00' * 33` is refused here rather than
    // silently truncated to its first operand; `readonly: true false` and a
    // missing comma (`default: 3 readonly: true`) likewise. Same text in all
    // seven tiers, at the leftover token's line:col.
    if (!optionError && this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
      this.errors.push(makeDiagnostic(
        `unexpected '${this.peek().value || this.peek().type}' in prop declaration (expected ',' or end of line)`,
        'error',
        this.loc(),
      ));
    }

    // In stateless contracts (SmartContract and UnsafeSmartContract),
    // all properties are always readonly.
    if (parentClass === 'SmartContract' || parentClass === 'UnsafeSmartContract') {
      isReadonly = true;
    }

    // Skip rest of line
    while (this.peek().type !== 'NEWLINE' && this.peek().type !== 'eof') {
      this.advance();
    }

    return {
      kind: 'property',
      name: this.declare(rawName),
      type: typeNode,
      readonly: isReadonly,
      initializer,
      ...(embedAlways ? { embedAlways: true } : {}),
      sourceLocation: loc,
    };
  }

  /**
   * N-313: `readonly:` and `embed_always:` take a literal `true` or `false`.
   * Any other value (`maybe`, `1`, a missing value) is refused, never
   * silently dropped. Same text in all seven tiers, at the value's line:col.
   */
  private badBooleanPropOption(option: string): void {
    const tok = this.peek();
    const got = tok.type === 'NEWLINE' || tok.type === 'eof' ? '<end of line>' : (tok.value || tok.type);
    this.errors.push(makeDiagnostic(
      `invalid value '${got}' for prop option '${option}' (expected true or false)`,
      'error',
      this.loc(),
    ));
  }

  private parseType(): TypeNode {
    const tok = this.advance();
    const rawName = tok.value;

    // Check for FixedArray[T, N] style generic
    if (this.peek().type === '[' && rawName === 'FixedArray') {
      this.advance(); // '['
      const elemType = this.nest.nested(this.loc(), () => this.parseType());
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

    let nameTok = this.advance();
    // N-050: `def self.m` / `def Vault.m` declares a singleton (class-level)
    // method, not a contract method.
    if (this.peek().type === '.') {
      this.advance(); // '.'
      nameTok = this.advance();
      this.errors.push(makeDiagnostic(staticMethodMessage(nameTok.value), 'error', loc));
    }
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
    const methodName = this.declare(rawName);

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
      const camelName = this.declare(rawName);

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
    return this.nest.nested(this.loc(), () => this.parseStatementInner());
  }

  private parseStatementInner(): Statement | null {
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

    // N-053: a token that can begin an expression begins an expression
    // statement (a private helper's last one is its implicit return value);
    // any other token is refused. Skipping it dropped `!` / `(` / literals.
    if (RB_EXPRESSION_START.has(this.peek().type)) {
      return { kind: 'expression_statement', expression: this.parseExpression(), sourceLocation: loc };
    }
    const tok = this.advance();
    this.errors.push(makeDiagnostic(unsupportedStatementMessage(tok.value || tok.type), 'error', loc));
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

    // Variables declared inside an if/elsif/else branch are scoped to that
    // branch in the typechecker (see 03-typecheck.ts case 'if_statement'
    // which pushScope/popScope around each branch). The parser must mirror
    // that scoping so a `name = expr` reappearing in a sibling branch is
    // emitted as a fresh `variable_decl`, not an `assignment` against an
    // out-of-scope local. Without this, sibling branches that re-declare
    // the same local trigger spurious "Undefined variable" errors in the
    // typechecker. Mirrors the canonical TS lexical-scope semantics.
    const localsBeforeThen = new Set(this.declaredLocals);
    const thenBranch = this.parseStatements();
    this.declaredLocals = new Set(localsBeforeThen);

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elsif') {
      const elifLoc = this.loc();
      elseBranch = [this.nest.nested(elifLoc, () => this.parseElsifStatement(elifLoc))];
      this.declaredLocals = new Set(localsBeforeThen);
    } else if (this.peek().type === 'else') {
      this.advance(); // 'else'
      this.skipNewlines();
      elseBranch = this.parseStatements();
      this.declaredLocals = new Set(localsBeforeThen);
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

    // See parseIfStatement comment: snapshot/restore declaredLocals around
    // each branch so the typechecker's per-branch lexical scoping matches.
    const localsBeforeThen = new Set(this.declaredLocals);
    const thenBranch = this.parseStatements();
    this.declaredLocals = new Set(localsBeforeThen);

    let elseBranch: Statement[] | undefined;

    if (this.peek().type === 'elsif') {
      const elifLoc = this.loc();
      elseBranch = [this.nest.nested(elifLoc, () => this.parseElsifStatement(elifLoc))];
      this.declaredLocals = new Set(localsBeforeThen);
    } else if (this.peek().type === 'else') {
      this.advance(); // 'else'
      this.skipNewlines();
      elseBranch = this.parseStatements();
      this.declaredLocals = new Set(localsBeforeThen);
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

    // See parseIfStatement comment: snapshot/restore declaredLocals around
    // the body so locals declared inside `unless` don't leak into siblings.
    const localsBeforeBody = new Set(this.declaredLocals);
    const body = this.parseStatements();
    this.declaredLocals = new Set(localsBeforeBody);

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
    const varName = this.declare(iterVar.value);

    this.expect('in');

    // Parse start expression
    let startExpr = this.parseExpression();

    // Three loop headers, all of them real Ruby that iterates exactly these
    // values:
    //
    //   for i in 0...n   -> 0, 1, … n-1   (exclusive, ascending)
    //   for i in 0..n    -> 0, 1, … n     (inclusive, ascending)
    //   for i in n.downto(m) -> n, n-1, … m  (inclusive, DESCENDING)
    //
    // `downto` is what lets the Ruby surface spell a countdown. Ruby's range
    // operators only ever ascend — `(5..2)` is empty, and `(2..5).reverse_each`
    // is an enumerator over a method chain rather than a loop header — so
    // `step = -1` was simply unreachable from this surface, and no fixture
    // could exercise it across all nine. `Integer#downto` is the language's
    // own countdown verb, it returns an Enumerator, and `for x in enum` is
    // valid Ruby over one: the spelling means in Ruby exactly what it compiles
    // to here.
    let isExclusive = false;
    let descending = false;
    let endExpr: Expression;

    // `5.downto(2)` is a postfix method call, so the start-expression parser
    // has already consumed the whole header by the time we get here. Match on
    // the shape it produced rather than on the tokens.
    const downtoBound = matchDowntoCall(startExpr);
    if (downtoBound) {
      startExpr = downtoBound.receiver;
      endExpr = downtoBound.bound;
      descending = true;
      isExclusive = false; // downto's bound is inclusive
    } else {
      // Expect range operator: .. (inclusive) or ... (exclusive)
      if (this.peek().type === '...') {
        isExclusive = true;
        this.advance();
      } else if (this.peek().type === '..') {
        isExclusive = false;
        this.advance();
      } else {
        this.errors.push(makeDiagnostic(
          `Expected range operator '..' or '...', or '.downto(n)', in for loop`,
          'error',
          this.loc(),
        ));
      }
      endExpr = this.parseExpression();
    }

    // Optional 'do' keyword
    this.match('do');
    this.skipNewlines();

    // Snapshot/restore declaredLocals around the loop body so locals
    // declared inside the loop don't leak into the surrounding scope —
    // matches how the typechecker treats the loop body.
    const localsBeforeBody = new Set(this.declaredLocals);
    // Pre-declare the iter var so the body parser sees `varName = ...`
    // as an assignment rather than re-declaration.
    this.declaredLocals.add(varName);
    const body = this.parseStatements();
    this.declaredLocals = new Set(localsBeforeBody);
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
      op: (descending ? '>=' : isExclusive ? '<' : '<=') as BinaryOp,
      left: { kind: 'identifier', name: varName },
      right: endExpr,
    };

    const update: Statement = {
      kind: 'expression_statement',
      expression: descending
        ? { kind: 'decrement_expr', operand: { kind: 'identifier', name: varName }, prefix: false }
        : { kind: 'increment_expr', operand: { kind: 'identifier', name: varName }, prefix: false },
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
    // @var = expr | @var += expr | @var[idx] = expr | @var.field = expr | @var as expression
    const start = this.pos;
    const ivarTok = this.advance(); // ivar token
    const rawName = ivarTok.value;
    const propName = snakeToCamel(rawName);
    let target: Expression = { kind: 'property_access', property: propName };

    // Consume any postfix chain that can appear on the LHS of an
    // assignment (index access, member access). We stop on `(` / method
    // calls because a call cannot be an assignment target.
    while (this.peek().type === '[' || this.peek().type === '.') {
      if (this.peek().type === '[') {
        this.advance();
        const index = this.parseExpression();
        this.expect(']');
        target = { kind: 'index_access', object: target, index };
      } else {
        this.advance(); // .
        const name = this.expect('ident').value;
        const camel = snakeToCamel(name);
        target = { kind: 'property_access', object: target, property: camel } as Expression;
      }
    }

    // Simple assignment: @var = expr  |  @var[i] = expr  |  @var.field = expr
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

    // Expression statement (@var on its own line, @var.method(...), or a
    // private helper's implicit return such as `@x + 1`). N-053: re-parse
    // from the ivar as a whole expression; continuing only the postfix chain
    // left `+ 1` behind, and the statement dispatcher skipped it.
    this.pos = start;
    return { kind: 'expression_statement', expression: this.parseExpression(), sourceLocation: loc };
  }

  private parseIdentStatement(loc: SourceLocation): Statement | null {
    const nameTok = this.peek();
    const rawName = nameTok.value;

    // Check for simple name = expr pattern (variable declaration or assignment)
    if (this.tokens[this.pos + 1]?.type === '=') {
      this.advance(); // consume ident
      this.advance(); // consume '='
      const value = this.parseExpression();
      const camelName = this.declare(rawName);

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
    return this.nest.nested(this.loc(), () => this.parseTernary());
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
      const operand = this.nest.nested(this.loc(), () => this.parseNot());
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
      const operand = this.nest.nested(this.loc(), () => this.parseUnary());
      return { kind: 'unary_expr', op: '-', operand };
    }
    if (this.peek().type === '~') {
      this.advance();
      const operand = this.nest.nested(this.loc(), () => this.parseUnary());
      return { kind: 'unary_expr', op: '~', operand };
    }
    if (this.peek().type === '!') {
      this.advance();
      const operand = this.nest.nested(this.loc(), () => this.parseUnary());
      return { kind: 'unary_expr', op: '!', operand };
    }
    return this.parsePower();
  }

  private parsePower(): Expression {
    const base = this.parsePostfix();

    // ** is right-associative
    if (this.peek().type === '**') {
      this.advance();
      const exp = this.nest.nested(this.loc(), () => this.parsePower()); // right-recursive for right-associativity
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

    // N-416: `nil` is not a Rúnar value; refused, never read as 0.
    if (tok.type === 'nil') {
      this.errors.push(makeDiagnostic(
        "'nil' is not a Rúnar value (use a number, true, false or a hex string)",
        'error',
        this.loc(),
      ));
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

/**
 * Destructure `<receiver>.downto(<bound>)` — the Ruby countdown header.
 *
 * Returns null for every other expression, including `downto` with the wrong
 * arity, so a malformed header falls through to the range-operator branch and
 * gets that branch's diagnostic rather than silently becoming a loop.
 */
function matchDowntoCall(
  expr: Expression,
): { receiver: Expression; bound: Expression } | null {
  if (expr.kind !== 'call_expr') return null;
  if (expr.callee.kind !== 'member_expr') return null;
  if (expr.callee.property !== 'downto') return null;
  if (expr.args.length !== 1) return null;
  return { receiver: expr.callee.object, bound: expr.args[0]! };
}

export function parseRubySource(source: string, fileName?: string): ParseResult {
  // R-146: this function is exported from the package index, so the
  // dispatcher's size guard has to be here too — see ./source-limits.ts.
  assertSourceWithinLimits(source, 'parseRubySource');
  const file = fileName ?? 'contract.runar.rb';
  const errors: CompilerDiagnostic[] = [];
  const tokens = tokenize(source, file, errors);
  const parser = new RbParser(tokens, file, errors);
  return withNestingLimit(file, () => parser.parse());
}
