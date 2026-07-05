/**
 * Metamorphic (EMI-style) source transforms for the Rúnar compiler (TS-GAP-009).
 *
 * Metamorphic testing is the cheapest oracle that catches *shared-design* bugs
 * (a mistake all seven compilers make identically, so cross-tier byte-parity
 * cannot see it) WITHOUT needing a golden reference. The idea: apply a
 * transform to a contract's source that is guaranteed to preserve its runtime
 * semantics, compile BOTH versions, execute them, and assert the compiled
 * BEHAVIOUR is unchanged. We compare executed accept/reject verdicts on the
 * BSV script engine (via `runDifferentialExecution().vmAccepted`) — NOT the
 * script bytes: a semantics-preserving edit (e.g. renaming a local) legitimately
 * shifts constructor-arg byte offsets, so byte-equality is the wrong oracle.
 *
 * Every transform here MUST be semantics-preserving for the contract shapes the
 * generators emit (stateless / arithmetic, `+ - *`, `=== !== < <= > >= && || !`,
 * fully-parenthesised expressions). A transform that occasionally produces
 * source the compiler rejects is acceptable — callers treat "both orig and
 * transformed compile" as a precondition and skip the pair otherwise. What a
 * transform must NEVER do is produce a pair where both compile but their
 * executed verdicts differ; that would be a false alarm masking (or faking) a
 * real bug. Each transform is therefore conservative: when it cannot apply
 * cleanly it returns the source UNCHANGED rather than guess.
 *
 * The transforms operate at the source-text level. That is sufficient — and
 * deliberately independent of the compiler's own parser — because the generated
 * contracts have a small, regular shape. They also work on the simple
 * hand-written contracts used in the unit tests.
 */

const RENAME_SUFFIX = '_mm';

/**
 * Identifiers that must never be treated as renameable locals: language
 * keywords, primitive/library type names, base classes, and built-in helpers.
 * Class name, method names and property names are added dynamically per source.
 */
const RESERVED = new Set<string>([
  'this',
  'super',
  'constructor',
  'class',
  'extends',
  'import',
  'export',
  'from',
  'return',
  'if',
  'else',
  'for',
  'while',
  'const',
  'let',
  'var',
  'new',
  'void',
  'true',
  'false',
  'null',
  'undefined',
  'public',
  'private',
  'readonly',
  // types
  'bigint',
  'boolean',
  'number',
  'string',
  'ByteString',
  'PubKey',
  'Sig',
  'Point',
  'FixedArray',
  'Readonly',
  // base classes
  'SmartContract',
  'StatefulSmartContract',
  'UnsafeSmartContract',
  // built-ins commonly present in generated contracts
  'assert',
  'toByteString',
  'checkSig',
  'checkPreimage',
  'sha256',
  'hash160',
]);

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Method / constructor header positions: `NAME(params) [: ret] {`. */
const METHOD_HEADER_RE =
  /(?:^|[\n;{}])\s*(?:public\s+|private\s+)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?::\s*[A-Za-z_]\w*\s*)?\{/g;

/** Collect the identifiers we must NOT rename for a given source. */
function collectReserved(src: string): Set<string> {
  const reserved = new Set(RESERVED);

  const classMatch = /\bclass\s+([A-Za-z_]\w*)/.exec(src);
  if (classMatch) reserved.add(classMatch[1]!);

  // Property names (`readonly foo: bigint;`). Only the `readonly` form is
  // trusted so we never mistake a parameter for a property. Property names are
  // already protected from rename because they are accessed as `this.<name>`
  // (never touched); adding them here additionally protects the constructor
  // parameters that echo their property's name.
  const roRe = /\breadonly\s+([A-Za-z_]\w*)\s*:/g;
  for (let m = roRe.exec(src); m; m = roRe.exec(src)) reserved.add(m[1]!);

  // Method / constructor names.
  for (let m = METHOD_HEADER_RE.exec(src); m; m = METHOD_HEADER_RE.exec(src)) {
    reserved.add(m[1]!);
  }
  METHOD_HEADER_RE.lastIndex = 0;

  return reserved;
}

/** Collect renameable local identifiers: method/constructor params + const/let names. */
function collectLocals(src: string, reserved: Set<string>): Set<string> {
  const locals = new Set<string>();

  // Parameters from every method / constructor header.
  for (let m = METHOD_HEADER_RE.exec(src); m; m = METHOD_HEADER_RE.exec(src)) {
    const params = m[2]!;
    for (const part of params.split(',')) {
      const pm = /^\s*([A-Za-z_]\w*)\s*:/.exec(part);
      if (pm) locals.add(pm[1]!);
    }
  }
  METHOD_HEADER_RE.lastIndex = 0;

  // Local const / let declarations.
  const declRe = /\b(?:const|let)\s+([A-Za-z_]\w*)/g;
  for (let m = declRe.exec(src); m; m = declRe.exec(src)) locals.add(m[1]!);

  // Never rename a reserved / class / method / property name (protects
  // `this.<prop>` and constructor params that echo a property name).
  for (const r of reserved) locals.delete(r);
  return locals;
}

/**
 * Rename local `const`/`let` variables and method parameters by appending a
 * deterministic suffix. Does NOT touch `this.` property accesses, property
 * declarations, method names, the class name, types, or keywords. A pure
 * alpha-rename is semantics-preserving; because it can shift constructor-arg
 * byte offsets it is exactly the kind of edit byte-parity would miss.
 */
export function renameLocals(src: string): string {
  const reserved = collectReserved(src);
  const locals = collectLocals(src, reserved);
  if (locals.size === 0) return src;

  const names = [...locals].sort((a, b) => b.length - a.length).map(escapeRegExp);
  // Match an identifier that is NOT part of a larger identifier and NOT a
  // member access (`this.name`); lookbehind excludes a preceding `.` or word
  // char, lookahead excludes a trailing word char. Single pass → no cascade.
  const re = new RegExp(`(?<![.\\w])(?:${names.join('|')})(?![\\w])`, 'g');
  return src.replace(re, (m) => m + RENAME_SUFFIX);
}

// ---------------------------------------------------------------------------
// reorderCommutative — swap operands of provably-commutative binary operators
// ---------------------------------------------------------------------------

/**
 * Binary operators recognised inside fully-parenthesised generated expressions,
 * longest-first so `===` is matched before `<`/`>` etc. Operators are always
 * space-delimited in the generator's output (`(l op r)`), which disambiguates a
 * unary `-` in a negative literal (`-5`, no surrounding spaces) from a binary
 * subtraction (` - `).
 */
const BIN_OPS = ['===', '!==', '<=', '>=', '&&', '||', '+', '-', '*', '<', '>'];

/** Operators whose operands may be swapped without changing the result. */
const COMMUTATIVE = new Set(['+', '*', '===', '!==', '&&', '||']);

/** Index of the ')' matching the '(' at `open`, or -1 if unbalanced. */
function matchParen(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * If `inner` is a single top-level binary expression `L op R` (op at paren
 * depth 0, space-delimited) whose operator is commutative, return `R op L`;
 * otherwise return `inner` unchanged. Requires EXACTLY one depth-0 operator so
 * we never mis-handle an operand list (`a, b`) or a chain.
 */
function swapTopLevel(inner: string): string {
  let depth = 0;
  const found: Array<{ start: number; end: number; op: string }> = [];
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === ' ' && depth === 0) {
      for (const op of BIN_OPS) {
        if (
          inner.startsWith(op, i + 1) &&
          inner[i + 1 + op.length] === ' '
        ) {
          found.push({ start: i, end: i + 1 + op.length, op });
          break;
        }
      }
    }
  }
  if (found.length !== 1) return inner;
  const { start, end, op } = found[0]!;
  if (!COMMUTATIVE.has(op)) return inner;
  const left = inner.slice(0, start);
  const right = inner.slice(end + 1);
  return `${right} ${op} ${left}`;
}

/** Recursively reorder every parenthesised group in `s`. */
function reorderParens(s: string): string {
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] === '(') {
      const j = matchParen(s, i);
      if (j === -1) {
        // Unbalanced (should not happen for valid source): copy verbatim.
        out += s.slice(i);
        break;
      }
      const inner = reorderParens(s.slice(i + 1, j));
      out += '(' + swapTopLevel(inner) + ')';
      i = j + 1;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

/**
 * Swap the operands of provably-commutative binary operators (`+ * === !== && ||`).
 * Never touches `-`, `/`, `<`, `<=`, `>`, `>=`. Because Rúnar expressions are
 * pure (no side effects), reordering a commutative operator's operands cannot
 * change the computed value — but it exercises a different codegen operand order
 * that byte-parity alone would not stress across the shared compiler design.
 */
export function reorderCommutative(src: string): string {
  return reorderParens(src);
}

// ---------------------------------------------------------------------------
// introduceLet — bind an assert condition to a fresh const
// ---------------------------------------------------------------------------

/**
 * Bind the first `assert(EXPR)` condition to a fresh boolean `const` and assert
 * that instead: `assert(EXPR)` → `const __mm_let0: boolean = (EXPR); assert(__mm_let0)`.
 * Introducing a let-binding for a pure subexpression is semantics-preserving;
 * it stresses the ANF binding / common-subexpression path. Returns the source
 * unchanged if no `assert(...)` statement is found.
 */
export function introduceLet(src: string): string {
  const m = /\bassert\s*\(/.exec(src);
  if (!m) return src;
  const openParen = m.index + m[0].length - 1; // index of '('
  const close = matchParen(src, openParen);
  if (close === -1) return src;
  const expr = src.slice(openParen + 1, close);
  const name = '__mm_let0';
  const replacement = `const ${name}: boolean = (${expr}); assert(${name})`;
  return src.slice(0, m.index) + replacement + src.slice(close + 1);
}

// ---------------------------------------------------------------------------
// insertDeadCode — inject never-executed / unused code
// ---------------------------------------------------------------------------

/** Match a public method header (`public name(params) [: ret] {`) — not the constructor. */
const PUBLIC_METHOD_HEADER_RE =
  /(\bpublic\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?::\s*[A-Za-z_]\w*\s*)?\{)/;

/**
 * Insert an unused `const` and a never-executed `if (false) { … }` branch at the
 * top of the first public method body. Both are dead: the const is never read
 * (generated contracts already contain unused locals, so this is valid Rúnar)
 * and the branch's condition is the literal `false`, so a correct compiler must
 * never enforce the assert inside it. A semantics-preserving edit that stresses
 * dead-code handling. Returns the source unchanged if no public method is found.
 */
export function insertDeadCode(src: string): string {
  const m = PUBLIC_METHOD_HEADER_RE.exec(src);
  if (!m) return src;
  const insertAt = m.index + m[1]!.length; // just after the method's `{`
  const dead =
    '\n    const __mm_dead: bigint = 42n;' +
    '\n    if (false) { assert(1n === 2n); }';
  return src.slice(0, insertAt) + dead + src.slice(insertAt);
}
