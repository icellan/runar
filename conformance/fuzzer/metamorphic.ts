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
// The remaining transforms are implemented in Task 9.2.
// ---------------------------------------------------------------------------

export function reorderCommutative(src: string): string {
  throw new Error('reorderCommutative: not implemented');
}

export function introduceLet(src: string): string {
  throw new Error('introduceLet: not implemented');
}

export function insertDeadCode(src: string): string {
  throw new Error('insertDeadCode: not implemented');
}
