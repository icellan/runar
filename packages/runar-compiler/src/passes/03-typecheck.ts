/**
 * Pass 3: Type-Check
 *
 * Type-checks the Rúnar AST. Builds type environments from properties,
 * constructor parameters, and method parameters, then verifies all
 * expressions have consistent types.
 */

import type {
  ContractNode,
  MethodNode,
  PropertyNode,
  Statement,
  Expression,
  TypeNode,
  SourceLocation,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { computeSideEffectSummary } from './side-effect-summary.js';
import type { MethodEffects, SideEffectSummary } from './side-effect-summary.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface TypeCheckResult {
  typedContract: ContractNode; // Same AST, types verified
  errors: CompilerDiagnostic[];
}

/**
 * Type-check a Rúnar AST. Returns the same AST (no transformation) plus
 * any type errors found.
 */
export function typecheck(contract: ContractNode): TypeCheckResult {
  const errors: CompilerDiagnostic[] = [];
  const checker = new TypeChecker(contract, errors);

  checker.checkConstructor();
  for (const method of contract.methods) {
    checker.checkMethod(method);
  }

  return { typedContract: contract, errors };
}

// ---------------------------------------------------------------------------
// Type representation for the checker
// ---------------------------------------------------------------------------

/** Internal type representation (simplified string-based). */
type TType = string; // e.g., 'bigint', 'boolean', 'ByteString', 'Sig', 'void', etc.

const VOID: TType = 'void';
const BIGINT: TType = 'bigint';
const BOOLEAN: TType = 'boolean';
const BYTESTRING: TType = 'ByteString';
const STATEFUL_CONTEXT: TType = 'StatefulContext';

// ---------------------------------------------------------------------------
// Built-in function signatures
// ---------------------------------------------------------------------------

interface FuncSig {
  params: TType[];
  returnType: TType;
}

const BUILTIN_FUNCTIONS: Map<string, FuncSig> = new Map([
  ['sha256',       { params: ['ByteString'], returnType: 'Sha256' }],
  ['ripemd160',    { params: ['ByteString'], returnType: 'Ripemd160' }],
  ['hash160',      { params: ['ByteString'], returnType: 'Ripemd160' }],
  ['hash256',      { params: ['ByteString'], returnType: 'Sha256' }],
  ['checkSig',     { params: ['Sig', 'PubKey'], returnType: 'boolean' }],
  ['checkMultiSig',{ params: ['Sig[]', 'PubKey[]'], returnType: 'boolean' }],
  ['assert',       { params: ['boolean'], returnType: 'void' }],
  ['len',          { params: ['ByteString'], returnType: 'bigint' }],
  ['cat',          { params: ['ByteString', 'ByteString'], returnType: 'ByteString' }],
  ['substr',       { params: ['ByteString', 'bigint', 'bigint'], returnType: 'ByteString' }],
  ['num2bin',      { params: ['bigint', 'bigint'], returnType: 'ByteString' }],
  ['bin2num',      { params: ['ByteString'], returnType: 'bigint' }],
  ['checkPreimage',{ params: ['SigHashPreimage'], returnType: 'boolean' }],
  ['verifyRabinSig', { params: ['ByteString', 'RabinSig', 'ByteString', 'RabinPubKey'], returnType: 'boolean' }],
  ['verifyWOTS',   { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_128s', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_128f', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_192s', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_192f', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_256s', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['verifySLHDSA_SHA2_256f', { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],
  ['sha256Compress',  { params: ['ByteString', 'ByteString'], returnType: 'ByteString' }],
  ['sha256Finalize',  { params: ['ByteString', 'ByteString', 'bigint'], returnType: 'ByteString' }],
  ['blake3Compress',  { params: ['ByteString', 'ByteString'], returnType: 'ByteString' }],
  ['blake3Hash',      { params: ['ByteString'], returnType: 'ByteString' }],
  ['abs',          { params: ['bigint'], returnType: 'bigint' }],
  ['min',          { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['max',          { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['within',       { params: ['bigint', 'bigint', 'bigint'], returnType: 'boolean' }],
  ['safediv',      { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['safemod',      { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['clamp',        { params: ['bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['sign',         { params: ['bigint'], returnType: 'bigint' }],
  ['pow',          { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['mulDiv',       { params: ['bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['percentOf',    { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['sqrt',         { params: ['bigint'], returnType: 'bigint' }],
  ['gcd',          { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['divmod',       { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['log2',         { params: ['bigint'], returnType: 'bigint' }],
  ['bool',         { params: ['bigint'], returnType: 'boolean' }],
  ['split',        { params: ['ByteString', 'bigint'], returnType: 'ByteString' }],
  ['reverseBytes', { params: ['ByteString'], returnType: 'ByteString' }],
  ['left',         { params: ['ByteString', 'bigint'], returnType: 'ByteString' }],
  ['right',        { params: ['ByteString', 'bigint'], returnType: 'ByteString' }],
  ['int2str',      { params: ['bigint', 'bigint'], returnType: 'ByteString' }],
  ['toByteString', { params: ['ByteString'], returnType: 'ByteString' }],
  ['exit',         { params: ['boolean'], returnType: 'void' }],
  ['pack',         { params: ['bigint'], returnType: 'ByteString' }],
  ['unpack',       { params: ['ByteString'], returnType: 'bigint' }],

  // Elliptic curve operations (secp256k1)
  ['ecAdd',              { params: ['Point', 'Point'], returnType: 'Point' }],
  ['ecMul',              { params: ['Point', 'bigint'], returnType: 'Point' }],
  ['ecMulGen',           { params: ['bigint'], returnType: 'Point' }],
  ['ecNegate',           { params: ['Point'], returnType: 'Point' }],
  ['ecOnCurve',          { params: ['Point'], returnType: 'boolean' }],
  ['ecModReduce',        { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['ecEncodeCompressed', { params: ['Point'], returnType: 'ByteString' }],
  ['ecMakePoint',        { params: ['bigint', 'bigint'], returnType: 'Point' }],
  ['ecPointX',           { params: ['Point'], returnType: 'bigint' }],
  ['ecPointY',           { params: ['Point'], returnType: 'bigint' }],

  // Elliptic curve operations (P-256 / NIST P-256 / secp256r1)
  ['p256Add',              { params: ['P256Point', 'P256Point'], returnType: 'P256Point' }],
  ['p256Mul',              { params: ['P256Point', 'bigint'], returnType: 'P256Point' }],
  ['p256MulGen',           { params: ['bigint'], returnType: 'P256Point' }],
  ['p256Negate',           { params: ['P256Point'], returnType: 'P256Point' }],
  ['p256OnCurve',          { params: ['P256Point'], returnType: 'boolean' }],
  ['p256EncodeCompressed', { params: ['P256Point'], returnType: 'ByteString' }],
  ['verifyECDSA_P256',     { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],

  // Elliptic curve operations (P-384 / NIST P-384 / secp384r1)
  ['p384Add',              { params: ['P384Point', 'P384Point'], returnType: 'P384Point' }],
  ['p384Mul',              { params: ['P384Point', 'bigint'], returnType: 'P384Point' }],
  ['p384MulGen',           { params: ['bigint'], returnType: 'P384Point' }],
  ['p384Negate',           { params: ['P384Point'], returnType: 'P384Point' }],
  ['p384OnCurve',          { params: ['P384Point'], returnType: 'boolean' }],
  ['p384EncodeCompressed', { params: ['P384Point'], returnType: 'ByteString' }],
  ['verifyECDSA_P384',     { params: ['ByteString', 'ByteString', 'ByteString'], returnType: 'boolean' }],

  // Baby Bear field arithmetic (p = 2013265921)
  ['bbFieldAdd',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bbFieldSub',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bbFieldMul',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bbFieldInv',         { params: ['bigint'], returnType: 'bigint' }],

  // Baby Bear quartic extension field (W = 11)
  ['bbExt4Mul0',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Mul1',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Mul2',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Mul3',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Inv0',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Inv1',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Inv2',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['bbExt4Inv3',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],

  // KoalaBear field arithmetic (p = 2130706433)
  ['kbFieldAdd',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['kbFieldSub',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['kbFieldMul',         { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['kbFieldInv',         { params: ['bigint'], returnType: 'bigint' }],

  // KoalaBear quartic extension field (W = 3)
  ['kbExt4Mul0',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Mul1',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Mul2',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Mul3',         { params: ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Inv0',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Inv1',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Inv2',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],
  ['kbExt4Inv3',         { params: ['bigint', 'bigint', 'bigint', 'bigint'], returnType: 'bigint' }],

  // BN254 field arithmetic (p = 21888...8583)
  ['bn254FieldAdd',      { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bn254FieldSub',      { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bn254FieldMul',      { params: ['bigint', 'bigint'], returnType: 'bigint' }],
  ['bn254FieldInv',      { params: ['bigint'], returnType: 'bigint' }],
  ['bn254FieldNeg',      { params: ['bigint'], returnType: 'bigint' }],

  // BN254 G1 curve operations
  ['bn254G1Add',         { params: ['Point', 'Point'], returnType: 'Point' }],
  ['bn254G1ScalarMul',   { params: ['Point', 'bigint'], returnType: 'Point' }],
  ['bn254G1Negate',      { params: ['Point'], returnType: 'Point' }],
  ['bn254G1OnCurve',     { params: ['Point'], returnType: 'boolean' }],

  // Merkle proof verification
  ['merkleRootSha256',   { params: ['ByteString', 'ByteString', 'bigint', 'bigint'], returnType: 'ByteString' }],
  ['merkleRootHash256',  { params: ['ByteString', 'ByteString', 'bigint', 'bigint'], returnType: 'ByteString' }],

  // Preimage extractors — numeric fields return bigint, byte fields return ByteString/Sha256
  ['extractVersion',       { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['extractHashPrevouts',  { params: ['SigHashPreimage'], returnType: 'Sha256' }],
  ['extractHashSequence',  { params: ['SigHashPreimage'], returnType: 'Sha256' }],
  ['extractOutpoint',      { params: ['SigHashPreimage'], returnType: 'ByteString' }],
  ['extractInputIndex',    { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['extractScriptCode',    { params: ['SigHashPreimage'], returnType: 'ByteString' }],
  ['extractAmount',        { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['extractSequence',      { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['extractOutputHash',    { params: ['SigHashPreimage'], returnType: 'Sha256' }],
  ['extractOutputs',       { params: ['SigHashPreimage'], returnType: 'Sha256' }],
  ['extractLocktime',      { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['extractSigHashType',   { params: ['SigHashPreimage'], returnType: 'bigint' }],
  ['buildChangeOutput',    { params: ['ByteString', 'bigint'], returnType: 'ByteString' }],
  // Intent sub-covenant intrinsics (BSVM Phase 13). Witness-bridge wrappers
  // that compile down to standard primitives + auto-injected method params.
  // See docs/cross-covenant-pattern.md.
  //
  // First arg of extractPrevOutputScript / requireOutputP2PKH MUST be an
  // integer literal — enforced as a special case in checkCallArgs.
  ['extractPrevOutputScript', { params: ['bigint', 'ByteString'], returnType: 'ByteString' }],
  ['requireOutputP2PKH',      { params: ['bigint', 'ByteString', 'bigint'], returnType: 'void' }],
  ['currentBlockHeight',      { params: [], returnType: 'bigint' }],
  // F-024 (R14): read-only view of the auto-injected `_newAmount` — the
  // satoshis of the default single-output state continuation.
  ['continuationAmount',      { params: [], returnType: 'bigint' }],
]);

// ---------------------------------------------------------------------------
// Known global constants (e.g., EC constants, SigHash namespace)
// ---------------------------------------------------------------------------

const KNOWN_GLOBALS: Map<string, TType> = new Map([
  ['SigHash', '<namespace>'], // SigHash.ALL, SigHash.FORKID, etc.
  ['EC_P', 'bigint'],         // secp256k1 field prime
  ['EC_N', 'bigint'],         // secp256k1 group order
  ['EC_G', 'Point'],          // secp256k1 generator point
]);

// ---------------------------------------------------------------------------
// Subtyping: Domain types that are subtypes of ByteString
// ---------------------------------------------------------------------------

/**
 * ByteString subtypes -- these types are all represented as byte strings
 * on the stack and can be passed where ByteString is expected.
 */
const BYTESTRING_SUBTYPES = new Set<TType>([
  'ByteString', 'PubKey', 'Sig', 'Sha256', 'Ripemd160',
  'Addr', 'SigHashPreimage', 'Point', 'P256Point', 'P384Point',
]);

/**
 * Bigint subtypes -- types that are represented as integers on the stack.
 */
const BIGINT_SUBTYPES = new Set<TType>([
  'bigint', 'RabinSig', 'RabinPubKey',
]);

/**
 * Is `t` a member of the ByteString family — i.e. does a value of this type
 * sit on the stack as a BYTE STRING rather than as a script NUMBER?
 *
 * N-076: this predicate is the single source of truth for that question, and
 * `04-anf-lower.ts` consults it rather than keeping a second copy of the list.
 * The two lists had already drifted: the lowerer's copy carried `RabinSig` and
 * `RabinPubKey`, which are `BIGINT_SUBTYPES` here, so `===` on a Rabin value
 * was annotated `bytes` and `+` on one lowered to OP_CAT.
 *
 * Anything NOT in this family is numeric: compared with OP_NUMEQUAL, added
 * with OP_ADD. Getting it backwards is a correctness defect in both
 * directions — OP_EQUAL on a number is over-strict (rejects a valid witness
 * that encodes the same value with different bytes), OP_NUMEQUAL on a hash is
 * under-strict (a trailing high-order zero compares equal), and OP_CAT where
 * OP_ADD belongs is a plain miscompile.
 */
export function isByteStringFamilyType(t: string): boolean {
  return BYTESTRING_SUBTYPES.has(t as TType);
}

/**
 * Is `t` a member of the bigint family — a value that sits on the stack as a
 * script NUMBER? The counterpart of `isByteStringFamilyType`, exported for the
 * same reason: 03b-expand-fixed-arrays needs the question answered and must
 * not keep a second copy of the list (N-133).
 */
export function isBigintFamilyType(t: string): boolean {
  return BIGINT_SUBTYPES.has(t as TType);
}

function isSubtype(actual: TType, expected: TType): boolean {
  if (actual === expected) return true;

  // <inferred> and <unknown> are compatible with anything
  if (actual === '<inferred>' || actual === '<unknown>') return true;
  if (expected === '<inferred>' || expected === '<unknown>') return true;

  // ByteString subtypes
  if (expected === 'ByteString' && BYTESTRING_SUBTYPES.has(actual)) return true;
  if (actual === 'ByteString' && BYTESTRING_SUBTYPES.has(expected)) return true;

  // Both in the ByteString family -> compatible (e.g. Addr and Ripemd160)
  if (BYTESTRING_SUBTYPES.has(actual) && BYTESTRING_SUBTYPES.has(expected)) return true;

  // bigint subtypes
  if (expected === 'bigint' && BIGINT_SUBTYPES.has(actual)) return true;
  if (actual === 'bigint' && BIGINT_SUBTYPES.has(expected)) return true;

  // Both in the bigint family -> compatible
  if (BIGINT_SUBTYPES.has(actual) && BIGINT_SUBTYPES.has(expected)) return true;

  // Array subtyping for checkMultiSig
  if (expected.endsWith('[]') && actual.endsWith('[]')) {
    return isSubtype(actual.slice(0, -2), expected.slice(0, -2));
  }

  return false;
}

function isBigintFamily(t: TType): boolean {
  return BIGINT_SUBTYPES.has(t);
}

function isByteFamily(t: TType): boolean {
  return BYTESTRING_SUBTYPES.has(t);
}

function isStatefulContextType(t: TType): boolean {
  return t === STATEFUL_CONTEXT;
}

/** One emitted state slot: what the continuation actually carries. */
interface StateSlot {
  name: string;
  type: TypeNode;
}

/**
 * The mutable state as `addOutput` sees it: one slot per value the state
 * continuation carries, which is NOT one per declared property.
 *
 * N-107. `expandFixedArrays` (pass 3b) runs immediately after this one and
 * splits `board: FixedArray<bigint, 3>` into `board__0 .. board__2`, so a
 * contract declaring `board` and `n` emits FOUR state values, not two.
 * `addOutput(satoshis, ...values)` is positional against the EMITTED values,
 * so counting declared properties answers the wrong question: the reference
 * rule refused `addOutput(1000n, board[0], board[1], board[2], n)` — the only
 * shape that lowers — with "expects 3 argument(s) ... got 5", and demanded
 * `addOutput(1000n, board, n)` instead, which type-checked and then died in
 * stack lowering because `board` has no stack slot of its own. There was no
 * accepted way to call addOutput from a contract with FixedArray state.
 *
 * Five of the six ports dodged this by scoping the rule out of FixedArray
 * contracts entirely, which meant they ACCEPTED a wrong-arity call and emitted
 * a continuation that disagreed with the contract's own state. Java got the
 * count right only because it ran the expansion BEFORE the typechecker
 * (N-106) — the same root cause, seen from the other side.
 *
 * The flattening mirrors `03b-expand-fixed-arrays.ts`'s `buildArrayMeta`
 * exactly, nesting and `__<i>` naming included, so the slot names in a
 * diagnostic are the synthetic property names the next pass will create.
 */
function expandedStateSlots(properties: PropertyNode[]): StateSlot[] {
  const slots: StateSlot[] = [];
  const push = (name: string, type: TypeNode): void => {
    // `length <= 0` is already a parse/validate error; keeping the property
    // whole here means the arity diagnostic never fires on a contract that is
    // going to be rejected anyway for a better reason.
    if (type.kind === 'fixed_array_type' && type.length > 0) {
      for (let i = 0; i < type.length; i++) push(`${name}__${i}`, type.element);
      return;
    }
    slots.push({ name, type });
  };
  for (const p of properties) {
    if (!p.readonly) push(p.name, p.type);
  }
  return slots;
}

function flattenAddOutputArgs(args: Expression[]): Expression[] {
  if (args.length === 2 && args[1]?.kind === 'array_literal') {
    return [args[0]!, ...args[1].elements];
  }
  return args;
}

// ---------------------------------------------------------------------------
// Type environment
// ---------------------------------------------------------------------------

class TypeEnv {
  private scopes: Map<string, TType>[] = [];

  constructor() {
    this.pushScope();
  }

  pushScope(): void {
    this.scopes.push(new Map());
  }

  popScope(): void {
    this.scopes.pop();
  }

  define(name: string, type: TType): void {
    const top = this.scopes[this.scopes.length - 1]!;
    top.set(name, type);
  }

  lookup(name: string): TType | undefined {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const t = this.scopes[i]!.get(name);
      if (t !== undefined) return t;
    }
    return undefined;
  }

  /** Index of the innermost scope that binds `name`, or -1 if none does. */
  scopeIndexOf(name: string): number {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      if (this.scopes[i]!.has(name)) return i;
    }
    return -1;
  }

  /** Index the next `pushScope()` will occupy. */
  get depth(): number {
    return this.scopes.length;
  }
}

// ---------------------------------------------------------------------------
// Affine types: values that can be consumed at most once
// ---------------------------------------------------------------------------

const AFFINE_TYPES = new Set<TType>(['Sig', 'SigHashPreimage']);

/**
 * Maps consuming function names to the parameter indices that consume
 * affine values.  For example, `checkSig` consumes parameter 0 (Sig).
 */
const CONSUMING_FUNCTIONS: Record<string, number[]> = {
  'checkSig':      [0],   // first param (Sig) is consumed
  'checkMultiSig': [0],   // first param (Sig[]) is consumed
  'checkPreimage': [0],   // first param (SigHashPreimage) is consumed
};

// ---------------------------------------------------------------------------
// Type checker
// ---------------------------------------------------------------------------

class TypeChecker {
  private readonly contract: ContractNode;
  private readonly errors: CompilerDiagnostic[];
  private readonly propTypes: Map<string, TType>;
  private readonly methodSigs: Map<string, FuncSig>;

  /**
   * Tracks affine values consumed within the current method /
   * constructor. Each entry is a canonical *origin key*, not a
   * variable name: a parameter is keyed by its name, a property
   * access by `prop:<name>`. Aliases (`const again: Sig = sig;`)
   * resolve to the original parameter's origin via `affineAliases`.
   * 2026-04-30 audit finding F6 — without origin tracking the
   * compiler accepted both `checkSig(sig, pk); checkSig(again, pk)`
   * and `checkSig(this.sig, pk); checkSig(this.sig, pk)`.
   */
  private consumedValues: Set<string> = new Set();

  /**
   * Maps a local variable name to the affine origin key it aliases.
   * Populated when a `variable_decl` of an affine-typed identifier or
   * property access is encountered.
   */
  private affineAliases: Map<string, string> = new Map();

  /**
   * F-110: for every enclosing loop that may run two or more times, the env
   * scope index its init/body bindings live at (innermost last). A bounded
   * loop is unrolled `count` times, so consuming an affine value bound below
   * the innermost such index is a consumption per iteration.
   */
  private repeatingLoopScopes: number[] = [];

  /** Lazily computed side-effect summary (follows private helpers). */
  private sideEffects: SideEffectSummary | null = null;

  private methodEffects(name: string): MethodEffects {
    if (this.sideEffects === null) this.sideEffects = computeSideEffectSummary(this.contract);
    const effects = this.sideEffects.get(name);
    if (!effects) throw new Error(`side-effect summary has no entry for method '${name}'`);
    return effects;
  }

  constructor(contract: ContractNode, errors: CompilerDiagnostic[]) {
    this.contract = contract;
    this.errors = errors;

    // Build property type map
    this.propTypes = new Map();
    for (const prop of contract.properties) {
      this.propTypes.set(prop.name, typeNodeToTType(prop.type));
    }

    // For StatefulSmartContract, add the implicit txPreimage property
    if (contract.parentClass === 'StatefulSmartContract') {
      this.propTypes.set('txPreimage', 'SigHashPreimage');
    }

    // Build method signature map (for this.method() calls)
    this.methodSigs = new Map();
    for (const method of contract.methods) {
      this.methodSigs.set(method.name, {
        params: method.params.map(p => typeNodeToTType(p.type)),
        returnType: method.visibility === 'public' ? 'void' : inferMethodReturnType(method),
      });
    }
  }

  checkConstructor(): void {
    const ctor = this.contract.constructor;
    const env = new TypeEnv();

    // Reset affine tracking for this scope
    this.consumedValues = new Set();
    this.affineAliases = new Map();

    // Add constructor params to env
    for (const param of ctor.params) {
      env.define(param.name, typeNodeToTType(param.type));
    }

    // Add properties to env (since constructor assigns them)
    for (const prop of this.contract.properties) {
      env.define(prop.name, typeNodeToTType(prop.type));
    }

    this.checkStatements(ctor.body, env, ctor.sourceLocation);
  }

  checkMethod(method: MethodNode): void {
    const env = new TypeEnv();

    // Reset affine tracking for this method
    this.consumedValues = new Set();
    this.affineAliases = new Map();

    // Add method params to env
    for (const param of method.params) {
      env.define(param.name, typeNodeToTType(param.type));
    }

    this.checkStatements(method.body, env, method.sourceLocation);

    // F-075: every guard below reads the method's effects from the shared
    // side-effect summary, which follows the private-helper call graph. That is
    // the same analysis ANF lowering uses to inject the continuation, and ANF
    // lowering inlines private helpers, so a body-local walk here let a
    // developer disable all three guards by moving the triggering call into a
    // helper while the continuation was still injected as if it were inline.
    const effects = this.methodEffects(method.name);

    // Crit-3 (BSVM Phase 13) — reject mixing requireOutputP2PKH() with
    // this.addDataOutput() in the same method (including its private
    // helpers). The intrinsic's
    // compile-time output-offset assumes a fixed 34-byte stride per output;
    // a preceding variable-length OP_RETURN output silently shifts the
    // OP_EQUALVERIFY target, letting the bond P2PKH route through an
    // unmatched index. v1 forbids the mix; v2 may relax with a
    // variable-stride decoder.
    const hasRequireP2PKH = effects.callsRequireOutputP2PKH;
    const hasAddDataOutput = effects.hasDataOutput;
    if (hasRequireP2PKH && hasAddDataOutput) {
      this.errors.push(makeDiagnostic(
        `method '${method.name}' mixes requireOutputP2PKH() with addDataOutput() — ` +
          `v1 of the intrinsic assumes a fixed 34-byte output stride and ` +
          `variable-length OP_RETURN outputs break the offset computation; ` +
          `split the addDataOutput call into a separate method`,
        'error',
        method.sourceLocation,
      ));
    }

    // Reject requireOutputP2PKH(0) in a method whose implicit single-output
    // state continuation ALSO claims output 0. A StatefulSmartContract method
    // that mutates state but uses no this.addOutput()/addRawOutput() re-creates
    // the contract's own (large codePart) script at output 0; requiring output
    // 0 to also be a 34-byte P2PKH is impossible (codePart >= 253 bytes forces a
    // 3-byte CompactSize length prefix, never the P2PKH template's 0x19), so the
    // contract is PERMANENTLY unspendable. The terminal case (no state mutation
    // -> no continuation) stays valid.
    //
    // R-300: "addOutput/addRawOutput layouts are left to the developer" used to
    // finish that sentence, and it was wrong — there is no layout the developer
    // can choose that makes the offsets work. `this.addOutput(...)` writes the
    // contract's continuation (codePart plus serialised state, hundreds of
    // bytes) at output 0, so `outputIndex * 34` lands INSIDE that script for
    // every index, and the assertion compares bytes from the middle of the
    // contract's own locking script against a P2PKH serialisation. No honest
    // spend satisfies it. `addRawOutput` is no better: its script length is a
    // runtime value, so the compiler cannot prove the stride either. Measured
    // before this guard existed — ts `success = true`, go `exit = 0` — see
    // conformance/negatives/N34-p2pkh-index-with-state-output.runar.ts.
    if (this.contract.parentClass === 'StatefulSmartContract') {
      if (hasRequireP2PKH && effects.hasStateOutput) {
        this.errors.push(makeDiagnostic(
          `method '${method.name}' mixes requireOutputP2PKH() with ` +
            `this.addOutput()/addRawOutput() — the intrinsic reads output i at byte ` +
            `offset i*34, which is only correct when every earlier output is exactly ` +
            `34 bytes, and a state-continuation output never is (codePart plus ` +
            `serialised state). The assertion would read bytes from the middle of the ` +
            `contract's own locking script, so the contract would be permanently ` +
            `unspendable. Assert the payment from a separate method that emits no ` +
            `output of its own`,
          'error',
          method.sourceLocation,
        ));
      }

      if (effects.requiresOutputP2PKHZero && effects.mutatesState && !effects.hasStateOutput) {
        this.errors.push(makeDiagnostic(
          `method '${method.name}' calls requireOutputP2PKH(0, ...) but also mutates state ` +
            `without this.addOutput()/addRawOutput() — the auto-injected single-output state ` +
            `continuation already claims output 0 (the contract's codePart), so output 0 cannot ` +
            `simultaneously be the required 34-byte P2PKH. This contract would be permanently ` +
            `unspendable. Assert the bond on a non-continuation output index, or make the method ` +
            `terminal (no state mutation)`,
          'error',
          method.sourceLocation,
        ));
      }
    }
  }

  private checkStatements(
    stmts: Statement[],
    env: TypeEnv,
    _parentLoc: SourceLocation,
  ): void {
    for (const stmt of stmts) {
      this.checkStatement(stmt, env);
    }
  }

  /**
   * Location of the statement currently being checked (R-143).
   *
   * Expression nodes do not carry a `sourceLocation` in this tier — the
   * parsers never set one on `call_expr` / `binary_expr` / `member_expr` and
   * friends, which is R-142 — so a diagnostic raised from inside an expression
   * has nothing of its own to report. The enclosing STATEMENT does have one,
   * and statement granularity is the difference between "somewhere in your
   * contract" and "line 14". Closing R-142 sharpens these to the exact operand
   * without any change here, because every site reads
   * `<expr>.sourceLocation ?? this.currentStmtLoc`.
   */
  private currentStmtLoc: SourceLocation | undefined;

  /**
   * F-024 (R14): `continuationAmount()` is a read-only view of the
   * auto-injected `_newAmount`. Without this check an assignment to it would
   * lower as a plain read and silently drop the write.
   */
  private refuseContinuationAmountWrite(target: Expression, loc: SourceLocation | undefined): void {
    if (target.kind === 'call_expr' && target.callee.kind === 'identifier' && target.callee.name === 'continuationAmount') {
      // F-024 (R14): the one diagnostic every tier emits for this write.
      this.errors.push(makeDiagnostic('continuationAmount() is read-only and cannot be assigned', 'error', loc));
    }
  }

  private checkStatement(stmt: Statement, env: TypeEnv): void {
    this.currentStmtLoc = stmt.sourceLocation ?? this.currentStmtLoc;
    switch (stmt.kind) {
      case 'variable_decl': {
        const initType = this.inferExprType(stmt.init, env);
        if (stmt.type) {
          const declaredType = typeNodeToTType(stmt.type);
          if (!isSubtype(initType, declaredType)) {
            this.errors.push(makeDiagnostic(
              `Type '${initType}' is not assignable to type '${declaredType}'`,
              'error',
              stmt.sourceLocation,
            ));
          }
          env.define(stmt.name, declaredType);
        } else {
          env.define(stmt.name, initType);
        }
        // Record affine alias: when the new local is affine-typed
        // and its initializer is itself an affine origin (param or
        // contract property), bind the local name to that origin so
        // a subsequent consume of either the local or the origin is
        // detected as a double-consume.
        const declType = stmt.type ? typeNodeToTType(stmt.type) : initType;
        if (AFFINE_TYPES.has(declType)) {
          const origin = this.affineOriginOfExpr(stmt.init);
          if (origin) {
            this.affineAliases.set(stmt.name, origin);
          }
        }
        break;
      }

      case 'assignment': {
        this.refuseContinuationAmountWrite(stmt.target, stmt.sourceLocation);
        const targetType = this.inferExprType(stmt.target, env);
        const valueType = this.inferExprType(stmt.value, env);
        if (!isSubtype(valueType, targetType)) {
          this.errors.push(makeDiagnostic(
            `Type '${valueType}' is not assignable to type '${targetType}'`,
            'error',
            stmt.sourceLocation,
          ));
        }
        break;
      }

      case 'if_statement': {
        const condType = this.inferExprType(stmt.condition, env);
        if (condType !== BOOLEAN) {
          this.errors.push(makeDiagnostic(
            `If condition must be boolean, got '${condType}'`,
            'error',
            stmt.sourceLocation,
          ));
        }
        env.pushScope();
        this.checkStatements(stmt.then, env, stmt.sourceLocation);
        env.popScope();
        if (stmt.else) {
          env.pushScope();
          this.checkStatements(stmt.else, env, stmt.sourceLocation);
          env.popScope();
        }
        break;
      }

      case 'for_statement': {
        const loopScope = env.depth;
        const repeats = loopMayRunTwice(stmt);
        env.pushScope();
        // Check init
        this.checkStatement(stmt.init, env);
        // Check condition
        const condType = this.inferExprType(stmt.condition, env);
        if (condType !== BOOLEAN) {
          this.errors.push(makeDiagnostic(
            `For loop condition must be boolean, got '${condType}'`,
            'error',
            stmt.sourceLocation,
          ));
        }
        // R-065: the update clause used to be skipped entirely, so
        // `for (let i = 0n; i < 3n; undefinedFn())` compiled clean -- a hole in
        // the rule that only Rúnar builtins and contract methods are callable
        // (CLAUDE.md names `console.log` explicitly). `02-validate.ts`
        // separately restricts the clause to a unit-step advance; this is the
        // type-level half of the same guard.
        this.checkStatement(stmt.update, env);
        // Check body. F-110: the body runs once per iteration; see
        // `repeatingLoopScopes`.
        if (repeats) this.repeatingLoopScopes.push(loopScope);
        this.checkStatements(stmt.body, env, stmt.sourceLocation);
        if (repeats) this.repeatingLoopScopes.pop();
        env.popScope();
        break;
      }

      case 'expression_statement':
        this.inferExprType(stmt.expression, env);
        break;

      case 'return_statement':
        if (stmt.value) {
          this.inferExprType(stmt.value, env);
        }
        break;
    }
  }

  /**
   * Infer the type of an expression. Returns the inferred type string.
   */
  inferExprType(expr: Expression, env: TypeEnv): TType {
    switch (expr.kind) {
      case 'bigint_literal':
        return BIGINT;

      case 'bool_literal':
        return BOOLEAN;

      case 'bytestring_literal':
        return BYTESTRING;

      case 'identifier': {
        if (expr.name === 'this') return '<this>';
        if (expr.name === 'super') return '<super>';
        if (expr.name === 'true' || expr.name === 'false') return BOOLEAN;
        // The blank identifier. `_ = x` is the Go / Rust / Zig discard idiom and
        // the Go DSL frontend emits it as an assignment TARGET, so it reaches the
        // identifier arm as a name to be typed. It is a discard, not a reference:
        // nothing is being looked up, so `undefined` is the wrong word for it.
        // Measured at the parent commit, go/rust/python/zig/ruby/java all compiled
        // `_ = doubled` to the same 7652957c009c77 while TS alone refused it with
        // "Undefined variable '_'" — invariant 1 (all seven parse all nine
        // surfaces) already broken for this shape. Listing it here rather than
        // letting the new fall-through reject it keeps the six tiers' bytes and
        // brings the seventh into line.
        if (expr.name === '_') return '<unknown>';

        const t = env.lookup(expr.name);
        if (t !== undefined) return t;

        // Check if it's a builtin function name (used as a reference)
        if (BUILTIN_FUNCTIONS.has(expr.name)) return '<builtin>';

        // Check if it's a contract property used as a bare identifier
        // (some frontends like Solidity and Java emit `pubKeyHash` instead of
        // `this.pubKeyHash`).
        //
        // This is deliberately checked BEFORE KNOWN_GLOBALS: a property named
        // `EC_P` / `EC_N` / `EC_G` / `SigHash` shadows the global, which is
        // what the other six tiers do and what lexical scoping implies. With
        // the two the other way round, a Java-surface contract declaring
        // `Bigint EC_G` and calling `ecMul(EC_G, k)` typed the bigint property
        // as the global `Point` and compiled a 424 KB EC scalar multiply over
        // a value that is not a point — while go, rust, python, zig, ruby and
        // java all rejected the same source with "argument 1 of ecMul():
        // expected 'Point', got 'bigint'".
        const propType = this.propTypes.get(expr.name);
        if (propType !== undefined) return propType;

        // Check if it's a known global constant
        const globalType = KNOWN_GLOBALS.get(expr.name);
        if (globalType !== undefined) return globalType;

        // Undeclared variable -- emit error
        this.errors.push(makeDiagnostic(
          `Undefined variable '${expr.name}'`,
          'error',
          expr.sourceLocation,
        ));
        return '<unknown>';
      }

      case 'property_access': {
        // this.x
        const propType = this.propTypes.get(expr.property);
        if (propType) return propType;

        this.errors.push(makeDiagnostic(
          `Property '${expr.property}' does not exist on the contract`,
          'error',
          expr.sourceLocation,
        ));
        return '<unknown>';
      }

      case 'member_expr': {
        const objType = this.inferExprType(expr.object, env);

        // this.method -> return function type
        if (objType === '<this>') {
          // Check if it's a property
          const propType = this.propTypes.get(expr.property);
          if (propType) return propType;

          // Check if it's a method
          if (this.methodSigs.has(expr.property)) return '<method>';

          // Special: getStateScript
          if (expr.property === 'getStateScript') return '<method>';

          this.errors.push(makeDiagnostic(
            `Property or method '${expr.property}' does not exist on the contract`,
            'error',
            expr.sourceLocation,
          ));
          return '<unknown>';
        }

        // R-143: every diagnostic in this branch passes a location. They are the
      // `ctx: runar.StatefulContext` calling convention — the shape the
      // `.runar.zig` surface uses — and all thirteen of them used to omit it,
      // while the sibling `this.<intrinsic>` branch a hundred lines below
      // passed it for the identical checks. Same mistake, reported as
      // `Counter.runar.ts:14:4: addOutput() expects …` on one surface and as a
      // bare sentence with no file, line or column on the other.
      if (isStatefulContextType(objType)) {
          if (expr.property === 'txPreimage') return 'SigHashPreimage';
          if (expr.property === 'getStateScript' || expr.property === 'addOutput' || expr.property === 'addRawOutput' || expr.property === 'addDataOutput') {
            return '<method>';
          }
        }

        // SigHash.ALL, SigHash.FORKID, etc.
        if (expr.object.kind === 'identifier' && expr.object.name === 'SigHash') {
          return BIGINT;
        }

        return '<unknown>';
      }

      case 'binary_expr':
        return this.checkBinaryExpr(expr, env);

      case 'unary_expr':
        return this.checkUnaryExpr(expr, env);

      case 'call_expr':
        return this.checkCallExpr(expr, env);

      case 'ternary_expr': {
        const condType = this.inferExprType(expr.condition, env);
        if (condType !== BOOLEAN) {
          this.errors.push(makeDiagnostic(
            `Ternary condition must be boolean, got '${condType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        const consequentType = this.inferExprType(expr.consequent, env);
        const alternateType = this.inferExprType(expr.alternate, env);

        if (consequentType !== alternateType) {
          // Allow subtypes
          if (isSubtype(alternateType, consequentType)) return consequentType;
          if (isSubtype(consequentType, alternateType)) return alternateType;

          this.errors.push(makeDiagnostic(
            `Ternary branches have incompatible types: '${consequentType}' and '${alternateType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        return consequentType;
      }

      case 'index_access': {
        const objType = this.inferExprType(expr.object, env);
        const indexType = this.inferExprType(expr.index, env);

        if (!isBigintFamily(indexType)) {
          this.errors.push(makeDiagnostic(
            `Array index must be bigint, got '${indexType}'`,
            'error',
            expr.sourceLocation,
          ));
        }

        // If the object type ends with '[]', return the element type
        if (objType.endsWith('[]')) {
          return objType.slice(0, -2);
        }

        return '<unknown>';
      }

      case 'increment_expr':
      case 'decrement_expr': {
        this.refuseContinuationAmountWrite(expr.operand, expr.sourceLocation);
        const operandType = this.inferExprType(expr.operand, env);
        if (!isBigintFamily(operandType)) {
          this.errors.push(makeDiagnostic(
            `${expr.kind === 'increment_expr' ? '++' : '--'} operator requires bigint, got '${operandType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        return BIGINT;
      }

      case 'array_literal': {
        if (expr.elements.length === 0) {
          return '<unknown>[]';
        }
        const elemType = this.inferExprType(expr.elements[0]!, env);
        for (let i = 1; i < expr.elements.length; i++) {
          const et = this.inferExprType(expr.elements[i]!, env);
          if (!isSubtype(et, elemType) && et !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `Array element type mismatch: expected '${elemType}', got '${et}'`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        return `${elemType}[]`;
      }
    }
  }

  private checkBinaryExpr(
    expr: Extract<Expression, { kind: 'binary_expr' }>,
    env: TypeEnv,
  ): TType {
    const leftType = this.inferExprType(expr.left, env);
    const rightType = this.inferExprType(expr.right, env);

    // ByteString concatenation: ByteString + ByteString -> ByteString (via OP_CAT)
    if (expr.op === '+') {
      if (isByteFamily(leftType) && isByteFamily(rightType)) {
        return BYTESTRING;
      }
    }

    // Arithmetic operators: bigint x bigint -> bigint
    const arithmeticOps = new Set(['+', '-', '*', '/', '%']);
    if (arithmeticOps.has(expr.op)) {
      if (!isBigintFamily(leftType)) {
        this.errors.push(makeDiagnostic(
          `Left operand of '${expr.op}' must be bigint, got '${leftType}'`,
          'error',
          expr.left.sourceLocation,
        ));
      }
      if (!isBigintFamily(rightType)) {
        this.errors.push(makeDiagnostic(
          `Right operand of '${expr.op}' must be bigint, got '${rightType}'`,
          'error',
          expr.right.sourceLocation,
        ));
      }
      return BIGINT;
    }

    // Comparison operators: bigint x bigint -> boolean
    const comparisonOps = new Set(['<', '<=', '>', '>=']);
    if (comparisonOps.has(expr.op)) {
      if (!isBigintFamily(leftType)) {
        this.errors.push(makeDiagnostic(
          `Left operand of '${expr.op}' must be bigint, got '${leftType}'`,
          'error',
          expr.left.sourceLocation,
        ));
      }
      if (!isBigintFamily(rightType)) {
        this.errors.push(makeDiagnostic(
          `Right operand of '${expr.op}' must be bigint, got '${rightType}'`,
          'error',
          expr.right.sourceLocation,
        ));
      }
      return BOOLEAN;
    }

    // Equality operators: T x T -> boolean (any matching types)
    const equalityOps = new Set(['===', '!==']);
    if (equalityOps.has(expr.op)) {
      // Allow comparison between compatible types
      if (!isSubtype(leftType, rightType) && !isSubtype(rightType, leftType)) {
        if (leftType !== '<unknown>' && rightType !== '<unknown>') {
          this.errors.push(makeDiagnostic(
            `Cannot compare '${leftType}' and '${rightType}' with '${expr.op}'`,
            'error',
            expr.sourceLocation,
          ));
        }
      }
      return BOOLEAN;
    }

    // Logical operators: boolean x boolean -> boolean
    const logicalOps = new Set(['&&', '||']);
    if (logicalOps.has(expr.op)) {
      if (leftType !== BOOLEAN && leftType !== '<unknown>') {
        this.errors.push(makeDiagnostic(
          `Left operand of '${expr.op}' must be boolean, got '${leftType}'`,
          'error',
          expr.left.sourceLocation,
        ));
      }
      if (rightType !== BOOLEAN && rightType !== '<unknown>') {
        this.errors.push(makeDiagnostic(
          `Right operand of '${expr.op}' must be boolean, got '${rightType}'`,
          'error',
          expr.right.sourceLocation,
        ));
      }
      return BOOLEAN;
    }

    // Shift operators: bigint x bigint -> bigint
    const shiftOps = new Set(['<<', '>>']);
    if (shiftOps.has(expr.op)) {
      if (!isBigintFamily(leftType)) {
        this.errors.push(makeDiagnostic(
          `Left operand of '${expr.op}' must be bigint, got '${leftType}'`,
          'error',
          expr.left.sourceLocation,
        ));
      }
      if (!isBigintFamily(rightType)) {
        this.errors.push(makeDiagnostic(
          `Right operand of '${expr.op}' must be bigint, got '${rightType}'`,
          'error',
          expr.right.sourceLocation,
        ));
      }
      return BIGINT;
    }

    // Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
    const bitwiseOps = new Set(['&', '|', '^']);
    if (bitwiseOps.has(expr.op)) {
      if (isByteFamily(leftType) && isByteFamily(rightType)) {
        return BYTESTRING;
      }
      if (!isBigintFamily(leftType)) {
        this.errors.push(makeDiagnostic(
          `Left operand of '${expr.op}' must be bigint or ByteString, got '${leftType}'`,
          'error',
          expr.left.sourceLocation,
        ));
      }
      if (!isBigintFamily(rightType)) {
        this.errors.push(makeDiagnostic(
          `Right operand of '${expr.op}' must be bigint or ByteString, got '${rightType}'`,
          'error',
          expr.right.sourceLocation,
        ));
      }
      return BIGINT;
    }

    return '<unknown>';
  }

  private checkUnaryExpr(
    expr: Extract<Expression, { kind: 'unary_expr' }>,
    env: TypeEnv,
  ): TType {
    const operandType = this.inferExprType(expr.operand, env);

    switch (expr.op) {
      case '!':
        if (operandType !== BOOLEAN && operandType !== '<unknown>') {
          this.errors.push(makeDiagnostic(
            `Operand of '!' must be boolean, got '${operandType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        return BOOLEAN;

      case '-':
        if (!isBigintFamily(operandType)) {
          this.errors.push(makeDiagnostic(
            `Operand of unary '-' must be bigint, got '${operandType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        return BIGINT;

      case '~':
        if (isByteFamily(operandType)) {
          return BYTESTRING;
        }
        if (!isBigintFamily(operandType)) {
          this.errors.push(makeDiagnostic(
            `Operand of '~' must be bigint or ByteString, got '${operandType}'`,
            'error',
            expr.sourceLocation,
          ));
        }
        return BIGINT;
    }
  }

  private checkCallExpr(
    expr: Extract<Expression, { kind: 'call_expr' }>,
    env: TypeEnv,
  ): TType {
    const callee = expr.callee;
    const args = expr.args;

    // super() call in constructor
    if (callee.kind === 'identifier' && callee.name === 'super') {
      // super() calls don't need type checking of args vs a signature;
      // the validator checks that super() passes all properties.
      for (const arg of args) {
        this.inferExprType(arg, env);
      }
      return VOID;
    }

    // Direct builtin call: assert(...), checkSig(...), sha256(...), etc.
    if (callee.kind === 'identifier') {
      // `asm` is a compile-time intrinsic — the parser has already
      // rewritten the `{ body, in_arity?, out_arity? }` object-literal
      // argument into three positional args (body, in_arity, out_arity).
      // Statement form returns void. The expression form
      // `asm<T>({...})` carries the captured return type on
      // `expr.asmReturnType` and produces a value of that type.
      if (callee.name === 'asm') {
        for (const arg of args) {
          this.inferExprType(arg, env);
        }
        if (expr.asmReturnType) {
          return expr.asmReturnType;
        }
        return VOID;
      }

      const sig = BUILTIN_FUNCTIONS.get(callee.name);
      if (sig) {
        return this.checkCallArgs(callee.name, sig, args, env);
      }

      // Check if it's a known contract method (called without this.)
      const methodSig = this.methodSigs.get(callee.name);
      if (methodSig) {
        return this.checkCallArgs(callee.name, methodSig, args, env);
      }

      // Check if it's a local variable in the environment
      const localType = env.lookup(callee.name);
      if (localType) {
        for (const arg of args) {
          this.inferExprType(arg, env);
        }
        return '<unknown>';
      }

      this.errors.push(makeDiagnostic(
        `Unknown function '${callee.name}'. Only Rúnar built-in functions and contract methods are allowed.`,
        'error',
        expr.sourceLocation,
      ));
      for (const arg of args) {
        this.inferExprType(arg, env);
      }
      return '<unknown>';
    }

    // this.method(...) or this.getStateScript()
    if (callee.kind === 'property_access') {
      const methodName = callee.property;

      if (methodName === 'getStateScript') {
        if (args.length !== 0) {
          this.errors.push(makeDiagnostic(
            `getStateScript() takes no arguments`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
        }
        return BYTESTRING;
      }

      if (methodName === 'addOutput') {
        const normalizedArgs = flattenAddOutputArgs(args);
        if (this.contract.parentClass !== 'StatefulSmartContract') {
          this.errors.push(makeDiagnostic(
            `addOutput() is only available in StatefulSmartContract`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
          return VOID;
        }
        const mutableProps = expandedStateSlots(this.contract.properties);
        const expectedArgCount = 1 + mutableProps.length;
        if (normalizedArgs.length !== expectedArgCount) {
          this.errors.push(makeDiagnostic(
            `addOutput() expects ${expectedArgCount} argument(s): satoshis + ${mutableProps.length} state value(s), got ${normalizedArgs.length}`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
        }
        // Type-check: first arg = bigint (satoshis)
        if (normalizedArgs.length >= 1) {
          const satoshisType = this.inferExprType(normalizedArgs[0]!, env);
          if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
              'error',
              args[0]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        // Type-check: remaining args match mutable property types
        for (let i = 0; i < mutableProps.length && i + 1 < normalizedArgs.length; i++) {
          const argType = this.inferExprType(normalizedArgs[i + 1]!, env);
          const propType = typeNodeToTType(mutableProps[i]!.type);
          if (!isSubtype(argType, propType) && argType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addOutput() argument ${i + 2} (${mutableProps[i]!.name}) must be '${propType}', got '${argType}'`,
              'error',
              // R-126: the NORMALIZED list, not the raw one. A tuple-form call —
              // `addOutput(sats, [a, b, c])` — arrives here with args.length === 2
              // while the loop runs over normalizedArgs, so args[i + 1] is
              // undefined for every i >= 1 and reading .sourceLocation off it
              // threw a TypeError out of the typechecker. Same expression the
              // StatefulContext copy already uses.
              normalizedArgs[i + 1]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        // Infer remaining args
        for (let i = expectedArgCount; i < normalizedArgs.length; i++) {
          this.inferExprType(normalizedArgs[i]!, env);
        }
        return VOID;
      }

      if (methodName === 'addRawOutput') {
        if (this.contract.parentClass !== 'StatefulSmartContract') {
          this.errors.push(makeDiagnostic(
            `addRawOutput() is only available in StatefulSmartContract`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
          return VOID;
        }
        if (args.length !== 2) {
          this.errors.push(makeDiagnostic(
            `addRawOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
        }
        if (args.length >= 1) {
          const satoshisType = this.inferExprType(args[0]!, env);
          if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addRawOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
              'error',
              args[0]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        if (args.length >= 2) {
          const scriptType = this.inferExprType(args[1]!, env);
          if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addRawOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
              'error',
              args[1]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        return VOID;
      }

      if (methodName === 'addDataOutput') {
        if (this.contract.parentClass !== 'StatefulSmartContract') {
          this.errors.push(makeDiagnostic(
            `addDataOutput() is only available in StatefulSmartContract`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
          return VOID;
        }
        if (args.length !== 2) {
          this.errors.push(makeDiagnostic(
            `addDataOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
            'error',
            expr.sourceLocation ?? this.currentStmtLoc,
          ));
        }
        if (args.length >= 1) {
          const satoshisType = this.inferExprType(args[0]!, env);
          if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addDataOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
              'error',
              args[0]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        if (args.length >= 2) {
          const scriptType = this.inferExprType(args[1]!, env);
          if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
            this.errors.push(makeDiagnostic(
              `addDataOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
              'error',
              args[1]!.sourceLocation ?? this.currentStmtLoc,
            ));
          }
        }
        return VOID;
      }

      // Check contract method signatures
      const methodSig = this.methodSigs.get(methodName);
      if (methodSig) {
        return this.checkCallArgs(methodName, methodSig, args, env);
      }

      this.errors.push(makeDiagnostic(
        `Unknown method 'this.${methodName}'. Only Rúnar built-in methods (addOutput, addRawOutput, addDataOutput, getStateScript) and contract methods are allowed.`,
        'error',
        expr.sourceLocation,
      ));
      for (const arg of args) {
        this.inferExprType(arg, env);
      }
      return '<unknown>';
    }

    // member_expr call: obj.method(...)
    if (callee.kind === 'member_expr') {
      const objType = this.inferExprType(callee.object, env);

      if (isStatefulContextType(objType)) {
        const methodName = callee.property;

        if (methodName === 'getStateScript') {
          if (args.length !== 0) {
            this.errors.push(makeDiagnostic(
              `getStateScript() takes no arguments`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          return BYTESTRING;
        }

        if (methodName === 'addOutput') {
          const normalizedArgs = flattenAddOutputArgs(args);
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          const mutableProps = expandedStateSlots(this.contract.properties);
          const expectedArgCount = 1 + mutableProps.length;
          if (normalizedArgs.length !== expectedArgCount) {
            this.errors.push(makeDiagnostic(
              `addOutput() expects ${expectedArgCount} argument(s): satoshis + ${mutableProps.length} state value(s), got ${normalizedArgs.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (normalizedArgs.length >= 1) {
            const satoshisType = this.inferExprType(normalizedArgs[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                normalizedArgs[0]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          for (let i = 0; i < mutableProps.length && i + 1 < normalizedArgs.length; i++) {
            const argType = this.inferExprType(normalizedArgs[i + 1]!, env);
            const propType = typeNodeToTType(mutableProps[i]!.type);
            if (!isSubtype(argType, propType) && argType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addOutput() argument ${i + 2} (${mutableProps[i]!.name}) must be '${propType}', got '${argType}'`,
                'error',
                normalizedArgs[i + 1]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          for (let i = expectedArgCount; i < normalizedArgs.length; i++) {
            this.inferExprType(normalizedArgs[i]!, env);
          }
          return VOID;
        }

        if (methodName === 'addRawOutput') {
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addRawOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          if (args.length !== 2) {
            this.errors.push(makeDiagnostic(
              `addRawOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (args.length >= 1) {
            const satoshisType = this.inferExprType(args[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addRawOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                args[0]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          if (args.length >= 2) {
            const scriptType = this.inferExprType(args[1]!, env);
            if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addRawOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
                'error',
                args[1]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          return VOID;
        }

        if (methodName === 'addDataOutput') {
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addDataOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          if (args.length !== 2) {
            this.errors.push(makeDiagnostic(
              `addDataOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (args.length >= 1) {
            const satoshisType = this.inferExprType(args[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addDataOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                args[0]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          if (args.length >= 2) {
            const scriptType = this.inferExprType(args[1]!, env);
            if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addDataOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
                'error',
                args[1]!.sourceLocation ?? expr.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          return VOID;
        }
      }

      if (objType === '<this>' || (callee.object.kind === 'identifier' && callee.object.name === 'this')) {
        const methodName = callee.property;

        if (methodName === 'getStateScript') {
          return BYTESTRING;
        }

        // addOutput / addRawOutput — delegate to the property_access handler
        // by treating this.addOutput(...) the same as this.addOutput(...) via property_access.
        // This handles formats (Python, Move, etc.) that produce member_expr instead of property_access.
        if (methodName === 'addOutput') {
          const normalizedArgs = flattenAddOutputArgs(args);
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          const mutableProps = expandedStateSlots(this.contract.properties);
          const expectedArgCount = 1 + mutableProps.length;
          if (normalizedArgs.length !== expectedArgCount) {
            this.errors.push(makeDiagnostic(
              `addOutput() expects ${expectedArgCount} argument(s): satoshis + ${mutableProps.length} state value(s), got ${normalizedArgs.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (normalizedArgs.length >= 1) {
            const satoshisType = this.inferExprType(normalizedArgs[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                args[0]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          for (let i = 0; i < mutableProps.length && i + 1 < normalizedArgs.length; i++) {
            const argType = this.inferExprType(normalizedArgs[i + 1]!, env);
            const propType = typeNodeToTType(mutableProps[i]!.type);
            if (!isSubtype(argType, propType) && argType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addOutput() argument ${i + 2} (${mutableProps[i]!.name}) must be '${propType}', got '${argType}'`,
                'error',
                // R-126: the NORMALIZED list, not the raw one. A tuple-form call —
                // `addOutput(sats, [a, b, c])` — arrives here with args.length === 2
                // while the loop runs over normalizedArgs, so args[i + 1] is
                // undefined for every i >= 1 and reading .sourceLocation off it
                // threw a TypeError out of the typechecker. Same expression the
                // StatefulContext copy already uses.
                normalizedArgs[i + 1]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          for (let i = expectedArgCount; i < normalizedArgs.length; i++) {
            this.inferExprType(normalizedArgs[i]!, env);
          }
          return VOID;
        }

        if (methodName === 'addRawOutput') {
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addRawOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          if (args.length !== 2) {
            this.errors.push(makeDiagnostic(
              `addRawOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (args.length >= 1) {
            const satoshisType = this.inferExprType(args[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addRawOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                args[0]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          if (args.length >= 2) {
            const scriptType = this.inferExprType(args[1]!, env);
            if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addRawOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
                'error',
                args[1]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          return VOID;
        }

        if (methodName === 'addDataOutput') {
          if (this.contract.parentClass !== 'StatefulSmartContract') {
            this.errors.push(makeDiagnostic(
              `addDataOutput() is only available in StatefulSmartContract`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
            return VOID;
          }
          if (args.length !== 2) {
            this.errors.push(makeDiagnostic(
              `addDataOutput() expects 2 arguments (satoshis, scriptBytes), got ${args.length}`,
              'error',
              expr.sourceLocation ?? this.currentStmtLoc,
            ));
          }
          if (args.length >= 1) {
            const satoshisType = this.inferExprType(args[0]!, env);
            if (!isBigintFamily(satoshisType) && satoshisType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addDataOutput() first argument (satoshis) must be bigint, got '${satoshisType}'`,
                'error',
                args[0]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          if (args.length >= 2) {
            const scriptType = this.inferExprType(args[1]!, env);
            if (!isSubtype(scriptType, BYTESTRING) && scriptType !== '<unknown>') {
              this.errors.push(makeDiagnostic(
                `addDataOutput() second argument (scriptBytes) must be ByteString, got '${scriptType}'`,
                'error',
                args[1]!.sourceLocation ?? this.currentStmtLoc,
              ));
            }
          }
          return VOID;
        }

        const methodSig = this.methodSigs.get(methodName);
        if (methodSig) {
          return this.checkCallArgs(methodName, methodSig, args, env);
        }
      }

      // Object is not this/self — reject (e.g., Math.floor, console.log)
      const objName = callee.object.kind === 'identifier' ? callee.object.name : '<expr>';
      this.errors.push(makeDiagnostic(
        `Unknown function '${objName}.${callee.property}'. Only Rúnar built-in functions and contract methods are allowed.`,
        'error',
        expr.sourceLocation,
      ));
      for (const arg of args) {
        this.inferExprType(arg, env);
      }
      return '<unknown>';
    }

    // Fallback
    this.inferExprType(callee, env);
    for (const arg of args) {
      this.inferExprType(arg, env);
    }
    return '<unknown>';
  }

  private checkCallArgs(
    funcName: string,
    sig: FuncSig,
    args: Expression[],
    env: TypeEnv,
  ): TType {
    // Special case: assert can take 1 or 2 args
    if (funcName === 'assert') {
      if (args.length < 1 || args.length > 2) {
        this.errors.push(makeDiagnostic(
          `assert() expects 1 or 2 arguments, got ${args.length}`,
          'error',
          args[0]?.sourceLocation,
        ));
      }
      if (args.length >= 1) {
        const condType = this.inferExprType(args[0]!, env);
        if (condType !== BOOLEAN && condType !== '<unknown>') {
          this.errors.push(makeDiagnostic(
            `assert() condition must be boolean, got '${condType}'`,
            'error',
            args[0]!.sourceLocation,
          ));
        }
      }
      if (args.length >= 2) {
        this.inferExprType(args[1]!, env);
      }
      return sig.returnType;
    }

    // Special case: checkMultiSig uses array params (`Sig[]`,
    // `PubKey[]`). Arity is checked here, then the standard subtype
    // loop below validates the array element types — without this
    // fall-through, `checkMultiSig([1n], [2n])` (bigint[] for both)
    // would compile cleanly. 2026-04-30 audit finding F5.
    if (funcName === 'checkMultiSig') {
      if (args.length !== 2) {
        this.errors.push(makeDiagnostic(
          `checkMultiSig() expects 2 arguments, got ${args.length}`,
          'error',
          args[0]?.sourceLocation,
        ));
        // Infer remaining args so subsequent expressions can use
        // them, then return — there is nothing meaningful to subtype
        // check against the expected `Sig[]` / `PubKey[]` signature.
        for (const arg of args) {
          this.inferExprType(arg, env);
        }
        this.checkAffineConsumption(funcName, args, env);
        return sig.returnType;
      }
      // Fall through to the standard subtype check below.
    }

    // extractPrevOutputScript / requireOutputP2PKH — the index arg MUST
    // be a compile-time integer literal so the ANF lowering can derive a
    // stable auto-injected witness-param name (extractPrevOutputScript) or
    // a constant byte offset (requireOutputP2PKH).
    if (funcName === 'extractPrevOutputScript' || funcName === 'requireOutputP2PKH') {
      if (args.length >= 1) {
        let litValue: bigint | null = null;
        if (args[0]!.kind === 'bigint_literal') {
          litValue = (args[0] as { value: bigint }).value;
        } else if (
          args[0]!.kind === 'unary_expr' &&
          (args[0] as { op: string }).op === '-' &&
          (args[0] as { operand: { kind: string } }).operand.kind === 'bigint_literal' &&
          // N-060: this arm exists ONLY to reach the "must be >= 0" message
          // below, so it must surrender anything that is not actually
          // negative. `-0n` negates to 0n and would sail past that bound
          // check, but ANF lowering matches on a bare bigint_literal: on a
          // unary_expr it falls through to `load_const ''` and the covenant
          // the intrinsic was supposed to install is silently absent. Let it
          // fall to the non-literal-index diagnostic instead.
          -(args[0] as { operand: { value: bigint } }).operand.value < 0n
        ) {
          // Accept `-N` (UnaryExpr "-" over BigIntLiteral) so the bounds
          // check below produces a clear "must be >= 0" rather than the
          // misleading "must be an integer literal" message.
          const inner = (args[0] as { operand: { value: bigint } }).operand;
          litValue = -inner.value;
        } else {
          this.errors.push(makeDiagnostic(
            `${funcName}() argument 1 (index) must be an integer literal`,
            'error',
            args[0]!.sourceLocation,
          ));
        }
        if (litValue !== null) {
          // R-2: bound the index literal. For requireOutputP2PKH, the
          // emitted Stack-IR computes byte-offset = idx * 34; require
          // 0 <= idx <= 1000 to keep the offset well under script-int
          // max and to reject obvious nonsense (e.g. negative or
          // astronomically large).
          const INT64_MAX = 9223372036854775807n;
          const INT64_MIN = -9223372036854775808n;
          if (litValue > INT64_MAX || litValue < INT64_MIN) {
            this.errors.push(makeDiagnostic(
              `${funcName}() argument 1 (index) must fit in int64; got ${litValue.toString()}`,
              'error',
              args[0]!.sourceLocation,
            ));
          } else {
            if (litValue < 0n) {
              this.errors.push(makeDiagnostic(
                `${funcName}() argument 1 (index) must be >= 0; got ${litValue.toString()}`,
                'error',
                args[0]!.sourceLocation,
              ));
            }
            if (funcName === 'requireOutputP2PKH' && litValue > 0n) {
              this.errors.push(makeDiagnostic(
                `requireOutputP2PKH() argument 1 (outputIndex) must be 0 in v1; got ${litValue.toString()}. The emitted Stack-IR reads output i at byte offset i*34, but Bitcoin outputs are variable length, so for i > 0 that offset is not an output boundary: an attacker sizes output 0 freely and places the expected 34 P2PKH bytes inside its OP_RETURN payload, leaving the transaction's real output i to pay whoever they like. Offset 0 IS a boundary, so index 0 is sound; other indexes need a CompactSize walk the v1 codegen does not emit`,
                'error',
                args[0]!.sourceLocation,
              ));
            }
          }
        }
      }
    }

    // extractPrevOutputScript variable-arity special case (2-arg full-hash
    // or 3-arg prefix-hash form, Crit-2 BSVM Phase 13). Validates types +
    // literal-only on the optional prefixLen, then returns the signature's
    // return type to bypass the standard arg-count check below (which would
    // otherwise reject the 3-arg form against the 2-arg sig table entry).
    if (funcName === 'extractPrevOutputScript') {
      if (args.length !== 2 && args.length !== 3) {
        this.errors.push(makeDiagnostic(
          `extractPrevOutputScript() expects 2 or 3 arguments, got ${args.length}`,
          'error',
          args[0]?.sourceLocation,
        ));
      }
      if (args.length >= 1) {
        this.inferExprType(args[0]!, env); // already validated as literal above
      }
      if (args.length >= 2) {
        const argType = this.inferExprType(args[1]!, env);
        if (!isSubtype(argType, 'ByteString') && argType !== '<unknown>') {
          this.errors.push(makeDiagnostic(
            `Argument 2 of extractPrevOutputScript(): expected 'ByteString', got '${argType}'`,
            'error',
            args[1]!.sourceLocation,
          ));
        }
      }
      if (args.length === 3) {
        if (args[2]!.kind !== 'bigint_literal') {
          this.errors.push(makeDiagnostic(
            `extractPrevOutputScript() argument 3 (prefixLen) must be an integer literal when supplied`,
            'error',
            args[2]!.sourceLocation,
          ));
        } else {
          // R-4: bound the prefixLen literal. The intrinsic hashes
          // substr(witness, 0, prefixLen) and compares against a
          // 32-byte SHA-256 hash. prefixLen < 32 is suspicious (the
          // prefix bytes don't even cover a hash-sized chunk).
          // prefixLen > 4 MiB exceeds MAX_SCRIPT_BYTES — wouldn't
          // fit in a legal Bitcoin Script anyway.
          const n = (args[2] as { value: bigint }).value;
          const INT64_MAX = 9223372036854775807n;
          const INT64_MIN = -9223372036854775808n;
          if (n > INT64_MAX || n < INT64_MIN) {
            this.errors.push(makeDiagnostic(
              `extractPrevOutputScript() argument 3 (prefixLen) must fit in int64; got ${n.toString()}`,
              'error',
              args[2]!.sourceLocation,
            ));
          } else {
            if (n < 32n) {
              this.errors.push(makeDiagnostic(
                `extractPrevOutputScript() argument 3 (prefixLen) must be >= 32 (the hash assertion compares a 32-byte SHA-256); got ${n.toString()}`,
                'error',
                args[2]!.sourceLocation,
              ));
            }
            if (n > 4n * 1024n * 1024n) {
              this.errors.push(makeDiagnostic(
                `extractPrevOutputScript() argument 3 (prefixLen) must be <= MAX_SCRIPT_BYTES (4 MiB); got ${n.toString()}`,
                'error',
                args[2]!.sourceLocation,
              ));
            }
          }
        }
        this.inferExprType(args[2]!, env);
      }
      // Infer trailing args for arity > 3 so subsequent expressions resolve.
      for (let i = 3; i < args.length; i++) {
        this.inferExprType(args[i]!, env);
      }
      return sig.returnType;
    }

    // requireOutputP2PKH, currentBlockHeight and continuationAmount need the
    // auto-injected txPreimage / _newAmount — only available in
    // StatefulSmartContract methods.
    if (funcName === 'requireOutputP2PKH' || funcName === 'currentBlockHeight' || funcName === 'continuationAmount') {
      if (this.contract.parentClass !== 'StatefulSmartContract') {
        this.errors.push(makeDiagnostic(
          `${funcName}() is only available in StatefulSmartContract methods`,
          'error',
          args[0]?.sourceLocation,
        ));
      }
    }

    // Standard argument count check
    if (args.length !== sig.params.length) {
      this.errors.push(makeDiagnostic(
        `${funcName}() expects ${sig.params.length} argument(s), got ${args.length}`,
        'error',
        args[0]?.sourceLocation,
      ));
    }

    const count = Math.min(args.length, sig.params.length);
    for (let i = 0; i < count; i++) {
      const argType = this.inferExprType(args[i]!, env);
      const expectedType = sig.params[i]!;

      if (!isSubtype(argType, expectedType) && argType !== '<unknown>') {
        this.errors.push(makeDiagnostic(
          `Argument ${i + 1} of ${funcName}(): expected '${expectedType}', got '${argType}'`,
          'error',
          args[i]!.sourceLocation,
        ));
      }
    }

    // Infer remaining args even if count mismatches
    for (let i = count; i < args.length; i++) {
      this.inferExprType(args[i]!, env);
    }

    // Affine type enforcement: check consuming function arguments
    this.checkAffineConsumption(funcName, args, env);

    return sig.returnType;
  }

  /**
   * Check affine type constraints: Sig and SigHashPreimage values may only
   * be consumed once (passed to a consuming function like checkSig or
   * checkPreimage).
   *
   * Tracks consumption by *origin*, not variable name, so aliases
   * (`const again = sig`) and property accesses (`this.sig`) cannot
   * be used to launder a double-consumption past the affine check.
   * 2026-04-30 audit finding F6.
   */
  private checkAffineConsumption(
    funcName: string,
    args: Expression[],
    env: TypeEnv,
  ): void {
    const consumedIndices = CONSUMING_FUNCTIONS[funcName];
    if (!consumedIndices) return;

    for (const paramIndex of consumedIndices) {
      if (paramIndex >= args.length) continue;

      const arg = args[paramIndex]!;
      const argType = this.affineExprType(arg, env);
      if (!argType || !AFFINE_TYPES.has(argType)) continue;

      const origin = this.affineOriginOfExpr(arg);
      if (!origin) continue;

      // Render a short label for the diagnostic — local name,
      // alias, or `this.<prop>` form. We print the source label
      // (not the canonical origin) so the error message points
      // back at the call-site expression.
      const label = arg.kind === 'identifier' ? arg.name
        : arg.kind === 'property_access' ? `this.${arg.property}`
        : origin;

      if (this.consumedValues.has(origin) || this.consumedPerLoopIteration(origin, env)) {
        this.errors.push(makeDiagnostic(
          `affine value '${label}' has already been consumed`,
          'error',
          arg.sourceLocation,
        ));
      } else {
        this.consumedValues.add(origin);
      }
    }
  }

  /**
   * F-110: true when `origin` is bound outside the innermost enclosing loop
   * that may run two or more times, so this one syntactic consumption is
   * executed once per iteration — a double use. A property, or a name the env
   * does not bind (a bare-identifier property), is always outside.
   */
  private consumedPerLoopIteration(origin: string, env: TypeEnv): boolean {
    const innermost = this.repeatingLoopScopes[this.repeatingLoopScopes.length - 1];
    if (innermost === undefined) return false;
    if (origin.startsWith('prop:')) return true;
    return env.scopeIndexOf(origin) < innermost;
  }

  /**
   * Resolve the canonical *origin key* of an expression for affine
   * tracking. Identifiers resolve through the alias map; property
   * accesses use a `prop:<name>` namespace; everything else returns
   * undefined (meaning "no traceable affine origin").
   */
  private affineOriginOfExpr(expr: Expression): string | undefined {
    if (expr.kind === 'identifier') {
      const aliased = this.affineAliases.get(expr.name);
      return aliased ?? expr.name;
    }
    if (expr.kind === 'property_access') {
      return `prop:${expr.property}`;
    }
    return undefined;
  }

  /**
   * Type-check helper: returns the inferred type of an expression
   * for affine purposes, defaulting to env lookup for identifiers
   * and the property-type map for `this.x`.
   */
  private affineExprType(expr: Expression, env: TypeEnv): TType | undefined {
    if (expr.kind === 'identifier') {
      return env.lookup(expr.name) ?? undefined;
    }
    if (expr.kind === 'property_access') {
      return this.propTypes.get(expr.property);
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * F-110: whether a for-statement may execute its body two or more times.
 * Mirrors the trip count `extractLoopShape` (04-anf-lower) unrolls; a shape it
 * cannot resolve is refused elsewhere and is treated as repeating here.
 */
function loopMayRunTwice(stmt: Extract<Statement, { kind: 'for_statement' }>): boolean {
  const literal = (e: Expression): bigint | null => {
    if (e.kind === 'bigint_literal') return e.value;
    if (e.kind === 'unary_expr' && e.op === '-') {
      const inner = literal(e.operand);
      return inner === null ? null : -inner;
    }
    return null;
  };
  const start = literal(stmt.init.init);
  const cond = stmt.condition;
  if (start === null || cond.kind !== 'binary_expr') return true;
  const bound = literal(cond.right);
  if (bound === null) return true;
  let count: bigint;
  switch (cond.op) {
    case '<': count = bound - start; break;
    case '<=': count = bound - start + 1n; break;
    case '>': count = start - bound; break;
    case '>=': count = start - bound + 1n; break;
    default: return true;
  }
  return count >= 2n;
}

function typeNodeToTType(node: TypeNode): TType {
  switch (node.kind) {
    case 'primitive_type':
      return node.name;
    case 'fixed_array_type': {
      const elemType = typeNodeToTType(node.element);
      return `${elemType}[]`;
    }
    case 'custom_type':
      return node.name;
  }
}

/**
 * Attempt to infer a private method's return type from its body.
 * Walks all return statements and infers the type of their return
 * expressions using a lightweight expression type inference. Returns
 * the unified type if all return expressions agree, or 'void' if
 * there are no return statements with values.
 */
function inferMethodReturnType(method: MethodNode): TType {
  const returnTypes = collectReturnTypes(method.body);

  if (returnTypes.length === 0) {
    return VOID;
  }

  // Unify: if all return types agree, return that type.
  // Otherwise fall back to the first one (best effort).
  const first = returnTypes[0]!;
  const allSame = returnTypes.every(t => t === first);
  if (allSame) {
    return first;
  }

  // Check if all are in the same type family
  const allBigint = returnTypes.every(t => BIGINT_SUBTYPES.has(t));
  if (allBigint) return BIGINT;

  const allBytes = returnTypes.every(t => BYTESTRING_SUBTYPES.has(t));
  if (allBytes) return BYTESTRING;

  const allBool = returnTypes.every(t => t === BOOLEAN);
  if (allBool) return BOOLEAN;

  // Mixed types -- return the first as a best effort
  return first;
}

/**
 * Collect inferred types from all return statements in a statement list,
 * recursively descending into if/else and for bodies.
 */
function collectReturnTypes(stmts: Statement[]): TType[] {
  const types: TType[] = [];
  for (const stmt of stmts) {
    switch (stmt.kind) {
      case 'return_statement':
        if (stmt.value) {
          types.push(inferExprTypeStatic(stmt.value));
        }
        break;
      case 'if_statement':
        types.push(...collectReturnTypes(stmt.then));
        if (stmt.else) {
          types.push(...collectReturnTypes(stmt.else));
        }
        break;
      case 'for_statement':
        types.push(...collectReturnTypes(stmt.body));
        break;
    }
  }
  return types;
}

/**
 * Lightweight static expression type inference that does not require
 * a type environment. Used for inferring return types of private methods
 * before the full type-check pass runs.
 */
function inferExprTypeStatic(expr: Expression): TType {
  switch (expr.kind) {
    case 'bigint_literal':
      return BIGINT;
    case 'bool_literal':
      return BOOLEAN;
    case 'bytestring_literal':
      return BYTESTRING;
    case 'identifier':
      if (expr.name === 'true' || expr.name === 'false') return BOOLEAN;
      return '<unknown>';
    case 'binary_expr': {
      const arithmeticOps = new Set(['+', '-', '*', '/', '%']);
      if (arithmeticOps.has(expr.op)) return BIGINT;
      const bitwiseOps = new Set(['&', '|', '^', '<<', '>>']);
      if (bitwiseOps.has(expr.op)) return BIGINT;
      // Comparison and equality operators, logical operators
      return BOOLEAN;
    }
    case 'unary_expr':
      if (expr.op === '!') return BOOLEAN;
      return BIGINT; // '-' and '~'
    case 'call_expr': {
      // Check if callee is a known builtin
      if (expr.callee.kind === 'identifier') {
        const sig = BUILTIN_FUNCTIONS.get(expr.callee.name);
        if (sig) return sig.returnType;
      }
      // this.method() via property_access
      if (expr.callee.kind === 'property_access') {
        const builtin = BUILTIN_FUNCTIONS.get(expr.callee.property);
        if (builtin) return builtin.returnType;
      }
      return '<unknown>';
    }
    case 'ternary_expr': {
      const consType = inferExprTypeStatic(expr.consequent);
      if (consType !== '<unknown>') return consType;
      return inferExprTypeStatic(expr.alternate);
    }
    case 'property_access':
    case 'member_expr':
    case 'index_access':
      return '<unknown>';
    case 'increment_expr':
    case 'decrement_expr':
      return BIGINT;
    case 'array_literal':
      return '<unknown>[]';
  }
}
