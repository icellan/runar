/**
 * Symbolic stack lifter — stateless single-method bodies.
 *
 * Walks an opcode stream maintaining a symbolic stack of SSA temp references.
 * Each opcode pops its operands as logical references and emits an ANF
 * binding describing the operation. The final remaining stack value
 * becomes the public method's terminal `assert` argument.
 *
 * Scope (v0.4):
 *
 *   - Pushes: OP_0/OP_FALSE, OP_1NEGATE, OP_1..OP_16, direct push 1..75,
 *     plus OP_PUSHDATA1 / OP_PUSHDATA2 / OP_PUSHDATA4 with arbitrary payload
 *     (the bytes are stored verbatim in the ANF load_const; the compiler
 *     re-emits the same encoding length-class on round-trip).
 *   - Arithmetic (bigint): OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
 *     OP_NEGATE, OP_ABS, OP_1ADD, OP_1SUB.
 *   - Comparison: OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_EQUAL, OP_EQUALVERIFY,
 *     OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL.
 *   - Logical: OP_NOT, OP_BOOLAND, OP_BOOLOR.
 *   - Hash: OP_HASH160, OP_SHA256, OP_RIPEMD160, OP_HASH256.
 *   - Crypto: OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG (with
 *     literal-constant sigCount / keyCount; see `tryLiftCheckMultiSig`).
 *   - ByteString: OP_CAT (2 → 1, builtin `cat`).
 *   - Verify: OP_VERIFY, OP_DROP.
 *   - Plumbing: OP_DUP, OP_SWAP, OP_NIP, OP_OVER, OP_ROT, OP_TUCK,
 *     OP_PICK / OP_ROLL (preceded by a small-int push for depth).
 *   - Control flow: OP_IF / OP_ELSE / OP_ENDIF — branches must end at
 *     equal stack height; phi-merge happens at the TOS slot. Nesting is
 *     capped at 4 levels (anything deeper is highly unlikely to be a
 *     Rúnar-emitted shape and aborts cleanly to raw_script).
 *
 * Out of scope (clean abort → raw_script):
 *
 *   - OP_NOTIF, OP_SPLIT (multi-return, not modeled in our ANF),
 *     OP_CHECKMULTISIG when the count operands aren't literal pushes,
 *     branches that diverge in deeper-than-TOS stack slots, or any
 *     opcode outside this enumeration.
 *
 * Type inference: light, use-site driven. Each SSA temp has an inferred
 * type that grows from `unknown` → concrete (`bigint`, `boolean`,
 * `ByteString`, `Sig`, `PubKey`) based on the opcode that consumes it.
 * Param types propagate up from the SSA temp that ultimately resolves
 * to a `load_param`. Contradictions abort the lift.
 */

import type {
  ANFProgram,
  ANFBinding,
  ANFValue,
  ANFParam,
  ANFMethod,
  ANFProperty,
} from 'runar-compiler';
import type { Op, MethodStream } from './types.js';
import { bytesToHex } from 'runar-testing';

// ---------------------------------------------------------------------------
// Type inference universe
// ---------------------------------------------------------------------------

/**
 * Inferred operand type. `unknown` is the bottom; refined as the value is
 * consumed by typed opcodes. Contradictions (e.g. `bigint` then required to
 * be `ByteString`) cause the lift to abort.
 */
type InferredType =
  | 'unknown'
  | 'bigint'
  | 'boolean'
  | 'bytes'
  | 'sig'
  | 'pubkey';

/** Returns a TS type name for the recovered source. */
function tsTypeName(t: InferredType): string {
  switch (t) {
    case 'bigint':  return 'bigint';
    case 'boolean': return 'boolean';
    case 'sig':     return 'Sig';
    case 'pubkey':  return 'PubKey';
    case 'bytes':   return 'ByteString';
    case 'unknown': return 'ByteString';
  }
}

/**
 * Try to unify `current` with `wanted`. Returns the unified type or `null`
 * if they conflict. `unknown` unifies with anything. Hash family
 * (`bytes` / `sig` / `pubkey`) all collapse to the wider category when
 * mixed against a less-specific one — `pubkey ∧ bytes = pubkey`, etc.
 */
function unify(current: InferredType, wanted: InferredType): InferredType | null {
  if (current === wanted) return current;
  if (current === 'unknown') return wanted;
  if (wanted === 'unknown') return current;
  // Bytes / pubkey / sig hierarchy: refine in the more specific direction.
  // `bytes` is a generic supertype of `sig` and `pubkey`. `sig` and `pubkey`
  // are sibling refinements that CONFLICT with each other (a single value
  // can't simultaneously be both a signature and a public key).
  if (current === 'bytes' && (wanted === 'sig' || wanted === 'pubkey')) return wanted;
  if (wanted === 'bytes' && (current === 'sig' || current === 'pubkey')) return current;
  return null; // conflict
}

// ---------------------------------------------------------------------------
// Lifter state
// ---------------------------------------------------------------------------

interface LiftState {
  /** Inferred type for each SSA temp by name. */
  types: Map<string, InferredType>;
  /** Param name in declaration order — bottom of stack = _p0, top = _p(N-1). */
  paramNames: string[];
  /** Emitted ANF bindings, in order. */
  bindings: ANFBinding[];
  /** Symbolic stack — each entry is an SSA temp reference. */
  stack: string[];
  /** Counter for fresh `_v` names. */
  vCounter: number;
  /**
   * Map from input-script byte offset → constructor `paramIndex`. Populated
   * from `DecompileOptions.constructorSlots` when the caller has access to
   * the artifact. An `OP_0` byte at one of these offsets is recovered as a
   * `load_prop` (`this.prop<i>`) instead of `load_const 0n`.
   */
  slotsByOffset: Map<number, number>;
  /**
   * Inferred type for each recovered property, keyed by `paramIndex`. Refined
   * by the same use-site logic as `types`.
   */
  propTypes: Map<number, InferredType>;
  /**
   * Set of `paramIndex` values whose property has been referenced at least
   * once. Used to drive the constructor-parameter list in the rendered
   * source: only emit properties that the recovered method actually loads.
   */
  propsUsed: Set<number>;
}

function freshName(state: LiftState): string {
  return `_v${state.vCounter++}`;
}

/** Refine the inferred type of an SSA temp, or abort on conflict. */
function refineType(state: LiftState, name: string, wanted: InferredType): boolean {
  const cur = state.types.get(name) ?? 'unknown';
  const unified = unify(cur, wanted);
  if (unified === null) return false;
  state.types.set(name, unified);
  return true;
}

// ---------------------------------------------------------------------------
// Opcode classification — does the lifter handle this byte?
// ---------------------------------------------------------------------------

/**
 * Opcodes the lifter refuses outright (no handling, no traversal).
 *
 * OP_IF / OP_ELSE / OP_ENDIF are NOT in this set — they're recognized
 * structurally as bracket-matched control flow by the main loop.
 * OP_NOTIF (0x64) is ALSO recognized structurally (as the inverse of
 * OP_IF: lift THEN/ELSE branches with the role swapped). See
 * `walkRange`'s control-flow dispatch and `liftIf`.
 *
 * This predicate currently returns `false` for every opcode — kept for
 * future use if a new opcode lands that needs an outright hard refusal.
 */
function isHardRefusedOpcode(_byte: number): boolean {
  return false;
}

/**
 * Push-opcode predicate. Includes OP_0/FALSE (0x00), direct push 0x01..0x4b,
 * OP_1NEGATE (0x4f), OP_1..OP_16 (0x51..0x60), and the variable-length
 * push family OP_PUSHDATA1/2/4 (0x4c..0x4e). For PUSHDATA*, the disassembler
 * has already decoded the payload into `op.data`; the lifter just pushes
 * the bytes verbatim as a ByteString load_const — the compiler picks the
 * same encoding length-class on round-trip because the length determines
 * which OP_PUSHDATA* opcode is selected at emit time.
 */
function isInlinePush(byte: number): boolean {
  if (byte === 0x00) return true;
  if (byte >= 0x01 && byte <= 0x4b) return true;
  if (byte >= 0x4c && byte <= 0x4e) return true; // OP_PUSHDATA1/2/4
  if (byte === 0x4f) return true;
  if (byte >= 0x51 && byte <= 0x60) return true;
  return false;
}

/** Extract the bigint or byte payload pushed by a push opcode. */
function readPushedConst(op: Op): { kind: 'int' | 'bytes'; intVal?: bigint; bytesVal?: Uint8Array } | null {
  if (op.byte === 0x00) return { kind: 'int', intVal: 0n };
  if (op.byte === 0x4f) return { kind: 'int', intVal: -1n };
  if (op.byte >= 0x51 && op.byte <= 0x60) return { kind: 'int', intVal: BigInt(op.byte - 0x50) };
  if (op.byte >= 0x01 && op.byte <= 0x4b && op.data) {
    // Inline push of N bytes. We model as ByteString unless context refines
    // it to a number later. We keep both interpretations on hand: decode as
    // script number for type-narrowed integer use, retain bytes for
    // byte-typed consumers.
    return { kind: 'bytes', bytesVal: op.data };
  }
  // OP_PUSHDATA1 / OP_PUSHDATA2 / OP_PUSHDATA4 — payload always present in
  // op.data; size determines the encoding class but the bytes themselves
  // are what end up on the stack.
  if (op.byte >= 0x4c && op.byte <= 0x4e && op.data) {
    return { kind: 'bytes', bytesVal: op.data };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lift result + entry point
// ---------------------------------------------------------------------------

export interface LiftResult {
  ok: true;
  program: ANFProgram;
  /** Inferred parameter types in declaration order. */
  paramTypes: InferredType[];
  /** Imports required by the recovered TS source. */
  imports: string[];
}

export interface LiftFailure {
  ok: false;
  /** First unhandled opcode name encountered, for the debug counter. */
  unhandled?: string;
  /** Human-readable reason for the abort. */
  reason: string;
}

export type LiftOutcome = LiftResult | LiftFailure;

/** Counts of unhandled opcodes encountered during all lift attempts. */
const UNHANDLED_COUNTS: Map<string, number> = new Map();

/** For tests + diagnostics: read the current unhandled-opcode tally. */
export function getUnhandledOpcodeCounts(): Map<string, number> {
  return new Map(UNHANDLED_COUNTS);
}

/** Reset the counters (test isolation). */
export function resetUnhandledOpcodeCounts(): void {
  UNHANDLED_COUNTS.clear();
}

/**
 * Attempt to lift a single straight-line opcode stream to a real
 * `ANFProgram`. Returns `{ ok: false, ... }` cleanly on any unsupported
 * opcode or stack-state contradiction. The caller is expected to fall
 * through to the byte-canonical `raw_script` floor in that case.
 */
export function liftStraightLine(
  ops: Op[],
  opts: {
    className?: string;
    methodName?: string;
    /**
     * Constructor placeholder byte offsets from the artifact. When supplied,
     * any `OP_0` at one of these offsets is recovered as a `load_prop`
     * referencing a synthesized property at that `paramIndex`, instead of a
     * `load_const 0n` literal. The recovered source declares the matching
     * properties on the contract class so re-compilation re-emits the
     * placeholder bytes at the same offsets.
     */
    constructorSlots?: Array<{ paramIndex: number; byteOffset: number }>;
  } = {},
): LiftOutcome {
  const className  = opts.className  ?? '_Recovered';
  const methodName = opts.methodName ?? '_method0';

  // Pre-scan: compute required param count + reject control flow / large pushes.
  const scan = preScanArity(ops);
  if (!scan.ok) return scan;

  // Build the slot lookup. Offsets are absolute byte positions in the
  // original locking script (matching `Op.offset` produced by the
  // disassembler).
  const slotsByOffset = new Map<number, number>();
  for (const slot of opts.constructorSlots ?? []) {
    slotsByOffset.set(slot.byteOffset, slot.paramIndex);
  }

  // Initialize state. Params are placed bottom-to-top: stack[0] = _p0.
  const state: LiftState = {
    types: new Map(),
    paramNames: Array.from({ length: scan.paramCount }, (_, i) => `_p${i}`),
    bindings: [],
    stack: [],
    vCounter: 0,
    slotsByOffset,
    propTypes: new Map(),
    propsUsed: new Set(),
  };

  // Emit a `load_param` binding for each param + push its SSA name on stack.
  for (const pname of state.paramNames) {
    const name = freshName(state);
    state.bindings.push({ name, value: { kind: 'load_param', name: pname } });
    state.types.set(name, 'unknown');
    state.stack.push(name);
  }

  // Walk the full opcode stream into `state.bindings`. OP_IF / OP_ELSE /
  // OP_ENDIF nesting is recognized structurally and emits an ANF `if`
  // binding via recursive sub-lifts of each branch.
  const walkRes = walkRange(state, ops, 0, ops.length, 0);
  if (walkRes !== null) return walkRes;

  // The final stack state must have exactly one truthy value on top — that's
  // the script result. We re-cast it as a terminal `assert(value)` so the
  // public-method validator accepts the recovered source.
  if (state.stack.length === 0) {
    return failOther('lifted body ended with empty stack');
  }
  const resultName = state.stack[state.stack.length - 1]!;
  const assertName = freshName(state);
  state.bindings.push({ name: assertName, value: { kind: 'assert', value: resultName } });

  // Post-lift fixup: ANF `if` bindings whose result feeds an `assert` MUST
  // be boolean-typed for the TS source emit to type-check. Stack-IR doesn't
  // care (OP_0 and OP_1 are the same as `false`/`true`), so we can safely
  // rewrite literal `1n` / `0n` ANF load_consts inside if-branch results
  // to boolean true / false. Same bytes; passes the TS type checker.
  retypeIfResultsForAssert(state.bindings);

  // Lower-level fixup: move `load_param` bindings that are only consumed
  // inside an if-branch into that branch. The surface Rúnar emitter does
  // this naturally — params not on the live stack at OP_IF time don't need
  // to be PICKed across the branches. Without this, our ANF re-compiles
  // to byte-different output even though it's semantically equivalent.
  state.bindings = sinkLoadParamsIntoIfBranches(state.bindings);

  // Surface-shape fixup (1): source-compile emits one `load_param` /
  // `load_prop` per source-level reference (one `value` reference in the
  // source ⇒ one load binding in the ANF), and the stack-lower then chooses
  // a DUP-first layout when those bindings reference the same param/prop.
  // Our lifter shares the SSA name across multiple consumer bindings, which
  // makes the stack-lower pick an OVER/SWAP-style layout instead and emit
  // byte-different output. Replicating the load at each consumer site
  // restores the source-compile shape so re-emission is byte-identical.
  state.bindings = replicateMultiUseLoads(state.bindings);

  // Surface-shape fixup (2): once duplicate loads exist, their POSITION
  // matters. Source-compile evaluates expressions left-to-right, so the
  // load for the LEFT operand appears before the load for the RIGHT
  // operand, both immediately preceding the consumer binding. Our lifter
  // emits load_prop bindings at the point where the placeholder byte is
  // seen and adds replicate-load_params separately, which can interleave
  // them out of operand order. Reorder pure load_param / load_prop
  // bindings so each consumer's operand loads appear directly before it
  // in operand-ref order — exactly the shape the stack-lower's DUP-first
  // codegen path expects.
  state.bindings = reorderConsumerOperands(state.bindings);

  // Build params with inferred types.
  const paramTypes: InferredType[] = state.paramNames.map((_p, idx) => {
    // The param's type comes from the SSA temp produced by its load_param.
    // The binding ordering puts param i at binding index i, with name _v(i).
    const bindingName = `_v${idx}`;
    return state.types.get(bindingName) ?? 'unknown';
  });

  const params: ANFParam[] = state.paramNames.map((pname, idx) => ({
    name: pname,
    type: tsTypeName(paramTypes[idx]!),
  }));

  // Properties: one per used constructor slot, in `paramIndex` order so that
  // the recovered constructor's parameter list matches the artifact's
  // `constructorSlots[].paramIndex` numbering. Type comes from each
  // property temp's inferred type (refined by use-site).
  refinePropTypesFromBindings(state);
  const usedIndices = [...state.propsUsed].sort((a, b) => a - b);
  const properties = usedIndices.map(idx => ({
    name: `prop${idx}`,
    type: tsTypeName(state.propTypes.get(idx) ?? 'unknown'),
    readonly: true,
  }));

  const program: ANFProgram = {
    contractName: className,
    properties,
    methods: [
      {
        name: methodName,
        params,
        isPublic: true,
        body: state.bindings,
      },
    ],
  };

  // Compute imports — `assert` always; `Sig`/`PubKey`/`ByteString` when used;
  // `checkSig` when referenced.
  const imports = new Set<string>();
  imports.add('SmartContract');
  imports.add('assert');
  for (const t of paramTypes) {
    if (t === 'sig') imports.add('Sig');
    if (t === 'pubkey') imports.add('PubKey');
    if (t === 'bytes' || t === 'unknown') imports.add('ByteString');
  }
  collectCallImports(state.bindings, imports);

  return { ok: true, program, paramTypes, imports: Array.from(imports) };
}

/**
 * Attempt to lift every method of a multi-method dispatch contract. Each
 * method's op stream (produced by `splitMethods()`) is fed through
 * `liftStraightLine` independently; on success, the per-method ANFPrograms
 * are merged into a single program whose `methods[]` carries one entry per
 * recovered method (named `_method0`, `_method1`, ...). The constructor /
 * property recovery comes from the union of every method's recovered
 * placeholders.
 *
 * **Failure semantics — no partial recovery.** If ANY method's lift fails
 * (unsupported opcode, stack contradiction, etc.) the whole call returns
 * `{ ok: false, ... }` carrying that first method's failure. The caller
 * (in practice `decompile()`) is expected to fall through to the byte-
 * canonical `raw_script` floor for the entire script: partial recovery
 * across the dispatch boundary isn't sound — re-emitting some methods as
 * recovered TS and others as `raw_script` would change the dispatch
 * preamble's method indices, breaking every spending path's ABI.
 *
 * The order of `methods` MUST match the dispatch index numbering produced
 * by the source compiler: method 0 in the source equals method 0 in the
 * dispatch preamble. `splitMethods()` already returns the streams in that
 * order, so we just preserve the array order here.
 */
export function liftMultiMethod(
  methods: MethodStream[],
  opts: {
    className?: string;
    /**
     * Constructor placeholder byte offsets from the artifact. Forwarded
     * verbatim to each per-method `liftStraightLine` call. Offsets are
     * absolute positions in the original locking script — the disassembler
     * preserves `op.offset` through `splitMethods()`, so the same offset
     * map works for every per-method op stream.
     */
    constructorSlots?: Array<{ paramIndex: number; byteOffset: number }>;
  } = {},
): LiftOutcome {
  if (methods.length === 0) {
    return failOther('liftMultiMethod called with zero methods');
  }
  const className = opts.className ?? '_Recovered';

  const liftedMethods: ANFMethod[] = [];
  const propsByName = new Map<string, ANFProperty>();
  const imports = new Set<string>();
  imports.add('SmartContract');
  imports.add('assert');

  for (const m of methods) {
    const sub = liftStraightLine(m.ops, {
      className,
      methodName: `_method${m.index}`,
      constructorSlots: opts.constructorSlots,
    });
    if (!sub.ok) {
      // First failure aborts the whole multi-method lift. The pipeline
      // falls through to raw_script — no partial recovery.
      return sub;
    }
    // Each sub.program has exactly one method (liftStraightLine always
    // produces a single-method ANFProgram). Pull it out and accumulate.
    const subMethod = sub.program.methods[0]!;
    liftedMethods.push(subMethod);

    // Merge recovered properties by name. Different methods may recover
    // the same `propN` placeholder; their declared TS surface types are
    // refined to the more specific category by the same lattice used per
    // method (`unify()`), where the order on disagreement is:
    //   bigint ∧ boolean → CONFLICT (caller falls through to raw_script
    //                                because verifyDecompilation will
    //                                see byte divergence)
    //   bytes ∧ {Sig,PubKey} → the more-specific sibling
    // We keep the per-method type names as-is and let conflict resolution
    // surface via the verify gate — this matches the single-method
    // semantics where contradictions abort the lift.
    for (const p of sub.program.properties) {
      const existing = propsByName.get(p.name);
      if (!existing) {
        propsByName.set(p.name, p);
        continue;
      }
      // Already declared by an earlier method. Pick the wider TS surface
      // type by simple precedence: Sig/PubKey > ByteString > bigint/boolean.
      // If they truly conflict (e.g. bigint vs ByteString) we keep the
      // first-seen — the verifier will catch any resulting byte divergence
      // and the pipeline falls through to raw_script.
      if (existing.type === 'ByteString' && (p.type === 'Sig' || p.type === 'PubKey')) {
        propsByName.set(p.name, p);
      }
    }

    for (const imp of sub.imports) imports.add(imp);
  }

  // Properties go into the merged program in `paramIndex` order — the
  // recovered constructor's parameter list must match the artifact's
  // `constructorSlots[].paramIndex` numbering so re-compilation lines up
  // at the same byte offsets.
  const properties = Array.from(propsByName.values()).sort((a, b) => {
    const am = a.name.match(/^prop(\d+)$/);
    const bm = b.name.match(/^prop(\d+)$/);
    if (!am || !bm) return a.name.localeCompare(b.name);
    return Number(am[1]) - Number(bm[1]);
  });

  // Ensure imports cover any property types the renderer will surface.
  for (const p of properties) {
    if (p.type === 'Sig') imports.add('Sig');
    if (p.type === 'PubKey') imports.add('PubKey');
    if (p.type === 'ByteString') imports.add('ByteString');
  }

  // Merge per-method paramTypes too — kept as a flat array for any
  // downstream refinement strategies that need to inspect them. We
  // concatenate in method order; consumers can re-split using
  // program.methods[i].params.length.
  const paramTypes: InferredType[] = [];
  // We don't have direct access to the original inferred-type structs
  // here (only the rendered TS type names from the per-method results),
  // so reconstruct them lossily — this is only consumed by the refinement
  // loop's debug paths and isn't load-bearing for correctness.
  for (const m of liftedMethods) {
    for (const p of m.params) {
      paramTypes.push(reverseTsTypeName(p.type));
    }
  }

  const program: ANFProgram = {
    contractName: className,
    properties,
    methods: liftedMethods,
  };

  return { ok: true, program, paramTypes, imports: Array.from(imports) };
}

/** Best-effort inverse of `tsTypeName`. Used only by refinement diagnostics. */
function reverseTsTypeName(ts: string): InferredType {
  switch (ts) {
    case 'bigint':     return 'bigint';
    case 'boolean':    return 'boolean';
    case 'Sig':        return 'sig';
    case 'PubKey':     return 'pubkey';
    case 'ByteString': return 'bytes';
    default:           return 'unknown';
  }
}

/**
 * Walk all bindings; for every `if` value whose result needs to be a
 * boolean (because it's the operand of an `assert`, or transitively the
 * TOS of another bool-consumed `if`'s branch), rewrite each branch's
 * TOS-producing load_const from bigint 1n/0n to boolean true/false.
 * Same compiled bytes (OP_1/OP_0), but the TS type checker now accepts
 * the source.
 */
function retypeIfResultsForAssert(bindings: ANFBinding[]): void {
  // First pass: collect the set of binding names that MUST be boolean.
  const boolDemanded = new Set<string>();
  collectBoolDemand(bindings, boolDemanded);

  // Apply the retype on every if-binding whose name is in `boolDemanded`.
  applyBoolRetype(bindings, boolDemanded);
}

/**
 * Walk all bindings (recursively into if-branches) and propagate the final
 * inferred type of each `load_prop` temp into `state.propTypes`. Use-site
 * refinement runs on `state.types` (keyed by SSA temp name) during the main
 * walk; after walking, each property's "final" type is the type of the temp
 * its `load_prop` binding produces. Multiple `load_prop` references to the
 * same property unify by `unify()` — keeping the lattice merge consistent
 * with the per-temp refinement.
 */
function refinePropTypesFromBindings(state: LiftState): void {
  function walk(bindings: ANFBinding[]): void {
    for (const b of bindings) {
      const v = b.value;
      if (v.kind === 'load_prop') {
        const match = v.name.match(/^prop(\d+)$/);
        if (!match) continue;
        const idx = Number(match[1]);
        const tempType = state.types.get(b.name) ?? 'unknown';
        const cur = state.propTypes.get(idx) ?? 'unknown';
        const merged = unify(cur, tempType);
        state.propTypes.set(idx, merged ?? cur);
      } else if (v.kind === 'if') {
        walk(v.then);
        walk(v.else);
      }
    }
  }
  walk(state.bindings);
}

/**
 * Walk bindings and collect the set of binding names whose VALUE must be
 * boolean. Bootstraps from `assert(value)` consumers and propagates
 * through `if` bindings: if an if-binding name is demanded boolean, the
 * TOS-producing binding of each of its branches is also demanded boolean.
 */
function collectBoolDemand(bindings: ANFBinding[], dest: Set<string>): void {
  // Initial seed: asserts at this scope demand boolean.
  for (const b of bindings) {
    if (b.value.kind === 'assert') dest.add(b.value.value);
  }
  // Bin name lookup (within this scope) for if-binding propagation.
  const byName = new Map<string, ANFBinding>();
  for (const b of bindings) byName.set(b.name, b);

  // Fixed-point propagation: for each if-binding whose name is demanded
  // boolean, mark each branch's last binding name as also demanded.
  let changed = true;
  while (changed) {
    changed = false;
    for (const b of bindings) {
      if (b.value.kind !== 'if') continue;
      if (!dest.has(b.name)) continue;
      const thenLast = b.value.then[b.value.then.length - 1];
      const elseLast = b.value.else[b.value.else.length - 1];
      if (thenLast && !dest.has(thenLast.name)) {
        dest.add(thenLast.name);
        changed = true;
      }
      if (elseLast && !dest.has(elseLast.name)) {
        dest.add(elseLast.name);
        changed = true;
      }
      // Also collect from inside the branches.
      collectBoolDemand(b.value.then, dest);
      collectBoolDemand(b.value.else, dest);
    }
  }
}

/** Apply load_const retyping (bigint 1n/0n → boolean true/false) on every
 *  binding whose name is in `demanded`. Recurses into nested if branches. */
function applyBoolRetype(bindings: ANFBinding[], demanded: Set<string>): void {
  for (const b of bindings) {
    if (demanded.has(b.name) && b.value.kind === 'load_const') {
      const v = b.value.value;
      if (typeof v === 'bigint') {
        if (v === 0n) b.value = { kind: 'load_const', value: false };
        else if (v === 1n) b.value = { kind: 'load_const', value: true };
      }
    }
    if (b.value.kind === 'if') {
      applyBoolRetype(b.value.then, demanded);
      applyBoolRetype(b.value.else, demanded);
    }
  }
}

/**
 * Move `load_param` bindings out of the top-level scope and into the
 * if-branch where they're consumed, IF the param is referenced only
 * inside that single if and not at the top level (other than as the
 * load_param binding itself).
 *
 * Why: the surface Rúnar emitter emits `load_param` lazily so params that
 * are only used inside an if-branch don't need to live on the stack
 * across the OP_IF. Mirroring that here keeps ANF round-trip byte-identical.
 */
function sinkLoadParamsIntoIfBranches(bindings: ANFBinding[]): ANFBinding[] {
  // Iterate until fixed point — sinking one param may expose another.
  let current = bindings;
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    // For each top-level load_param binding, count usages outside of `if`
    // bindings. If 0, and all uses are within a SINGLE if (then/else),
    // sink it. If both branches reference it, duplicate.
    for (let i = 0; i < current.length; i++) {
      const b = current[i]!;
      if (b.value.kind !== 'load_param') continue;
      const paramName = b.name;
      const usage = analyzeTopLevelUsage(current, i, paramName);
      if (usage === null) continue; // not sink-able
      const { ifIdx, usedInThen, usedInElse } = usage;
      const ifBinding = current[ifIdx]!;
      if (ifBinding.value.kind !== 'if') continue;
      // Build new branches with the load_param duplicated into each branch
      // that uses it. Same name across both branches is fine since SSA
      // names are unique per program — but lowerIf treats branches as
      // independent scopes. To be safe, give each its own fresh name and
      // alias.
      const newThen = usedInThen
        ? [{ name: paramName, value: { kind: 'load_param', name: (b.value as { kind: 'load_param'; name: string }).name } } as ANFBinding, ...ifBinding.value.then]
        : ifBinding.value.then;
      const newElse = usedInElse
        ? [{ name: paramName, value: { kind: 'load_param', name: (b.value as { kind: 'load_param'; name: string }).name } } as ANFBinding, ...ifBinding.value.else]
        : ifBinding.value.else;
      // Replace the if binding with one whose branches carry the load_param,
      // and remove the top-level load_param binding.
      const newIf: ANFBinding = {
        ...ifBinding,
        value: {
          kind: 'if',
          cond: ifBinding.value.cond,
          then: newThen,
          else: newElse,
        },
      };
      // Remove `b` (load_param at i) and replace `ifBinding` (at ifIdx).
      // Careful with index order: if i < ifIdx, removing i shifts ifIdx left by 1.
      const next: ANFBinding[] = [];
      for (let k = 0; k < current.length; k++) {
        if (k === i) continue;
        if (k === ifIdx) next.push(newIf);
        else next.push(current[k]!);
      }
      current = next;
      changed = true;
      break; // restart pass with the new layout.
    }
    if (!changed) break;
  }
  // Recurse into nested ifs.
  return current.map(b => {
    if (b.value.kind !== 'if') return b;
    return {
      ...b,
      value: {
        kind: 'if',
        cond: b.value.cond,
        then: sinkLoadParamsIntoIfBranches(b.value.then),
        else: sinkLoadParamsIntoIfBranches(b.value.else),
      },
    };
  });
}

/**
 * Inspect top-level usage of `paramName` (defined at `bindings[defIdx]`).
 * If the only references are within a single subsequent `if` binding's
 * branches (and not outside it), return that if's index plus which
 * branches use it. Otherwise return null.
 */
function analyzeTopLevelUsage(
  bindings: ANFBinding[],
  defIdx: number,
  paramName: string,
): { ifIdx: number; usedInThen: boolean; usedInElse: boolean } | null {
  let ifIdx = -1;
  let usedInThen = false;
  let usedInElse = false;
  for (let i = 0; i < bindings.length; i++) {
    if (i === defIdx) continue;
    const b = bindings[i]!;
    const v = b.value;
    if (v.kind === 'if') {
      const inThen = referencesName(v.then, paramName);
      const inElse = referencesName(v.else, paramName);
      if (inThen || inElse) {
        if (ifIdx !== -1) return null; // referenced in more than one top-level if
        ifIdx = i;
        usedInThen = inThen;
        usedInElse = inElse;
      }
    } else {
      // Any non-if top-level binding referencing paramName disqualifies it.
      if (refsInValue(v).includes(paramName)) return null;
    }
  }
  if (ifIdx === -1) return null;
  return { ifIdx, usedInThen, usedInElse };
}

/**
 * For every top-level `load_param` / `load_prop` binding whose name is
 * referenced by 2+ subsequent top-level bindings, replace the original
 * binding with N fresh copies — one inserted immediately before each
 * consumer, with the consumer's ref rewritten to the fresh copy.
 *
 * Why: source-compile produces one load binding per source reference
 * (e.g. `value > this.lo` then `value < this.hi` generates two separate
 * `load_param value` bindings). The stack-lower then chooses the DUP-first
 * layout that matches the source-compile output. Our lifter shares SSA
 * names across consumers, which gives the lower an OVER/SWAP-style layout
 * choice — semantically equivalent but byte-different. Replication brings
 * the ANF shape in line with source-compile so re-emission round-trips.
 *
 * Multi-use loads inside if-branches are already addressed by
 * `sinkLoadParamsIntoIfBranches` (which inlines the load into the only
 * branch that uses it); this helper handles the remaining case where the
 * load is used multiple times AT THE SAME SCOPE.
 *
 * Recurses into if-branches so nested re-uses get the same treatment.
 */
function replicateMultiUseLoads(bindings: ANFBinding[]): ANFBinding[] {
  // First recurse so inner scopes get fixed too. We rebuild any `if`
  // binding with cleaned branches before counting top-level uses, so the
  // top-level pass operates on a stable shape.
  const recursed: ANFBinding[] = bindings.map(b => {
    if (b.value.kind !== 'if') return b;
    return {
      ...b,
      value: {
        kind: 'if',
        cond: b.value.cond,
        then: replicateMultiUseLoads(b.value.then),
        else: replicateMultiUseLoads(b.value.else),
      },
    };
  });

  // Identify top-level loads + count their consumers at this scope.
  const loadPayload = new Map<string, ANFValue>();
  for (const b of recursed) {
    if (b.value.kind === 'load_param' || b.value.kind === 'load_prop') {
      loadPayload.set(b.name, b.value);
    }
  }
  if (loadPayload.size === 0) return recursed;

  const useCount = new Map<string, number>();
  for (const b of recursed) {
    if (b.value.kind === 'load_param' || b.value.kind === 'load_prop') continue;
    // Count direct refs at this scope AND any refs inside if-branches
    // (a load consumed by an if-branch counts as one consumer of the load
    // — the branch was already processed by the recursive call, which
    // doesn't see the outer load).
    const refs: string[] = [...refsInValue(b.value)];
    if (b.value.kind === 'if') {
      collectRefsInScope(b.value.then, refs);
      collectRefsInScope(b.value.else, refs);
    }
    for (const r of refs) {
      if (loadPayload.has(r)) useCount.set(r, (useCount.get(r) ?? 0) + 1);
    }
  }

  // Loads with use count < 2 are left alone; the existing single-use shape
  // already byte-matches source-compile.
  const multiUse = new Set<string>();
  for (const [name, count] of useCount) {
    if (count >= 2) multiUse.add(name);
  }
  if (multiUse.size === 0) return recursed;

  // Counter for fresh `_dup` names; ensure no collisions with existing
  // binding names anywhere in the bindings list.
  const existing = new Set<string>();
  for (const b of recursed) existing.add(b.name);
  let dupCounter = 0;
  function freshDup(): string {
    while (existing.has(`_dup${dupCounter}`)) dupCounter++;
    const name = `_dup${dupCounter++}`;
    existing.add(name);
    return name;
  }

  const out: ANFBinding[] = [];
  for (const b of recursed) {
    // Drop the original multi-use load — we'll replicate at each consumer.
    if (
      (b.value.kind === 'load_param' || b.value.kind === 'load_prop') &&
      multiUse.has(b.name)
    ) {
      continue;
    }

    // For consumer bindings, rewrite refs to multi-use loads via fresh
    // duplicates inserted immediately before this binding. For `if`
    // bindings, rewrite both the condition AND any refs inside the
    // branches that reach back to the outer scope.
    const rewrites = new Map<string, string>();
    const refs: string[] = [...refsInValue(b.value)];
    if (b.value.kind === 'if') {
      collectRefsInScope(b.value.then, refs);
      collectRefsInScope(b.value.else, refs);
    }
    for (const r of refs) {
      if (multiUse.has(r) && !rewrites.has(r)) {
        const newName = freshDup();
        out.push({ name: newName, value: loadPayload.get(r)! });
        rewrites.set(r, newName);
      }
    }
    if (rewrites.size === 0) {
      out.push(b);
    } else {
      out.push({ ...b, value: rewriteValueRefs(b.value, rewrites) });
    }
  }

  return out;
}

/**
 * Collect ALL ref names that appear in a binding scope, recursing through
 * nested `if` branches. Used to detect whether a load at an outer scope is
 * consumed (even indirectly) by a binding at the current scope.
 */
function collectRefsInScope(bindings: ANFBinding[], out: string[]): void {
  for (const b of bindings) {
    for (const r of refsInValue(b.value)) out.push(r);
    if (b.value.kind === 'if') {
      collectRefsInScope(b.value.then, out);
      collectRefsInScope(b.value.else, out);
    }
  }
}

/**
 * Rewrite an ANFValue's operand refs according to `rewrites`. For `if`
 * values, both the condition AND any refs inside the branches that hit a
 * rewritten name are updated, so a duplicate inserted at the outer scope
 * is seen by every inner consumer.
 */
function rewriteValueRefs(v: ANFValue, rewrites: Map<string, string>): ANFValue {
  const sub = (n: string): string => rewrites.get(n) ?? n;
  switch (v.kind) {
    case 'bin_op': return { ...v, left: sub(v.left), right: sub(v.right) };
    case 'unary_op': return { ...v, operand: sub(v.operand) };
    case 'call': return { ...v, args: v.args.map(sub) };
    case 'method_call': return { ...v, object: sub(v.object), args: v.args.map(sub) };
    case 'if': return {
      kind: 'if',
      cond: sub(v.cond),
      then: rewriteBindingsRefs(v.then, rewrites),
      else: rewriteBindingsRefs(v.else, rewrites),
    };
    case 'assert': return { ...v, value: sub(v.value) };
    case 'array_literal': return { ...v, elements: v.elements.map(sub) };
    case 'update_prop': return { ...v, value: sub(v.value) };
    case 'check_preimage': return { ...v, preimage: sub(v.preimage) };
    case 'deserialize_state': return { ...v, preimage: sub(v.preimage) };
    case 'add_output': return {
      ...v,
      satoshis: sub(v.satoshis),
      stateValues: v.stateValues.map(sub),
      preimage: v.preimage ? sub(v.preimage) : v.preimage,
    };
    case 'add_raw_output': return { ...v, satoshis: sub(v.satoshis), scriptBytes: sub(v.scriptBytes) };
    case 'add_data_output': return { ...v, satoshis: sub(v.satoshis), scriptBytes: sub(v.scriptBytes) };
    case 'load_const':
      if (typeof v.value === 'string' && v.value.startsWith('@ref:')) {
        return { kind: 'load_const', value: `@ref:${sub(v.value.slice(5))}` };
      }
      return v;
    case 'load_param':
    case 'load_prop':
    case 'get_state_script':
    case 'loop':
    case 'raw_script':
      return v;
  }
}

/** Apply rewrites recursively to every binding's value in a scope. */
function rewriteBindingsRefs(bindings: ANFBinding[], rewrites: Map<string, string>): ANFBinding[] {
  return bindings.map(b => ({ ...b, value: rewriteValueRefs(b.value, rewrites) }));
}

/**
 * Reorder pure `load_param` / `load_prop` bindings so each consumer's
 * operand loads appear immediately before it in operand-ref order. This
 * matches source-compile's left-to-right ANF emission and lets the
 * stack-lower pick the DUP-first codegen layout instead of OVER/SWAP.
 *
 * Algorithm: linear scan with a small "pending-loads" map. Pure loads are
 * queued by their SSA name. When a non-load (consumer) binding appears,
 * for each operand ref in order, drain the matching queued load (if any)
 * into the output right before the consumer.
 *
 * Pure loads are safe to reorder: they have no side effects, depend on
 * no other binding, and reproduce the same Stack-IR push when emitted
 * later (load_param via stackMap lookup, load_prop via OP_0 placeholder).
 *
 * `load_const` is INTENTIONALLY excluded — its `@ref:` aliasing form
 * encodes an SSA copy that the stack-lower depends on resolving in place.
 *
 * Recurses through `if` branches so loads inside a branch are reordered
 * relative to their in-branch consumers.
 */
function reorderConsumerOperands(bindings: ANFBinding[]): ANFBinding[] {
  // Recurse first so nested branches present clean sub-sequences.
  const recursed: ANFBinding[] = bindings.map(b => {
    if (b.value.kind !== 'if') return b;
    return {
      ...b,
      value: {
        kind: 'if',
        cond: b.value.cond,
        then: reorderConsumerOperands(b.value.then),
        else: reorderConsumerOperands(b.value.else),
      },
    };
  });

  const out: ANFBinding[] = [];
  const pending = new Map<string, ANFBinding>();
  for (const b of recursed) {
    if (b.value.kind === 'load_param' || b.value.kind === 'load_prop') {
      pending.set(b.name, b);
      continue;
    }
    // `load_const` with a plain literal value is also pure and safe to
    // queue. The `@ref:<name>` aliasing form encodes an SSA copy whose
    // resolution depends on stack-lower's per-binding position, so we
    // leave those in place.
    if (
      b.value.kind === 'load_const' &&
      !(typeof b.value.value === 'string' && b.value.value.startsWith('@ref:'))
    ) {
      pending.set(b.name, b);
      continue;
    }
    // Consumer binding: drain its operand loads in left-to-right order.
    const refs = refsInValue(b.value);
    for (const r of refs) {
      const queued = pending.get(r);
      if (queued !== undefined) {
        out.push(queued);
        pending.delete(r);
      }
    }
    out.push(b);
  }
  // Any loads still pending at end of scope weren't referenced by a
  // consumer in this scope (could happen if a load is only used inside an
  // inner if-branch's condition AFTER it's been hoisted by some earlier
  // pass). Emit them in their original relative order so they remain
  // available — they'll be DCE'd by the compiler if truly unused.
  for (const queued of pending.values()) out.push(queued);
  return out;
}

/** Recursively check whether any binding in `bindings` references `name`. */
function referencesName(bindings: ANFBinding[], name: string): boolean {
  for (const b of bindings) {
    if (refsInValue(b.value).includes(name)) return true;
    if (b.value.kind === 'if') {
      if (referencesName(b.value.then, name)) return true;
      if (referencesName(b.value.else, name)) return true;
    }
  }
  return false;
}

/** Direct operand references of an ANFValue (not recursing into nested branches). */
function refsInValue(v: ANFValue): string[] {
  switch (v.kind) {
    case 'load_param': return [];
    case 'load_const':
      if (typeof v.value === 'string' && v.value.startsWith('@ref:')) {
        return [v.value.slice(5)];
      }
      return [];
    case 'bin_op': return [v.left, v.right];
    case 'unary_op': return [v.operand];
    case 'call': return v.args;
    case 'method_call': return [v.object, ...v.args];
    case 'if': return [v.cond];
    case 'assert': return [v.value];
    case 'array_literal': return v.elements;
    case 'update_prop': return [v.value];
    case 'check_preimage': return [v.preimage];
    case 'deserialize_state': return [v.preimage];
    case 'add_output': return [v.satoshis, ...v.stateValues, v.preimage].filter(Boolean) as string[];
    case 'add_raw_output': return [v.satoshis, v.scriptBytes];
    case 'add_data_output': return [v.satoshis, v.scriptBytes];
    case 'load_prop': return [];
    case 'get_state_script': return [];
    case 'loop': return [];
    case 'raw_script': return [];
  }
}


/** Walk an ANF binding list, adding any `call` / nested if-call func names to `imports`. */
function collectCallImports(bindings: ANFBinding[], imports: Set<string>): void {
  for (const b of bindings) {
    const v = b.value;
    if (v.kind === 'call') imports.add(v.func);
    else if (v.kind === 'if') {
      collectCallImports(v.then, imports);
      collectCallImports(v.else, imports);
    }
  }
}

// ---------------------------------------------------------------------------
// Main walker — operates on a [start, end) slice of `ops`
// ---------------------------------------------------------------------------

/** Maximum allowed OP_IF nesting depth. Beyond this we abort to raw_script.
 *  16 covers anything plausible from the Rúnar emitter — the guard exists
 *  to prevent pathologically deep recursion budgets on adversarial input,
 *  not as a soundness constraint. The recursive walker handles arbitrary
 *  depth correctly. */
const MAX_IF_NESTING = 16;

/**
 * Walk ops[start..end) and append bindings to `state`. Returns null on
 * success, or a `LiftFailure` on a clean abort. OP_IF / OP_ELSE / OP_ENDIF
 * are recognized structurally and produce a single ANF `if` binding via
 * recursive sub-walks of each branch.
 *
 * `ifDepth` tracks nesting so deeply-nested control flow (unlikely in
 * Rúnar emit) doesn't blow the budget.
 */
function walkRange(
  state: LiftState,
  ops: Op[],
  start: number,
  end: number,
  ifDepth: number,
): LiftFailure | null {
  let i = start;
  while (i < end) {
    const op = ops[i]!;

    // ----- OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF --------------------------
    // OP_NOTIF is the inverse of OP_IF: it takes the THEN branch when the
    // condition is FALSE. We model it by lifting the same block with the
    // branch roles swapped — what the script writes after OP_NOTIF becomes
    // the ANF `if`'s ELSE branch, and what appears after OP_ELSE becomes
    // the THEN branch. This way the ANF `if` always speaks "if (cond)" and
    // re-compilation through the standard ANF→Stack lowering re-emits an
    // OP_IF (not OP_NOTIF). The recovered TS source therefore uses the
    // normal `cond ? then : else` ternary form — there's no surface need
    // for an explicit `!cond` because the swap absorbs the inversion.
    if (op.byte === 0x63 /* OP_IF */ || op.byte === 0x64 /* OP_NOTIF */) {
      if (ifDepth >= MAX_IF_NESTING) {
        return failUnhandled(op.name, `nesting deeper than ${MAX_IF_NESTING}`);
      }
      const bracket = findIfBracket(ops, i + 1, end);
      if (!bracket.ok) {
        return failOther((bracket as LiftFailure).reason);
      }
      const swap = op.byte === 0x64;
      const ifRes = liftIf(state, ops, i, bracket.elseIdx, bracket.endIdx, ifDepth, swap);
      if (ifRes !== null) return ifRes;
      i = bracket.endIdx + 1;
      continue;
    }
    if (op.byte === 0x67 || op.byte === 0x68) {
      return failUnhandled(op.name, 'OP_ELSE/OP_ENDIF without matching OP_IF/OP_NOTIF');
    }

    // ----- OP_PICK / OP_ROLL fused with preceding small-int push ---------
    if (op.byte === 0x79 || op.byte === 0x7a) {
      const prev = i > 0 ? ops[i - 1] : undefined;
      if (!prev || !isInlinePush(prev.byte)) {
        return failUnhandled(op.name, 'OP_PICK/OP_ROLL requires a preceding small-int push for depth');
      }
      const lastBind = state.bindings[state.bindings.length - 1]!;
      if (lastBind.value.kind !== 'load_const') {
        return failUnhandled(op.name, 'OP_PICK/OP_ROLL preceding push was not a load_const');
      }
      const depthRaw = lastBind.value.value;
      let depth: number;
      if (typeof depthRaw === 'bigint') depth = Number(depthRaw);
      else return failUnhandled(op.name, 'OP_PICK/OP_ROLL depth was not a numeric const');
      state.bindings.pop();
      state.stack.pop();
      if (depth < 0 || depth >= state.stack.length) {
        return failUnhandled(op.name, `OP_PICK/OP_ROLL depth ${depth} out of range`);
      }
      const targetIdx = state.stack.length - 1 - depth;
      const targetRef = state.stack[targetIdx]!;
      if (op.byte === 0x79) {
        state.stack.push(targetRef);
      } else {
        state.stack.splice(targetIdx, 1);
        state.stack.push(targetRef);
      }
      i++;
      continue;
    }

    // ----- Inline / variable-length push ---------------------------------
    if (isInlinePush(op.byte)) {
      // OP_0 at a constructor-slot offset is a deployment-time placeholder,
      // not a literal zero push. Recover it as a `load_prop` so the rendered
      // source declares (and references) the matching property. Re-emit then
      // produces `OP_0` at the same offset.
      if (op.byte === 0x00 && state.slotsByOffset.has(op.offset)) {
        const paramIndex = state.slotsByOffset.get(op.offset)!;
        const propName = `prop${paramIndex}`;
        const name = freshName(state);
        state.bindings.push({ name, value: { kind: 'load_prop', name: propName } });
        // Type starts at `unknown`; use-site refinement (refineType) will
        // narrow it as the property flows into typed operands.
        state.types.set(name, 'unknown');
        state.propsUsed.add(paramIndex);
        if (!state.propTypes.has(paramIndex)) {
          state.propTypes.set(paramIndex, 'unknown');
        }
        state.stack.push(name);
        i++;
        continue;
      }

      const pushed = readPushedConst(op);
      if (pushed === null) {
        return failUnhandled(op.name, 'unexpected push shape');
      }
      const name = freshName(state);
      if (pushed.kind === 'int') {
        state.bindings.push({ name, value: { kind: 'load_const', value: pushed.intVal! } });
        state.types.set(name, 'bigint');
      } else {
        state.bindings.push({
          name,
          value: { kind: 'load_const', value: bytesToHex(pushed.bytesVal!) },
        });
        state.types.set(name, 'bytes');
      }
      state.stack.push(name);
      i++;
      continue;
    }

    // ----- OP_CHECKMULTISIG (data-dependent arity) -----------------------
    if (op.byte === 0xae) {
      const cms = tryLiftCheckMultiSig(state, ops, i);
      if (!cms.ok) return cms;
      i++;
      continue;
    }

    // ----- OP_SPLIT explicitly aborts (multi-return) ---------------------
    if (op.byte === 0x7f) {
      return failUnhandled('OP_SPLIT', 'multi-return opcode not modeled in lifter ANF (clean abort to raw_script)');
    }

    // ----- OP_CAT (binary, 2 ByteStrings → 1 ByteString) -----------------
    if (op.byte === 0x7e) {
      const n = state.stack.length;
      if (n < 2) return failOther('OP_CAT: not enough operands');
      // Both operands are ByteString-typed.
      if (!refineType(state, state.stack[n - 2]!, 'bytes')) return failOther('OP_CAT: left operand type conflict');
      if (!refineType(state, state.stack[n - 1]!, 'bytes')) return failOther('OP_CAT: right operand type conflict');
      const step = emitCall(state, 'cat', 2, 'bytes');
      if (step !== null) return step;
      i++;
      continue;
    }

    // ----- Generic opcode dispatch ---------------------------------------
    const step = stepOpcode(state, op);
    if (step !== null) return step;
    i++;
  }
  return null;
}

/**
 * Lift an OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF block. Both branches are
 * walked recursively in cloned states; their final stacks must match the
 * pre-IF stack EXCEPT for the top slot (which becomes the if-binding
 * output). Anything more divergent aborts cleanly to raw_script.
 *
 * `swapBranches` is true when the source opcode was OP_NOTIF — in that
 * case we swap the byte ranges so the resulting ANF `if` always means
 * "execute then-bindings when cond is truthy", matching the surface
 * compiler's emit conventions.
 */
function liftIf(
  state: LiftState,
  ops: Op[],
  ifIdx: number,
  elseIdx: number | undefined,
  endIdx: number,
  ifDepth: number,
  swapBranches: boolean = false,
): LiftFailure | null {
  // Pop the condition from the parent stack.
  if (state.stack.length === 0) return failOther('OP_IF: no condition on stack');
  const cond = state.stack.pop()!;

  // Snapshot the parent stack as a baseline for both branches.
  const baseStack = [...state.stack];

  // Script-byte ranges for each lexical branch (then = post-IF/NOTIF until
  // OP_ELSE-or-OP_ENDIF; else = post-OP_ELSE until OP_ENDIF, or empty when
  // there's no OP_ELSE). For OP_NOTIF we swap which range feeds which ANF
  // arm so the ANF semantics remain "if (cond) THEN else ELSE".
  const lexThenStart = ifIdx + 1;
  const lexThenEnd = elseIdx !== undefined ? elseIdx : endIdx;
  const lexElseStart = elseIdx !== undefined ? elseIdx + 1 : -1;
  const lexElseEnd = endIdx;
  const hasLexElse = elseIdx !== undefined;

  // Pick which lexical range feeds the ANF "then" arm and which feeds "else".
  const anfThenStart = swapBranches && hasLexElse ? lexElseStart : lexThenStart;
  const anfThenEnd   = swapBranches && hasLexElse ? lexElseEnd   : lexThenEnd;
  const anfElseStart = swapBranches ? lexThenStart : (hasLexElse ? lexElseStart : -1);
  const anfElseEnd   = swapBranches ? lexThenEnd   : (hasLexElse ? lexElseEnd   : -1);
  // OP_NOTIF with no OP_ELSE: the ANF "then" arm is empty (the script only
  // does work when cond is FALSE). We model that by walking an empty range
  // for the ANF-then and walking the lexical THEN range for the ANF-else.
  const hasAnfElse = swapBranches ? true : hasLexElse;

  // ---- THEN branch ----
  // Slot lookup, prop-type map, and propsUsed are shared by-reference so any
  // `load_prop` recovered inside the branch contributes to the same recovered
  // property set as the parent. Types map is also shared — refinements
  // propagate across branches.
  const thenState: LiftState = {
    types: state.types,           // shared — refinements should propagate
    paramNames: state.paramNames, // shared (read-only)
    bindings: [],
    stack: [...baseStack],
    vCounter: state.vCounter,
    slotsByOffset: state.slotsByOffset,
    propTypes: state.propTypes,
    propsUsed: state.propsUsed,
  };
  if (swapBranches && !hasLexElse) {
    // ANF-then is empty; nothing to walk.
  } else {
    const thenRes = walkRange(thenState, ops, anfThenStart, anfThenEnd, ifDepth + 1);
    if (thenRes !== null) return thenRes;
  }
  state.vCounter = thenState.vCounter;

  // ---- ELSE branch ----
  const elseState: LiftState = {
    types: state.types,
    paramNames: state.paramNames,
    bindings: [],
    stack: [...baseStack],
    vCounter: state.vCounter,
    slotsByOffset: state.slotsByOffset,
    propTypes: state.propTypes,
    propsUsed: state.propsUsed,
  };
  if (hasAnfElse) {
    const elseRes = walkRange(elseState, ops, anfElseStart, anfElseEnd, ifDepth + 1);
    if (elseRes !== null) return elseRes;
    state.vCounter = elseState.vCounter;
  }
  // If there's no OP_ELSE, elseState's stack stays equal to baseStack.

  // ---- Merge ----
  // Stack heights MUST match between the two branches. Rúnar emits ifs that
  // produce a single merged TOS value (the phi slot); everything beneath
  // must match identically across branches. We accept any final branch
  // depth d as long as:
  //
  //   (a) both branches reach the same depth, and
  //   (b) ALL slots below TOS match, and
  //   (c) at most the TOS slot diverges.
  //
  // Two sub-cases:
  //   * branches don't diverge at all (TOS matches) — the if expression
  //     has no fresh produced value; it's a side-effect-only if (no phi).
  //   * branches diverge ONLY at TOS — that's the phi slot, becomes the
  //     if-binding's output, sits on the parent stack at TOS.
  if (thenState.stack.length !== elseState.stack.length) {
    return failOther(
      `OP_IF: branch height mismatch (then=${thenState.stack.length}, else=${elseState.stack.length})`,
    );
  }
  const branchDepth = thenState.stack.length;
  // Locate the lowest divergence index between branches (if any).
  let divergenceAt = -1;
  for (let k = 0; k < branchDepth; k++) {
    if (thenState.stack[k] !== elseState.stack[k]) { divergenceAt = k; break; }
  }
  // If divergence exists, it MUST be exactly at TOS (k === branchDepth - 1)
  // and there must be no further divergence above (well, TOS is the top, so
  // there is nothing above).
  const hasPhi = divergenceAt !== -1;
  if (hasPhi && divergenceAt !== branchDepth - 1) {
    return failOther(`OP_IF: deep stack slot ${divergenceAt} diverges between branches`);
  }
  const tosIndex = branchDepth - 1;

  // Build the ANF `if` binding. The binding's name becomes the SSA temp
  // for the merged TOS. If both branches' TOS already share the same
  // name AND the branches contain only side-effects (no fresh value to
  // merge), we can elide the if-binding's output and just reuse that
  // name. But to keep the structure uniform we always wrap.
  const ifName = freshName(state);

  // If branches produce a TOS-level merged value, the ANF `if` node
  // implicitly returns the last binding of each branch. We need each
  // branch's last binding to be the one whose VALUE represents the
  // produced TOS. The walker already left those bindings in place — but
  // we must ensure each branch's final binding NAME *is* the slot that
  // ends up at TOS (otherwise compileFromANF can't tell which value to
  // route through the if).
  //
  // Strategy: if the TOS slot in a branch isn't the name of that branch's
  // last binding, append a synthetic "alias" binding that re-binds the TOS
  // value to a fresh name. The compiler treats `load_const` with `@ref:`
  // values as aliases (see 05-stack-lower.ts:1149). This way the if's
  // output is well-defined.
  // For the phi case ensure each branch's last binding NAME equals the TOS
  // value (the ANF `if` binding's result is the implicit last expression of
  // each branch).
  if (hasPhi && tosIndex >= 0) {
    aliasBranchTosIfNeeded(state, thenState, tosIndex);
    aliasBranchTosIfNeeded(state, elseState, tosIndex);
  }

  state.bindings.push({
    name: ifName,
    value: {
      kind: 'if',
      cond,
      then: thenState.bindings,
      else: elseState.bindings,
    },
  });

  // Reconstruct the parent stack. Slots [0..branchDepth-1) below the phi
  // (or all branch slots if no phi) are common to both branches and form
  // the new parent stack base. The phi slot — if present — becomes the
  // if-binding's name (ifName).
  state.stack = thenState.stack.slice(0, hasPhi ? tosIndex : branchDepth);
  if (hasPhi) {
    state.stack.push(ifName);
    // Type unify both branches' TOS types into the if-binding result.
    const thenType = state.types.get(thenState.stack[tosIndex]!) ?? 'unknown';
    const elseType = state.types.get(elseState.stack[tosIndex]!) ?? 'unknown';
    const merged = unify(thenType, elseType);
    state.types.set(ifName, merged ?? 'unknown');
  }

  // The condition is used as the if-binding's `cond`. Refine its type to
  // boolean so renderTsSource can emit it as a proper TS condition.
  refineType(state, cond, 'boolean');

  return null;
}

/**
 * If a branch's TOS is NOT the name of its last-emitted binding, append a
 * synthetic `@ref:` load_const that aliases the TOS to a fresh name so the
 * surrounding `if` value-binding has an unambiguous per-branch output.
 */
function aliasBranchTosIfNeeded(
  parent: LiftState,
  branch: LiftState,
  tosIndex: number,
): void {
  const top = branch.stack[tosIndex]!;
  const last = branch.bindings[branch.bindings.length - 1];
  if (last && last.name === top) return;
  const aliasName = freshName(parent);
  branch.vCounter = parent.vCounter;
  branch.bindings.push({
    name: aliasName,
    value: { kind: 'load_const', value: `@ref:${top}` },
  });
  branch.stack[tosIndex] = aliasName;
  const tType = parent.types.get(top) ?? 'unknown';
  parent.types.set(aliasName, tType);
}

/**
 * Recognize the canonical OP_CHECKMULTISIG byte shape:
 *
 *     OP_0 <sig_1>...<sig_N> <pushN> <key_1>...<key_M> <pushM> OP_CHECKMULTISIG
 *
 * On entry the symbolic stack already contains those items. We walk back
 * from the top: keyCount push (literal), pop M keys, sigCount push
 * (literal), pop N sigs, dummy OP_0. If anything doesn't match, return
 * `{ ok: false }` so the caller falls through to raw_script.
 */
function tryLiftCheckMultiSig(
  state: LiftState,
  _ops: Op[],
  _idx: number,
): { ok: true } | LiftFailure {
  // Read sig/key counts from the live symbolic stack. At this point the
  // top should be a literal load_const for keyCount; sigCount sits at depth
  // (keyCount + 1) below the top. If either isn't a literal, abort.
  const counts = readMultiSigCountsFromState(state);
  if (counts === null) {
    return failUnhandled('OP_CHECKMULTISIG', 'sig/key count not a literal load_const on the symbolic stack');
  }
  const { sigCount, keyCount } = counts;
  if (sigCount < 0 || keyCount < 0 || sigCount > 20 || keyCount > 20) {
    return failUnhandled('OP_CHECKMULTISIG', `unsupported sig/key count (${sigCount}/${keyCount})`);
  }
  // Verify the symbolic stack has enough items.
  // Layout (top → bottom): keyCount-temp, [keys M], sigCount-temp, [sigs N], dummy.
  const needed = 1 /*keyCount*/ + keyCount + 1 /*sigCount*/ + sigCount + 1 /*dummy*/;
  if (state.stack.length < needed) {
    return failOther(`OP_CHECKMULTISIG: stack too shallow (${state.stack.length} < ${needed})`);
  }
  // Pop in reverse order.
  // keyCount push:
  const keyCountRef = state.stack.pop()!;
  void keyCountRef; // we discard — the count is a literal handled at re-emit
  const keys: string[] = [];
  for (let k = 0; k < keyCount; k++) keys.unshift(state.stack.pop()!);
  const sigCountRef = state.stack.pop()!;
  void sigCountRef;
  const sigs: string[] = [];
  for (let s = 0; s < sigCount; s++) sigs.unshift(state.stack.pop()!);
  const dummyRef = state.stack.pop()!;
  void dummyRef;

  // Drop the count-push bindings + dummy from the bindings list. They were
  // emitted as load_const; we need to remove them so the re-emit goes
  // through the checkMultiSig stack-lower which re-pushes them itself.
  // The sigs and keys, however, MUST stay in the bindings — the array
  // literals reference them by name.
  scrubBindings(state, [dummyRef, sigCountRef, keyCountRef]);

  // Refine types: sigs as Sig, keys as PubKey.
  for (const s of sigs) if (!refineType(state, s, 'sig')) return failOther('OP_CHECKMULTISIG: sig type conflict');
  for (const k of keys) if (!refineType(state, k, 'pubkey')) return failOther('OP_CHECKMULTISIG: pubkey type conflict');

  // Emit two array-literal bindings + a call binding.
  const sigsArrName = freshName(state);
  state.bindings.push({ name: sigsArrName, value: { kind: 'array_literal', elements: sigs } });
  state.types.set(sigsArrName, 'unknown');
  const keysArrName = freshName(state);
  state.bindings.push({ name: keysArrName, value: { kind: 'array_literal', elements: keys } });
  state.types.set(keysArrName, 'unknown');
  const resName = freshName(state);
  state.bindings.push({
    name: resName,
    value: { kind: 'call', func: 'checkMultiSig', args: [sigsArrName, keysArrName] },
  });
  state.types.set(resName, 'boolean');
  state.stack.push(resName);
  return { ok: true };
}

/**
 * Remove the trailing `load_const` bindings whose names are in `names`.
 * Used by OP_CHECKMULTISIG lift to drop the count/dummy pushes that the
 * stack-lower pass will re-emit on its own.
 */
function scrubBindings(state: LiftState, names: string[]): void {
  const set = new Set(names);
  // We can only safely drop bindings that are still pure load_consts and
  // appear at the tail (so we don't shift other refs). Walk from the end
  // backward and drop matches.
  for (let i = state.bindings.length - 1; i >= 0 && set.size > 0; i--) {
    const b = state.bindings[i]!;
    if (set.has(b.name) && b.value.kind === 'load_const') {
      state.bindings.splice(i, 1);
      set.delete(b.name);
    } else if (set.has(b.name)) {
      // Non-load_const — leave alone; the rebuilder won't strip it.
      set.delete(b.name);
    }
  }
}

// ---------------------------------------------------------------------------
// Pre-scan: arity + supported-op check
// ---------------------------------------------------------------------------

interface PreScanOk { ok: true; paramCount: number }
function preScanArity(ops: Op[]): PreScanOk | LiftFailure {
  // For pre-scan we walk the WHOLE script accounting for OP_IF / OP_ELSE /
  // OP_ENDIF as bracket-matched control flow. The condition-pop happens at
  // OP_IF; after that, we conservatively take the MAX depth contribution
  // of THEN vs ELSE for arity computation. This is sound for stack-balanced
  // Rúnar IF emissions where both branches end at equal heights.
  return preScanRange(ops, 0, ops.length, 0);
}

function preScanRange(
  ops: Op[],
  start: number,
  end: number,
  initialDepth: number,
): PreScanOk | LiftFailure {
  let depth = initialDepth;
  let min = initialDepth;
  // Parallel "small-int literal value" stack — each entry is the value of
  // a literal push, or null if non-literal / unknown. Used so OP_CHECKMULTISIG
  // pre-scan can read its sig/key counts directly from the visible top.
  // We only carry entries for items that are on the stack ABOVE baseline;
  // items below baseline (phantom params) are unknown.
  const litStack: (number | null)[] = [];
  let i = start;
  while (i < end) {
    const op = ops[i]!;
    if (isHardRefusedOpcode(op.byte)) {
      return failUnhandled(op.name, 'opcode refused by lifter');
    }

    if (op.byte === 0x63 /* OP_IF */ || op.byte === 0x64 /* OP_NOTIF */) {
      // Both OP_IF and OP_NOTIF consume one stack item (the condition) and
      // bracket-match the same OP_ELSE / OP_ENDIF structure. The difference
      // (which branch runs) only matters at lift time, not for arity.
      depth -= 1;
      if (litStack.length > 0) litStack.pop();
      if (depth < min) min = depth;
      // Find matching OP_ELSE / OP_ENDIF at the same depth.
      const block = findIfBracket(ops, i + 1, end);
      if (!block.ok) return block;
      // Pre-scan THEN.
      const thenRes = preScanRange(ops, i + 1, block.elseIdx ?? block.endIdx, depth);
      if (!thenRes.ok) return thenRes;
      let combinedMinDelta = thenRes.paramCount; // params required from outside
      // Pre-scan ELSE (or empty body).
      if (block.elseIdx !== undefined) {
        const elseRes = preScanRange(ops, block.elseIdx + 1, block.endIdx, depth);
        if (!elseRes.ok) return elseRes;
        if (elseRes.paramCount > combinedMinDelta) combinedMinDelta = elseRes.paramCount;
      }
      // Reserve enough params for the deeper branch.
      if (depth - combinedMinDelta < min) min = depth - combinedMinDelta;
      depth += 1;
      litStack.push(null);
      i = block.endIdx + 1;
      continue;
    }
    if (op.byte === 0x67 || op.byte === 0x68) {
      // Stray OP_ELSE / OP_ENDIF — malformed for our pre-scan caller.
      return failUnhandled(op.name, 'unmatched control-flow op');
    }

    // OP_CHECKMULTISIG arity is data-dependent (sigCount + keyCount). Read
    // both from the literal-value stack — that's the only sound way when
    // sigs/keys may be params.
    if (op.byte === 0xae /* OP_CHECKMULTISIG */) {
      if (litStack.length === 0) {
        return failUnhandled(op.name, 'OP_CHECKMULTISIG keyCount not on visible stack');
      }
      const keyCountRaw = litStack[litStack.length - 1];
      if (keyCountRaw === null || keyCountRaw === undefined || keyCountRaw < 0 || keyCountRaw > 20) {
        return failUnhandled(op.name, 'OP_CHECKMULTISIG keyCount not a literal small int');
      }
      const keyCount: number = keyCountRaw;
      // sigCount sits at (keyCount + 1) below the top.
      const sigCountIdx = litStack.length - 1 - keyCount - 1;
      if (sigCountIdx < 0) {
        return failUnhandled(op.name, 'OP_CHECKMULTISIG sigCount below visible stack (not literal)');
      }
      const sigCountRaw = litStack[sigCountIdx];
      if (sigCountRaw === null || sigCountRaw === undefined || sigCountRaw < 0 || sigCountRaw > 20) {
        return failUnhandled(op.name, 'OP_CHECKMULTISIG sigCount not a literal small int');
      }
      const sigCount: number = sigCountRaw;
      const pops = sigCount + keyCount + 3;
      const preDepth = depth;
      const floor = preDepth - pops;
      if (floor < min) min = floor;
      depth = depth - pops + 1;
      // Drain literal stack to match new depth.
      const consumed = Math.min(pops, litStack.length);
      for (let k = 0; k < consumed; k++) litStack.pop();
      litStack.push(null); // result is boolean
      if (depth < min) min = depth;
      i++;
      continue;
    }

    const meta = arityForOpcode(op);
    if (meta === null) {
      return failUnhandled(op.name, 'opcode not in lifter set');
    }

    // Update litStack alongside depth. We special-case PURE PLUMBING opcodes
    // (DUP, SWAP, NIP, OVER, ROT, TUCK, PICK, ROLL, DROP) to PRESERVE the
    // tracked literal values across stack rearrangements — that's what
    // lets the OP_CHECKMULTISIG prescan succeed when the surface compiler
    // routes the count pushes through OP_ROT/OP_ROLL stack juggling.
    if (isInlinePush(op.byte)) {
      const pushed = readPushedConst(op);
      if (pushed !== null && pushed.kind === 'int' && pushed.intVal !== undefined) {
        const n = Number(pushed.intVal);
        litStack.push(Number.isSafeInteger(n) ? n : null);
      } else {
        litStack.push(null);
      }
    } else if (op.byte === 0x76 /* OP_DUP */) {
      const top = litStack.length > 0 ? litStack[litStack.length - 1]! : null;
      litStack.push(top);
    } else if (op.byte === 0x7c /* OP_SWAP */) {
      const n = litStack.length;
      if (n >= 2) {
        const a = litStack[n - 1]!;
        const b = litStack[n - 2]!;
        litStack[n - 1] = b;
        litStack[n - 2] = a;
      }
    } else if (op.byte === 0x77 /* OP_NIP */) {
      const n = litStack.length;
      if (n >= 2) {
        litStack.splice(n - 2, 1); // remove second-from-top
      } else if (n === 1) {
        // The second-from-top is a phantom param (unknown). Drop the
        // tracked top into the unknown slot — net effect: visible stack
        // loses one entry.
        litStack.pop();
      }
    } else if (op.byte === 0x78 /* OP_OVER */) {
      const n = litStack.length;
      const second = n >= 2 ? litStack[n - 2]! : null;
      litStack.push(second);
    } else if (op.byte === 0x7b /* OP_ROT */) {
      const n = litStack.length;
      if (n >= 3) {
        const third = litStack[n - 3]!;
        litStack.splice(n - 3, 1);
        litStack.push(third);
      } else if (n > 0) {
        // Partial visibility — third entry is a phantom. The rotation
        // brings a phantom on top: top becomes null.
        litStack.push(null);
      }
    } else if (op.byte === 0x7d /* OP_TUCK */) {
      const n = litStack.length;
      if (n >= 2) {
        const top = litStack[n - 1]!;
        litStack.splice(n - 2, 0, top);
      } else if (n === 1) {
        // Tuck top under a phantom; visible literal still on top.
        const top = litStack[n - 1]!;
        litStack.unshift(top);
      } else {
        litStack.push(null);
      }
    } else if (op.byte === 0x75 /* OP_DROP */) {
      if (litStack.length > 0) litStack.pop();
    } else if (op.byte === 0x79 /* OP_PICK */ || op.byte === 0x7a /* OP_ROLL */) {
      // Fused with preceding small-int push for depth: the push already
      // landed on litStack; pop it (that's the depth operand), then
      // duplicate (PICK) or move (ROLL) the entry at that depth to top.
      //
      // We ALSO override the generic arity-driven floor calc: when the
      // depth operand is a known literal D, the real stack-floor demand
      // for this op is `preDepth - (2 + D)` (the depth-push + D-deep
      // item access). The generic table uses minDepth=2 which would
      // under-count param demand for any non-zero D.
      const depthRaw = litStack.length > 0 ? litStack[litStack.length - 1]! : null;
      if (litStack.length > 0) litStack.pop();
      if (depthRaw !== null && depthRaw >= 0) {
        // preDepth = depth BEFORE this op finishes. We're inside the
        // generic dispatch below, so depth has NOT yet been decremented.
        const preDepth = depth;
        const floor = preDepth - (2 + depthRaw);
        if (floor < min) min = floor;
      }
      if (depthRaw !== null && depthRaw >= 0 && depthRaw < litStack.length) {
        const idx = litStack.length - 1 - depthRaw;
        const moved = litStack[idx]!;
        if (op.byte === 0x7a /* OP_ROLL */) {
          litStack.splice(idx, 1);
        }
        litStack.push(moved);
      } else {
        // Depth points below the visible horizon (or unknown) — result
        // is opaque.
        litStack.push(null);
      }
    } else {
      // Generic op — consumes meta.minDepth, produces (meta.minDepth + delta)
      // opaque results.
      const popsCount = Math.max(0, meta.minDepth ?? 0);
      const consumed = Math.min(popsCount, litStack.length);
      for (let k = 0; k < consumed; k++) litStack.pop();
      const pushes = (meta.minDepth ?? 0) + meta.delta;
      for (let k = 0; k < pushes; k++) litStack.push(null);
    }

    depth += meta.delta;
    // Track minDepth-driven param demand ONLY for ops that actually consume
    // inputs (minDepth > 0). The floor reached during an op is
    // `preDepth - minDepth` (after pops, before pushes). For pure pushes
    // (minDepth=0) `preDepth < 0` is fine because pushes just append.
    if (meta.minDepth !== undefined && meta.minDepth > 0) {
      const preDepth = depth - meta.delta;
      const floor = preDepth - meta.minDepth;
      if (floor < min) min = floor;
    }
    if (depth < min) min = depth;
    i++;
  }
  if (process.env.RUNAR_DEBUG_PRESCAN) console.error('[prescan] range', start, '-', end, 'initialDepth=', initialDepth, 'min=', min, 'paramCount=', initialDepth - min);
  return { ok: true, paramCount: initialDepth - min };
}

/**
 * Given that ops[start] is the byte AFTER an OP_IF (or OP_NOTIF — both open
 * a balanced control-flow block terminated by OP_ENDIF), find the matching
 * OP_ELSE (if any) and OP_ENDIF at the same nesting depth.
 */
function findIfBracket(
  ops: Op[],
  start: number,
  end: number,
): { ok: true; elseIdx: number | undefined; endIdx: number } | LiftFailure {
  let nest = 0;
  let elseIdx: number | undefined;
  for (let j = start; j < end; j++) {
    const b = ops[j]!.byte;
    if (b === 0x63 || b === 0x64) nest++; // OP_IF or OP_NOTIF — opens a block
    else if (b === 0x67 && nest === 0 && elseIdx === undefined) elseIdx = j;
    else if (b === 0x68) {
      if (nest === 0) return { ok: true, elseIdx, endIdx: j };
      nest--;
    }
  }
  return failOther('OP_IF/OP_NOTIF without matching OP_ENDIF');
}

/**
 * Read the keyCount and sigCount that an OP_CHECKMULTISIG would consume,
 * by looking at the live symbolic stack. The TOS must be a `load_const`
 * bigint binding (keyCount). The element at depth `keyCount + 1` below the
 * top is sigCount (also a load_const bigint). Returns null if either isn't
 * a clean literal.
 */
function readMultiSigCountsFromState(state: LiftState): { sigCount: number; keyCount: number } | null {
  if (state.stack.length === 0) return null;
  const keyCountName = state.stack[state.stack.length - 1]!;
  const keyCountBind = findBindingByName(state.bindings, keyCountName);
  if (!keyCountBind || keyCountBind.value.kind !== 'load_const') return null;
  const kcRaw = keyCountBind.value.value;
  if (typeof kcRaw !== 'bigint') return null;
  const keyCount = Number(kcRaw);
  if (!Number.isSafeInteger(keyCount)) return null;
  const sigCountStackIdx = state.stack.length - 1 - keyCount - 1;
  if (sigCountStackIdx < 0) return null;
  const sigCountName = state.stack[sigCountStackIdx]!;
  const sigCountBind = findBindingByName(state.bindings, sigCountName);
  if (!sigCountBind || sigCountBind.value.kind !== 'load_const') return null;
  const scRaw = sigCountBind.value.value;
  if (typeof scRaw !== 'bigint') return null;
  const sigCount = Number(scRaw);
  if (!Number.isSafeInteger(sigCount)) return null;
  return { sigCount, keyCount };
}

function findBindingByName(bindings: ANFBinding[], name: string): ANFBinding | undefined {
  for (let i = bindings.length - 1; i >= 0; i--) {
    if (bindings[i]!.name === name) return bindings[i]!;
  }
  return undefined;
}


interface OpArity {
  /** Net stack delta (push count - pop count) for this op (or paired op for PICK/ROLL). */
  delta: number;
  /** Minimum pre-op stack depth required. */
  minDepth: number;
}

/**
 * Arity table — null for unsupported opcodes. The lifter ABORTS cleanly on
 * any null entry (the caller falls through to raw_script).
 */
function arityForOpcode(op: Op): OpArity | null {
  const b = op.byte;
  // Inline pushes: +1, no pops.
  if (isInlinePush(b)) return { delta: 1, minDepth: 0 };
  switch (b) {
    case 0x76: return { delta: 1, minDepth: 1 }; // OP_DUP
    case 0x77: return { delta: -1, minDepth: 2 }; // OP_NIP — removes second
    case 0x78: return { delta: 1, minDepth: 2 }; // OP_OVER — duplicates 2nd
    case 0x7b: return { delta: 0, minDepth: 3 }; // OP_ROT
    case 0x7c: return { delta: 0, minDepth: 2 }; // OP_SWAP
    case 0x7d: return { delta: 1, minDepth: 2 }; // OP_TUCK
    case 0x75: return { delta: -1, minDepth: 1 }; // OP_DROP
    case 0x69: return { delta: -1, minDepth: 1 }; // OP_VERIFY
    // OP_PICK/OP_ROLL: handled as fused pair with the prior push. The push
    // contributed +1 to depth; PICK then pops the depth (-1) and pushes
    // the duplicated item (+1) → net 0 from PICK itself. ROLL pops depth
    // (-1) and re-pushes the moved item (+1) → net 0. Combined with the
    // preceding push: PICK pair = +1, ROLL pair = 0. But arityForOpcode
    // is called per-op; the push was already counted. So the op itself:
    case 0x79: return { delta: 0, minDepth: 2 }; // OP_PICK — pops depth, dups
    case 0x7a: return { delta: -1, minDepth: 2 }; // OP_ROLL — pops depth, moves (no dup)
    // Unary arithmetic / logical: -1 + 1 = 0.
    case 0x8b: return { delta: 0, minDepth: 1 }; // OP_1ADD
    case 0x8c: return { delta: 0, minDepth: 1 }; // OP_1SUB
    case 0x8f: return { delta: 0, minDepth: 1 }; // OP_NEGATE
    case 0x90: return { delta: 0, minDepth: 1 }; // OP_ABS
    case 0x91: return { delta: 0, minDepth: 1 }; // OP_NOT
    // Hashes: -1 + 1 = 0.
    case 0xa6: return { delta: 0, minDepth: 1 }; // OP_RIPEMD160
    case 0xa8: return { delta: 0, minDepth: 1 }; // OP_SHA256
    case 0xa9: return { delta: 0, minDepth: 1 }; // OP_HASH160
    case 0xaa: return { delta: 0, minDepth: 1 }; // OP_HASH256
    // Binary arithmetic / comparison: -2 + 1 = -1.
    case 0x93: return { delta: -1, minDepth: 2 }; // OP_ADD
    case 0x94: return { delta: -1, minDepth: 2 }; // OP_SUB
    case 0x95: return { delta: -1, minDepth: 2 }; // OP_MUL
    case 0x96: return { delta: -1, minDepth: 2 }; // OP_DIV
    case 0x97: return { delta: -1, minDepth: 2 }; // OP_MOD
    case 0x9a: return { delta: -1, minDepth: 2 }; // OP_BOOLAND
    case 0x9b: return { delta: -1, minDepth: 2 }; // OP_BOOLOR
    case 0x87: return { delta: -1, minDepth: 2 }; // OP_EQUAL
    case 0x88: return { delta: -2, minDepth: 2 }; // OP_EQUALVERIFY — pops 2, no push
    case 0x9c: return { delta: -1, minDepth: 2 }; // OP_NUMEQUAL
    case 0x9d: return { delta: -2, minDepth: 2 }; // OP_NUMEQUALVERIFY
    case 0x9f: return { delta: -1, minDepth: 2 }; // OP_LESSTHAN
    case 0xa0: return { delta: -1, minDepth: 2 }; // OP_GREATERTHAN
    case 0xa1: return { delta: -1, minDepth: 2 }; // OP_LESSTHANOREQUAL
    case 0xa2: return { delta: -1, minDepth: 2 }; // OP_GREATERTHANOREQUAL
    // Crypto.
    case 0xac: return { delta: -1, minDepth: 2 }; // OP_CHECKSIG
    case 0xad: return { delta: -2, minDepth: 2 }; // OP_CHECKSIGVERIFY
    // ByteString plumbing.
    case 0x7e: return { delta: -1, minDepth: 2 }; // OP_CAT
    // Note: OP_CHECKMULTISIG (0xae) is data-dependent; handled in pre-scan
    // via `sniffMultiSigCounts` and in the main loop via
    // `tryLiftCheckMultiSig`. It does NOT appear in this table.
    // Note: OP_SPLIT (0x7f) is multi-return — intentionally absent. The
    // lifter aborts on it; the caller falls through to raw_script. ANF's
    // single-output binding shape can't model a 2-output opcode cleanly
    // without inventing a tuple-destructure construct that the rest of the
    // compiler doesn't speak.
    default:   return null;
  }
}

// ---------------------------------------------------------------------------
// Opcode-step dispatch — emit ANF bindings as the symbolic stack evolves
// ---------------------------------------------------------------------------

/**
 * Apply one opcode to the lifter state. Returns null on success, a
 * `LiftFailure` on a clean abort.
 */
function stepOpcode(state: LiftState, op: Op): LiftFailure | null {
  // Plumbing first (no ANF emission needed — pure stack moves).
  switch (op.byte) {
    case 0x76: { // OP_DUP
      const top = state.stack[state.stack.length - 1]!;
      state.stack.push(top);
      return null;
    }
    case 0x77: { // OP_NIP — remove 2nd-from-top
      const n = state.stack.length;
      state.stack.splice(n - 2, 1);
      return null;
    }
    case 0x78: { // OP_OVER — dup 2nd-from-top
      const second = state.stack[state.stack.length - 2]!;
      state.stack.push(second);
      return null;
    }
    case 0x7b: { // OP_ROT — top-3 left rotation: a b c → b c a
      const n = state.stack.length;
      const a = state.stack.splice(n - 3, 1)[0]!;
      state.stack.push(a);
      return null;
    }
    case 0x7c: { // OP_SWAP
      const n = state.stack.length;
      const t = state.stack[n - 1]!; state.stack[n - 1] = state.stack[n - 2]!; state.stack[n - 2] = t;
      return null;
    }
    case 0x7d: { // OP_TUCK: a b → b a b
      const n = state.stack.length;
      const top = state.stack[n - 1]!;
      state.stack.splice(n - 2, 0, top);
      return null;
    }
    case 0x75: { // OP_DROP
      state.stack.pop();
      return null;
    }
    case 0x69: { // OP_VERIFY — pop top, emit assert
      const r = state.stack.pop()!;
      const aname = freshName(state);
      state.bindings.push({ name: aname, value: { kind: 'assert', value: r } });
      return null;
    }
  }

  // Unary numeric operators that map to UNARYOP_OPCODES.
  if (op.byte === 0x8f /* OP_NEGATE */) return emitUnary(state, '-', 'bigint');
  if (op.byte === 0x90 /* OP_ABS    */) return emitCall(state, 'abs', 1, 'bigint');
  if (op.byte === 0x8b /* OP_1ADD   */) {
    // Need a temp for the constant `1n`, then bin_op '+'. Pass `'bigint'`
    // as the operand-type hint so the *left* operand (the existing TOS
    // before we pushed the constant) is refined to bigint — without this
    // hint, a load_param feeding straight into OP_1ADD retains its
    // `unknown` type and the renderer surfaces it as `ByteString`,
    // which then fails the TS typecheck (`Left operand of '+' must be
    // bigint`). Same fix below for OP_1SUB.
    const aTemp = pushConst(state, 1n, 'bigint');
    if (aTemp === null) return failOther('1ADD: failed to push const');
    return emitBin(state, '+', 'bigint', 'bigint');
  }
  if (op.byte === 0x8c /* OP_1SUB   */) {
    pushConst(state, 1n, 'bigint');
    return emitBin(state, '-', 'bigint', 'bigint');
  }
  if (op.byte === 0x91 /* OP_NOT */) {
    // Two semantics: bigint → `=== 0n`; boolean → `!`. Inspect operand type.
    const top = state.stack[state.stack.length - 1]!;
    const tt = state.types.get(top) ?? 'unknown';
    if (tt === 'boolean') {
      return emitUnary(state, '!', 'boolean');
    }
    // Default: bigint `=== 0n`.
    if (!refineType(state, top, 'bigint')) return failOther('OP_NOT: operand type conflict');
    pushConst(state, 0n, 'bigint');
    // Emit `===` with a numeric hint so the peephole rewrites
    // `OP_0 OP_NUMEQUAL` → `OP_NOT` (matches the original byte).
    return emitBin(state, '===', 'boolean');
  }

  // Hashes — the input is always byte-typed (ByteString-or-narrower).
  if (op.byte === 0xa6) { refineType(state, state.stack[state.stack.length - 1]!, 'bytes'); return emitCall(state, 'ripemd160', 1, 'bytes'); }
  if (op.byte === 0xa8) { refineType(state, state.stack[state.stack.length - 1]!, 'bytes'); return emitCall(state, 'sha256',    1, 'bytes'); }
  if (op.byte === 0xa9) { refineType(state, state.stack[state.stack.length - 1]!, 'bytes'); return emitCall(state, 'hash160',   1, 'bytes'); }
  if (op.byte === 0xaa) { refineType(state, state.stack[state.stack.length - 1]!, 'bytes'); return emitCall(state, 'hash256',   1, 'bytes'); }

  // Binary arithmetic.
  if (op.byte === 0x93) return emitBin(state, '+',   'bigint', 'bigint');
  if (op.byte === 0x94) return emitBin(state, '-',   'bigint', 'bigint');
  if (op.byte === 0x95) return emitBin(state, '*',   'bigint', 'bigint');
  if (op.byte === 0x96) return emitBin(state, '/',   'bigint', 'bigint');
  if (op.byte === 0x97) return emitBin(state, '%',   'bigint', 'bigint');
  // Comparisons + booleans.
  if (op.byte === 0x9c) return emitBin(state, '===', 'boolean', 'bigint');
  if (op.byte === 0x9f) return emitBin(state, '<',   'boolean', 'bigint');
  if (op.byte === 0xa0) return emitBin(state, '>',   'boolean', 'bigint');
  if (op.byte === 0xa1) return emitBin(state, '<=',  'boolean', 'bigint');
  if (op.byte === 0xa2) return emitBin(state, '>=',  'boolean', 'bigint');
  if (op.byte === 0x9a) return emitBin(state, '&&',  'boolean', 'boolean');
  if (op.byte === 0x9b) return emitBin(state, '||',  'boolean', 'boolean');
  // Byte-typed equality. The compiler's BinOp emits OP_EQUAL when
  // `result_type === 'bytes'` on a `===`. Inspect operand types — refine
  // to bytes if both compatible.
  if (op.byte === 0x87) {
    // Treat as ByteString equality if any operand is bytes-family;
    // otherwise leave at default bigint. Inspect top-two.
    const n = state.stack.length;
    const aT = state.types.get(state.stack[n - 2]!) ?? 'unknown';
    const bT = state.types.get(state.stack[n - 1]!) ?? 'unknown';
    const isBytes = (t: InferredType) => t === 'bytes' || t === 'sig' || t === 'pubkey';
    const operandHint: 'bigint' | 'bytes' = (isBytes(aT) || isBytes(bT)) ? 'bytes' : 'bigint';
    if (operandHint === 'bytes') {
      // Refine both operands toward bytes.
      if (!refineType(state, state.stack[n - 2]!, 'bytes')) return failOther('OP_EQUAL: operand conflict');
      if (!refineType(state, state.stack[n - 1]!, 'bytes')) return failOther('OP_EQUAL: operand conflict');
      return emitBinTyped(state, '===', 'boolean', 'bytes');
    }
    return emitBin(state, '===', 'boolean', 'bigint');
  }
  if (op.byte === 0x88) {
    // OP_EQUALVERIFY — same as OP_EQUAL followed by OP_VERIFY (the
    // compiler does NOT emit this single opcode; peephole produces it from
    // `OP_EQUAL OP_VERIFY`. But the lifter sees it post-peephole. We model
    // it as bin_op + assert; the peephole on the re-compile path will
    // collapse them back).
    const n = state.stack.length;
    const aT = state.types.get(state.stack[n - 2]!) ?? 'unknown';
    const bT = state.types.get(state.stack[n - 1]!) ?? 'unknown';
    const isBytes = (t: InferredType) => t === 'bytes' || t === 'sig' || t === 'pubkey';
    if (isBytes(aT) || isBytes(bT)) {
      refineType(state, state.stack[n - 2]!, 'bytes');
      refineType(state, state.stack[n - 1]!, 'bytes');
      const f1 = emitBinTyped(state, '===', 'boolean', 'bytes'); if (f1) return f1;
    } else {
      const f1 = emitBin(state, '===', 'boolean', 'bigint'); if (f1) return f1;
    }
    const r = state.stack.pop()!;
    const aname = freshName(state);
    state.bindings.push({ name: aname, value: { kind: 'assert', value: r } });
    return null;
  }
  if (op.byte === 0x9d) {
    // OP_NUMEQUALVERIFY — numeric ===, then assert.
    const f1 = emitBin(state, '===', 'boolean', 'bigint'); if (f1) return f1;
    const r = state.stack.pop()!;
    const aname = freshName(state);
    state.bindings.push({ name: aname, value: { kind: 'assert', value: r } });
    return null;
  }
  // Crypto.
  if (op.byte === 0xac) {
    // OP_CHECKSIG: top = pubkey, second = sig. The two operands MUST be
    // distinct in type — a single SSA temp can't simultaneously be Sig and
    // PubKey, so DUP-then-CHECKSIG aborts the lifter (the caller falls
    // through to raw_script).
    const n = state.stack.length;
    if (!refineType(state, state.stack[n - 2]!, 'sig'))    return failOther('OP_CHECKSIG: sig operand type conflict');
    if (!refineType(state, state.stack[n - 1]!, 'pubkey')) return failOther('OP_CHECKSIG: pubkey operand type conflict');
    return emitCall(state, 'checkSig', 2, 'boolean');
  }
  if (op.byte === 0xad) {
    const n = state.stack.length;
    if (!refineType(state, state.stack[n - 2]!, 'sig'))    return failOther('OP_CHECKSIGVERIFY: sig conflict');
    if (!refineType(state, state.stack[n - 1]!, 'pubkey')) return failOther('OP_CHECKSIGVERIFY: pubkey conflict');
    const f1 = emitCall(state, 'checkSig', 2, 'boolean'); if (f1) return f1;
    const r = state.stack.pop()!;
    const aname = freshName(state);
    state.bindings.push({ name: aname, value: { kind: 'assert', value: r } });
    return null;
  }

  return failUnhandled(op.name, 'unhandled in stepOpcode');
}

// ---------------------------------------------------------------------------
// Emission helpers
// ---------------------------------------------------------------------------

function pushConst(state: LiftState, v: bigint | string, t: InferredType): string {
  const name = freshName(state);
  state.bindings.push({ name, value: { kind: 'load_const', value: v } });
  state.types.set(name, t);
  state.stack.push(name);
  return name;
}

function emitUnary(state: LiftState, op: string, operandType: InferredType): LiftFailure | null {
  const operand = state.stack.pop()!;
  if (!refineType(state, operand, operandType)) {
    return failOther(`unary ${op}: operand type conflict`);
  }
  const name = freshName(state);
  const value: ANFValue = { kind: 'unary_op', op, operand };
  state.bindings.push({ name, value });
  state.types.set(name, operandType);
  state.stack.push(name);
  return null;
}

function emitBin(
  state: LiftState,
  op: string,
  resultType: InferredType,
  operandType?: InferredType,
): LiftFailure | null {
  const right = state.stack.pop()!;
  const left  = state.stack.pop()!;
  if (operandType !== undefined) {
    if (!refineType(state, left, operandType))  return failOther(`bin_op ${op}: left operand conflict`);
    if (!refineType(state, right, operandType)) return failOther(`bin_op ${op}: right operand conflict`);
  }
  const name = freshName(state);
  state.bindings.push({ name, value: { kind: 'bin_op', op, left, right } });
  state.types.set(name, resultType);
  state.stack.push(name);
  return null;
}

function emitBinTyped(
  state: LiftState,
  op: string,
  resultType: InferredType,
  hint: 'bytes',
): LiftFailure | null {
  const right = state.stack.pop()!;
  const left  = state.stack.pop()!;
  const name = freshName(state);
  state.bindings.push({
    name,
    value: { kind: 'bin_op', op, left, right, result_type: hint },
  });
  state.types.set(name, resultType);
  state.stack.push(name);
  return null;
}

function emitCall(
  state: LiftState,
  fn: string,
  arity: number,
  resultType: InferredType,
): LiftFailure | null {
  if (state.stack.length < arity) return failOther(`call ${fn}: not enough operands`);
  const args: string[] = [];
  for (let i = 0; i < arity; i++) args.unshift(state.stack.pop()!);
  const name = freshName(state);
  state.bindings.push({ name, value: { kind: 'call', func: fn, args } });
  state.types.set(name, resultType);
  state.stack.push(name);
  return null;
}

// ---------------------------------------------------------------------------
// Failure helpers (with debug counter)
// ---------------------------------------------------------------------------

function failUnhandled(opName: string, reason: string): LiftFailure {
  UNHANDLED_COUNTS.set(opName, (UNHANDLED_COUNTS.get(opName) ?? 0) + 1);
  // Best-effort debug logging — opt-IN via env var. Tests / pipelines stay
  // quiet by default; the counter (getUnhandledOpcodeCounts) is the
  // primary signal future work uses to drive opcode-support priorities.
  if (process.env.RUNAR_DECOMPILER_DEBUG_UNHANDLED) {
    // eslint-disable-next-line no-console
    console.error(`[runar-decompiler/symexec-lift] unhandled opcode: ${opName} — ${reason}`);
  }
  return { ok: false, unhandled: opName, reason };
}

function failOther(reason: string): LiftFailure {
  return { ok: false, reason };
}

// ---------------------------------------------------------------------------
// TS source renderer
// ---------------------------------------------------------------------------

/**
 * Render an ANF program (produced by the lifter) as a TS Rúnar source string.
 * The bindings are walked in order and emitted as `let` declarations followed
 * by a trailing `assert(...)` or terminal statement. Operator precedence is
 * handled by emitting parens around all non-trivial expressions — produces
 * verbose-but-correct source that re-compiles to the same bytes.
 */
export function renderTsSource(result: LiftResult, opts: { className?: string } = {}): string {
  const className = opts.className ?? result.program.contractName ?? '_Recovered';

  const importSet = new Set(result.imports);
  importSet.add('SmartContract');
  importSet.add('assert');
  // Properties may use Sig/PubKey/ByteString in their declared TS types,
  // which require importing the matching surface aliases.
  for (const p of result.program.properties) {
    if (p.type === 'Sig') importSet.add('Sig');
    if (p.type === 'PubKey') importSet.add('PubKey');
    if (p.type === 'ByteString') importSet.add('ByteString');
  }
  const importList = Array.from(importSet).sort().join(', ');

  // Render every method in the program. Each method's body is its own
  // scope — SSA names from one method don't leak into another, so we
  // build a fresh `exprs` / `typeOf` map per method.
  const methodBlocks: string[] = result.program.methods.map(method => {
    const exprs = new Map<string, string>();
    const typeOf = new Map<string, string>();
    inferContextualTypes(method.body, typeOf);
    const statements: string[] = [];
    renderBindings(method.body, exprs, statements, '    ', typeOf);
    const params = method.params
      .map(p => `${p.name}: ${p.type}`)
      .join(', ');
    return `  public ${method.name}(${params}): void {\n${statements.join('\n')}\n  }`;
  });

  // Constructor — when the recovered program declares properties (one per
  // constructor placeholder slot in the input bytes), the contract surface
  // uses the explicit-field form the Rúnar parser expects: each property is
  // declared as `readonly <name>: <type>;` in the class body, the
  // constructor takes plain (non-modifier) parameters and forwards them to
  // `super(...)` and to per-field `this.<name> = <name>` assignments. The
  // TS-shorthand `constructor(public readonly x: T)` form is NOT recognized
  // by `parseContractClass`, which only registers explicit class-body
  // declarations as Rúnar properties.
  const fieldDecls = result.program.properties
    .map(p => `  readonly ${p.name}: ${p.type};`)
    .join('\n');
  const ctorParams = result.program.properties
    .map(p => `${p.name}: ${p.type}`)
    .join(', ');
  const superArgs = result.program.properties.map(p => p.name).join(', ');
  const assigns = result.program.properties
    .map(p => `    this.${p.name} = ${p.name};`)
    .join('\n');
  const ctorBody = result.program.properties.length > 0
    ? `\n${fieldDecls}\n\n  constructor(${ctorParams}) {\n    super(${superArgs});\n${assigns}\n  }\n`
    : `\n  constructor() {\n    super();\n  }\n`;

  return `import { ${importList} } from 'runar-lang';

export class ${className} extends SmartContract {${ctorBody}
${methodBlocks.join('\n\n')}
}
`;
}

/**
 * Walk the bindings and propagate contextual surface types. The current
 * heuristic is narrow: `checkMultiSig`'s first arg-array's elements get
 * type `Sig`; second arg-array's elements get type `PubKey`.
 */
function inferContextualTypes(
  bindings: ANFBinding[],
  typeOf: Map<string, string>,
): void {
  const byName = new Map<string, ANFBinding>();
  for (const b of bindings) byName.set(b.name, b);
  for (const b of bindings) {
    const v = b.value;
    if (v.kind === 'call' && v.func === 'checkMultiSig' && v.args.length === 2) {
      const sigArrName = v.args[0]!;
      const keyArrName = v.args[1]!;
      const sigArr = byName.get(sigArrName);
      const keyArr = byName.get(keyArrName);
      if (sigArr && sigArr.value.kind === 'array_literal') {
        for (const e of sigArr.value.elements) typeOf.set(e, 'Sig');
      }
      if (keyArr && keyArr.value.kind === 'array_literal') {
        for (const e of keyArr.value.elements) typeOf.set(e, 'PubKey');
      }
    }
    if (v.kind === 'if') {
      inferContextualTypes(v.then, typeOf);
      inferContextualTypes(v.else, typeOf);
    }
  }
}

function renderBindings(
  bindings: ANFBinding[],
  exprs: Map<string, string>,
  statements: string[],
  indent: string,
  typeOf: Map<string, string>,
): void {
  for (const b of bindings) {
    const v = b.value;
    switch (v.kind) {
      case 'load_param': {
        exprs.set(b.name, v.name);
        break;
      }
      case 'load_prop': {
        exprs.set(b.name, `this.${v.name}`);
        break;
      }
      case 'load_const': {
        // Handle `@ref:` aliases — render as a reference to the inner name's
        // rendered expression. The compiler will collapse them at
        // stack-lowering time.
        if (typeof v.value === 'string' && v.value.startsWith('@ref:')) {
          const refName = v.value.slice(5);
          const refExpr = exprs.get(refName) ?? refName;
          exprs.set(b.name, refExpr);
          break;
        }
        const contextual = typeOf.get(b.name);
        const lit = renderConst(v.value, contextual);
        exprs.set(b.name, lit);
        break;
      }
      case 'bin_op': {
        const l = exprs.get(v.left)  ?? v.left;
        const r = exprs.get(v.right) ?? v.right;
        exprs.set(b.name, `(${l} ${v.op} ${r})`);
        break;
      }
      case 'unary_op': {
        const o = exprs.get(v.operand) ?? v.operand;
        exprs.set(b.name, `(${v.op}${o})`);
        break;
      }
      case 'call': {
        const args = v.args.map(a => exprs.get(a) ?? a).join(', ');
        exprs.set(b.name, `${v.func}(${args})`);
        break;
      }
      case 'array_literal': {
        const elems = v.elements.map(e => exprs.get(e) ?? e).join(', ');
        exprs.set(b.name, `[${elems}]`);
        break;
      }
      case 'if': {
        // Render as a TS ternary so it stays an expression. Use a recursive
        // sub-render to materialize each branch's bindings, then take the
        // final expression as the branch value.
        const condExpr = exprs.get(v.cond) ?? v.cond;
        const thenExpr = renderBranchAsExpr(v.then, exprs, typeOf);
        const elseExpr = renderBranchAsExpr(v.else, exprs, typeOf);
        exprs.set(b.name, `(${condExpr} ? ${thenExpr} : ${elseExpr})`);
        break;
      }
      case 'assert': {
        const e = exprs.get(v.value) ?? v.value;
        statements.push(`${indent}assert(${e});`);
        break;
      }
      default:
        // Anything else means the lifter's output drifted out of the
        // supported subset — the verifier will catch it.
        statements.push(`${indent}// unhandled ANF kind: ${v.kind}`);
    }
  }
}

/**
 * Recursively render a branch as a single expression. The branch's
 * "result" is its last binding's rendered expression. Side-effects in
 * branches (asserts, statements) are NOT modeled — those abort the lift.
 */
function renderBranchAsExpr(
  bindings: ANFBinding[],
  exprs: Map<string, string>,
  typeOf: Map<string, string>,
): string {
  if (bindings.length === 0) return 'true';
  // Snapshot the exprs map so sub-branch bindings don't leak.
  const localExprs = new Map(exprs);
  const localStatements: string[] = [];
  renderBindings(bindings, localExprs, localStatements, '', typeOf);
  // Copy newly created binding names back to the outer map so sibling
  // statements (e.g. a top-level assert that references the branch result)
  // can resolve them. This is safe because all SSA names are unique.
  for (const [k, val] of localExprs.entries()) {
    if (!exprs.has(k)) exprs.set(k, val);
  }
  const lastName = bindings[bindings.length - 1]!.name;
  return localExprs.get(lastName) ?? lastName;
}

function renderConst(v: string | bigint | boolean, contextualType?: string): string {
  if (typeof v === 'bigint') return `${v.toString()}n`;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  // ByteString literal — encode as hex string with the Rúnar bytes-literal
  // shape. The compiler accepts hex-string literals typed as `ByteString`
  // when they appear in assert/comparison context, so emit a tagged
  // template-like form: `'0xHEX'` is the standard Rúnar surface.
  const t = contextualType ?? 'ByteString';
  return `'${v}' as ${t}`;
}
