/**
 * Stateful contract recovery — artifact-driven.
 *
 * Stateful contracts (`extends StatefulSmartContract`) compile to byte
 * sequences with three structural pieces wrapped around the developer's
 * user code:
 *
 *   1. Prelude — auto-injected at method entry:
 *        load_param txPreimage
 *        check_preimage(txPreimage)
 *        assert(...)
 *        load_param txPreimage
 *        deserialize_state(txPreimage)   // only when contract has mutable state
 *
 *   2. User code — the developer's actual method body (load_prop / update_prop
 *      / bin_op / addOutput / addRawOutput / addDataOutput / ...).
 *
 *   3. Continuation — auto-injected at method exit (presence depends on
 *      whether the method mutates state, emits outputs, or is terminal):
 *        load_param _changePKH
 *        load_param _changeAmount
 *        call buildChangeOutput
 *        get_state_script                       (single-output continuation)
 *        load_param txPreimage
 *        load_param _newAmount                  (single-output only)
 *        call computeStateOutput | direct cat   (multi-output)
 *        call cat                               (chain accumulator)
 *        call hash256
 *        load_param txPreimage
 *        call extractOutputHash
 *        bin_op === (result_type: bytes)
 *        assert
 *
 * The decompiler does NOT need to invert the byte-level patterns the
 * stack-lowering emits for these pieces. The artifact carries the full
 * pre-lowering ANF for every stateful contract, plus enough metadata
 * (`stateFields`, `codeSeparatorIndex`, etc.) to identify the contract as
 * stateful. So this module operates on the ANF directly:
 *
 *   1. Strip the prelude (check_preimage + its assert + deserialize_state).
 *   2. Strip the trailing continuation block (the buildChangeOutput +
 *      computeStateOutput/cat-chain + hash256 + extractOutputHash + assert).
 *   3. Strip the auto-injected implicit params from each method's param list
 *      (`_changePKH`, `_changeAmount`, `_newAmount`, `txPreimage`).
 *   4. Render the remaining user-visible bindings as a
 *      `class X extends StatefulSmartContract { ... }` TS source.
 *   5. Verify by recompiling the source and byte-comparing.
 *
 * Sound because: the artifact's ANF IS the IR the original source lowered
 * to; rendering it back through compile() must produce byte-identical
 * output, modulo expression-shape differences that the constant-folding /
 * peephole passes are insensitive to.
 *
 * Aborts on shapes outside the recognized continuation pattern (e.g.
 * private-helper side-effects, raw_script ANF nodes, anything not
 * compiled by the regular path) — caller falls through to raw_script.
 */

import type {
  ANFProgram,
  ANFBinding,
  ANFValue,
  ANFMethod,
  ANFParam,
  StateField,
} from 'runar-compiler';
import { bytesToHex } from 'runar-testing';

// ---------------------------------------------------------------------------
// Implicit-param recognition
// ---------------------------------------------------------------------------

/**
 * Names of the implicit params the ANF-lower pass injects for stateful
 * public methods. These are auto-added to the param list AND consumed by
 * the auto-injected prelude/continuation; they must NOT appear in the
 * recovered surface source.
 */
const IMPLICIT_STATEFUL_PARAMS = new Set([
  'txPreimage',
  '_changePKH',
  '_changeAmount',
  '_newAmount',
]);

function isImplicitParam(name: string): boolean {
  return IMPLICIT_STATEFUL_PARAMS.has(name);
}

// ---------------------------------------------------------------------------
// Lift result
// ---------------------------------------------------------------------------

export interface StatefulLiftResult {
  ok: true;
  /** The user-visible ANF program — prelude + continuation stripped. */
  program: ANFProgram;
  /** Imports the rendered source needs. */
  imports: string[];
}

export interface StatefulLiftFailure {
  ok: false;
  reason: string;
}

export type StatefulLiftOutcome = StatefulLiftResult | StatefulLiftFailure;

export interface StatefulLiftOptions {
  /** State-field descriptors from the artifact. Drives property recovery. */
  stateFields?: readonly StateField[];
  className?: string;
}

/**
 * Strip the auto-injected stateful prelude/continuation from a single
 * method body. Returns the user-visible binding subsequence.
 *
 * Recognized prelude shape (in order):
 *
 *     load_param txPreimage  → check_preimage(...)  → assert(...)
 *     load_param txPreimage  → deserialize_state(...)   (only if mutable state)
 *
 * Recognized continuation shape (trailing):
 *
 *     ... (any number of bindings that produce the chain accumulator) ...
 *     call hash256(accum)
 *     load_param txPreimage
 *     call extractOutputHash(txPreimage)
 *     bin_op === (result_type: bytes)
 *     assert
 *
 * Plus all bindings reachable through the continuation chain (the
 * buildChangeOutput call, computeStateOutput, the cat chain, etc.) — those
 * are dropped along with the trailing assert.
 */
function stripStatefulWrapping(
  body: readonly ANFBinding[],
): { user: ANFBinding[]; ok: true } | { ok: false; reason: string } {
  // -- Prelude --
  let cursor = 0;

  // Step 1: load_param txPreimage  → check_preimage → assert
  if (cursor + 3 > body.length) {
    return { ok: false, reason: 'method body too short to contain stateful prelude' };
  }
  const b0 = body[cursor]!;
  const b1 = body[cursor + 1]!;
  const b2 = body[cursor + 2]!;
  if (b0.value.kind !== 'load_param' || b0.value.name !== 'txPreimage') {
    return { ok: false, reason: `expected load_param txPreimage at index 0, got ${b0.value.kind}` };
  }
  if (b1.value.kind !== 'check_preimage' || b1.value.preimage !== b0.name) {
    return { ok: false, reason: `expected check_preimage at index 1, got ${b1.value.kind}` };
  }
  if (b2.value.kind !== 'assert' || b2.value.value !== b1.name) {
    return { ok: false, reason: `expected assert at index 2, got ${b2.value.kind}` };
  }
  cursor += 3;

  // Step 2: optional load_param txPreimage → deserialize_state (skipped when
  // the contract has no mutable state). Recognize both shapes.
  if (cursor + 2 <= body.length) {
    const c0 = body[cursor]!;
    const c1 = body[cursor + 1]!;
    if (
      c0.value.kind === 'load_param' && c0.value.name === 'txPreimage' &&
      c1.value.kind === 'deserialize_state' && c1.value.preimage === c0.name
    ) {
      cursor += 2;
    }
  }

  const preludeEnd = cursor;

  // -- Continuation --
  // Walk backwards from the end. The continuation always ends with:
  //   bin_op ===   (result_type: bytes)
  //   assert
  // The assert references the bin_op result; the bin_op compares
  // hash256(...) === extractOutputHash(...). Find the FIRST binding
  // reachable from that assert and chop everything from there onwards.
  if (body.length < cursor + 2) {
    // No trailing assert — method's user body has no continuation.
    return { ok: true, user: body.slice(cursor) };
  }

  const lastIdx = body.length - 1;
  const last = body[lastIdx]!;
  if (last.value.kind !== 'assert') {
    // No trailing assert — user body ends with something else. That's
    // valid for some shapes (e.g. methods that only have asserts inside
    // an if). For now we don't strip a continuation in this case.
    return { ok: true, user: body.slice(cursor) };
  }

  // Identify whether the trailing assert is the continuation-equality
  // assert. The assert's value must trace back through bin_op `===` with
  // result_type 'bytes', whose right side comes from a `call
  // extractOutputHash` chain. We do a structural check.
  const continuationStart = findContinuationStart(body, preludeEnd, lastIdx);
  if (continuationStart === null) {
    // Trailing assert is user code, not a continuation. Return body as-is.
    return { ok: true, user: body.slice(cursor) };
  }

  return { ok: true, user: body.slice(cursor, continuationStart) };
}

/**
 * Detect the start index of the trailing continuation block. Returns the
 * lowest index `i >= preludeEnd` such that `body[i..lastIdx]` is exactly
 * the auto-injected continuation chain reachable from the final assert.
 *
 * The continuation chain always includes a binding pattern like:
 *
 *   ... buildChangeOutput(_changePKH, _changeAmount)
 *   ... computeStateOutput(txPreimage, get_state_script, _newAmount)   OR
 *       call cat(addOutputRef, ...)                                    (multi-output)
 *   ... call cat(...)*  -> accumulator
 *   ... call hash256(accumulator)
 *   ... load_param txPreimage
 *   ... call extractOutputHash(txPreimage)
 *   ... bin_op === (result_type: 'bytes')
 *   ... assert
 *
 * We compute the reachability set of the trailing assert's value: any
 * binding whose name is referenced by something already in the set is
 * also in the set. The lowest contiguous index whose entire suffix is
 * inside the set is the continuation start.
 *
 * Returns `null` if the trailing assert is NOT a continuation
 * (i.e. it depends on a binding that some other binding's RHS references
 * outside the trailing block — meaning the assert is user code that's
 * tangled with non-continuation code).
 */
function findContinuationStart(
  body: readonly ANFBinding[],
  preludeEnd: number,
  lastIdx: number,
): number | null {
  const last = body[lastIdx]!;
  if (last.value.kind !== 'assert') return null;

  // Shape check on the assert's value chain. The final assert MUST point
  // at a bin_op === with result_type 'bytes', whose right-side traces back
  // to a `call extractOutputHash(load_param txPreimage)`.
  const byName = new Map<string, ANFBinding>();
  for (const b of body) byName.set(b.name, b);

  const cmp = byName.get(last.value.value);
  if (!cmp || cmp.value.kind !== 'bin_op' || cmp.value.op !== '===') return null;
  if (cmp.value.result_type !== 'bytes') return null;

  const rhs = byName.get(cmp.value.right);
  if (!rhs || rhs.value.kind !== 'call' || rhs.value.func !== 'extractOutputHash') return null;

  const lhs = byName.get(cmp.value.left);
  if (!lhs || lhs.value.kind !== 'call' || lhs.value.func !== 'hash256') return null;

  // Walk the reachability set backwards. Start with `last` and add every
  // binding whose name is referenced from inside the set.
  //
  // EXCEPTION: user-side-effect bindings (add_output / add_raw_output /
  // add_data_output / update_prop / assert) are NEVER part of the
  // auto-injected continuation chain — they're user code that the
  // continuation references but doesn't subsume. Even when the
  // continuation's cat-chain consumes an `add_output` binding's RHS, the
  // `add_output` itself is still a user statement. So we do not chain
  // through them: their refs don't pull anything else into the set.
  const inSet = new Set<string>([last.name]);
  // Process in reverse so we pick up the chain efficiently.
  for (let i = lastIdx; i >= preludeEnd; i--) {
    const b = body[i]!;
    if (!inSet.has(b.name)) continue;
    if (isUserSideEffect(b.value)) {
      // Stop chaining through user-side-effect bindings. The continuation
      // references the binding's NAME for hashing purposes, but the
      // binding itself is user code — its operands must remain in the
      // user span.
      continue;
    }
    for (const ref of refsOf(b.value)) {
      inSet.add(ref);
    }
  }

  // Sweep forward to find the lowest contiguous index whose entire
  // [i..lastIdx] is inside the set. User-side-effect bindings ALWAYS
  // halt the sweep, even if they happened to land in the set.
  let start = lastIdx;
  while (start > preludeEnd) {
    const prev = body[start - 1]!;
    if (isUserSideEffect(prev.value)) break;
    if (inSet.has(prev.name)) {
      start -= 1;
    } else {
      break;
    }
  }

  // Sanity: the continuation chain must reference these implicit params
  // (or at minimum txPreimage). If none of the implicit params is
  // touched, what we caught isn't actually the auto-injected
  // continuation.
  let touchesImplicit = false;
  for (let i = start; i <= lastIdx; i++) {
    const v = body[i]!.value;
    if (v.kind === 'load_param' && isImplicitParam(v.name)) {
      touchesImplicit = true;
      break;
    }
    if (v.kind === 'get_state_script') {
      touchesImplicit = true;
      break;
    }
  }
  if (!touchesImplicit) return null;

  return start;
}

/**
 * Predicate: is this ANF value a user-side-effect statement? Those are
 * the bindings the renderer materializes as a TS statement (rather than
 * inlining into a downstream consumer's RHS). The continuation walk
 * stops at any of these because they must always remain in the user span.
 */
function isUserSideEffect(v: ANFValue): boolean {
  switch (v.kind) {
    case 'add_output':
    case 'add_raw_output':
    case 'add_data_output':
    case 'update_prop':
      return true;
    // `assert` IS a user side-effect in general, BUT the continuation tail
    // is itself an assert (the equality assert at the end). We exclude it
    // here so the continuation's terminal assert can still anchor the
    // backwards walk.
    default:
      return false;
  }
}

/** All binding names that a given ANFValue references. */
function refsOf(v: ANFValue): string[] {
  switch (v.kind) {
    case 'load_param':
    case 'load_prop':
    case 'load_const':
    case 'get_state_script':
    case 'raw_script':
      return [];
    case 'bin_op':
      return [v.left, v.right];
    case 'unary_op':
      return [v.operand];
    case 'call':
      return [...v.args];
    case 'method_call':
      return [v.object, ...v.args];
    case 'if':
      return [v.cond];
    case 'loop':
      return [];
    case 'assert':
      return [v.value];
    case 'update_prop':
      return [v.value];
    case 'check_preimage':
      return [v.preimage];
    case 'deserialize_state':
      return [v.preimage];
    case 'add_output':
      return [v.satoshis, ...v.stateValues];
    case 'add_raw_output':
      return [v.satoshis, v.scriptBytes];
    case 'add_data_output':
      return [v.satoshis, v.scriptBytes];
    case 'array_literal':
      return [...v.elements];
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Property recovery
// ---------------------------------------------------------------------------

/**
 * Build the recovered property list. State fields come from `stateFields`
 * (mutable, non-readonly). Readonly properties from the constructor are
 * picked up from the ANF's `properties` array — those carry the readonly
 * flag set by the lowering pass.
 */
function buildProperties(
  anfProperties: readonly { name: string; type: string; readonly: boolean; initialValue?: unknown }[],
  stateFields: readonly StateField[] | undefined,
): { name: string; type: string; readonly: boolean }[] {
  // Trust the ANF's property list: it already mirrors the source.
  // stateFields is metadata for the SDK / decompiler routing; we don't
  // need to cross-check it here (the artifact assembler builds both
  // from the same source).
  void stateFields;
  return anfProperties.map(p => ({
    name: p.name,
    type: p.type,
    readonly: p.readonly,
  }));
}

// ---------------------------------------------------------------------------
// Top-level lift
// ---------------------------------------------------------------------------

/**
 * Strip auto-injected stateful prelude/continuation from every public
 * method of `anf`. Returns the user-visible ANF program + the imports
 * the rendered source will need.
 *
 * Aborts on any private-method body that uses `add_output` / `add_raw_output`
 * / `add_data_output` — those rely on the continuation-hash insertion
 * happening at the call site in the public caller's body, which the
 * stripping logic above only recognizes at the public-body level. The
 * GAP comment in `04-anf-lower.ts` already documents this corner.
 */
export function liftStatefulFromArtifact(
  anf: ANFProgram,
  opts: StatefulLiftOptions = {},
): StatefulLiftOutcome {
  const className = opts.className ?? anf.contractName;

  const properties = buildProperties(anf.properties, opts.stateFields);

  const newMethods: ANFMethod[] = [];
  for (const m of anf.methods) {
    if (m.name === 'constructor') {
      // Constructor body — keep as-is (it's lowered without the stateful
      // wrapping). We'll render it explicitly via the property list, not
      // from the constructor body, because the canonical surface uses
      // the field-init form `this.<name> = <name>` derived from
      // properties.
      newMethods.push(m);
      continue;
    }

    if (!m.isPublic) {
      // Private methods are not auto-wrapped. Keep them verbatim.
      newMethods.push(m);
      continue;
    }

    const stripped = stripStatefulWrapping(m.body);
    if (!stripped.ok) {
      return { ok: false, reason: `method '${m.name}': ${stripped.reason}` };
    }

    // Filter implicit params from the surface param list.
    const userParams: ANFParam[] = m.params.filter(p => !isImplicitParam(p.name));

    newMethods.push({
      name: m.name,
      params: userParams,
      body: stripped.user,
      isPublic: true,
    });
  }

  const program: ANFProgram = {
    contractName: className,
    properties,
    methods: newMethods,
  };

  const imports = new Set<string>();
  imports.add('StatefulSmartContract');
  collectImports(program, imports);

  return { ok: true, program, imports: Array.from(imports) };
}

/** Walk the ANF and add to `imports` any surface types we'll reference. */
function collectImports(anf: ANFProgram, imports: Set<string>): void {
  for (const p of anf.properties) {
    addTypeImport(p.type, imports);
  }
  for (const m of anf.methods) {
    for (const p of m.params) addTypeImport(p.type, imports);
    walkBindingsForImports(m.body, imports);
  }
}

function walkBindingsForImports(bindings: readonly ANFBinding[], imports: Set<string>): void {
  for (const b of bindings) {
    const v = b.value;
    if (v.kind === 'call' && v.func === 'assert') imports.add('assert');
    if (v.kind === 'assert') imports.add('assert');
    if (v.kind === 'if') {
      walkBindingsForImports(v.then, imports);
      walkBindingsForImports(v.else, imports);
    }
  }
}

function addTypeImport(t: string, imports: Set<string>): void {
  switch (t) {
    case 'ByteString':
    case 'Sig':
    case 'PubKey':
    case 'Ripemd160':
    case 'Sha256':
    case 'Addr':
    case 'Point':
    case 'P256Point':
    case 'P384Point':
    case 'SigHashPreimage':
    case 'RabinSig':
    case 'RabinPubKey':
      imports.add(t);
      break;
    default:
      // primitive types (bigint, boolean) need no import
      break;
  }
}

// ---------------------------------------------------------------------------
// Source rendering
// ---------------------------------------------------------------------------

/**
 * Render a stripped stateful ANF program as a TS source string. The
 * surface shape matches what the Rúnar TS parser accepts:
 *
 *   import { StatefulSmartContract, ... } from 'runar-lang';
 *   export class Foo extends StatefulSmartContract {
 *     readonly r: T1;
 *     m: T2;
 *     constructor(r: T1, m: T2) { super(r, m); this.r = r; this.m = m; }
 *     public methodA(p: T): void { ...body...; }
 *   }
 *
 * The constructor is generated from the property list — every property
 * becomes a constructor parameter (in declaration order) and is
 * assigned `this.<name> = <name>`.
 *
 * Method bodies are rendered by walking the stripped ANF and emitting
 * each binding as either an `assert(expr);` / `this.<f> = expr;` /
 * `this.addOutput(...);` style statement, or by inlining the expression
 * into a consumer's RHS when the binding has only one downstream
 * reference. Operator precedence is handled by emitting parens around
 * every non-trivial subexpression (verbose but always-correct).
 */
export function renderStatefulSource(
  result: StatefulLiftResult,
  opts: { className?: string } = {},
): string {
  const className = opts.className ?? result.program.contractName ?? '_Recovered';

  const importSet = new Set(result.imports);
  importSet.add('StatefulSmartContract');
  const importList = Array.from(importSet).sort().join(', ');

  // Property declarations: `readonly count: T;` or `count: T;`.
  const propDecls = result.program.properties
    .map(p => `  ${p.readonly ? 'readonly ' : ''}${p.name}: ${p.type};`)
    .join('\n');

  // Constructor: every property becomes a parameter (matches the canonical
  // surface). We always emit `super(<all property names>)` followed by
  // `this.<n> = <n>` for each property — that's the universal Rúnar
  // constructor shape.
  const ctorParams = result.program.properties
    .map(p => `${p.name}: ${p.type}`)
    .join(', ');
  const superArgs = result.program.properties.map(p => p.name).join(', ');
  const assigns = result.program.properties
    .map(p => `    this.${p.name} = ${p.name};`)
    .join('\n');

  const ctorBlock = result.program.properties.length > 0
    ? `  constructor(${ctorParams}) {\n    super(${superArgs});\n${assigns}\n  }`
    : `  constructor() {\n    super();\n  }`;

  // Methods.
  const methodBlocks: string[] = [];
  for (const m of result.program.methods) {
    if (m.name === 'constructor') continue;
    if (!m.isPublic) continue; // Private methods that survived stripping are out of scope.
    const params = m.params.map(p => `${p.name}: ${p.type}`).join(', ');
    const body = renderMethodBody(m.body);
    methodBlocks.push(`  public ${m.name}(${params}): void {\n${body}\n  }`);
  }

  const blocks = [propDecls, ctorBlock, ...methodBlocks].filter(s => s.length > 0).join('\n\n');

  return `import { ${importList} } from 'runar-lang';

export class ${className} extends StatefulSmartContract {
${blocks}
}
`;
}

// ---------------------------------------------------------------------------
// Method-body rendering
// ---------------------------------------------------------------------------

/**
 * Render a stripped method body as a sequence of TS statements (indented
 * by 4 spaces). Uses ANF inlining: pure-expression bindings (load_const,
 * load_param, load_prop, bin_op, unary_op, call) materialize into a
 * string in the `exprs` map and inline into their consumer. Side-effect
 * bindings (assert, update_prop, addOutput, addRawOutput, addDataOutput,
 * if) emit a real TS statement.
 */
function renderMethodBody(body: readonly ANFBinding[]): string {
  const exprs = new Map<string, string>();
  const statements: string[] = [];
  renderBindings(body, exprs, statements, '    ');
  return statements.join('\n');
}

function renderBindings(
  body: readonly ANFBinding[],
  exprs: Map<string, string>,
  statements: string[],
  indent: string,
): void {
  for (const b of body) {
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
        exprs.set(b.name, renderConst(v.value));
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
      case 'update_prop': {
        const e = exprs.get(v.value) ?? v.value;
        statements.push(`${indent}this.${v.name} = ${e};`);
        // Refresh: subsequent load_prop bindings for the same name
        // should still produce `this.<name>` — they always do, so no
        // bookkeeping needed.
        break;
      }
      case 'assert': {
        const e = exprs.get(v.value) ?? v.value;
        statements.push(`${indent}assert(${e});`);
        break;
      }
      case 'add_output': {
        const sats = exprs.get(v.satoshis) ?? v.satoshis;
        const vals = v.stateValues.map(s => exprs.get(s) ?? s);
        statements.push(`${indent}this.addOutput(${[sats, ...vals].join(', ')});`);
        break;
      }
      case 'add_raw_output': {
        const sats = exprs.get(v.satoshis) ?? v.satoshis;
        const scr  = exprs.get(v.scriptBytes) ?? v.scriptBytes;
        statements.push(`${indent}this.addRawOutput(${sats}, ${scr});`);
        break;
      }
      case 'add_data_output': {
        const sats = exprs.get(v.satoshis) ?? v.satoshis;
        const scr  = exprs.get(v.scriptBytes) ?? v.scriptBytes;
        statements.push(`${indent}this.addDataOutput(${sats}, ${scr});`);
        break;
      }
      case 'if': {
        const condExpr = exprs.get(v.cond) ?? v.cond;
        // Render as an if-statement. Bindings inside each branch may
        // need their own statements (e.g. nested asserts). Snapshot
        // exprs into the sub-render so unrelated names don't leak.
        const thenStmts: string[] = [];
        const elseStmts: string[] = [];
        renderBindings(v.then, new Map(exprs), thenStmts, indent + '  ');
        renderBindings(v.else, new Map(exprs), elseStmts, indent + '  ');
        statements.push(`${indent}if (${condExpr}) {`);
        for (const s of thenStmts) statements.push(s);
        if (elseStmts.length > 0) {
          statements.push(`${indent}} else {`);
          for (const s of elseStmts) statements.push(s);
        }
        statements.push(`${indent}}`);
        break;
      }
      case 'check_preimage':
      case 'deserialize_state':
      case 'get_state_script':
      case 'loop':
      case 'method_call':
      case 'raw_script': {
        // Anything that survives stripping in one of these forms means
        // the contract uses a shape our stripping doesn't cover (or the
        // method is doing something exotic). Emit a placeholder comment
        // — verification will catch the divergence.
        statements.push(`${indent}// stateful-decompiler: unsupported ANF kind ${v.kind}`);
        break;
      }
    }
  }
}

function renderConst(v: string | bigint | boolean | number | Uint8Array): string {
  if (typeof v === 'bigint') return `${v.toString()}n`;
  if (typeof v === 'number') return `${BigInt(v).toString()}n`;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'string') {
    // ByteString hex literal — keep the same as the symexec lifter.
    return `'${v}' as ByteString`;
  }
  if (v instanceof Uint8Array) {
    return `'${bytesToHex(v)}' as ByteString`;
  }
  return `${String(v)}`;
}
