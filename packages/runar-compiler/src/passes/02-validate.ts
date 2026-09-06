/**
 * Pass 2: Validate
 *
 * Validates the Rúnar AST against the language subset constraints.
 * This pass does NOT modify the AST; it only reports errors and warnings.
 */

import type {
  ContractNode,
  MethodNode,
  Statement,
  Expression,
  TypeNode,
  PrimitiveTypeName,
  SourceLocation,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { validateSighashUsage } from './sighash-validate.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ValidationResult {
  errors: CompilerDiagnostic[];
  warnings: CompilerDiagnostic[];
}

/**
 * Validate a parsed Rúnar AST against the language subset constraints.
 */
export function validate(contract: ContractNode): ValidationResult {
  const errors: CompilerDiagnostic[] = [];
  const warnings: CompilerDiagnostic[] = [];
  const ctx: ValidationContext = { errors, warnings, contract };

  // Structural guard: contract name must be non-empty.
  if (!contract.name) {
    errors.push(makeDiagnostic('Contract name must not be empty', 'error'));
    return { errors, warnings };
  }

  validateProperties(ctx);
  validateConstructor(ctx);
  validateMethods(ctx);
  checkNoRecursion(ctx);

  // Issue #123: reject preimage-field reads / output bindings that are unsound
  // under a method's declared @sighash mode (security core). This pass emits
  // both errors (unsound usages) and warnings (e.g. an explicit single-output
  // SINGLE covenant whose same-index value cannot be pinned statically), so
  // route each diagnostic to the matching bucket.
  for (const d of validateSighashUsage(contract)) {
    (d.severity === 'warning' ? warnings : errors).push(d);
  }

  return { errors, warnings };
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface ValidationContext {
  errors: CompilerDiagnostic[];
  warnings: CompilerDiagnostic[];
  contract: ContractNode;
}

// ---------------------------------------------------------------------------
// Property validation
// ---------------------------------------------------------------------------

const VALID_PRIMITIVE_TYPES = new Set<string>([
  'bigint', 'boolean', 'ByteString', 'PubKey', 'Sig', 'Sha256',
  'Ripemd160', 'Addr', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point',
  'P256Point', 'P384Point',
]);

function validateProperties(ctx: ValidationContext): void {
  for (const prop of ctx.contract.properties) {
    validatePropertyType(prop.type, prop.sourceLocation, ctx);

    // txPreimage is an implicit property of StatefulSmartContract
    if (ctx.contract.parentClass === 'StatefulSmartContract' && prop.name === 'txPreimage') {
      ctx.errors.push(makeDiagnostic(
        `'txPreimage' is an implicit property of StatefulSmartContract and must not be declared`,
        'error',
        prop.sourceLocation,
      ));
    }

    // Validate initializer if present
    if (prop.initializer) {
      // FixedArray properties may use an array literal of literal elements.
      // The individual elements are still literal-restricted; nested arrays
      // are allowed when the property type is a nested FixedArray.
      if (prop.type.kind === 'fixed_array_type') {
        if (!isArrayLiteralOfLiterals(prop.initializer)) {
          ctx.errors.push(makeDiagnostic(
            `Property '${prop.name}' initializer must be an array literal of literal values`,
            'error',
            prop.sourceLocation,
          ));
        }
      } else if (!isLiteralExpression(prop.initializer)) {
        ctx.errors.push(makeDiagnostic(
          `Property '${prop.name}' initializer must be a literal value (number, boolean, or hex string)`,
          'error',
          prop.sourceLocation,
        ));
      }
    }
  }

  // SmartContract (and the asm-escape-hatch UnsafeSmartContract) require
  // all properties to be readonly. State mutation is StatefulSmartContract
  // territory.
  if (
    ctx.contract.parentClass === 'SmartContract' ||
    ctx.contract.parentClass === 'UnsafeSmartContract'
  ) {
    for (const prop of ctx.contract.properties) {
      if (!prop.readonly) {
        ctx.errors.push(makeDiagnostic(
          `Property '${prop.name}' in ${ctx.contract.parentClass} must be readonly. Use StatefulSmartContract for mutable state.`,
          'error',
          prop.sourceLocation,
        ));
      }
    }
  }

  // Warn if StatefulSmartContract has no mutable properties
  if (ctx.contract.parentClass === 'StatefulSmartContract') {
    const hasMutableProps = ctx.contract.properties.some(p => !p.readonly);
    if (!hasMutableProps) {
      ctx.warnings.push(makeDiagnostic(
        'StatefulSmartContract has no mutable properties; consider using SmartContract instead',
        'warning',
        ctx.contract.constructor.sourceLocation,
      ));
    }
  }
}

/** Check if an expression is a literal (allowed as property initializer). */
function isLiteralExpression(expr: Expression): boolean {
  if (expr.kind === 'bigint_literal') return true;
  if (expr.kind === 'bool_literal') return true;
  if (expr.kind === 'bytestring_literal') return true;
  // Allow negative literals: -42n
  if (expr.kind === 'unary_expr' && expr.op === '-' && expr.operand.kind === 'bigint_literal') return true;
  return false;
}

/**
 * Allow a property initializer of the form `[lit, lit, ...]` for
 * FixedArray properties. Elements may themselves be array literals for
 * nested FixedArrays. Each leaf must still be a literal value.
 */
function isArrayLiteralOfLiterals(expr: Expression): boolean {
  if (expr.kind !== 'array_literal') return false;
  for (const el of expr.elements) {
    if (el.kind === 'array_literal') {
      if (!isArrayLiteralOfLiterals(el)) return false;
    } else if (!isLiteralExpression(el)) {
      return false;
    }
  }
  return true;
}

function validatePropertyType(
  type: TypeNode,
  loc: SourceLocation,
  ctx: ValidationContext,
): void {
  switch (type.kind) {
    case 'primitive_type':
      if (!VALID_PRIMITIVE_TYPES.has(type.name)) {
        if (type.name === 'void') {
          ctx.errors.push(makeDiagnostic(
            `Property type 'void' is not valid`,
            'error',
            loc,
          ));
        }
      }
      break;

    case 'fixed_array_type':
      if (type.length <= 0) {
        ctx.errors.push(makeDiagnostic(
          `FixedArray length must be a positive integer`,
          'error',
          loc,
        ));
      }
      validatePropertyType(type.element, loc, ctx);
      break;

    case 'custom_type':
      ctx.errors.push(makeDiagnostic(
        `Unsupported type '${type.name}' in property declaration. Use one of: ${[...VALID_PRIMITIVE_TYPES].join(', ')}, or FixedArray<T, N>`,
        'error',
        loc,
      ));
      break;
  }
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

function validateConstructor(ctx: ValidationContext): void {
  const ctor = ctx.contract.constructor;
  const propNames = new Set(ctx.contract.properties.map(p => p.name));

  // Check that constructor has a super() call as first statement
  if (ctor.body.length === 0) {
    ctx.errors.push(makeDiagnostic(
      'Constructor must call super() as its first statement',
      'error',
      ctor.sourceLocation,
    ));
    return;
  }

  const firstStmt = ctor.body[0]!;
  if (!isSuperCall(firstStmt)) {
    ctx.errors.push(makeDiagnostic(
      'Constructor must call super() as its first statement',
      'error',
      ctor.sourceLocation,
    ));
  }

  // Check that all properties without initializers are assigned in constructor
  const assignedProps = new Set<string>();
  for (const stmt of ctor.body) {
    if (stmt.kind === 'assignment') {
      const target = stmt.target;
      if (target.kind === 'property_access') {
        assignedProps.add(target.property);
      }
    }
  }

  // Properties with initializers don't need constructor assignments
  const propsWithInitializers = new Set(
    ctx.contract.properties.filter(p => p.initializer).map(p => p.name),
  );

  for (const propName of propNames) {
    if (!assignedProps.has(propName) && !propsWithInitializers.has(propName)) {
      ctx.errors.push(makeDiagnostic(
        `Property '${propName}' must be assigned in the constructor`,
        'error',
        ctor.sourceLocation,
      ));
    }
  }

  // Validate constructor params have type annotations
  for (const param of ctor.params) {
    if (param.type.kind === 'custom_type' && param.type.name === 'unknown') {
      ctx.errors.push(makeDiagnostic(
        `Constructor parameter '${param.name}' must have a type annotation`,
        'error',
        ctor.sourceLocation,
      ));
    }
    if (param.type.kind === 'fixed_array_type') {
      ctx.errors.push(makeDiagnostic(
        `Constructor parameter '${param.name}' cannot be a FixedArray. Use initialized properties or pass each element as a separate parameter.`,
        'error',
        ctor.sourceLocation,
      ));
    }
  }

  // Validate statements in constructor body
  for (const stmt of ctor.body) {
    validateStatement(stmt, ctx);
  }

  validateConstructorSlotBijection(ctx);
}

// ---------------------------------------------------------------------------
// Constructor parameter <-> deploy-time property bijection (NEW-002)
// ---------------------------------------------------------------------------

/**
 * A property's deploy-time value comes from a constructor ARGUMENT, and the
 * artifact addresses those arguments POSITIONALLY:
 *
 *   - `abi.constructor.params` is built from the constructor SIGNATURE
 *     (`artifact/assembler.ts#extractABI`);
 *   - a constructor slot's `paramIndex` is an index into
 *     `properties.filter(p => p.initialValue === undefined)`
 *     (`05-stack-lower.ts#lowerLoadProp`);
 *   - the SDK splices `constructorArgs[slot.paramIndex]` into the slot's bytes.
 *
 * Two independently-built lists, assumed to line up. Nothing checked that they
 * do, so any program where they disagree deployed an argument into ANOTHER
 * property's slot — silently, with no diagnostic. That is a fund-safety defect:
 * the deployed contract authorises a value the developer never passed for that
 * property.
 *
 * INVARIANT ENFORCED HERE. Every constructor parameter initialises exactly one
 * property that needs a deploy-time value, and the i-th parameter initialises
 * the i-th such property. A program that cannot satisfy it has no
 * representation in the positional artifact model and is rejected rather than
 * mis-wired.
 *
 * "Needs a deploy-time value" mirrors `04-anf-lower.ts#lowerProperties` exactly:
 * a property carries a compile-time `initialValue` iff it has an initializer
 * the constructor does NOT override by assigning it a bare parameter. So a
 * property is deploy-time iff it has no initializer, or it has one that a
 * constructor parameter overrides (NEW-001).
 *
 * Only a BARE parameter reference counts as initialising a property, for the
 * same reason as in ANF lowering: the constructor body is never lowered to
 * script, so a computed form (`this.p = seed + 1n`) has no deploy-time value
 * any tier could honour. A property with any non-parameter assignment is
 * therefore treated as uninitialised, which is what makes `this.count = 0n`
 * inside the constructor an error pointing at the property-initializer form.
 */
function validateConstructorSlotBijection(ctx: ValidationContext): void {
  const ctor = ctx.contract.constructor;
  const paramIndex = new Map<string, number>();
  ctor.params.forEach((p, i) => paramIndex.set(p.name, i));

  // property -> the distinct bare parameters assigned to it; a property with
  // any non-parameter assignment is recorded with an EMPTY set, matching
  // `constructorAssignedProperties` in 04-anf-lower.ts.
  const propToParams = new Map<string, Set<string>>();
  const paramToProps = new Map<string, Set<string>>();
  for (const stmt of ctor.body) {
    if (stmt.kind !== 'assignment') continue;
    if (stmt.target.kind !== 'property_access') continue;
    const prop = stmt.target.property;
    if (stmt.value.kind !== 'identifier' || !paramIndex.has(stmt.value.name)) {
      propToParams.set(prop, new Set());
      continue;
    }
    const param = stmt.value.name;
    if (!propToParams.has(prop)) propToParams.set(prop, new Set());
    propToParams.get(prop)!.add(param);
    if (!paramToProps.has(param)) paramToProps.set(param, new Set());
    paramToProps.get(param)!.add(prop);
  }

  const loc = ctor.sourceLocation;
  const before = ctx.errors.length;

  // (a) One parameter feeding several properties. Only one of them could own
  //     the argument, so the rest would silently keep a default or deploy
  //     undefined. Reported per parameter so the message names both properties.
  for (const [param, props] of paramToProps) {
    if (props.size > 1) {
      ctx.errors.push(makeDiagnostic(
        `Constructor parameter '${param}' initialises more than one property ` +
          `(${[...props].join(', ')}). Each constructor parameter is spliced into ` +
          `exactly one property's deploy-time slot, so only the first would receive ` +
          `the argument. Declare one parameter per property.`,
        'error',
        loc,
      ));
    }
  }

  // (b) One property fed by several parameters — no single argument owns it.
  for (const [prop, params] of propToParams) {
    if (params.size > 1) {
      ctx.errors.push(makeDiagnostic(
        `Property '${prop}' is assigned more than one constructor parameter ` +
          `(${[...params].join(', ')}). Each property that needs a deploy-time value ` +
          `corresponds to exactly one constructor parameter.`,
        'error',
        loc,
      ));
    }
  }

  // (c) A property that needs a deploy-time value but whose constructor
  //     assignment is not a parameter (`this.count = 0n`). A property assigned
  //     NOTHING is already reported above ("must be assigned in the
  //     constructor"), so it is skipped here rather than double-reported.
  for (const prop of ctx.contract.properties) {
    if (prop.initializer !== undefined) continue;
    const assigned = propToParams.get(prop.name);
    if (assigned === undefined) continue; // reported by the assignment check
    if (assigned.size >= 1) continue; // 1 = fine, >1 reported by (b)
    ctx.errors.push(makeDiagnostic(
      `Property '${prop.name}' has no initializer and is not assigned a constructor ` +
        `parameter, so it has no deploy-time value. The constructor body is not ` +
        `compiled into the locking script — give the property a literal initializer ` +
        `(e.g. '${prop.name}: bigint = 0n') or assign it a constructor parameter ` +
        `(e.g. 'this.${prop.name} = ${prop.name}').`,
      'error',
      prop.sourceLocation ?? loc,
    ));
  }

  // (d) A parameter that initialises nothing. Its argument would be dropped and
  //     — because slots are positional — every later argument would land in the
  //     wrong property's slot.
  for (const param of ctor.params) {
    if (paramToProps.has(param.name)) continue;
    ctx.errors.push(makeDiagnostic(
      `Constructor parameter '${param.name}' does not initialise any property. ` +
        `Constructor arguments are spliced into property slots positionally, so an ` +
        `unused parameter drops its own argument and shifts every later one into ` +
        `the wrong property's slot. Assign it ('this.${param.name} = ${param.name}') ` +
        `or remove the parameter.`,
      'error',
      loc,
    ));
  }

  // (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions being
  //     compared are themselves the thing that is broken.
  if (ctx.errors.length !== before) return;

  const deployProps = ctx.contract.properties.filter(
    p => p.initializer === undefined || (propToParams.get(p.name)?.size ?? 0) === 1,
  );
  for (let i = 0; i < deployProps.length; i++) {
    const prop = deployProps[i]!;
    const param = [...(propToParams.get(prop.name) ?? [])][0];
    if (param === undefined) continue; // unreachable once (c) holds
    const declared = paramIndex.get(param)!;
    if (declared === i) continue;
    ctx.errors.push(makeDiagnostic(
      `Property '${prop.name}' occupies deploy-time slot ${i}, but the constructor ` +
        `parameter that initialises it ('${param}') is declared at position ${declared}. ` +
        `Constructor arguments are spliced positionally, so the deployed script would ` +
        `carry argument ${i} — advertised by the ABI as parameter ` +
        `'${ctor.params[i]?.name ?? '?'}' — in this property's slot. Declare the ` +
        `parameters in the same order as the properties they initialise.`,
      'error',
      loc,
    ));
  }
}

function isSuperCall(stmt: Statement): boolean {
  if (stmt.kind !== 'expression_statement') return false;
  const expr = stmt.expression;
  if (expr.kind !== 'call_expr') return false;
  if (expr.callee.kind !== 'identifier') return false;
  return expr.callee.name === 'super';
}

// ---------------------------------------------------------------------------
// Method validation
// ---------------------------------------------------------------------------

function validateMethods(ctx: ValidationContext): void {
  // A contract with no public methods has no spending entry points and
  // compiles to an empty script — never what the author meant (usually a
  // missing `public` modifier; methods default to private).
  if (!ctx.contract.methods.some((m) => m.visibility === 'public')) {
    ctx.errors.push(makeDiagnostic(
      `Contract '${ctx.contract.name}' has no public methods — no spending entry points; add 'public' to at least one method`,
      'error',
    ));
  }

  for (const method of ctx.contract.methods) {
    validateMethod(method, ctx);
  }
}

function validateMethod(method: MethodNode, ctx: ValidationContext): void {
  // All params must have type annotations
  for (const param of method.params) {
    if (param.type.kind === 'custom_type' && param.type.name === 'unknown') {
      ctx.errors.push(makeDiagnostic(
        `Parameter '${param.name}' in method '${method.name}' must have a type annotation`,
        'error',
        method.sourceLocation,
      ));
    }

    // No 'number' type
    if (param.type.kind === 'primitive_type') {
      checkNoNumberType(param.type.name, method.sourceLocation, ctx);
    }

    // FixedArray not allowed as method parameter
    if (param.type.kind === 'fixed_array_type') {
      ctx.errors.push(makeDiagnostic(
        `Parameter '${param.name}' in method '${method.name}' cannot be a FixedArray. Arrays are only allowed as contract properties.`,
        'error',
        method.sourceLocation,
      ));
    }
  }

  // Public methods must end with an assert() call (unless StatefulSmartContract,
  // where the compiler auto-injects the final assert; or UnsafeSmartContract,
  // where a terminal asm({...}) provides the truthy stack value).
  if (method.visibility === 'public' && ctx.contract.parentClass === 'SmartContract') {
    if (!endsWithAssert(method.body)) {
      ctx.errors.push(makeDiagnostic(
        `Public method '${method.name}' must end with an assert() call`,
        'error',
        method.sourceLocation,
      ));
    }
  }

  // UnsafeSmartContract public methods must end with either an assert()
  // call or a terminal asm({..., out_arity: 1}) — either way the script
  // has to leave a truthy value on the stack.
  if (method.visibility === 'public' && ctx.contract.parentClass === 'UnsafeSmartContract') {
    if (!endsWithAssert(method.body) && !endsWithTerminalAsm(method.body)) {
      ctx.errors.push(makeDiagnostic(
        `Public method '${method.name}' must end with an assert() call or a terminal asm({...}) with out_arity 1`,
        'error',
        method.sourceLocation,
      ));
    }
  }

  // `return` is a PRIVATE-helper construct only (NEW-012).
  if (method.visibility === 'public') {
    rejectReturnInPublicMethod(method, ctx);
  }

  // Warn on manual preimage boilerplate in StatefulSmartContract
  if (ctx.contract.parentClass === 'StatefulSmartContract' && method.visibility === 'public') {
    warnManualPreimageUsage(method, ctx);
  }

  // #131: warn when a public method gates on extractLocktime but never asserts
  // the spending tx is non-final (extractSequence < 0xffffffff). Advisory only.
  if (method.visibility === 'public') {
    warnLocktimeWithoutSequenceGuard(method, ctx);
  }

  // Gate `asm({...})` calls on UnsafeSmartContract and check the
  // structural args. Walking the body once here keeps the diagnostic
  // close to the call site.
  validateAsmUsage(method, ctx);

  // `readonly` properties may only be assigned in the constructor.
  checkReadonlyWrites(method, ctx);

  // Validate all statements in method body
  for (const stmt of method.body) {
    validateStatement(stmt, ctx);
  }
}

/**
 * `spec/grammar.md:161` — "Public methods MUST return `void`."
 * `spec/grammar.md:168` — "Private methods may return a value."
 *
 * And `spec/semantics.md` gives `return` no early-exit meaning at all: §4.6
 * defines it ONLY as "the value of this method is v" (the private-helper
 * inlining semantics), while §4.7 sequences statements UNCONDITIONALLY —
 * there is no rule under which the statements after a `return` are skipped.
 *
 * The compiler used to accept both spellings in a public method and lower them
 * as if they were the tail of an inlined helper, which produced two different
 * broken scripts (NEW-012):
 *
 *   - `return;`      the enclosing branch had no result to contribute, so its
 *                    arm yielded OP_0 and the whole script evaluated FALSE.
 *                    `Spend`: "The top stack element must be truthy after
 *                    script evaluation." An unspendable UTXO from source that
 *                    compiled clean.
 *   - `return expr;` the returned value became the branch result and hence the
 *                    script's final truthiness, so any truthy `expr` spent the
 *                    contract WITHOUT reaching the guarding assert. Fail-OPEN,
 *                    and invisible to every differential oracle because the
 *                    interpreter, the ScriptVM and `Spend` all agreed.
 *
 * Rejecting here is the same rule the Java tier has always enforced for the
 * valued form ("public method '<name>' must not return a value"); this brings
 * the remaining tiers in line and covers the bare form too.
 */
function rejectReturnInPublicMethod(method: MethodNode, ctx: ValidationContext): void {
  for (const stmt of findReturnStatements(method.body)) {
    ctx.errors.push(makeDiagnostic(
      `Public method '${method.name}' must not use \`return\`: public methods are ` +
      `spending entry points, they return void (spec/grammar.md:161) and must end ` +
      `with an assert() that encodes the spending condition (spec/grammar.md:162). ` +
      `Rúnar has no early exit — restructure the guard as an if/else, or move the ` +
      `logic into a private helper, where \`return\` is allowed.`,
      'error',
      stmt.sourceLocation ?? method.sourceLocation,
    ));
  }
}

/** Every `return` in `body`, at any nesting depth (if/else arms, loop bodies). */
function findReturnStatements(body: Statement[]): Extract<Statement, { kind: 'return_statement' }>[] {
  const found: Extract<Statement, { kind: 'return_statement' }>[] = [];
  const walk = (stmts: Statement[]): void => {
    for (const stmt of stmts) {
      switch (stmt.kind) {
        case 'return_statement':
          found.push(stmt);
          break;
        case 'if_statement':
          walk(stmt.then);
          if (stmt.else) walk(stmt.else);
          break;
        case 'for_statement':
          walk(stmt.body);
          break;
        default:
          break;
      }
    }
  };
  walk(body);
  return found;
}

function endsWithAssert(body: Statement[]): boolean {
  if (body.length === 0) return false;

  const last = body[body.length - 1]!;

  // Direct assert() call as expression statement
  if (last.kind === 'expression_statement') {
    return isAssertCall(last.expression);
  }

  // If/else where both branches end with assert
  if (last.kind === 'if_statement') {
    const thenEnds = endsWithAssert(last.then);
    const elseEnds = last.else ? endsWithAssert(last.else) : false;
    return thenEnds && elseEnds;
  }

  return false;
}

function isAssertCall(expr: Expression): boolean {
  if (expr.kind !== 'call_expr') return false;
  if (expr.callee.kind === 'identifier' && expr.callee.name === 'assert') {
    return true;
  }
  return false;
}

function isAsmCall(expr: Expression): boolean {
  return (
    expr.kind === 'call_expr' &&
    expr.callee.kind === 'identifier' &&
    expr.callee.name === 'asm'
  );
}

/**
 * UnsafeSmartContract terminator check — the last statement is an
 * `asm({...})` call with the parser-normalised positional args
 * `(body, in_arity, out_arity)` and out_arity literal === 1n.
 *
 * If/else branches that both terminate in an asm({...}) with out_arity 1
 * also count, mirroring the asserts-on-both-branches rule.
 */
function endsWithTerminalAsm(body: Statement[]): boolean {
  if (body.length === 0) return false;
  const last = body[body.length - 1]!;
  if (last.kind === 'expression_statement' && isAsmCall(last.expression)) {
    const call = last.expression as Extract<Expression, { kind: 'call_expr' }>;
    // The parser always rewrites asm({...}) into positional (body, in_arity, out_arity).
    if (call.args.length === 3) {
      const outArity = call.args[2];
      if (outArity && outArity.kind === 'bigint_literal' && outArity.value === 1n) {
        return true;
      }
    }
    return false;
  }
  if (last.kind === 'if_statement') {
    const thenEnds = endsWithTerminalAsm(last.then) || endsWithAssert(last.then);
    const elseEnds = last.else
      ? endsWithTerminalAsm(last.else) || endsWithAssert(last.else)
      : false;
    return thenEnds && elseEnds;
  }
  return false;
}

/**
 * Walk a method body and validate every `asm({...})` call:
 *
 *  - Reject any asm() outside an UnsafeSmartContract.
 *  - Confirm the parser-normalised arg shape: (body, in_arity, out_arity)
 *    where body is a bytestring literal with even-length hex and the
 *    arities are non-negative bigint literals.
 *
 * The parser already pushes most of these diagnostics; this pass is
 * the back-stop that runs even when the parser shape is technically
 * well-formed (e.g. a hand-built AST loaded from JSON) and is the only
 * layer that knows about the contract's parentClass.
 */
function validateAsmUsage(method: MethodNode, ctx: ValidationContext): void {
  walkExpressionsInBody(method.body, (expr) => {
    if (!isAsmCall(expr)) return;
    if (expr.kind !== 'call_expr') return;
    const loc = expr.sourceLocation;

    if (ctx.contract.parentClass !== 'UnsafeSmartContract') {
      ctx.errors.push(makeDiagnostic(
        `'asm' is only available in contracts extending UnsafeSmartContract; got ${ctx.contract.parentClass}. Move the call into a class that extends UnsafeSmartContract (and import { UnsafeSmartContract } from 'runar-lang').`,
        'error',
        loc,
      ));
      return;
    }

    if (expr.args.length !== 3) {
      ctx.errors.push(makeDiagnostic(
        `asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }`,
        'error',
        loc,
      ));
      return;
    }

    const [bodyArg, inArityArg, outArityArg] = expr.args;

    if (!bodyArg || bodyArg.kind !== 'bytestring_literal') {
      ctx.errors.push(makeDiagnostic(
        `asm() body must be a hex string literal`,
        'error',
        loc,
      ));
      return;
    }

    const body = bodyArg.value;
    if (body.length === 0) {
      ctx.errors.push(makeDiagnostic(
        `asm() body must be a non-empty hex string literal`,
        'error',
        loc,
      ));
    } else if (body.length % 2 !== 0) {
      ctx.errors.push(makeDiagnostic(
        `asm() body has odd hex length (${body.length}); each opcode byte requires two hex characters`,
        'error',
        loc,
      ));
    } else if (!/^[0-9a-fA-F]+$/.test(body)) {
      ctx.errors.push(makeDiagnostic(
        `asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed`,
        'error',
        loc,
      ));
    }

    if (!inArityArg || inArityArg.kind !== 'bigint_literal' || inArityArg.value < 0n) {
      ctx.errors.push(makeDiagnostic(
        `asm() in_arity must be a non-negative integer literal`,
        'error',
        loc,
      ));
    }

    if (!outArityArg || outArityArg.kind !== 'bigint_literal' || outArityArg.value < 0n) {
      ctx.errors.push(makeDiagnostic(
        `asm() out_arity must be a non-negative integer literal`,
        'error',
        loc,
      ));
    }

    // Expression-form `asm<T>({...})` returns a value that flows into
    // a let-binding — exactly ONE stack value, so out_arity must be 1.
    // Reject any explicit out_arity != 1 with a clear diagnostic.
    if (
      expr.asmReturnType !== undefined &&
      outArityArg &&
      outArityArg.kind === 'bigint_literal' &&
      outArityArg.value !== 1n
    ) {
      ctx.errors.push(makeDiagnostic(
        `Expression-form asm<${expr.asmReturnType}>() must have out_arity 1 (got ${outArityArg.value}); only a single stack value can be bound to the result variable.`,
        'error',
        loc,
      ));
    }
  });
}

// ---------------------------------------------------------------------------
// Statement validation
// ---------------------------------------------------------------------------

function validateStatement(stmt: Statement, ctx: ValidationContext): void {
  switch (stmt.kind) {
    case 'variable_decl':
      validateVariableDecl(stmt, ctx);
      break;

    case 'assignment':
      validateExpression(stmt.target, ctx);
      validateExpression(stmt.value, ctx);
      break;

    case 'if_statement':
      validateExpression(stmt.condition, ctx);
      for (const s of stmt.then) validateStatement(s, ctx);
      if (stmt.else) {
        for (const s of stmt.else) validateStatement(s, ctx);
      }
      break;

    case 'for_statement':
      validateForStatement(stmt, ctx);
      break;

    case 'expression_statement':
      validateExpression(stmt.expression, ctx);
      break;

    case 'return_statement':
      if (stmt.value) {
        validateExpression(stmt.value, ctx);
      }
      break;
  }
}

function validateVariableDecl(
  stmt: Extract<Statement, { kind: 'variable_decl' }>,
  ctx: ValidationContext,
): void {
  // Check for disallowed 'number' type
  if (stmt.type && stmt.type.kind === 'primitive_type') {
    checkNoNumberType(stmt.type.name, stmt.sourceLocation, ctx);
  }
  if (stmt.type && stmt.type.kind === 'fixed_array_type') {
    ctx.errors.push(makeDiagnostic(
      `Local variable '${stmt.name}' cannot be a FixedArray. Arrays are only allowed as contract properties.`,
      'error',
      stmt.sourceLocation,
    ));
  }
  validateExpression(stmt.init, ctx);
}

function validateForStatement(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: ValidationContext,
): void {
  // Validate that for-loop bounds are compile-time determinable
  // The condition should compare the iter var to a constant
  validateExpression(stmt.condition, ctx);

  // Check that the loop bound is a compile-time constant. Non-zero starts and
  // countdown loops (`i--` with `>`/`>=`) are supported: the ANF loop node
  // carries an explicit start value and step direction (issue #121), so
  // lowering binds `iterVar = start + i*step` on each unrolled iteration.
  if (stmt.condition.kind === 'binary_expr') {
    const bound = stmt.condition.right;
    if (!isCompileTimeConstant(bound)) {
      ctx.errors.push(makeDiagnostic(
        'For loop bound must be a compile-time constant (literal or const variable)',
        'error',
        stmt.sourceLocation,
      ));
    }
  }

  // Validate init
  validateExpression(stmt.init.init, ctx);

  // Validate body
  for (const s of stmt.body) {
    validateStatement(s, ctx);
  }
}

function isCompileTimeConstant(expr: Expression): boolean {
  if (expr.kind === 'bigint_literal') return true;
  if (expr.kind === 'bool_literal') return true;
  if (expr.kind === 'identifier') return true; // Could be a const; we trust the parser
  if (expr.kind === 'unary_expr' && expr.op === '-') {
    return isCompileTimeConstant(expr.operand);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Readonly property writes
// ---------------------------------------------------------------------------

/**
 * `spec/semantics.md`:
 *   `<this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property`
 * `spec/grammar.md`: readonly properties "cannot be reassigned".
 *
 * The constructor is exempt — that is where every contract initialises its
 * readonly properties — so this check runs per METHOD only (the constructor
 * is validated by `validateConstructor`, which never calls in here).
 *
 * Three AST shapes reach `update_prop` in ANF lowering and are all covered:
 *   `this.p = e`          — assignment with a `property_access` target
 *   `this.p++` / `this.p--` — increment/decrement over a `property_access`
 *   `this.arr[i] = e`     — assignment through an `index_access` rooted at a
 *                           `property_access`
 */
function checkReadonlyWrites(method: MethodNode, ctx: ValidationContext): void {
  const readonlyProps = new Set(
    ctx.contract.properties.filter(p => p.readonly).map(p => p.name),
  );
  if (readonlyProps.size === 0) return;

  const report = (name: string, loc: SourceLocation | undefined): void => {
    ctx.errors.push(makeDiagnostic(
      `Cannot assign to readonly property '${name}' in method '${method.name}'. ` +
      `readonly properties may only be assigned in the constructor.`,
      'error',
      loc,
    ));
  };

  /**
   * Resolve the contract property an assignment target writes to, if any.
   * Unwraps `index_access` chains so `this.grid[i][j] = v` resolves to `grid`.
   */
  const writtenProperty = (target: Expression): string | undefined => {
    let node: Expression = target;
    while (node.kind === 'index_access') node = node.object;
    return node.kind === 'property_access' ? node.property : undefined;
  };

  const visitExpr = (expr: Expression, loc: SourceLocation | undefined): void => {
    walkExpr(expr, (e) => {
      if (e.kind !== 'increment_expr' && e.kind !== 'decrement_expr') return;
      const name = writtenProperty(e.operand);
      if (name !== undefined && readonlyProps.has(name)) {
        report(name, e.sourceLocation ?? loc);
      }
    });
  };

  const visitStatements = (stmts: Statement[]): void => {
    for (const stmt of stmts) {
      switch (stmt.kind) {
        case 'assignment': {
          const name = writtenProperty(stmt.target);
          if (name !== undefined && readonlyProps.has(name)) {
            report(name, stmt.sourceLocation);
          }
          visitExpr(stmt.target, stmt.sourceLocation);
          visitExpr(stmt.value, stmt.sourceLocation);
          break;
        }

        case 'variable_decl':
          visitExpr(stmt.init, stmt.sourceLocation);
          break;

        case 'expression_statement':
          visitExpr(stmt.expression, stmt.sourceLocation);
          break;

        case 'return_statement':
          if (stmt.value) visitExpr(stmt.value, stmt.sourceLocation);
          break;

        case 'if_statement':
          visitExpr(stmt.condition, stmt.sourceLocation);
          visitStatements(stmt.then);
          if (stmt.else) visitStatements(stmt.else);
          break;

        case 'for_statement':
          visitStatements([stmt.init, stmt.update]);
          visitExpr(stmt.condition, stmt.sourceLocation);
          visitStatements(stmt.body);
          break;
      }
    }
  };

  visitStatements(method.body);
}

// ---------------------------------------------------------------------------
// Expression validation
// ---------------------------------------------------------------------------

function validateExpression(expr: Expression, ctx: ValidationContext): void {
  switch (expr.kind) {
    case 'binary_expr':
      validateExpression(expr.left, ctx);
      validateExpression(expr.right, ctx);
      break;

    case 'unary_expr':
      validateExpression(expr.operand, ctx);
      break;

    case 'call_expr': {
      validateExpression(expr.callee, ctx);
      // assert() message (2nd arg) is a human-readable string, not hex — skip validation
      const isAssert = expr.callee.kind === 'identifier' && expr.callee.name === 'assert';
      for (let i = 0; i < expr.args.length; i++) {
        if (isAssert && i >= 1) continue;
        validateExpression(expr.args[i]!, ctx);
      }
      break;
    }

    case 'member_expr':
      validateExpression(expr.object, ctx);
      break;

    case 'ternary_expr':
      validateExpression(expr.condition, ctx);
      validateExpression(expr.consequent, ctx);
      validateExpression(expr.alternate, ctx);
      break;

    case 'index_access':
      validateExpression(expr.object, ctx);
      validateExpression(expr.index, ctx);
      break;

    case 'increment_expr':
    case 'decrement_expr':
      validateExpression(expr.operand, ctx);
      break;

    // Leaf nodes -- nothing to validate
    case 'identifier':
    case 'bigint_literal':
    case 'bool_literal':
    case 'property_access':
      break;

    case 'bytestring_literal': {
      const val = expr.value;
      if (val.length > 0) {
        if (val.length % 2 !== 0) {
          ctx.errors.push(makeDiagnostic(
            `ByteString literal '${val}' has odd length (${val.length}) — hex strings must have an even number of characters`,
            'error',
            expr.sourceLocation,
          ));
        } else if (!/^[0-9a-fA-F]*$/.test(val)) {
          ctx.errors.push(makeDiagnostic(
            `ByteString literal '${val}' contains non-hex characters — only 0-9, a-f, A-F are allowed`,
            'error',
            expr.sourceLocation,
          ));
        }
      }
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Recursion detection
// ---------------------------------------------------------------------------

function checkNoRecursion(ctx: ValidationContext): void {
  // Build call graph: method name -> set of methods it calls
  const callGraph = new Map<string, Set<string>>();
  const methodNames = new Set<string>();

  for (const method of ctx.contract.methods) {
    methodNames.add(method.name);
    const calls = new Set<string>();
    collectMethodCalls(method.body, calls);
    callGraph.set(method.name, calls);
  }

  // Also add constructor
  {
    const calls = new Set<string>();
    collectMethodCalls(ctx.contract.constructor.body, calls);
    callGraph.set('constructor', calls);
  }

  // Check for cycles using DFS
  for (const method of ctx.contract.methods) {
    const visited = new Set<string>();
    const stack = new Set<string>();

    if (hasCycle(method.name, callGraph, methodNames, visited, stack)) {
      ctx.errors.push(makeDiagnostic(
        `Recursion detected: method '${method.name}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.`,
        'error',
        method.sourceLocation,
      ));
    }
  }
}

function collectMethodCalls(
  stmts: Statement[],
  calls: Set<string>,
): void {
  for (const stmt of stmts) {
    collectMethodCallsInStatement(stmt, calls);
  }
}

function collectMethodCallsInStatement(
  stmt: Statement,
  calls: Set<string>,
): void {
  switch (stmt.kind) {
    case 'expression_statement':
      collectMethodCallsInExpr(stmt.expression, calls);
      break;
    case 'variable_decl':
      collectMethodCallsInExpr(stmt.init, calls);
      break;
    case 'assignment':
      collectMethodCallsInExpr(stmt.target, calls);
      collectMethodCallsInExpr(stmt.value, calls);
      break;
    case 'if_statement':
      collectMethodCallsInExpr(stmt.condition, calls);
      collectMethodCalls(stmt.then, calls);
      if (stmt.else) collectMethodCalls(stmt.else, calls);
      break;
    case 'for_statement':
      collectMethodCallsInExpr(stmt.condition, calls);
      collectMethodCalls(stmt.body, calls);
      break;
    case 'return_statement':
      if (stmt.value) collectMethodCallsInExpr(stmt.value, calls);
      break;
  }
}

function collectMethodCallsInExpr(
  expr: Expression,
  calls: Set<string>,
): void {
  switch (expr.kind) {
    case 'call_expr':
      // Check if callee is `this.methodName`
      if (expr.callee.kind === 'property_access') {
        calls.add(expr.callee.property);
      }
      // Also check if callee is `this.method` via member_expr
      if (expr.callee.kind === 'member_expr' &&
          expr.callee.object.kind === 'identifier' &&
          expr.callee.object.name === 'this') {
        calls.add(expr.callee.property);
      }
      collectMethodCallsInExpr(expr.callee, calls);
      for (const arg of expr.args) {
        collectMethodCallsInExpr(arg, calls);
      }
      break;
    case 'binary_expr':
      collectMethodCallsInExpr(expr.left, calls);
      collectMethodCallsInExpr(expr.right, calls);
      break;
    case 'unary_expr':
      collectMethodCallsInExpr(expr.operand, calls);
      break;
    case 'member_expr':
      collectMethodCallsInExpr(expr.object, calls);
      break;
    case 'ternary_expr':
      collectMethodCallsInExpr(expr.condition, calls);
      collectMethodCallsInExpr(expr.consequent, calls);
      collectMethodCallsInExpr(expr.alternate, calls);
      break;
    case 'index_access':
      collectMethodCallsInExpr(expr.object, calls);
      collectMethodCallsInExpr(expr.index, calls);
      break;
    case 'increment_expr':
    case 'decrement_expr':
      collectMethodCallsInExpr(expr.operand, calls);
      break;
    default:
      // Leaf nodes
      break;
  }
}

function hasCycle(
  methodName: string,
  callGraph: Map<string, Set<string>>,
  methodNames: Set<string>,
  visited: Set<string>,
  stack: Set<string>,
): boolean {
  if (stack.has(methodName)) return true;
  if (visited.has(methodName)) return false;

  visited.add(methodName);
  stack.add(methodName);

  const calls = callGraph.get(methodName);
  if (calls) {
    for (const callee of calls) {
      if (methodNames.has(callee)) {
        if (hasCycle(callee, callGraph, methodNames, visited, stack)) {
          return true;
        }
      }
    }
  }

  stack.delete(methodName);
  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function checkNoNumberType(
  _typeName: PrimitiveTypeName,
  _loc: SourceLocation,
  _ctx: ValidationContext,
): void {
  // 'number' would not be a PrimitiveTypeName in Rúnar (it's excluded from
  // the type union), so this is mainly a sanity check. If we ever see it
  // via custom_type, we'd catch it elsewhere.
}

// ---------------------------------------------------------------------------
// StatefulSmartContract: warn on manual preimage boilerplate
// ---------------------------------------------------------------------------

function warnManualPreimageUsage(method: MethodNode, ctx: ValidationContext): void {
  walkExpressionsInBody(method.body, (expr) => {
    // Detect manual checkPreimage(...)
    if (expr.kind === 'call_expr' &&
        expr.callee.kind === 'identifier' &&
        expr.callee.name === 'checkPreimage') {
      ctx.warnings.push(makeDiagnostic(
        `StatefulSmartContract auto-injects checkPreimage(); calling it manually in '${method.name}' will cause a duplicate verification`,
        'warning',
        method.sourceLocation,
      ));
    }
    // Detect manual this.getStateScript()
    if (expr.kind === 'call_expr' &&
        expr.callee.kind === 'property_access' &&
        expr.callee.property === 'getStateScript') {
      ctx.warnings.push(makeDiagnostic(
        `StatefulSmartContract auto-injects state continuation; calling getStateScript() manually in '${method.name}' is redundant`,
        'warning',
        method.sourceLocation,
      ));
    }
  });
}

// ---------------------------------------------------------------------------
// #131: locktime soundness — extractLocktime needs an extractSequence guard
// ---------------------------------------------------------------------------

/** Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value. */
const SEQUENCE_FINAL = 0xffffffffn;

/** True when `expr` is a direct call to the named intrinsic, e.g. `f(...)`. */
function isCallToNamed(expr: Expression, name: string): boolean {
  return (
    expr.kind === 'call_expr' &&
    expr.callee.kind === 'identifier' &&
    expr.callee.name === name
  );
}

/**
 * True when `expr` reads the transaction locktime. Both the raw intrinsic
 * `extractLocktime(preimage)` and its ergonomic sugar `currentBlockHeight()`
 * (which the ANF pass desugars to `extractLocktime(txPreimage)`) count —
 * either read is unsound without a sequence-finality guard.
 */
function isLocktimeRead(expr: Expression): boolean {
  return isCallToNamed(expr, 'extractLocktime') || isCallToNamed(expr, 'currentBlockHeight');
}

/**
 * True when `expr` is an `extractSequence(...) < <final>`-style comparison
 * (the guard that makes a locktime gate consensus-enforced). Accepts the two
 * natural spellings: `extractSequence(pre) < N` / `<= N`, and the reversed
 * `N > extractSequence(pre)` / `>= ...`. `N` must be a bigint literal no
 * greater than the finality sentinel, so the guard genuinely forces
 * non-finality.
 */
function isSequenceFinalityGuard(expr: Expression): boolean {
  if (expr.kind !== 'binary_expr') return false;
  const boundOk = (e: Expression): boolean =>
    e.kind === 'bigint_literal' && e.value <= SEQUENCE_FINAL;
  if ((expr.op === '<' || expr.op === '<=') &&
      isCallToNamed(expr.left, 'extractSequence') && boundOk(expr.right)) {
    return true;
  }
  if ((expr.op === '>' || expr.op === '>=') &&
      isCallToNamed(expr.right, 'extractSequence') && boundOk(expr.left)) {
    return true;
  }
  return false;
}

/**
 * #131: warn when `method` (transitively, through the private-helper call
 * graph) reads the tx locktime but never asserts the tx is non-final. A
 * locktime gate is not consensus-enforced unless `extractSequence < 0xffffffff`
 * is also asserted — otherwise an all-final-sequence spend bypasses it.
 * Advisory (warning) only — no effect on emitted bytecode.
 */
function warnLocktimeWithoutSequenceGuard(method: MethodNode, ctx: ValidationContext): void {
  const privateMethods = new Map(
    ctx.contract.methods
      .filter(m => m.visibility === 'private')
      .map(m => [m.name, m] as const),
  );

  let readsLocktime = false;
  let hasSequenceGuard = false;
  const visited = new Set<string>([method.name]);
  const queue: MethodNode[] = [method];

  while (queue.length > 0) {
    const current = queue.shift()!;
    walkExpressionsInBody(current.body, (expr) => {
      if (isLocktimeRead(expr)) readsLocktime = true;
      if (isSequenceFinalityGuard(expr)) hasSequenceGuard = true;
    });
    // Follow calls into private helpers so a guard (or locktime read) supplied
    // by an inlined helper is seen by the public entry point.
    const calls = new Set<string>();
    collectMethodCalls(current.body, calls);
    for (const callee of calls) {
      if (!visited.has(callee) && privateMethods.has(callee)) {
        visited.add(callee);
        queue.push(privateMethods.get(callee)!);
      }
    }
  }

  if (readsLocktime && !hasSequenceGuard) {
    ctx.warnings.push(makeDiagnostic(
      `method '${method.name}' reads extractLocktime but does not assert ` +
        `extractSequence < 0xffffffff; a locktime gate is not consensus-enforced ` +
        `unless the tx is non-final — add ` +
        `assert(extractSequence(this.txPreimage) < 0xffffffffn)`,
      'warning',
      method.sourceLocation,
    ));
  }
}

function walkExpressionsInBody(
  stmts: Statement[],
  visitor: (expr: Expression) => void,
): void {
  for (const stmt of stmts) {
    walkExpressionsInStatement(stmt, visitor);
  }
}

function walkExpressionsInStatement(
  stmt: Statement,
  visitor: (expr: Expression) => void,
): void {
  switch (stmt.kind) {
    case 'expression_statement':
      walkExpr(stmt.expression, visitor);
      break;
    case 'variable_decl':
      walkExpr(stmt.init, visitor);
      break;
    case 'assignment':
      walkExpr(stmt.target, visitor);
      walkExpr(stmt.value, visitor);
      break;
    case 'if_statement':
      walkExpr(stmt.condition, visitor);
      walkExpressionsInBody(stmt.then, visitor);
      if (stmt.else) walkExpressionsInBody(stmt.else, visitor);
      break;
    case 'for_statement':
      walkExpr(stmt.condition, visitor);
      walkExpressionsInBody(stmt.body, visitor);
      break;
    case 'return_statement':
      if (stmt.value) walkExpr(stmt.value, visitor);
      break;
  }
}

function walkExpr(expr: Expression, visitor: (expr: Expression) => void): void {
  visitor(expr);
  switch (expr.kind) {
    case 'binary_expr':
      walkExpr(expr.left, visitor);
      walkExpr(expr.right, visitor);
      break;
    case 'unary_expr':
      walkExpr(expr.operand, visitor);
      break;
    case 'call_expr':
      walkExpr(expr.callee, visitor);
      for (const arg of expr.args) walkExpr(arg, visitor);
      break;
    case 'member_expr':
      walkExpr(expr.object, visitor);
      break;
    case 'ternary_expr':
      walkExpr(expr.condition, visitor);
      walkExpr(expr.consequent, visitor);
      walkExpr(expr.alternate, visitor);
      break;
    case 'index_access':
      walkExpr(expr.object, visitor);
      walkExpr(expr.index, visitor);
      break;
    case 'increment_expr':
    case 'decrement_expr':
      walkExpr(expr.operand, visitor);
      break;
  }
}
