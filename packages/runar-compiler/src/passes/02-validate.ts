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
  SourceLocation,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { validateSighashUsage } from './sighash-validate.js';
import { isReservedSourceName } from './reserved-names.js';
import { InputLimits } from 'runar-ir-schema';

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
  const callDepthExceeded = checkNoRecursion(ctx);
  checkReservedNames(ctx);
  checkRedeclarations(ctx);
  // N-180: the Rabin-provenance and sighash passes walk the private-method
  // call graph; past MAX_CALL_DEPTH that walk is the very depth the limit
  // refuses, so stop here.
  if (callDepthExceeded) return { errors, warnings };
  checkRabinPubKeyProvenance(ctx);

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

/**
 * N-065 / N-060: refuse a declared identifier spelled like a name a compiler
 * pass mints (see `reserved-names.ts` for the families). Checks properties,
 * method names, constructor and method parameters, locals and loop variables.
 * A stateful `txPreimage` PROPERTY keeps its older, dedicated diagnostic.
 */
function checkReservedNames(ctx: ValidationContext): void {
  const stateful = ctx.contract.parentClass === 'StatefulSmartContract';
  const check = (name: string, loc: SourceLocation): void => {
    if (isReservedSourceName(name, stateful)) {
      // Same sentence as `reservedNameMessage` (the --ir loader's), spelled out
      // here so the diagnostic-coverage extractor can read the template.
      ctx.errors.push(makeDiagnostic(
        `'${name}' is reserved for compiler-generated names and cannot be used as an identifier`,
        'error',
        loc,
      ));
    }
  };
  const walk = (stmts: readonly Statement[]): void => {
    for (const s of stmts) {
      if (s.kind === 'variable_decl') check(s.name, s.sourceLocation);
      else if (s.kind === 'if_statement') {
        walk(s.then);
        if (s.else) walk(s.else);
      } else if (s.kind === 'for_statement') {
        check(s.init.name, s.init.sourceLocation);
        walk(s.body);
      }
    }
  };

  for (const prop of ctx.contract.properties) {
    if (stateful && prop.name === 'txPreimage') continue;
    check(prop.name, prop.sourceLocation);
  }
  for (const method of [ctx.contract.constructor, ...ctx.contract.methods]) {
    if (method.name !== 'constructor') check(method.name, method.sourceLocation);
    for (const p of method.params) check(p.name, method.sourceLocation);
    walk(method.body);
  }
}

/**
 * N-509: a local cannot be re-declared in the same scope (spec/grammar.md,
 * Statement Restrictions). A scope is one statement list -- a method or
 * constructor body, an if branch, an else branch, a loop body -- and a
 * method's parameters belong to its body's top-level list. A declaration in
 * a NESTED list that reuses an outer name (shadowing) is not a re-declaration;
 * the spec is silent on it and every tier lowers it as the renamed program.
 * The loop iterator lives in the loop header, not in the body list.
 */
function checkRedeclarations(ctx: ValidationContext): void {
  const walk = (stmts: readonly Statement[], declared: Set<string>): void => {
    for (const s of stmts) {
      if (s.kind === 'variable_decl') {
        if (declared.has(s.name)) {
          ctx.errors.push(makeDiagnostic(
            `'${s.name}' is already declared in this scope and cannot be re-declared`,
            'error',
            s.sourceLocation,
          ));
        }
        declared.add(s.name);
      } else if (s.kind === 'if_statement') {
        walk(s.then, new Set());
        if (s.else) walk(s.else, new Set());
      } else if (s.kind === 'for_statement') {
        walk(s.body, new Set());
      }
    }
  };
  for (const method of [ctx.contract.constructor, ...ctx.contract.methods]) {
    walk(method.body, new Set(method.params.map((p) => p.name)));
  }
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

      // F-265: the shape checks above only ask "is this a literal node at
      // all?" -- they never validate a ByteStringLiteral's HEX FORMAT. That
      // check lives in `validateExpression`'s `bytestring_literal` arm,
      // which a method body reaches via the statement walk but a property
      // INITIALIZER never did: it is read directly off `prop.initializer`
      // and is not part of that walk. A malformed hex literal here (e.g.
      // `"zzz" as ByteString`, or `toByteString('zzz')`) used to sail
      // through this pass and only surface two passes later as an opaque
      // stack-lowering error with no source location -- `validateExpression`
      // recurses into array elements and `toByteString(...)` args, so this
      // also covers FixedArray initializer elements.
      validateExpression(prop.initializer, ctx);
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
  // `toByteString('<hex>')` IS the ByteStringLiteral production -- see
  // spec/grammar.md section 11:
  //
  //     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
  //
  // 0e192af6 folded it in ANF lowering, which covers every EXPRESSION
  // position. This check runs on the AST, BEFORE ANF lowering, so an
  // initializer still arrives here as a call node and was refused -- in the
  // one position the `.runar.rs` surface needs it, since the Rust DSL writes
  // initializers as assignments inside `init()` that the parser LIFTS into
  // `PropertyNode.initializer`, and a bare `'1976a914'` is a `&str` that
  // cannot be assigned to a `ByteString` (`Vec<u8>`).
  //
  // Accepting it here is only half the job: `extractLiteralValue` in
  // 04-anf-lower.ts must UNWRAP the same shape, or the property validates and
  // then loses its default entirely.
  if (isToByteStringLiteral(expr)) return true;
  return false;
}

/**
 * `toByteString(<literal>)` -- the ByteStringLiteral production.
 *
 * Literal argument ONLY. `toByteString(x)` for a non-literal `x` is not this
 * production; it stays an ordinary identity-cast call and remains a
 * non-literal initializer.
 */
export function isToByteStringLiteral(expr: Expression): boolean {
  return expr.kind === 'call_expr'
    && expr.callee.kind === 'identifier'
    && expr.callee.name === 'toByteString'
    && expr.args.length === 1
    && expr.args[0]!.kind === 'bytestring_literal';
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
        } else {
          // R-246: any other unrecognised primitive name used to fall through
          // in silence, while the identical name arriving as a `custom_type` is
          // refused below. No parser produces a `primitive_type` with an unknown
          // name today — they all map an unrecognised name to `custom_type` —
          // but `validate` takes an AST, and the frontend is not the only thing
          // that builds one.
          ctx.errors.push(makeDiagnostic(
            `Unsupported type '${type.name}' in property declaration. Use one of: ${[...VALID_PRIMITIVE_TYPES].join(', ')}, or FixedArray<T, N>`,
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
    // N-325: a named type that is not a Rúnar type is refused, not carried
    // through as an opaque name nothing downstream compares. `unknown` is the
    // missing-annotation case above; `StatefulContext` is the explicit context
    // parameter of the Zig/Go/Move stateful surfaces, dropped by ANF lowering.
    if (param.type.kind === 'custom_type' && param.type.name !== 'unknown' && param.type.name !== 'StatefulContext') {
      ctx.errors.push(makeDiagnostic(
        `Type '${param.type.name}' of parameter '${param.name}' in constructor is not a Rúnar type`,
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
    // N-325: see the constructor check above.
    if (param.type.kind === 'custom_type' && param.type.name !== 'unknown' && param.type.name !== 'StatefulContext') {
      ctx.errors.push(makeDiagnostic(
        `Type '${param.type.name}' of parameter '${param.name}' in method '${method.name}' is not a Rúnar type`,
        'error',
        method.sourceLocation,
      ));
    }

    // No 'number' type
    if (param.type.kind === 'primitive_type') {
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
  // the spending tx is non-final (extractSequence !== 0xffffffff). Advisory only.
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
      validateIndexAssignmentTarget(stmt, ctx);
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

/**
 * N-002 (F-013's rule, shared verbatim by all seven tiers): only a FixedArray
 * property is index-writable. Any other index target (a ByteString property,
 * a local, a parameter, a member-chained root) is left alone by
 * 03b-expand-fixed-arrays and ANF lowering lowers it as a READ, dropping the
 * write -- a deployable script whose state never changes. Reject it here with
 * a location instead.
 */
function validateIndexAssignmentTarget(
  stmt: Extract<Statement, { kind: 'assignment' }>,
  ctx: ValidationContext,
): void {
  if (stmt.target.kind !== 'index_access') return;
  let root: Expression = stmt.target;
  while (root.kind === 'index_access') root = root.object;
  const rootProp = root.kind === 'property_access' ? root.property : undefined;
  const isFixedArrayProp = ctx.contract.properties.some(
    (p) => p.name === rootProp && p.type.kind === 'fixed_array_type',
  );
  if (!isFixedArrayProp) {
    ctx.errors.push(makeDiagnostic(
      'index assignment is only supported on FixedArray contract properties; ' +
        'the target here is not a FixedArray property',
      'error',
      stmt.sourceLocation,
    ));
  }
}

function validateVariableDecl(
  stmt: Extract<Statement, { kind: 'variable_decl' }>,
  ctx: ValidationContext,
): void {
  // Check for disallowed 'number' type
  if (stmt.type && stmt.type.kind === 'primitive_type') {
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

  validateForConditionTestsIterator(stmt, ctx);

  // Validate init
  validateExpression(stmt.init.init, ctx);

  validateForUpdate(stmt, ctx);

  validateNoOutputIntrinsicInLoop(stmt, ctx);

  // Validate body
  for (const s of stmt.body) {
    validateStatement(s, ctx);
  }
}

/**
 * Reject any for-loop whose condition does not test the iterator itself.
 *
 * The comment above used to say "the condition should compare the iter var to
 * a constant" and then the code read only `stmt.condition.right`. Nothing
 * required `condition.left` to BE the iterator, and `extractLoopShape` ignores
 * left entirely: it computes `count = bound - start` from the right-hand side
 * and the init value. So the source
 *
 *   for (let i = 0n; i + 1n < 2n; i++) { ... }
 *
 * runs ONCE in TypeScript (i=0: 0+1 < 2; i=1: 1+1 < 2 is false) and TWICE in
 * the emitted script (count = 2 - 0). The extra lap executes the `else` arm
 * the source can never reach. Measured on `@bsv/sdk` `Spend.validate()` with a
 * vault whose signature check sits in the first lap and whose second lap sets
 * `authorized = true`: the phantom-lap loop ACCEPTED an empty signature, while
 * the semantically identical `i < 1n` rejected it.
 *
 * Refusal rather than lowering: evaluating a general condition per iteration
 * means unrolling against a real interpreter at ANF time, which is a language
 * extension with no golden behind it. The loop model the ANF node can carry is
 * exactly `start + k*step` tested against a constant bound, so the condition
 * must name the iterator on the left. Same shape as R-065's for-update
 * rejection, and the diagnostic text is shared verbatim with the other six
 * tiers.
 *
 * The direction rule (`<`/`<=` counts up, `>`/`>=` counts down) is NOT
 * duplicated here: `extractLoopShape` already refuses a mismatch in every
 * tier, and `conformance/negatives/N42-loop-direction-mismatch.runar.ts`
 * gates that across all seven.
 */
function validateForConditionTestsIterator(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: ValidationContext,
): void {
  const iter = stmt.init.name;
  const cond = stmt.condition;
  if (
    cond.kind === 'binary_expr' &&
    cond.left.kind === 'identifier' &&
    cond.left.name === iter
  ) {
    return;
  }

  ctx.errors.push(makeDiagnostic(
    `For loop condition must compare the loop variable '${iter}' to a compile-time ` +
    `constant (\`${iter} < 10n\`). The unrolled loop binds the iterator as ` +
    '`start + k*step` and takes its trip count from the bound alone, so a condition ' +
    'whose left-hand side is anything else -- a computed expression, or a different ' +
    'variable -- is not the condition the loop actually evaluates',
    'error',
    stmt.sourceLocation,
  ));
}

/**
 * Reject any output intrinsic called inside a loop body (R-127).
 *
 * `lowerForStatement` lowers the body into `ctx.subContext()`, which starts
 * with a fresh empty `_addOutputRefs`, and nothing propagates that list back to
 * the method context -- unlike `lowerIfStatement`, which concatenates each
 * arm's outputs into a single ref precisely so the parent sees them. The
 * continuation hash is then built from whatever `addOutput` calls sit at the
 * method's TOP level, while the loop's outputs are still emitted into the
 * transaction. Measured on a two-iteration loop before this check existed:
 *
 *   loop only                 ts/go/rust/python blew up inside stack lowering
 *                             ("method parameter '_newAmount' is not on the
 *                             stack at a post-consumption reference"),
 *                             zig/ruby emitted a covenant over the WRONG
 *                             output set, java emitted none.
 *   loop + one top-level call compiled clean everywhere, and the ANF
 *                             continuation hashed exactly ONE leaf while three
 *                             outputs were built.
 *
 * A continuation committing to fewer outputs than the transaction creates is
 * spendable only by a hand-crafted transaction, is rejected by every shipped
 * SDK, and the successor it produces is permanently unspendable (CL-BUG-164).
 *
 * Refusal rather than lowering: propagating the refs cannot work by name,
 * because the loop is unrolled at stack-lowering time and one body binding name
 * denotes N physical slots -- `findDepth` would resolve it to the last
 * iteration alone. A correct lowering means unrolling at ANF time, a language
 * feature with no golden behind it; refusing removes nothing that works today
 * (no fixture or example in the repo declares an output inside a loop). Same
 * shape as R-065's for-update rejection, and the diagnostic text is shared
 * verbatim with the other six tiers.
 */
const OUTPUT_INTRINSIC_NAMES = new Set<string>([
  'addOutput', 'addRawOutput', 'addDataOutput',
]);

function outputIntrinsicCallName(expr: Expression): string | undefined {
  if (expr.kind !== 'call_expr') return undefined;
  const callee = expr.callee;
  // `this.addOutput(...)` parses as property_access in some frontends and as
  // member_expr in others; the Go/Move surfaces additionally spell it on a
  // StatefulContext parameter (`ctx.addOutput(...)`). Matching the property
  // name alone covers all three, and no non-intrinsic carries these names.
  const property =
    callee.kind === 'property_access' ? callee.property
      : callee.kind === 'member_expr' ? callee.property
        : undefined;
  if (property !== undefined && OUTPUT_INTRINSIC_NAMES.has(property)) return property;
  return undefined;
}

/** The private method a call names, or undefined. */
function privateMethodCallName(expr: Expression, ctx: ValidationContext): string | undefined {
  if (expr.kind !== 'call_expr') return undefined;
  const callee = expr.callee;
  const property =
    callee.kind === 'property_access' ? callee.property
      : callee.kind === 'member_expr' ? callee.property
        : callee.kind === 'identifier' ? callee.name
          : undefined;
  if (property === undefined) return undefined;
  const m = ctx.contract.methods.find(
    (x) => x.name === property && x.visibility === 'private',
  );
  return m ? property : undefined;
}

interface OutputIntrinsicSite {
  /** The intrinsic's name, e.g. `addOutput`. */
  intrinsic: string;
  /** The private method it was reached through, if any. */
  via?: string;
  location: SourceLocation | undefined;
}

/**
 * First output intrinsic reachable from `stmts`, following calls to private
 * methods (a public method that delegates `addOutput` to a private helper has
 * that helper INLINED at ANF time, so a helper called in a loop lands its
 * outputs in the loop's sub-context exactly like a direct call would).
 */
function findOutputIntrinsic(
  stmts: readonly Statement[],
  ctx: ValidationContext,
  seen: Set<string>,
): OutputIntrinsicSite | undefined {
  for (const stmt of stmts) {
    const found = findOutputIntrinsicInStatement(stmt, ctx, seen);
    if (found) return found;
  }
  return undefined;
}

/**
 * First output intrinsic reachable from `expr`, following calls to private
 * methods; the site is reported at `location`.
 */
function findOutputIntrinsicInExpr(
  expr: Expression,
  ctx: ValidationContext,
  seen: Set<string>,
  location: SourceLocation | undefined,
): OutputIntrinsicSite | undefined {
  const intrinsic = outputIntrinsicCallName(expr);
  if (intrinsic !== undefined) {
    return { intrinsic, location };
  }
  const helper = privateMethodCallName(expr, ctx);
  if (helper !== undefined && !seen.has(helper)) {
    seen.add(helper);
    const body = ctx.contract.methods.find((m) => m.name === helper)?.body ?? [];
    const nested = findOutputIntrinsic(body, ctx, seen);
    if (nested) {
      return { intrinsic: nested.intrinsic, via: helper, location };
    }
  }
  // Recurse into sub-expressions: an intrinsic can sit inside an argument
  // list or an operand, not only as a bare expression statement.
  for (const child of subExpressions(expr)) {
    const found = findOutputIntrinsicInExpr(child, ctx, seen, location);
    if (found) return found;
  }
  return undefined;
}

function findOutputIntrinsicInStatement(
  stmt: Statement,
  ctx: ValidationContext,
  seen: Set<string>,
): OutputIntrinsicSite | undefined {
  const fromExpr = (expr: Expression): OutputIntrinsicSite | undefined =>
    findOutputIntrinsicInExpr(expr, ctx, seen, stmt.sourceLocation);

  switch (stmt.kind) {
    case 'expression_statement':
      return fromExpr(stmt.expression);
    case 'variable_decl':
      return fromExpr(stmt.init);
    case 'assignment':
      return fromExpr(stmt.value);
    case 'return_statement':
      return stmt.value ? fromExpr(stmt.value) : undefined;
    case 'if_statement': {
      const inCond = fromExpr(stmt.condition);
      if (inCond) return inCond;
      return findOutputIntrinsic([...stmt.then, ...(stmt.else ?? [])], ctx, seen);
    }
    case 'for_statement': {
      const inHeader =
        findOutputIntrinsicInStatement(stmt.init, ctx, seen) ??
        fromExpr(stmt.condition) ??
        findOutputIntrinsicInStatement(stmt.update, ctx, seen);
      if (inHeader) return inHeader;
      return findOutputIntrinsic(stmt.body, ctx, seen);
    }
    default:
      return undefined;
  }
}

/** Direct sub-expressions of `expr`, for the intrinsic search above. */
function subExpressions(expr: Expression): Expression[] {
  switch (expr.kind) {
    case 'call_expr':
      return [...expr.args];
    case 'binary_expr':
      return [expr.left, expr.right];
    case 'unary_expr':
      return [expr.operand];
    case 'ternary_expr':
      return [expr.condition, expr.consequent, expr.alternate];
    case 'index_access':
      return [expr.object, expr.index];
    case 'array_literal':
      return [...expr.elements];
    default:
      return [];
  }
}

function validateNoOutputIntrinsicInLoop(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: ValidationContext,
): void {
  const site = findOutputIntrinsic(stmt.body, ctx, new Set<string>());
  if (site === undefined) return;
  ctx.errors.push(loopOutputIntrinsicDiagnostic(
    site.intrinsic,
    site.via,
    site.location ?? stmt.sourceLocation,
  ));
}

/**
 * The R-127 diagnostic, shared verbatim with the other six tiers and with the
 * pass-4 backstop in `04-anf-lower.ts` (N-006). The message stays an inline
 * template at this `makeDiagnostic` call so the diagnostic-coverage extractor
 * (`__tests__/support/diagnostic-sites.ts`) can reduce it to a template.
 */
function loopOutputIntrinsicDiagnostic(
  intrinsic: string,
  via: string | undefined,
  loc?: SourceLocation,
): CompilerDiagnostic {
  const viaClause = via !== undefined ? ` (reached through private method '${via}')` : '';
  return makeDiagnostic(
    `Output intrinsic '${intrinsic}'${viaClause} cannot be called inside a loop body. `
    + `A loop body lowers into its own scope whose declared outputs never reach the method's `
    + `output list, so the continuation hash would commit to fewer outputs than the transaction `
    + `actually creates: the spend is rejected by every shipped SDK and any successor it produces `
    + `is unspendable. Move the call out of the loop.`,
    'error',
    loc,
  );
}

/** The R-127 message text, for the pass-4 backstop. */
export function loopOutputIntrinsicMessage(intrinsic: string, via?: string): string {
  return loopOutputIntrinsicDiagnostic(intrinsic, via).message;
}

/**
 * Reject any output intrinsic in either arm of a ternary expression (N-049).
 *
 * `lowerTernaryExpr` lowers each arm into `ctx.subContext()`, whose fresh
 * `_addOutputRefs` is dropped when the arm is folded into the `if` binding --
 * unlike `lowerIfStatement`, which merges each arm's outputs into one ref so
 * the parent sees them. Measured on every tier before this check existed
 * (EXT-2 TernaryToll): `c ? this.addRawOutput(p, payee) : this.addRawOutput(p,
 * refund)` beside one top-level `addOutput` compiled to a continuation over the
 * state output and the change only, so a spend that DROPS the payout was
 * accepted and the honest spend rejected; without the top-level call the
 * method died on the internal "_newAmount is not on the stack" error.
 *
 * Refusal rather than lowering (fail-closed, same shape as R-127): the
 * if/else statement form already expresses a conditional output correctly,
 * and no fixture or example wraps an output intrinsic in a ternary. Private
 * helpers are followed because they are inlined into the arm at ANF time. A
 * ternary that only selects VALUES (`addRawOutput(p, c ? a : b)`) is untouched.
 */
function validateNoOutputIntrinsicInTernaryArm(
  expr: Extract<Expression, { kind: 'ternary_expr' }>,
  ctx: ValidationContext,
): void {
  for (const arm of [expr.consequent, expr.alternate]) {
    const site = findOutputIntrinsicInExpr(arm, ctx, new Set<string>(), expr.sourceLocation);
    if (site === undefined) continue;
    ctx.errors.push(ternaryOutputIntrinsicDiagnostic(site.intrinsic, site.via, site.location));
    return;
  }
}

/**
 * The N-049 diagnostic, shared verbatim with the other six tiers and with the
 * pass-4 backstop in `04-anf-lower.ts`. Inline template at the `makeDiagnostic`
 * call for the diagnostic-coverage extractor, as R-127's.
 */
function ternaryOutputIntrinsicDiagnostic(
  intrinsic: string,
  via: string | undefined,
  loc?: SourceLocation,
): CompilerDiagnostic {
  const viaClause = via !== undefined ? ` (reached through private method '${via}')` : '';
  return makeDiagnostic(
    `Output intrinsic '${intrinsic}'${viaClause} cannot be called inside a conditional (ternary) expression arm. `
    + `A ternary arm lowers into its own scope whose declared outputs never reach the method's `
    + `output list, so the continuation hash would commit to fewer outputs than the transaction `
    + `actually creates: a spender can drop the output and the honest spend is rejected. `
    + `Use an if/else statement instead.`,
    'error',
    loc,
  );
}

/** The N-049 message text, for the pass-4 backstop. */
export function ternaryOutputIntrinsicMessage(intrinsic: string, via?: string): string {
  return ternaryOutputIntrinsicDiagnostic(intrinsic, via).message;
}

/**
 * Reject any for-loop update clause the loop model cannot represent (R-065).
 *
 * The ANF `loop` node carries exactly `{ count, iterVar, start, step, body }`
 * and synthesizes the iterator on unrolled iteration k as `start + k*step`.
 * There is no slot for an arbitrary update statement, and `extractLoopStep`
 * only ever understood a unit step — everything else was silently coerced to
 * `+1` (or `-1` from the comparison direction) and the clause itself was
 * discarded. That made three distinct failures indistinguishable from a
 * correct compile:
 *
 *   * `for (let i = 0n; i < 5n; undefinedFn())` produced byte-identical
 *     output. A nonexistent function name raised nothing.
 *   * `for (let i = 0n; i < 5n; this.count++)` dropped the state write.
 *   * `while (i < 10) : (i += 2)` (Zig frontend) unrolled 10 times over
 *     i = 0..9 instead of 5 times over i = 0,2,4,6,8.
 *
 * `spec/grammar.md`'s ForStatement production admits only
 * `Identifier ('++' | '--')`, and its Statement Restrictions say "The loop
 * variable MUST use simple increment (`++`) or decrement (`--`)". So rejecting
 * is the fix rather than lowering: appending the update's lowering to the loop
 * body would re-emit `i++` as a dead binding on every loop that already
 * compiles correctly, moving bytes across the whole corpus to express nothing.
 *
 * The accepted set is every shape the nine frontends actually synthesize:
 * `i++`/`i--`/`++i`/`--i`; the assignment spelling `i = i + 1` / `i = i - 1` /
 * `i = 1 + i` that `i += 1` becomes in the Solidity, Zig and Java parsers; and
 * the effect-free no-op sentinel (a literal or a bare identifier) that the
 * while-shaped parsers synthesize when the source has no continue expression
 * at all -- but only on a loop whose condition does not test its declared
 * iterator. Such a loop carries a placeholder iterator and is already refused
 * by the condition rule, so tolerating its sentinel just avoids a second
 * diagnostic. On a loop whose condition DOES test the iterator a no-op update
 * leaves it unchanged forever, yet the unrolled loop would still step it by
 * one: `var i = 3; while (i < 5) : (i)` (Zig), `for (...; i)` and
 * `for (...; 0n)` compiled two laps over i = 3, 4 (N-116).
 *
 * The advanced variable must be the declared iterator or the identifier the
 * condition tests. Both are needed: the Zig parser only folds
 * `var i = 0; while (i < N) : (i += 1)` into a single for_statement when the
 * declaration is the immediately preceding statement, so an unfolded loop
 * carries a placeholder init while the update advances the real `i` named in
 * the condition.
 *
 * The diagnostic text is shared verbatim with the other six tiers.
 */
function validateForUpdate(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: ValidationContext,
): void {
  // Names the update is allowed to advance: the declared iterator, plus the
  // identifier the condition tests (see the doc comment's Zig case).
  const allowed: string[] = [stmt.init.name];
  if (stmt.condition.kind === 'binary_expr' && stmt.condition.left.kind === 'identifier') {
    allowed.push(stmt.condition.left.name);
  }

  const conditionTestsIterator =
    stmt.condition.kind === 'binary_expr' &&
    stmt.condition.left.kind === 'identifier' &&
    stmt.condition.left.name === stmt.init.name;

  if (isRepresentableForUpdate(allowed, stmt.update, !conditionTestsIterator)) return;

  ctx.errors.push(makeDiagnostic(
    'For loop update must advance the loop variable by one (`i++`, `i--`, ' +
    '`i = i + 1n`, `i = i - 1n`). The unrolled loop carries only a start value and a ' +
    'unit step, so any other update clause -- a function call, a state mutation, or a ' +
    'non-unit step such as `i += 2` -- cannot be represented and would be discarded',
    'error',
    stmt.sourceLocation,
  ));
}

/**
 * True when `expr` names one of the identifiers the update is allowed to
 * advance. A property access, an index access or anything else is never
 * accepted: those are the side effects that used to be dropped.
 */
function isAllowedLoopVar(allowed: string[], expr: Expression): boolean {
  return expr.kind === 'identifier' && allowed.includes(expr.name);
}

function isLiteralOne(expr: Expression): boolean {
  return expr.kind === 'bigint_literal' && expr.value === 1n;
}

function isRepresentableForUpdate(
  allowed: string[],
  update: Statement,
  acceptNoOpSentinel: boolean,
): boolean {
  if (update.kind === 'expression_statement') {
    const e = update.expression;
    if (e.kind === 'increment_expr' || e.kind === 'decrement_expr') {
      return isAllowedLoopVar(allowed, e.operand);
    }
    // The no-op sentinel a while-shaped frontend synthesizes when the source
    // carries no continue expression: zig's `while (c) {}`, move's
    // `while (c) {}`, go's `for c {}`. Reading a literal or a bare identifier
    // has no effect, so discarding it loses nothing -- on a loop the condition
    // rule already refuses. On a real iterator it does not advance (N-116).
    return acceptNoOpSentinel &&
      (e.kind === 'bigint_literal' || e.kind === 'bool_literal' || e.kind === 'identifier');
  }

  // `i += 1` / `i -= 1` arrive here as `i = i + 1` / `i = i - 1`.
  if (update.kind === 'assignment') {
    if (!isAllowedLoopVar(allowed, update.target)) return false;
    const v = update.value;
    if (v.kind !== 'binary_expr') return false;
    if (v.op === '+') {
      return (isAllowedLoopVar(allowed, v.left) && isLiteralOne(v.right)) ||
        (isLiteralOne(v.left) && isAllowedLoopVar(allowed, v.right));
    }
    if (v.op === '-') {
      return isAllowedLoopVar(allowed, v.left) && isLiteralOne(v.right);
    }
    return false;
  }

  return false;
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
      validateNoOutputIntrinsicInTernaryArm(expr, ctx);
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

    case 'array_literal':
      for (const el of expr.elements) validateExpression(el, ctx);
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

/** Reports recursion and N-180 call depth; true iff MAX_CALL_DEPTH was exceeded. */
function checkNoRecursion(ctx: ValidationContext): boolean {
  // Build call graph: method name -> set of methods it calls
  const callGraph = new Map<string, Set<string>>();
  const methodNames = new Set<string>();

  for (const method of ctx.contract.methods) {
    methodNames.add(method.name);
    const calls = new Set<string>();
    collectMethodCalls(method.body, calls, true);
    callGraph.set(method.name, calls);
  }

  // Also add constructor
  {
    const calls = new Set<string>();
    collectMethodCalls(ctx.contract.constructor.body, calls, true);
    callGraph.set('constructor', calls);
  }

  // N-180: one iterative pass over the call graph answers both questions for
  // every method — does it reach a cycle, and how deep is its call chain — in
  // O(methods + calls). The old per-method DFS restarted from scratch for each
  // method (quadratic on a chain) and recursed once per link.
  const { reachesCycle, depth } = analyzeCallGraph(callGraph, methodNames);

  for (const method of ctx.contract.methods) {
    if (reachesCycle.get(method.name)) {
      ctx.errors.push(makeDiagnostic(
        `Recursion detected: method '${method.name}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.`,
        'error',
        method.sourceLocation,
      ));
    }
  }

  // N-180: private methods are inlined at every call site, so the call depth is
  // the inlining depth. Report the first method (declaration order) past it.
  for (const method of ctx.contract.methods) {
    if (!reachesCycle.get(method.name) && (depth.get(method.name) ?? 0) > InputLimits.MAX_CALL_DEPTH) {
      ctx.errors.push(makeDiagnostic(
        `call depth of method '${method.name}' exceeds MAX_CALL_DEPTH (limit=${InputLimits.MAX_CALL_DEPTH})`,
        'error',
        method.sourceLocation,
      ));
      return true;
    }
  }
  return false;
}

/**
 * N-180: for every method in `methodNames`, whether it reaches a call cycle,
 * and (when it does not) its call depth: 0 if it calls no contract method, else
 * 1 + the largest call depth among the contract methods it calls. Iterative
 * three-colour DFS with memoisation, so O(methods + calls) and no host
 * recursion. `reachesCycle` matches what a fresh DFS from each method reports.
 */
function analyzeCallGraph(
  callGraph: Map<string, Set<string>>,
  methodNames: Set<string>,
): { reachesCycle: Map<string, boolean>; depth: Map<string, number> } {
  const reachesCycle = new Map<string, boolean>();
  const depth = new Map<string, number>();
  const onStack = new Set<string>();

  for (const root of methodNames) {
    if (reachesCycle.has(root)) continue;
    const stack: Array<{ name: string; callees: string[]; next: number; cyc: boolean; depth: number }> = [];
    const push = (name: string) => {
      onStack.add(name);
      stack.push({ name, callees: [...(callGraph.get(name) ?? [])], next: 0, cyc: false, depth: 0 });
    };
    push(root);
    while (stack.length > 0) {
      const top = stack[stack.length - 1]!;
      if (top.next < top.callees.length) {
        const callee = top.callees[top.next++]!;
        if (!methodNames.has(callee)) continue;
        if (onStack.has(callee)) {
          top.cyc = true;
        } else if (reachesCycle.has(callee)) {
          if (reachesCycle.get(callee)) top.cyc = true;
          else top.depth = Math.max(top.depth, 1 + depth.get(callee)!);
        } else {
          push(callee);
        }
        continue;
      }
      stack.pop();
      onStack.delete(top.name);
      reachesCycle.set(top.name, top.cyc);
      depth.set(top.name, top.depth);
      const parent = stack[stack.length - 1];
      if (parent) {
        if (top.cyc) parent.cyc = true;
        else parent.depth = Math.max(parent.depth, 1 + top.depth);
      }
    }
  }
  return { reachesCycle, depth };
}

function collectMethodCalls(
  stmts: Statement[],
  calls: Set<string>,
  bareCalls = false,
): void {
  for (const stmt of stmts) {
    collectMethodCallsInStatement(stmt, calls, bareCalls);
  }
}

function collectMethodCallsInStatement(
  stmt: Statement,
  calls: Set<string>,
  bareCalls = false,
): void {
  switch (stmt.kind) {
    case 'expression_statement':
      collectMethodCallsInExpr(stmt.expression, calls, bareCalls);
      break;
    case 'variable_decl':
      collectMethodCallsInExpr(stmt.init, calls, bareCalls);
      break;
    case 'assignment':
      collectMethodCallsInExpr(stmt.target, calls, bareCalls);
      collectMethodCallsInExpr(stmt.value, calls, bareCalls);
      break;
    case 'if_statement':
      collectMethodCallsInExpr(stmt.condition, calls, bareCalls);
      collectMethodCalls(stmt.then, calls, bareCalls);
      if (stmt.else) collectMethodCalls(stmt.else, calls, bareCalls);
      break;
    case 'for_statement':
      collectMethodCallsInStatement(stmt.init, calls, bareCalls);
      collectMethodCallsInExpr(stmt.condition, calls, bareCalls);
      collectMethodCallsInStatement(stmt.update, calls, bareCalls);
      collectMethodCalls(stmt.body, calls, bareCalls);
      break;
    case 'return_statement':
      if (stmt.value) collectMethodCallsInExpr(stmt.value, calls, bareCalls);
      break;
  }
}

function collectMethodCallsInExpr(
  expr: Expression,
  calls: Set<string>,
  bareCalls = false,
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
      // N-180: the Solidity, Move and Java surfaces call a helper as a bare
      // `m(...)`. Counted only for the recursion / call-depth graph
      // (`bareCalls`), and only names of contract methods count there
      // (analyzeCallGraph filters by methodNames), so builtins are unaffected.
      if (bareCalls && expr.callee.kind === 'identifier') {
        calls.add(expr.callee.name);
      }
      collectMethodCallsInExpr(expr.callee, calls, bareCalls);
      for (const arg of expr.args) {
        collectMethodCallsInExpr(arg, calls, bareCalls);
      }
      break;
    case 'binary_expr':
      collectMethodCallsInExpr(expr.left, calls, bareCalls);
      collectMethodCallsInExpr(expr.right, calls, bareCalls);
      break;
    case 'unary_expr':
      collectMethodCallsInExpr(expr.operand, calls, bareCalls);
      break;
    case 'member_expr':
      collectMethodCallsInExpr(expr.object, calls, bareCalls);
      break;
    case 'ternary_expr':
      collectMethodCallsInExpr(expr.condition, calls, bareCalls);
      collectMethodCallsInExpr(expr.consequent, calls, bareCalls);
      collectMethodCallsInExpr(expr.alternate, calls, bareCalls);
      break;
    case 'index_access':
      collectMethodCallsInExpr(expr.object, calls, bareCalls);
      collectMethodCallsInExpr(expr.index, calls, bareCalls);
      break;
    case 'increment_expr':
    case 'decrement_expr':
      collectMethodCallsInExpr(expr.operand, calls, bareCalls);
      break;
    case 'array_literal':
      for (const el of expr.elements) collectMethodCallsInExpr(el, calls, bareCalls);
      break;
    default:
      // Leaf nodes
      break;
  }
}

// ---------------------------------------------------------------------------
// F-286: verifyRabinSig's public key must not be chosen by the spender
// ---------------------------------------------------------------------------

/**
 * The one diagnostic every tier emits for F-286 (user decision R78).
 */
export const RABIN_PUBKEY_PROVENANCE_MESSAGE =
  'verifyRabinSig public key (4th argument) must be a contract property or a literal; ' +
  'a spender-supplied Rabin modulus lets anyone forge a signature';

/**
 * N-205 (a): the diagnostic every tier emits when a mutable key property is
 * written, outside the constructor, with a value the F-286 rule does not trust.
 */
export function rabinKeyWriteMessage(prop: string): string {
  return (
    `verifyRabinSig public key property '${prop}' may only be assigned a contract property or a literal ` +
    'outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature'
  );
}

/**
 * `verifyRabinSig(msg, sig, padding, n)` checks `(sig² + padding) mod n ==
 * SHA256(msg) mod n`. A spender who chooses `n` forges any message (`n = 1`,
 * `sig = 0` passes on chain), so the modulus must be fixed by the deployer.
 *
 * Trusted values for the 4th argument:
 *   - a property read: `this.x` (`property_access`, or `member_expr` on
 *     `this`), or a bare identifier naming a property that no parameter or
 *     local of the method shadows (the Java surface's bare field);
 *   - a bigint literal;
 *   - a local whose initialiser AND every assignment to it are trusted;
 *   - a parameter of a PRIVATE method that every call site (at least one)
 *     binds to a trusted value in the caller (least fixed point, so chains of
 *     helpers work and an uncalled or cyclic helper stays untrusted).
 * Everything else — public and constructor parameters, arithmetic, ternaries,
 * calls — is refused.
 */
function checkRabinPubKeyProvenance(ctx: ValidationContext): void {
  const contract = ctx.contract;
  const propertyNames = new Set(contract.properties.map((p) => p.name));
  const privateMethods = new Map<string, MethodNode>();
  for (const m of contract.methods) {
    if (m.visibility === 'private') privateMethods.set(m.name, m);
  }

  // Per method: local name -> every value bound to it (inits + assignments),
  // and names that are ever ++/-- (never trusted).
  interface Scope {
    method: MethodNode;
    params: Set<string>;
    bindings: Map<string, Expression[]>;
    mutated: Set<string>;
    /** N-205: names declared as locals (a bare property write also lands in `bindings`). */
    declared: Set<string>;
  }
  const scopeOf = (method: MethodNode): Scope => {
    const scope: Scope = {
      method,
      params: new Set(method.params.map((p) => p.name)),
      bindings: new Map(),
      mutated: new Set(),
      declared: new Set(),
    };
    const bind = (name: string, value: Expression) => {
      const list = scope.bindings.get(name) ?? [];
      list.push(value);
      scope.bindings.set(name, list);
    };
    const visitExpr = (expr: Expression) => {
      walkExpr(expr, (e) => {
        if ((e.kind === 'increment_expr' || e.kind === 'decrement_expr') && e.operand.kind === 'identifier') {
          scope.mutated.add(e.operand.name);
        }
      });
    };
    const visit = (stmts: Statement[]) => {
      for (const stmt of stmts) {
        switch (stmt.kind) {
          case 'variable_decl':
            scope.declared.add(stmt.name);
            bind(stmt.name, stmt.init);
            visitExpr(stmt.init);
            break;
          case 'assignment':
            if (stmt.target.kind === 'identifier') bind(stmt.target.name, stmt.value);
            visitExpr(stmt.target);
            visitExpr(stmt.value);
            break;
          case 'expression_statement':
            visitExpr(stmt.expression);
            break;
          case 'if_statement':
            visitExpr(stmt.condition);
            visit(stmt.then);
            if (stmt.else) visit(stmt.else);
            break;
          case 'for_statement':
            visit([stmt.init]);
            visitExpr(stmt.condition);
            visit([stmt.update]);
            visit(stmt.body);
            break;
          case 'return_statement':
            if (stmt.value) visitExpr(stmt.value);
            break;
        }
      }
    };
    visit(method.body);
    return scope;
  };

  const allMethods = [contract.constructor, ...contract.methods];
  const scopes = new Map<MethodNode, Scope>(allMethods.map((m) => [m, scopeOf(m)]));

  // Private method name -> indices of parameters proven trusted so far.
  const trustedParams = new Map<string, Set<number>>();
  for (const name of privateMethods.keys()) trustedParams.set(name, new Set());

  const isTrusted = (expr: Expression, scope: Scope, visiting: Set<string>): boolean => {
    switch (expr.kind) {
      case 'property_access':
        return true;
      case 'member_expr':
        return expr.object.kind === 'identifier' && expr.object.name === 'this';
      case 'bigint_literal':
        return true;
      case 'identifier': {
        const name = expr.name;
        const isParam = scope.params.has(name);
        const locals = scope.bindings.get(name);
        if (!isParam && !locals) return propertyNames.has(name);
        if (scope.mutated.has(name)) return false;
        if (isParam) {
          const method = scope.method;
          if (method.visibility !== 'private' || method === contract.constructor) return false;
          const idx = method.params.findIndex((p) => p.name === name);
          if (!trustedParams.get(method.name)?.has(idx)) return false;
        }
        if (locals) {
          if (visiting.has(name)) return false;
          visiting.add(name);
          const ok = locals.every((v) => isTrusted(v, scope, visiting));
          visiting.delete(name);
          if (!ok) return false;
        }
        return true;
      }
      default:
        return false;
    }
  };

  const privateCallee = (expr: Expression): string | undefined => {
    if (expr.kind !== 'call_expr') return undefined;
    const c = expr.callee;
    let name: string | undefined;
    if (c.kind === 'property_access') name = c.property;
    else if (c.kind === 'member_expr' && c.object.kind === 'identifier' && c.object.name === 'this') name = c.property;
    return name !== undefined && privateMethods.has(name) ? name : undefined;
  };

  // Every call site of every private method, with the caller's scope.
  const callSites = new Map<string, { args: Expression[]; scope: Scope }[]>();
  for (const name of privateMethods.keys()) callSites.set(name, []);
  for (const scope of scopes.values()) {
    walkExpressionsInBodyDeep(scope.method.body, (e) => {
      const callee = privateCallee(e);
      if (callee !== undefined && e.kind === 'call_expr') callSites.get(callee)!.push({ args: e.args, scope });
    });
  }

  // Least fixed point: a parameter becomes trusted once every call site binds
  // it to a trusted value. Monotone, so it terminates.
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, method] of privateMethods) {
      const sites = callSites.get(name)!;
      if (sites.length === 0) continue;
      const trusted = trustedParams.get(name)!;
      for (let i = 0; i < method.params.length; i++) {
        if (trusted.has(i)) continue;
        if (sites.every((s) => s.args[i] !== undefined && isTrusted(s.args[i]!, s.scope, new Set()))) {
          trusted.add(i);
          changed = true;
        }
      }
    }
  }

  for (const scope of scopes.values()) {
    walkExpressionsInBodyDeep(scope.method.body, (e) => {
      if (
        e.kind === 'call_expr' &&
        e.callee.kind === 'identifier' &&
        e.callee.name === 'verifyRabinSig' &&
        e.args.length >= 4 &&
        !isTrusted(e.args[3]!, scope, new Set())
      ) {
        // N-464 (user decision R186): anchored at the 4th argument itself.
        ctx.errors.push(makeDiagnostic(
          RABIN_PUBKEY_PROVENANCE_MESSAGE,
          'error',
          e.args[3]!.sourceLocation ?? e.sourceLocation ?? scope.method.sourceLocation,
        ));
      }
    });
  }

  // N-205 (a): a MUTABLE property used as the key is state the previous spend
  // chose, so outside the constructor it may only be written with a value
  // `isTrusted` accepts. KEY properties: those whose value reaches a 4th
  // argument, closed under "is written into a key property" (so a trusted
  // property read on the right-hand side is itself held to the rule).
  const sourcesOf = (expr: Expression, scope: Scope, out: Set<string>, visiting: Set<string>): void => {
    switch (expr.kind) {
      case 'property_access':
        out.add(expr.property);
        return;
      case 'member_expr':
        if (expr.object.kind === 'identifier' && expr.object.name === 'this') out.add(expr.property);
        return;
      case 'identifier': {
        const name = expr.name;
        const isParam = scope.params.has(name);
        const locals = scope.bindings.get(name);
        if (!isParam && !locals) {
          if (propertyNames.has(name)) out.add(name);
          return;
        }
        const key = `${scope.method.name}\u0000${name}`;
        if (visiting.has(key)) return;
        visiting.add(key);
        for (const v of locals ?? []) sourcesOf(v, scope, out, visiting);
        const method = scope.method;
        if (isParam && method.visibility === 'private' && method !== contract.constructor) {
          const idx = method.params.findIndex((p) => p.name === name);
          for (const site of callSites.get(method.name) ?? []) {
            const arg = site.args[idx];
            if (arg !== undefined) sourcesOf(arg, site.scope, out, visiting);
          }
        }
        return;
      }
      default:
        return;
    }
  };

  const keyProps = new Set<string>();
  for (const scope of scopes.values()) {
    walkExpressionsInBodyDeep(scope.method.body, (e) => {
      if (e.kind === 'call_expr' && e.callee.kind === 'identifier' && e.callee.name === 'verifyRabinSig' && e.args.length >= 4) {
        sourcesOf(e.args[3]!, scope, keyProps, new Set());
      }
    });
  }

  // Every write to a property outside the constructor. `value` is undefined
  // for ++/--, which no value makes trusted.
  interface PropWrite { prop: string; value: Expression | undefined; scope: Scope; loc: SourceLocation }
  const writes: PropWrite[] = [];
  const mutableProps = contract.properties.filter((p) => !p.readonly).map((p) => p.name);
  const writtenProp = (target: Expression, scope: Scope): string | undefined => {
    if (target.kind === 'property_access') return target.property;
    if (target.kind === 'member_expr' && target.object.kind === 'identifier' && target.object.name === 'this') {
      return target.property;
    }
    if (
      target.kind === 'identifier' &&
      propertyNames.has(target.name) &&
      !scope.params.has(target.name) &&
      !scope.declared.has(target.name)
    ) {
      return target.name;
    }
    return undefined;
  };
  const collectAssignments = (stmts: Statement[], scope: Scope): void => {
    for (const stmt of stmts) {
      switch (stmt.kind) {
        case 'assignment': {
          const prop = writtenProp(stmt.target, scope);
          if (prop !== undefined) writes.push({ prop, value: stmt.value, scope, loc: stmt.sourceLocation });
          break;
        }
        case 'if_statement':
          collectAssignments(stmt.then, scope);
          if (stmt.else) collectAssignments(stmt.else, scope);
          break;
        case 'for_statement':
          collectAssignments([stmt.init, stmt.update], scope);
          collectAssignments(stmt.body, scope);
          break;
      }
    }
  };
  for (const scope of scopes.values()) {
    if (scope.method === contract.constructor) continue;
    collectAssignments(scope.method.body, scope);
    walkExpressionsInBodyDeep(scope.method.body, (e) => {
      const loc = e.sourceLocation ?? scope.method.sourceLocation;
      if (e.kind === 'increment_expr' || e.kind === 'decrement_expr') {
        const prop = writtenProp(e.operand, scope);
        if (prop !== undefined) writes.push({ prop, value: undefined, scope, loc });
      } else if (outputIntrinsicCallName(e) === 'addOutput' && e.kind === 'call_expr') {
        // addOutput(satoshis, ...values): values are positional over the
        // mutable properties in declaration order. A single array-literal
        // value list (`addOutput(sats, [a, b])`, the Zig tuple form) is
        // unpacked, as ANF lowering's flattenAddOutputArgs does.
        const values = e.args.length === 2 && e.args[1]!.kind === 'array_literal' ? e.args[1].elements : e.args.slice(1);
        values.forEach((value, i) => {
          const prop = mutableProps[i];
          if (prop !== undefined) writes.push({ prop, value, scope, loc });
        });
      }
    });
  }

  let grew = true;
  while (grew) {
    const before = keyProps.size;
    for (const w of writes) {
      if (keyProps.has(w.prop) && w.value !== undefined && isTrusted(w.value, w.scope, new Set())) {
        sourcesOf(w.value, w.scope, keyProps, new Set());
      }
    }
    grew = keyProps.size !== before;
  }

  const mutable = new Set(mutableProps);
  for (const w of writes) {
    if (!keyProps.has(w.prop) || !mutable.has(w.prop)) continue;
    if (w.value !== undefined && isTrusted(w.value, w.scope, new Set())) continue;
    ctx.errors.push(makeDiagnostic(rabinKeyWriteMessage(w.prop), 'error', w.loc));
  }
}

/**
 * Like `walkExpressionsInBody`, but also visits every `for` loop's init and
 * update, at any nesting depth.
 */
function walkExpressionsInBodyDeep(stmts: Statement[], visitor: (expr: Expression) => void): void {
  for (const stmt of stmts) {
    switch (stmt.kind) {
      case 'if_statement':
        walkExpr(stmt.condition, visitor);
        walkExpressionsInBodyDeep(stmt.then, visitor);
        if (stmt.else) walkExpressionsInBodyDeep(stmt.else, visitor);
        break;
      case 'for_statement':
        walkExpressionsInBodyDeep([stmt.init], visitor);
        walkExpr(stmt.condition, visitor);
        walkExpressionsInBodyDeep([stmt.update], visitor);
        walkExpressionsInBodyDeep(stmt.body, visitor);
        break;
      default:
        walkExpressionsInStatement(stmt, visitor);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
 * True when `expr` is a comparison on `extractSequence(...)` that genuinely
 * EXCLUDES the finality sentinel `0xffffffff`, reading the field as the
 * unsigned 32-bit wire value it is (see `emitUnsignedBin2Num` in
 * `05-stack-lower.ts`).
 *
 * Accepted:
 *   `extractSequence(pre) !== 0xffffffffn`   and the reversed spelling
 *   `extractSequence(pre) <  N`, 0 < N <= 0xffffffff   (reversed: `N > ...`)
 *   `extractSequence(pre) <= N`, N <  0xffffffff   (reversed: `N >= ...`)
 *
 * Deliberately NOT accepted: `<= 0xffffffff` and `>= 0xffffffff`. nSequence
 * cannot exceed 0xffffffff, so those are true for every transaction including
 * the final one — a tautology that used to silence this warning on a contract
 * with no guard at all (W1 / FinalCountdown).
 *
 * Also NOT accepted: `extractSequence(pre) < 0n`. Unsigned nSequence is never
 * negative, so that comparison is vacuous (F7).
 */
function isSequenceFinalityGuard(expr: Expression): boolean {
  if (expr.kind !== 'binary_expr') return false;
  const isFinalSentinel = (e: Expression): boolean =>
    e.kind === 'bigint_literal' && e.value === SEQUENCE_FINAL;
  const strictBoundOk = (e: Expression): boolean =>
    e.kind === 'bigint_literal' && e.value > 0n && e.value <= SEQUENCE_FINAL;
  const nonStrictBoundOk = (e: Expression): boolean =>
    e.kind === 'bigint_literal' && e.value < SEQUENCE_FINAL;

  if (expr.op === '!==') {
    return (
      (isCallToNamed(expr.left, 'extractSequence') && isFinalSentinel(expr.right)) ||
      (isCallToNamed(expr.right, 'extractSequence') && isFinalSentinel(expr.left))
    );
  }
  if (expr.op === '<' && isCallToNamed(expr.left, 'extractSequence')) {
    return strictBoundOk(expr.right);
  }
  if (expr.op === '<=' && isCallToNamed(expr.left, 'extractSequence')) {
    return nonStrictBoundOk(expr.right);
  }
  if (expr.op === '>' && isCallToNamed(expr.right, 'extractSequence')) {
    return strictBoundOk(expr.left);
  }
  if (expr.op === '>=' && isCallToNamed(expr.right, 'extractSequence')) {
    return nonStrictBoundOk(expr.left);
  }
  return false;
}

/**
 * True when asserting `expr` logically implies a sequence-finality guard.
 *
 * A matching comparison nested under `!` (or `||`) does NOT count: e.g.
 * `assert(!(extractSequence !== 0xffffffffn))` requires a FINAL sequence.
 * `&&` does imply each conjunct, so a guard on either side is enough.
 */
function assertionImpliesSequenceGuard(expr: Expression): boolean {
  if (isSequenceFinalityGuard(expr)) return true;
  if (expr.kind === 'binary_expr' && expr.op === '&&') {
    return assertionImpliesSequenceGuard(expr.left) || assertionImpliesSequenceGuard(expr.right);
  }
  return false;
}

/**
 * #131: warn when `method` (transitively, through the private-helper call
 * graph) reads the tx locktime but never asserts the tx is non-final. A
 * locktime gate is not consensus-enforced unless `extractSequence !== 0xffffffff`
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
      if (isAssertCall(expr) && expr.kind === 'call_expr') {
        for (const arg of expr.args) {
          if (assertionImpliesSequenceGuard(arg)) hasSequenceGuard = true;
        }
      }
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
        `extractSequence is not 0xffffffff; a locktime gate is not ` +
        `consensus-enforced unless the tx is non-final — add ` +
        `assert(extractSequence(this.txPreimage) !== 0xffffffffn)`,
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
      walkExpressionsInStatement(stmt.init, visitor);
      walkExpr(stmt.condition, visitor);
      walkExpressionsInStatement(stmt.update, visitor);
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
    case 'array_literal':
      for (const el of expr.elements) walkExpr(el, visitor);
      break;
  }
}
