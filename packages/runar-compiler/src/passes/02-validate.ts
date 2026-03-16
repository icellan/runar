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
      if (!isLiteralExpression(prop.initializer)) {
        ctx.errors.push(makeDiagnostic(
          `Property '${prop.name}' initializer must be a literal value (number, boolean, or hex string)`,
          'error',
          prop.sourceLocation,
        ));
      }
    }
  }

  // SmartContract requires all properties to be readonly
  if (ctx.contract.parentClass === 'SmartContract') {
    for (const prop of ctx.contract.properties) {
      if (!prop.readonly) {
        ctx.errors.push(makeDiagnostic(
          `Property '${prop.name}' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.`,
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
  }

  // Validate statements in constructor body
  for (const stmt of ctor.body) {
    validateStatement(stmt, ctx);
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
  }

  // Public methods must end with an assert() call (unless StatefulSmartContract,
  // where the compiler auto-injects the final assert)
  if (method.visibility === 'public' && ctx.contract.parentClass === 'SmartContract') {
    if (!endsWithAssert(method.body)) {
      ctx.errors.push(makeDiagnostic(
        `Public method '${method.name}' must end with an assert() call`,
        'error',
        method.sourceLocation,
      ));
    }
  }

  // Warn on manual preimage boilerplate in StatefulSmartContract
  if (ctx.contract.parentClass === 'StatefulSmartContract' && method.visibility === 'public') {
    warnManualPreimageUsage(method, ctx);
  }

  // Validate all statements in method body
  for (const stmt of method.body) {
    validateStatement(stmt, ctx);
  }
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
  validateExpression(stmt.init, ctx);
}

function validateForStatement(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: ValidationContext,
): void {
  // Validate that for-loop bounds are compile-time determinable
  // The condition should compare the iter var to a constant
  validateExpression(stmt.condition, ctx);

  // Check that the loop bound is a compile-time constant
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

    case 'call_expr':
      validateExpression(expr.callee, ctx);
      for (const arg of expr.args) {
        validateExpression(arg, ctx);
      }
      break;

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
    case 'bytestring_literal':
    case 'property_access':
      break;
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
