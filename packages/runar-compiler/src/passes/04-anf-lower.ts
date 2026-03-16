/**
 * Pass 4: ANF Lower
 *
 * Lowers the Rúnar AST to A-Normal Form (ANF) IR. This is the critical
 * transformation pass -- it flattens all nested expressions into a
 * sequence of let-bindings where every right-hand side is a simple value.
 *
 * Example:
 *   assert(checkSig(sig, this.pk))
 * becomes:
 *   let t0 = load_param("sig")
 *   let t1 = load_prop("pk")
 *   let t2 = call("checkSig", [t0, t1])
 *   let t3 = assert(t2)
 */

import type {
  ContractNode,
  ParamNode,
  Statement,
  Expression,
  TypeNode,
} from '../ir/index.js';
import type {
  ANFProgram,
  ANFMethod,
  ANFParam,
  ANFBinding,
  ANFValue,
  ANFProperty,
  BinOp,
  ANFUnaryOp,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Lower a validated Rúnar AST to ANF IR.
 */
export function lowerToANF(contract: ContractNode): ANFProgram {
  const properties = lowerProperties(contract);
  const methods = lowerMethods(contract);

  // Post-pass: lift update_prop from if-else branches into flat conditionals.
  // This prevents phantom stack entries in stack lowering for patterns like
  // position dispatch (different properties updated in different branches).
  for (const method of methods) {
    method.body = liftBranchUpdateProps(method.body);
  }

  return {
    contractName: contract.name,
    properties,
    methods,
  };
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

function lowerProperties(contract: ContractNode): ANFProperty[] {
  return contract.properties.map(prop => {
    const anfProp: ANFProperty = {
      name: prop.name,
      type: typeNodeToString(prop.type),
      readonly: prop.readonly,
    };

    // Extract literal value from property initializer
    if (prop.initializer) {
      anfProp.initialValue = extractLiteralValue(prop.initializer);
    }

    return anfProp;
  });
}

/** Extract a literal value from an Expression for ANFProperty.initialValue. */
function extractLiteralValue(expr: Expression): string | bigint | boolean | undefined {
  switch (expr.kind) {
    case 'bigint_literal':
      return expr.value;
    case 'bool_literal':
      return expr.value;
    case 'bytestring_literal':
      return expr.value;
    case 'unary_expr':
      if (expr.op === '-' && expr.operand.kind === 'bigint_literal') {
        return -expr.operand.value;
      }
      return undefined;
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

function lowerMethods(contract: ContractNode): ANFMethod[] {
  const result: ANFMethod[] = [];

  // Lower constructor
  const ctorCtx = new LoweringContext(contract);
  lowerStatements(contract.constructor.body, ctorCtx);
  result.push({
    name: 'constructor',
    params: lowerParams(contract.constructor.params),
    body: ctorCtx.bindings,
    isPublic: false,
  });

  // Lower each method
  for (const method of contract.methods) {
    const methodCtx = new LoweringContext(contract);

    if (contract.parentClass === 'StatefulSmartContract' && method.visibility === 'public') {
      // Determine if this method verifies hashOutputs (needs change output support).
      // Methods that use addOutput or mutate state need hashOutputs verification.
      // Non-mutating methods (like close/destroy) don't verify outputs.
      const needsChangeOutput = methodMutatesState(method, contract) || methodHasAddOutput(method);

      // Register implicit parameters
      if (needsChangeOutput) {
        methodCtx.addParam('_changePKH');
        methodCtx.addParam('_changeAmount');
      }
      // Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
      // Multi-output (addOutput) methods already specify amounts explicitly per output.
      const needsNewAmount = methodMutatesState(method, contract) && !methodHasAddOutput(method);
      if (needsNewAmount) {
        methodCtx.addParam('_newAmount');
      }
      methodCtx.addParam('txPreimage');

      // Inject checkPreimage(txPreimage) at the start
      const preimageRef = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
      const checkResult = methodCtx.emit({ kind: 'check_preimage', preimage: preimageRef });
      methodCtx.emit({ kind: 'assert', value: checkResult });

      // Deserialize mutable state from the preimage's scriptCode.
      const stateProps = contract.properties.filter(p => p.kind === 'property' && !p.readonly);
      if (stateProps.length > 0) {
        const preimageRef3 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
        methodCtx.emit({ kind: 'deserialize_state', preimage: preimageRef3 });
      }

      // Lower the developer's method body
      lowerStatements(method.body, methodCtx);

      // Determine state continuation type
      const addOutputRefs = methodCtx.getAddOutputRefs();
      if (addOutputRefs.length > 0 || methodMutatesState(method, contract)) {
        // Build the P2PKH change output for hashOutputs verification
        const changePKHRef = methodCtx.emit({ kind: 'load_param', name: '_changePKH' });
        const changeAmountRef = methodCtx.emit({ kind: 'load_param', name: '_changeAmount' });
        const changeOutputRef = methodCtx.emit({ kind: 'call', func: 'buildChangeOutput', args: [changePKHRef, changeAmountRef] });

        if (addOutputRefs.length > 0) {
          // Multi-output continuation: concat all outputs + change output, hash
          let accumulated = addOutputRefs[0]!;
          for (let i = 1; i < addOutputRefs.length; i++) {
            accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, addOutputRefs[i]!] });
          }
          accumulated = methodCtx.emit({ kind: 'call', func: 'cat', args: [accumulated, changeOutputRef] });
          const hashRef = methodCtx.emit({ kind: 'call', func: 'hash256', args: [accumulated] });
          const preimageRef2 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const outputHashRef = methodCtx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef2] });
          const eqRef = methodCtx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
          methodCtx.emit({ kind: 'assert', value: eqRef });
        } else {
          // Single-output continuation: build raw output bytes, concat with change, hash
          const stateScriptRef = methodCtx.emit({ kind: 'get_state_script' });
          const preimageRef2 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const newAmountRef = methodCtx.emit({ kind: 'load_param', name: '_newAmount' });
          const contractOutputRef = methodCtx.emit({ kind: 'call', func: 'computeStateOutput', args: [preimageRef2, stateScriptRef, newAmountRef] });
          const allOutputs = methodCtx.emit({ kind: 'call', func: 'cat', args: [contractOutputRef, changeOutputRef] });
          const hashRef = methodCtx.emit({ kind: 'call', func: 'hash256', args: [allOutputs] });
          const preimageRef4 = methodCtx.emit({ kind: 'load_param', name: 'txPreimage' });
          const outputHashRef = methodCtx.emit({ kind: 'call', func: 'extractOutputHash', args: [preimageRef4] });
          const eqRef = methodCtx.emit({ kind: 'bin_op', op: '===', left: hashRef, right: outputHashRef, result_type: 'bytes' });
          methodCtx.emit({ kind: 'assert', value: eqRef });
        }
      }

      // Build augmented params list for ABI
      const augmentedParams: ParamNode[] = [...method.params];
      if (needsChangeOutput) {
        augmentedParams.push(
          { kind: 'param', name: '_changePKH', type: { kind: 'primitive_type', name: 'Ripemd160' } },
          { kind: 'param', name: '_changeAmount', type: { kind: 'primitive_type', name: 'bigint' } },
        );
      }
      if (needsNewAmount) {
        augmentedParams.push(
          { kind: 'param', name: '_newAmount', type: { kind: 'primitive_type', name: 'bigint' } },
        );
      }
      augmentedParams.push(
        { kind: 'param', name: 'txPreimage', type: { kind: 'primitive_type', name: 'SigHashPreimage' } },
      );

      result.push({
        name: method.name,
        params: lowerParams(augmentedParams),
        body: methodCtx.bindings,
        isPublic: true,
      });
    } else {
      lowerStatements(method.body, methodCtx);
      result.push({
        name: method.name,
        params: lowerParams(method.params),
        body: methodCtx.bindings,
        isPublic: method.visibility === 'public',
      });
    }
  }

  return result;
}

function lowerParams(params: ParamNode[]): ANFParam[] {
  return params.map(p => ({
    name: p.name,
    type: typeNodeToString(p.type),
  }));
}

// ---------------------------------------------------------------------------
// Lowering context: manages temp variable generation
// ---------------------------------------------------------------------------

class LoweringContext {
  bindings: ANFBinding[] = [];
  private counter = 0;
  private readonly contract: ContractNode;
  private readonly paramNames: Set<string> = new Set();
  private readonly localNames: Set<string> = new Set();
  private readonly localByteVars: Set<string> = new Set();
  private readonly _addOutputRefs: string[] = [];
  /** Maps local variable names to their current ANF binding name.
   *  Updated after if-statements that reassign locals in both branches. */
  private readonly localAliases: Map<string, string> = new Map();
  /** Debug: source location to attach to emitted ANF bindings. */
  currentSourceLoc: { file: string; line: number; column: number } | undefined;

  constructor(contract: ContractNode) {
    this.contract = contract;
  }

  /** Generate a fresh temporary name. */
  freshTemp(): string {
    return `t${this.counter++}`;
  }

  /** Emit a binding and return the bound name. */
  emit(value: ANFValue): string {
    const name = this.freshTemp();
    const binding: ANFBinding = { name, value };
    if (this.currentSourceLoc) binding.sourceLoc = this.currentSourceLoc;
    this.bindings.push(binding);
    return name;
  }

  /** Emit a binding with a specific name (for named variables). */
  emitNamed(name: string, value: ANFValue): void {
    const binding: ANFBinding = { name, value };
    if (this.currentSourceLoc) binding.sourceLoc = this.currentSourceLoc;
    this.bindings.push(binding);
  }

  /** Record a parameter name so we know to use load_param for it. */
  addParam(name: string): void {
    this.paramNames.add(name);
  }

  /** Record a local variable name so we know it's a local ref. */
  addLocal(name: string): void {
    this.localNames.add(name);
  }

  /** Record a local variable as byte-typed. */
  addLocalByteVar(name: string): void {
    this.localByteVars.add(name);
  }

  /** Check if a local variable is byte-typed. */
  isLocalByteVar(name: string): boolean {
    return this.localByteVars.has(name);
  }

  isParam(name: string): boolean {
    return this.paramNames.has(name);
  }

  isLocal(name: string): boolean {
    return this.localNames.has(name);
  }

  /** Set the current ANF binding for a local variable (after if-statement reassignment). */
  setLocalAlias(localName: string, bindingName: string): void {
    this.localAliases.set(localName, bindingName);
  }

  /** Get the current ANF binding for a local variable, or undefined if not aliased. */
  getLocalAlias(localName: string): string | undefined {
    return this.localAliases.get(localName);
  }

  isProperty(name: string): boolean {
    return this.contract.properties.some(p => p.name === name);
  }

  /** Track an addOutput binding ref for multi-output continuation. */
  addOutputRef(ref: string): void {
    this._addOutputRefs.push(ref);
  }

  /** Get all addOutput refs collected during lowering. */
  getAddOutputRefs(): string[] {
    return this._addOutputRefs;
  }

  /** Look up the type of a method parameter by name. Returns the type string or null. */
  getParamType(name: string): string | null {
    // Search all methods' params for a matching name
    for (const method of [this.contract.constructor, ...this.contract.methods]) {
      for (const p of method.params) {
        if (p.name === name) {
          return typeNodeToString(p.type);
        }
      }
    }
    return null;
  }

  /** Look up the type of a contract property by name. Returns the type string or null. */
  getPropertyType(name: string): string | null {
    for (const p of this.contract.properties) {
      if (p.name === name) {
        return typeNodeToString(p.type);
      }
    }
    return null;
  }

  /** Create a sub-context for nested blocks (if/else, loops). */
  subContext(): LoweringContext {
    const sub = new LoweringContext(this.contract);
    sub.counter = this.counter;
    // Share the parameter, local name sets, and aliases
    for (const p of this.paramNames) sub.paramNames.add(p);
    for (const l of this.localNames) sub.localNames.add(l);
    for (const b of this.localByteVars) sub.localByteVars.add(b);
    for (const [k, v] of this.localAliases) sub.localAliases.set(k, v);
    return sub;
  }

  /** Sync the counter back from a sub-context. */
  syncCounter(sub: LoweringContext): void {
    this.counter = Math.max(this.counter, sub.counter);
  }
}

// ---------------------------------------------------------------------------
// Statement lowering
// ---------------------------------------------------------------------------

function lowerStatements(stmts: Statement[], ctx: LoweringContext): void {
  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i]!;

    // Early-return nesting: when an if-statement's then-block ends with a
    // return and there is no else-branch, the remaining statements after the
    // if are unreachable from the then-branch.  Nest them into the else-branch
    // so that only one value ends up on the stack (the return value from
    // whichever branch executes).  Without this, both branches produce values
    // and the stack becomes misaligned.
    if (
      stmt.kind === 'if_statement' &&
      !stmt.else &&
      i + 1 < stmts.length &&
      branchEndsWithReturn(stmt.then)
    ) {
      const remaining = stmts.slice(i + 1);
      const modifiedIf: typeof stmt = {
        ...stmt,
        else: remaining,
      };
      lowerStatement(modifiedIf, ctx);
      return; // remaining stmts are now inside the else branch
    }

    lowerStatement(stmt, ctx);
  }
}

/** Check whether a statement list always terminates with a return_statement. */
function branchEndsWithReturn(stmts: Statement[]): boolean {
  if (stmts.length === 0) return false;
  const last = stmts[stmts.length - 1]!;
  if (last.kind === 'return_statement') return true;
  // Also handle if-else where both branches return:
  // if (A) { return X; } else { return Y; }
  if (last.kind === 'if_statement' && last.else) {
    return branchEndsWithReturn(last.then) && branchEndsWithReturn(last.else);
  }
  return false;
}

function lowerStatement(stmt: Statement, ctx: LoweringContext): void {
  // Propagate source location to emitted ANF bindings
  ctx.currentSourceLoc = stmt.sourceLocation;

  switch (stmt.kind) {
    case 'variable_decl':
      lowerVariableDecl(stmt, ctx);
      break;

    case 'assignment':
      lowerAssignment(stmt, ctx);
      break;

    case 'if_statement':
      lowerIfStatement(stmt, ctx);
      break;

    case 'for_statement':
      lowerForStatement(stmt, ctx);
      break;

    case 'expression_statement':
      lowerExpressionStatement(stmt, ctx);
      break;

    case 'return_statement':
      lowerReturnStatement(stmt, ctx);
      break;
  }

  ctx.currentSourceLoc = undefined;
}

function lowerVariableDecl(
  stmt: Extract<Statement, { kind: 'variable_decl' }>,
  ctx: LoweringContext,
): void {
  const valueRef = lowerExprToRef(stmt.init, ctx);
  ctx.addLocal(stmt.name);

  // Track byte-typed locals so equality comparisons use OP_EQUAL
  if (isByteTypedExpr(stmt.init, ctx)) {
    ctx.addLocalByteVar(stmt.name);
  }

  // Emit a binding that aliases the variable name to the computed value.
  // We load the temp as a const reference to the computed value.
  ctx.emitNamed(stmt.name, { kind: 'load_const', value: `@ref:${valueRef}` });
}

function lowerAssignment(
  stmt: Extract<Statement, { kind: 'assignment' }>,
  ctx: LoweringContext,
): void {
  const valueRef = lowerExprToRef(stmt.value, ctx);

  // this.x = expr -> update_prop
  if (stmt.target.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: stmt.target.property, value: valueRef });
    return;
  }

  // local = expr -> re-bind (in ANF, this is just a new binding with the same name)
  if (stmt.target.kind === 'identifier') {
    ctx.emitNamed(stmt.target.name, { kind: 'load_const', value: `@ref:${valueRef}` });
    return;
  }

  // For other targets (index access, etc.), lower the target and emit.
  // In practice, index-access assignment would need more sophisticated lowering.
  lowerExprToRef(stmt.target, ctx);
}

function lowerIfStatement(
  stmt: Extract<Statement, { kind: 'if_statement' }>,
  ctx: LoweringContext,
): void {
  const condRef = lowerExprToRef(stmt.condition, ctx);

  // Lower then-block into sub-context
  const thenCtx = ctx.subContext();
  lowerStatements(stmt.then, thenCtx);
  ctx.syncCounter(thenCtx);

  // Lower else-block into sub-context
  const elseCtx = ctx.subContext();
  if (stmt.else) {
    lowerStatements(stmt.else, elseCtx);
  }
  ctx.syncCounter(elseCtx);

  const ifName = ctx.emit({
    kind: 'if',
    cond: condRef,
    then: thenCtx.bindings,
    else: elseCtx.bindings,
  });

  // Propagate addOutput refs from sub-contexts: when both branches produce
  // the same number of addOutput calls, the if-expression result represents
  // each addOutput (only one branch executes at runtime).
  const thenOutputRefs = thenCtx.getAddOutputRefs();
  const elseOutputRefs = elseCtx.getAddOutputRefs();
  if (thenOutputRefs.length > 0 || elseOutputRefs.length > 0) {
    // Use the if-expression result as the addOutput ref since only one branch executes
    ctx.addOutputRef(ifName);
  }

  // If both branches end by reassigning the same local variable,
  // alias that variable to the if-expression result so that subsequent
  // references resolve to the branch output, not the dead initial value.
  const thenLast = thenCtx.bindings[thenCtx.bindings.length - 1];
  const elseLast = elseCtx.bindings[elseCtx.bindings.length - 1];
  if (thenLast && elseLast &&
      thenLast.name === elseLast.name &&
      ctx.isLocal(thenLast.name)) {
    ctx.setLocalAlias(thenLast.name, ifName);
  }
}

function lowerForStatement(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
  ctx: LoweringContext,
): void {
  // Extract the loop count from the for-statement.
  // Rúnar requires bounded loops, so we try to determine the count statically.
  const count = extractLoopCount(stmt);

  // Lower body into sub-context
  const bodyCtx = ctx.subContext();
  lowerStatements(stmt.body, bodyCtx);
  ctx.syncCounter(bodyCtx);

  ctx.emit({
    kind: 'loop',
    count,
    body: bodyCtx.bindings,
    iterVar: stmt.init.name,
  });
}

/**
 * Extract a compile-time loop count from a for statement.
 *
 * Supports patterns like:
 *   for (let i = 0n; i < 10n; i++)
 *   for (let i: bigint = 0n; i < N; i++)
 *
 * Returns the count (number of iterations). Falls back to 0 if
 * the pattern is not recognized.
 */
function extractLoopCount(
  stmt: Extract<Statement, { kind: 'for_statement' }>,
): number {
  // Try to extract start value
  const startVal = extractBigIntValue(stmt.init.init);

  // Try to extract the bound from the condition
  if (stmt.condition.kind === 'binary_expr') {
    const boundVal = extractBigIntValue(stmt.condition.right);

    if (startVal !== null && boundVal !== null) {
      const op = stmt.condition.op;
      if (op === '<') return Math.max(0, Number(boundVal - startVal));
      if (op === '<=') return Math.max(0, Number(boundVal - startVal + 1n));
      if (op === '>') return Math.max(0, Number(startVal - boundVal));
      if (op === '>=') return Math.max(0, Number(startVal - boundVal + 1n));
    }

    // If we can at least get the bound, assume start = 0
    if (boundVal !== null) {
      const op = stmt.condition.op;
      if (op === '<') return Number(boundVal);
      if (op === '<=') return Number(boundVal) + 1;
    }
  }

  throw new Error('Cannot determine loop bound at compile time. For-loop bounds must be integer literals.');
}

function extractBigIntValue(expr: Expression): bigint | null {
  if (expr.kind === 'bigint_literal') return expr.value;
  if (expr.kind === 'unary_expr' && expr.op === '-') {
    const inner = extractBigIntValue(expr.operand);
    return inner !== null ? -inner : null;
  }
  return null;
}

function lowerExpressionStatement(
  stmt: Extract<Statement, { kind: 'expression_statement' }>,
  ctx: LoweringContext,
): void {
  lowerExprToRef(stmt.expression, ctx);
}

function lowerReturnStatement(
  stmt: Extract<Statement, { kind: 'return_statement' }>,
  ctx: LoweringContext,
): void {
  if (stmt.value) {
    const ref = lowerExprToRef(stmt.value, ctx);
    // If the returned ref is not the name of the last emitted binding, emit
    // an explicit load so the return value is the last (top-of-stack) binding.
    // This matters when a local variable is returned after control flow (e.g.,
    // `let count = 0n; if (...) { count += 1n; } return count;`).  Without
    // this, the last binding is the if, not `count`, so inlineMethodCall in
    // stack lowering can't find the return value.
    const lastBinding = ctx.bindings[ctx.bindings.length - 1];
    if (lastBinding && lastBinding.name !== ref) {
      ctx.emit({ kind: 'load_const', value: `@ref:${ref}` });
    }
  }
}

// ---------------------------------------------------------------------------
// Expression lowering -- the heart of ANF conversion
// ---------------------------------------------------------------------------

/**
 * Lower an expression to ANF form and return the name of the temp variable
 * holding its value.
 */
function lowerExprToRef(expr: Expression, ctx: LoweringContext): string {
  switch (expr.kind) {
    case 'bigint_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'bool_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'bytestring_literal':
      return ctx.emit({ kind: 'load_const', value: expr.value });

    case 'identifier':
      return lowerIdentifier(expr, ctx);

    case 'property_access':
      // this.txPreimage in StatefulSmartContract -> load_param (it's an implicit param, not a stored property)
      if (ctx.isParam(expr.property)) {
        return ctx.emit({ kind: 'load_param', name: expr.property });
      }
      // this.x -> load_prop
      return ctx.emit({ kind: 'load_prop', name: expr.property });

    case 'member_expr':
      return lowerMemberExpr(expr, ctx);

    case 'binary_expr':
      return lowerBinaryExpr(expr, ctx);

    case 'unary_expr':
      return lowerUnaryExpr(expr, ctx);

    case 'call_expr':
      return lowerCallExpr(expr, ctx);

    case 'ternary_expr':
      return lowerTernaryExpr(expr, ctx);

    case 'index_access':
      return lowerIndexAccess(expr, ctx);

    case 'increment_expr':
      return lowerIncrementExpr(expr, ctx);

    case 'decrement_expr':
      return lowerDecrementExpr(expr, ctx);

    case 'array_literal': {
      const elementRefs = expr.elements.map(elem => lowerExprToRef(elem, ctx));
      return ctx.emit({ kind: 'array_literal', elements: elementRefs });
    }
  }
}

function lowerIdentifier(
  expr: Extract<Expression, { kind: 'identifier' }>,
  ctx: LoweringContext,
): string {
  const name = expr.name;

  // 'this' is not a value in ANF -- it's handled at the member level
  if (name === 'this') {
    return ctx.emit({ kind: 'load_const', value: '@this' });
  }

  // Check if it's a parameter
  if (ctx.isParam(name)) {
    return ctx.emit({ kind: 'load_param', name });
  }

  // Check if it's a local variable -- reference it directly
  // (or use its alias if reassigned by an if-statement)
  if (ctx.isLocal(name)) {
    return ctx.getLocalAlias(name) ?? name;
  }

  // Check if it's a contract property
  if (ctx.isProperty(name)) {
    return ctx.emit({ kind: 'load_prop', name });
  }

  // Assume it's a parameter (method params are the most common case
  // and the context may not have them all registered)
  return ctx.emit({ kind: 'load_param', name });
}

function lowerMemberExpr(
  expr: Extract<Expression, { kind: 'member_expr' }>,
  ctx: LoweringContext,
): string {
  // this.x -> load_prop
  if (expr.object.kind === 'identifier' && expr.object.name === 'this') {
    return ctx.emit({ kind: 'load_prop', name: expr.property });
  }

  // SigHash.ALL etc. -> load constant
  if (expr.object.kind === 'identifier' && expr.object.name === 'SigHash') {
    const sigHashValues: Record<string, bigint> = {
      ALL: 0x01n,
      NONE: 0x02n,
      SINGLE: 0x03n,
      FORKID: 0x40n,
      ANYONECANPAY: 0x80n,
    };
    const val = sigHashValues[expr.property];
    if (val !== undefined) {
      return ctx.emit({ kind: 'load_const', value: val });
    }
  }

  // General member access: lower the object, then emit a method_call placeholder
  const objRef = lowerExprToRef(expr.object, ctx);
  return ctx.emit({ kind: 'method_call', object: objRef, method: expr.property, args: [] });
}

function lowerBinaryExpr(
  expr: Extract<Expression, { kind: 'binary_expr' }>,
  ctx: LoweringContext,
): string {
  const leftRef = lowerExprToRef(expr.left, ctx);
  const rightRef = lowerExprToRef(expr.right, ctx);

  // For equality operators, annotate with operand type so stack lowering
  // can choose OP_EQUAL vs OP_NUMEQUAL.
  const binOp: BinOp = { kind: 'bin_op', op: expr.op, left: leftRef, right: rightRef };
  if (expr.op === '===' || expr.op === '!==') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  // For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
  if (expr.op === '+') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  // For bitwise &, |, ^, annotate byte-typed operands.
  if (expr.op === '&' || expr.op === '|' || expr.op === '^') {
    if (isByteTypedExpr(expr.left, ctx) || isByteTypedExpr(expr.right, ctx)) {
      binOp.result_type = 'bytes';
    }
  }
  return ctx.emit(binOp);
}

function lowerUnaryExpr(
  expr: Extract<Expression, { kind: 'unary_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const unaryOp: ANFUnaryOp = { kind: 'unary_op', op: expr.op, operand: operandRef };
  // For ~, annotate byte-typed operands so downstream passes know the result is bytes.
  if (expr.op === '~' && isByteTypedExpr(expr.operand, ctx)) {
    unaryOp.result_type = 'bytes';
  }
  return ctx.emit(unaryOp);
}

function lowerCallExpr(
  expr: Extract<Expression, { kind: 'call_expr' }>,
  ctx: LoweringContext,
): string {
  const callee = expr.callee;

  // super(...) call -- emit property initializations
  if (callee.kind === 'identifier' && callee.name === 'super') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    return ctx.emit({ kind: 'call', func: 'super', args: argRefs });
  }

  // assert(expr) -> flatten to assert value
  if (callee.kind === 'identifier' && callee.name === 'assert') {
    if (expr.args.length >= 1) {
      const valueRef = lowerExprToRef(expr.args[0]!, ctx);
      return ctx.emit({ kind: 'assert', value: valueRef });
    }
    // assert() with no args -- should have been caught by validator
    return ctx.emit({ kind: 'assert', value: ctx.emit({ kind: 'load_const', value: false }) });
  }

  // checkPreimage(preimage) -> special node
  if (callee.kind === 'identifier' && callee.name === 'checkPreimage') {
    if (expr.args.length >= 1) {
      const preimageRef = lowerExprToRef(expr.args[0]!, ctx);
      return ctx.emit({ kind: 'check_preimage', preimage: preimageRef });
    }
  }

  // this.addOutput(satoshis, val1, val2, ...) -> special node
  if (callee.kind === 'property_access' && callee.property === 'addOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const stateValues = argRefs.slice(1);
    const ref = ctx.emit({ kind: 'add_output', satoshis, stateValues, preimage: '' });
    ctx.addOutputRef(ref);
    return ref;
  }

  // this.addRawOutput(satoshis, scriptBytes) -> special node
  if (callee.kind === 'property_access' && callee.property === 'addRawOutput') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    const satoshis = argRefs[0]!;
    const scriptBytes = argRefs[1]!;
    const ref = ctx.emit({ kind: 'add_raw_output', satoshis, scriptBytes });
    ctx.addOutputRef(ref);
    return ref;
  }

  // this.getStateScript() -> special node
  if (callee.kind === 'property_access' && callee.property === 'getStateScript') {
    return ctx.emit({ kind: 'get_state_script' });
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      callee.object.name === 'this' &&
      callee.property === 'getStateScript') {
    return ctx.emit({ kind: 'get_state_script' });
  }

  // this.method(...) -> method_call
  if (callee.kind === 'property_access') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    return ctx.emit({
      kind: 'method_call',
      object: ctx.emit({ kind: 'load_const', value: '@this' }),
      method: callee.property,
      args: argRefs,
    });
  }
  if (callee.kind === 'member_expr' &&
      callee.object.kind === 'identifier' &&
      callee.object.name === 'this') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    return ctx.emit({
      kind: 'method_call',
      object: ctx.emit({ kind: 'load_const', value: '@this' }),
      method: callee.property,
      args: argRefs,
    });
  }

  // Direct function call: sha256(x), checkSig(sig, pk), etc.
  if (callee.kind === 'identifier') {
    const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
    return ctx.emit({ kind: 'call', func: callee.name, args: argRefs });
  }

  // General call expression
  const calleeRef = lowerExprToRef(callee, ctx);
  const argRefs = expr.args.map(arg => lowerExprToRef(arg, ctx));
  return ctx.emit({ kind: 'method_call', object: calleeRef, method: 'call', args: argRefs });
}

function lowerTernaryExpr(
  expr: Extract<Expression, { kind: 'ternary_expr' }>,
  ctx: LoweringContext,
): string {
  const condRef = lowerExprToRef(expr.condition, ctx);

  const thenCtx = ctx.subContext();
  lowerExprToRef(expr.consequent, thenCtx);
  ctx.syncCounter(thenCtx);

  const elseCtx = ctx.subContext();
  lowerExprToRef(expr.alternate, elseCtx);
  ctx.syncCounter(elseCtx);

  return ctx.emit({
    kind: 'if',
    cond: condRef,
    then: thenCtx.bindings,
    else: elseCtx.bindings,
  });
}

function lowerIndexAccess(
  expr: Extract<Expression, { kind: 'index_access' }>,
  ctx: LoweringContext,
): string {
  const objRef = lowerExprToRef(expr.object, ctx);
  const indexRef = lowerExprToRef(expr.index, ctx);

  // Index access is lowered as a call to an internal accessor function
  return ctx.emit({
    kind: 'call',
    func: '__array_access',
    args: [objRef, indexRef],
  });
}

function lowerIncrementExpr(
  expr: Extract<Expression, { kind: 'increment_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const oneRef = ctx.emit({ kind: 'load_const', value: 1n });
  const result = ctx.emit({ kind: 'bin_op', op: '+', left: operandRef, right: oneRef });

  // If the operand is a named variable, update it
  if (expr.operand.kind === 'identifier') {
    ctx.emitNamed(expr.operand.name, { kind: 'load_const', value: `@ref:${result}` });
  }
  if (expr.operand.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: expr.operand.property, value: result });
  }

  // Prefix: return new value. Postfix: return original value.
  return expr.prefix ? result : operandRef;
}

function lowerDecrementExpr(
  expr: Extract<Expression, { kind: 'decrement_expr' }>,
  ctx: LoweringContext,
): string {
  const operandRef = lowerExprToRef(expr.operand, ctx);
  const oneRef = ctx.emit({ kind: 'load_const', value: 1n });
  const result = ctx.emit({ kind: 'bin_op', op: '-', left: operandRef, right: oneRef });

  // If the operand is a named variable, update it
  if (expr.operand.kind === 'identifier') {
    ctx.emitNamed(expr.operand.name, { kind: 'load_const', value: `@ref:${result}` });
  }
  if (expr.operand.kind === 'property_access') {
    ctx.emit({ kind: 'update_prop', name: expr.operand.property, value: result });
  }

  return expr.prefix ? result : operandRef;
}

// ---------------------------------------------------------------------------
// Type inference helpers for equality semantics
// ---------------------------------------------------------------------------

/** Byte-typed primitive names — values that are already byte sequences. */
const BYTE_TYPES = new Set([
  'ByteString', 'PubKey', 'Sig', 'Sha256', 'Ripemd160', 'Addr', 'SigHashPreimage', 'Point',
]);

/** Builtin functions that return byte-typed values. */
const BYTE_RETURNING_FUNCTIONS = new Set([
  'sha256', 'ripemd160', 'hash160', 'hash256', 'cat', 'num2bin', 'int2str',
  'reverseBytes', 'substr', 'left', 'right',
  'ecAdd', 'ecMul', 'ecMulGen', 'ecNegate', 'ecMakePoint', 'ecEncodeCompressed',
  'extractOutpoint', 'extractHashPrevouts', 'extractHashSequence', 'extractOutputHash',
  'extractVersion', 'extractLocktime', 'extractSigHashType',
  'blake3Compress', 'blake3Hash',
]);

/**
 * Determine whether an expression is byte-typed (ByteString, PubKey, Sig, etc.).
 * This is a best-effort heuristic used to annotate equality operators.
 */
function isByteTypedExpr(expr: Expression, ctx: LoweringContext): boolean {
  switch (expr.kind) {
    case 'bytestring_literal':
      return true;

    case 'identifier': {
      // Check if it's a parameter or property with a byte type
      const paramType = ctx.getParamType(expr.name);
      if (paramType && BYTE_TYPES.has(paramType)) return true;
      const propType = ctx.getPropertyType(expr.name);
      if (propType && BYTE_TYPES.has(propType)) return true;
      // Check if it's a local variable known to be byte-typed
      if (ctx.isLocalByteVar(expr.name)) return true;
      return false;
    }

    case 'property_access': {
      // this.x — check the property type
      const propType = ctx.getPropertyType(expr.property);
      if (propType && BYTE_TYPES.has(propType)) return true;
      return false;
    }

    case 'member_expr': {
      if (expr.object.kind === 'identifier' && expr.object.name === 'this') {
        const propType = ctx.getPropertyType(expr.property);
        if (propType && BYTE_TYPES.has(propType)) return true;
      }
      return false;
    }

    case 'call_expr': {
      // sha256(x), hash160(x), etc.
      if (expr.callee.kind === 'identifier' && BYTE_RETURNING_FUNCTIONS.has(expr.callee.name)) {
        return true;
      }
      return false;
    }

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function typeNodeToString(node: TypeNode): string {
  switch (node.kind) {
    case 'primitive_type':
      return node.name;
    case 'fixed_array_type':
      return `FixedArray<${typeNodeToString(node.element)}, ${node.length}>`;
    case 'custom_type':
      return node.name;
  }
}

// ---------------------------------------------------------------------------
// State mutation analysis for StatefulSmartContract
// ---------------------------------------------------------------------------

/**
 * Determine whether a method mutates any mutable (non-readonly) property.
 * Conservative: if ANY code path can mutate state, returns true.
 */
function methodMutatesState(
  method: { body: Statement[] },
  contract: ContractNode,
): boolean {
  const mutablePropNames = new Set(
    contract.properties.filter(p => !p.readonly).map(p => p.name),
  );
  if (mutablePropNames.size === 0) return false;
  return bodyMutatesState(method.body, mutablePropNames);
}

function bodyMutatesState(stmts: Statement[], mutableProps: Set<string>): boolean {
  for (const stmt of stmts) {
    if (stmtMutatesState(stmt, mutableProps)) return true;
  }
  return false;
}

function stmtMutatesState(stmt: Statement, mutableProps: Set<string>): boolean {
  switch (stmt.kind) {
    case 'assignment':
      if (stmt.target.kind === 'property_access' && mutableProps.has(stmt.target.property)) {
        return true;
      }
      return false;
    case 'expression_statement':
      return exprMutatesState(stmt.expression, mutableProps);
    case 'if_statement':
      return bodyMutatesState(stmt.then, mutableProps) ||
             (stmt.else ? bodyMutatesState(stmt.else, mutableProps) : false);
    case 'for_statement':
      return stmtMutatesState(stmt.update, mutableProps) ||
             bodyMutatesState(stmt.body, mutableProps);
    default:
      return false;
  }
}

function exprMutatesState(expr: Expression, mutableProps: Set<string>): boolean {
  if (expr.kind === 'increment_expr' || expr.kind === 'decrement_expr') {
    if (expr.operand.kind === 'property_access' && mutableProps.has(expr.operand.property)) {
      return true;
    }
  }
  return false;
}

function methodHasAddOutput(method: { body: Statement[] }): boolean {
  return bodyHasAddOutput(method.body);
}

function bodyHasAddOutput(stmts: Statement[]): boolean {
  for (const stmt of stmts) {
    if (stmtHasAddOutput(stmt)) return true;
  }
  return false;
}

function stmtHasAddOutput(stmt: Statement): boolean {
  switch (stmt.kind) {
    case 'expression_statement':
      return exprHasAddOutput(stmt.expression);
    case 'if_statement':
      return bodyHasAddOutput(stmt.then) ||
             (stmt.else ? bodyHasAddOutput(stmt.else) : false);
    case 'for_statement':
      return bodyHasAddOutput(stmt.body);
    default:
      return false;
  }
}

function exprHasAddOutput(expr: Expression): boolean {
  if (expr.kind === 'call_expr' && expr.callee.kind === 'property_access' &&
      (expr.callee.property === 'addOutput' || expr.callee.property === 'addRawOutput')) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Post-ANF pass: lift update_prop from if-else branches
// ---------------------------------------------------------------------------
//
// Transforms if-else chains where each branch ends with update_prop into
// flat conditional assignments. This prevents phantom stack entries in
// stack lowering.
//
// Before:
//   if (pos === 0) { this.c0 = turn; }
//   else if (pos === 1) { this.c1 = turn; }
//   else { this.c4 = turn; }
//
// After:
//   this.c0 = (pos === 0) ? turn : this.c0;
//   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;
//   this.c4 = (!cond0 && !cond1) ? turn : this.c4;

interface UpdateBranch {
  /** Bindings that compute this branch's condition (hoisted from nested else). */
  condSetupBindings: ANFBinding[];
  /** Temp holding this branch's local condition (null for final else). */
  condRef: string | null;
  /** Property being updated. */
  propName: string;
  /** Bindings that compute the new value (everything before update_prop in the branch). */
  valueBindings: ANFBinding[];
  /** Temp holding the new value (from the update_prop). */
  valueRef: string;
}

/**
 * Recursively collect branches from a nested if-else chain where every
 * branch ends with exactly one update_prop.
 */
function collectUpdateBranches(
  ifCond: string,
  thenBindings: ANFBinding[],
  elseBindings: ANFBinding[],
): UpdateBranch[] | null {
  const thenUpdate = extractBranchUpdate(thenBindings);
  if (!thenUpdate) return null;

  const branches: UpdateBranch[] = [{
    condSetupBindings: [],
    condRef: ifCond,
    ...thenUpdate,
  }];

  if (elseBindings.length === 0) return null;

  // Check if else is another if (else-if chain)
  const lastElse = elseBindings[elseBindings.length - 1]!;
  if (lastElse.value.kind === 'if') {
    const innerIf = lastElse.value;
    const condSetup = elseBindings.slice(0, -1);
    if (!allBindingsSideEffectFree(condSetup)) return null;

    const innerBranches = collectUpdateBranches(
      innerIf.cond, innerIf.then, innerIf.else,
    );
    if (!innerBranches) return null;

    // Prepend condition setup to first inner branch
    innerBranches[0]!.condSetupBindings = [
      ...condSetup,
      ...innerBranches[0]!.condSetupBindings,
    ];
    branches.push(...innerBranches);
    return branches;
  }

  // Otherwise, else branch should end with update_prop (final else)
  const elseUpdate = extractBranchUpdate(elseBindings);
  if (elseUpdate) {
    branches.push({
      condSetupBindings: [],
      condRef: null,
      ...elseUpdate,
    });
    return branches;
  }

  // Handle unreachable else: assert(false) as the final else is dead code.
  // We can still transform the preceding branches — each branch's condition
  // fully guards its update, and the else path never executes.
  if (isAssertFalseElse(elseBindings)) {
    return branches;
  }

  return null;
}

function extractBranchUpdate(
  bindings: ANFBinding[],
): { propName: string; valueBindings: ANFBinding[]; valueRef: string } | null {
  if (bindings.length === 0) return null;
  const last = bindings[bindings.length - 1]!;
  if (last.value.kind !== 'update_prop') return null;
  const valueBindings = bindings.slice(0, -1);
  if (!allBindingsSideEffectFree(valueBindings)) return null;
  return {
    propName: last.value.name,
    valueRef: last.value.value,
    valueBindings,
  };
}

/**
 * Check if an else branch is just `assert(false)` — unreachable dead code
 * that acts as a safety net in position dispatch chains.
 */
function isAssertFalseElse(bindings: ANFBinding[]): boolean {
  if (bindings.length === 0) return false;
  const last = bindings[bindings.length - 1]!;
  if (last.value.kind !== 'assert') return false;

  // The assert's value should reference a binding that is load_const false
  const assertRef = last.value.value;
  const refBinding = bindings.find(b => b.name === assertRef);
  if (refBinding && refBinding.value.kind === 'load_const' && refBinding.value.value === false) {
    return true;
  }

  return false;
}

function allBindingsSideEffectFree(bindings: ANFBinding[]): boolean {
  return bindings.every(b => {
    const k = b.value.kind;
    return k === 'load_prop' || k === 'load_param' || k === 'load_const' ||
           k === 'bin_op' || k === 'unary_op';
  });
}

/**
 * Find the max temp index in a binding tree (e.g. t47 → 47).
 */
function maxTempIndex(bindings: ANFBinding[]): number {
  let max = -1;
  for (const b of bindings) {
    const m = b.name.match(/^t(\d+)$/);
    if (m) max = Math.max(max, parseInt(m[1]!));
    if (b.value.kind === 'if') {
      max = Math.max(max, maxTempIndex(b.value.then), maxTempIndex(b.value.else));
    } else if (b.value.kind === 'loop') {
      max = Math.max(max, maxTempIndex(b.value.body));
    }
  }
  return max;
}

/**
 * Remap temp references in an ANF value according to a name mapping.
 */
function remapValueRefs(value: ANFValue, map: Record<string, string>): ANFValue {
  const r = (ref: string) => map[ref] || ref;
  switch (value.kind) {
    case 'load_param':
    case 'load_prop':
    case 'get_state_script':
      return value;
    case 'load_const': {
      if (typeof value.value === 'string' && value.value.startsWith('@ref:')) {
        const target = value.value.slice(5);
        const remapped = map[target];
        if (remapped) return { ...value, value: `@ref:${remapped}` };
      }
      return value;
    }
    case 'bin_op':
      return { ...value, left: r(value.left), right: r(value.right) };
    case 'unary_op':
      return { ...value, operand: r(value.operand) };
    case 'call':
      return { ...value, args: value.args.map(r) };
    case 'method_call':
      return { ...value, object: r(value.object), args: value.args.map(r) };
    case 'assert':
      return { ...value, value: r(value.value) };
    case 'update_prop':
      return { ...value, value: r(value.value) };
    case 'check_preimage':
      return { ...value, preimage: r(value.preimage) };
    case 'deserialize_state':
      return { ...value, preimage: r(value.preimage) };
    case 'add_output':
      return { ...value, satoshis: r(value.satoshis), stateValues: value.stateValues.map(r), preimage: r(value.preimage) };
    case 'add_raw_output':
      return { ...value, satoshis: r(value.satoshis), scriptBytes: r(value.scriptBytes) };
    case 'if':
      return { ...value, cond: r(value.cond) };
    case 'loop':
      return value;
    default:
      return value;
  }
}

/**
 * Walk a method body and transform if-bindings whose branches all end
 * with update_prop into flat conditional assignments.
 */
function liftBranchUpdateProps(bindings: ANFBinding[]): ANFBinding[] {
  let nextIdx = maxTempIndex(bindings) + 1;
  const fresh = () => `t${nextIdx++}`;

  const result: ANFBinding[] = [];

  for (const binding of bindings) {
    if (binding.value.kind !== 'if') {
      result.push(binding);
      continue;
    }

    const ifVal = binding.value;
    const branches = collectUpdateBranches(ifVal.cond, ifVal.then, ifVal.else);

    if (!branches || branches.length < 2) {
      result.push(binding);
      continue;
    }

    // --- Transform: flatten into conditional assignments ---

    // 1. Hoist condition setup bindings with fresh names
    const nameMap: Record<string, string> = {};
    const condRefs: (string | null)[] = [];

    for (const branch of branches) {
      for (const csb of branch.condSetupBindings) {
        const newName = fresh();
        nameMap[csb.name] = newName;
        result.push({ name: newName, value: remapValueRefs(csb.value, nameMap) });
      }
      condRefs.push(
        branch.condRef
          ? (nameMap[branch.condRef] || branch.condRef)
          : null,
      );
    }

    // 2. Compute effective condition for each branch
    //    Branch 0: cond0
    //    Branch k>0: !cond0 && !cond1 && ... && !cond(k-1) && cond_k
    //    Final else: !cond0 && !cond1 && ... && !cond(N-2)
    const effectiveConds: string[] = [];
    const negatedConds: string[] = [];

    for (let i = 0; i < branches.length; i++) {
      if (i === 0) {
        effectiveConds.push(condRefs[0]!);
        continue;
      }

      // Negate any prior conditions not yet negated
      for (let j = negatedConds.length; j < i; j++) {
        if (condRefs[j] === null) continue;
        const negName = fresh();
        result.push({
          name: negName,
          value: { kind: 'unary_op', op: '!', operand: condRefs[j]! },
        });
        negatedConds.push(negName);
      }

      // AND all negated conditions together
      let andRef = negatedConds[0]!;
      for (let j = 1; j < Math.min(i, negatedConds.length); j++) {
        const andName = fresh();
        result.push({
          name: andName,
          value: { kind: 'bin_op', op: '&&', left: andRef, right: negatedConds[j]! },
        });
        andRef = andName;
      }

      if (condRefs[i] !== null) {
        // Middle branch: AND with own condition
        const finalName = fresh();
        result.push({
          name: finalName,
          value: { kind: 'bin_op', op: '&&', left: andRef, right: condRefs[i]! },
        });
        effectiveConds.push(finalName);
      } else {
        // Final else: just the AND of negations
        effectiveConds.push(andRef);
      }
    }

    // 3. For each branch, emit: load_old, conditional if-expression, update_prop
    for (let i = 0; i < branches.length; i++) {
      const branch = branches[i]!;

      // Load old property value
      const oldPropRef = fresh();
      result.push({
        name: oldPropRef,
        value: { kind: 'load_prop', name: branch.propName },
      });

      // Remap value bindings for the then-branch
      const branchMap: Record<string, string> = { ...nameMap };
      const thenBindings: ANFBinding[] = [];
      for (const vb of branch.valueBindings) {
        const newName = fresh();
        branchMap[vb.name] = newName;
        thenBindings.push({
          name: newName,
          value: remapValueRefs(vb.value, branchMap),
        });
      }

      // Else branch: keep old property value
      const keepName = fresh();
      const elseBindings: ANFBinding[] = [
        { name: keepName, value: { kind: 'load_const', value: `@ref:${oldPropRef}` } },
      ];

      // Emit conditional if-expression
      const condIfRef = fresh();
      result.push({
        name: condIfRef,
        value: {
          kind: 'if',
          cond: effectiveConds[i]!,
          then: thenBindings,
          else: elseBindings,
        },
      });

      // Emit update_prop
      result.push({
        name: fresh(),
        value: { kind: 'update_prop', name: branch.propName, value: condIfRef },
      });
    }
  }

  return result;
}
