//! Pass 4: ANF Lower
//!
//! Lowers the Rúnar AST to A-Normal Form (ANF) IR. This is the critical
//! transformation pass -- it flattens all nested expressions into a sequence
//! of let-bindings where every right-hand side is a simple value.
//!
//! Example:
//!   assert(checkSig(sig, this.pk))
//! becomes:
//!   let t0 = load_param("sig")
//!   let t1 = load_prop("pk")
//!   let t2 = call("checkSig", [t0, t1])
//!   let t3 = assert(t2)
//!
//! This matches the TypeScript reference compiler's 04-anf-lower.ts exactly.
//! Key design decisions:
//! - No parameter pre-loading (params are loaded lazily on first reference)
//! - addParam is never called (matching TS where addParam exists but is unused)
//! - Local variables are tracked via localNames set
//! - Properties are checked against the contract

use std::collections::{HashMap, HashSet};

use super::ast::*;
use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lower a type-checked Rúnar AST to ANF IR.
pub fn lower_to_anf(contract: &ContractNode) -> ANFProgram {
    let properties = lower_properties(contract);
    let mut methods = lower_methods(contract);

    // Post-process: lift nested if-else chains with update_prop into flat
    // conditional assignments. This matches the TS reference compiler's
    // liftBranchUpdateProps transformation (04-anf-lower.ts line 50).
    for method in &mut methods {
        method.body = lift_branch_update_props(method.body.clone());
    }

    ANFProgram {
        contract_name: contract.name.clone(),
        properties,
        methods,
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

fn lower_properties(contract: &ContractNode) -> Vec<ANFProperty> {
    contract
        .properties
        .iter()
        .map(|prop| ANFProperty {
            name: prop.name.clone(),
            prop_type: type_node_to_string(&prop.prop_type),
            readonly: prop.readonly,
            initial_value: prop.initializer.as_ref().and_then(extract_literal_value),
        })
        .collect()
}

fn extract_literal_value(expr: &Expression) -> Option<serde_json::Value> {
    match expr {
        Expression::BigIntLiteral { value } => Some(serde_json::Value::Number(
            serde_json::Number::from(*value),
        )),
        Expression::BoolLiteral { value } => Some(serde_json::Value::Bool(*value)),
        Expression::ByteStringLiteral { value } => {
            Some(serde_json::Value::String(value.clone()))
        }
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => {
            if let Expression::BigIntLiteral { value } = operand.as_ref() {
                Some(serde_json::Value::Number(serde_json::Number::from(-*value)))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn lower_methods(contract: &ContractNode) -> Vec<ANFMethod> {
    let mut result = Vec::new();

    // Lower constructor (the TS reference includes the constructor in output)
    let mut ctor_ctx = LoweringContext::new(contract);
    lower_statements(&contract.constructor.body, &mut ctor_ctx);
    result.push(ANFMethod {
        name: "constructor".to_string(),
        params: lower_params(&contract.constructor.params),
        body: ctor_ctx.bindings,
        is_public: false,
    });

    // Lower each method (including private methods as separate entries)
    for method in &contract.methods {
        let mut method_ctx = LoweringContext::new(contract);

        if contract.parent_class == "StatefulSmartContract"
            && method.visibility == Visibility::Public
        {
            // Determine if this method verifies hashOutputs (needs change output support).
            // Methods that use addOutput or mutate state need hashOutputs verification.
            // Non-mutating methods (like close/destroy) don't verify outputs.
            let needs_change_output =
                method_mutates_state(method, contract) || method_has_add_output(method);

            // Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
            // Methods with addOutput don't need it (they build outputs explicitly).
            let needs_new_amount =
                method_mutates_state(method, contract) && !method_has_add_output(method);

            // Register implicit parameters
            if needs_change_output {
                method_ctx.add_param("_changePKH");
                method_ctx.add_param("_changeAmount");
            }
            if needs_new_amount {
                method_ctx.add_param("_newAmount");
            }
            method_ctx.add_param("txPreimage");

            // Inject checkPreimage(txPreimage) at the start
            let preimage_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let check_result = method_ctx.emit(ANFValue::CheckPreimage {
                preimage: preimage_ref,
            });
            method_ctx.emit(ANFValue::Assert {
                value: check_result,
            });

            // Deserialize mutable state from the preimage's scriptCode.
            // On subsequent spends, the state is embedded in the script (after OP_RETURN),
            // so we extract it from the scriptCode field rather than using hardcoded initial values.
            let has_state_prop = contract.properties.iter().any(|p| !p.readonly);
            if has_state_prop {
                let preimage_ref3 = method_ctx.emit(ANFValue::LoadParam {
                    name: "txPreimage".to_string(),
                });
                method_ctx.emit(ANFValue::DeserializeState {
                    preimage: preimage_ref3,
                });
            }

            // Lower the developer's method body
            lower_statements(&method.body, &mut method_ctx);

            // Determine state continuation type
            let add_output_refs = method_ctx.add_output_refs.clone();
            if !add_output_refs.is_empty() || method_mutates_state(method, contract) {
                // Build the P2PKH change output for hashOutputs verification
                let change_pkh_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changePKH".to_string(),
                });
                let change_amount_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changeAmount".to_string(),
                });
                let change_output_ref = method_ctx.emit(ANFValue::Call {
                    func: "buildChangeOutput".to_string(),
                    args: vec![change_pkh_ref, change_amount_ref],
                });

                if !add_output_refs.is_empty() {
                    // Multi-output continuation: concat all outputs + change output, hash
                    let mut accumulated = add_output_refs[0].clone();
                    for i in 1..add_output_refs.len() {
                        accumulated = method_ctx.emit(ANFValue::Call {
                            func: "cat".to_string(),
                            args: vec![accumulated, add_output_refs[i].clone()],
                        });
                    }
                    accumulated = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![accumulated, change_output_ref],
                    });
                    let hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "hash256".to_string(),
                        args: vec![accumulated],
                    });
                    let preimage_ref2 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let output_hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "extractOutputHash".to_string(),
                        args: vec![preimage_ref2],
                    });
                    let eq_ref = method_ctx.emit(ANFValue::BinOp {
                        op: "===".to_string(),
                        left: hash_ref,
                        right: output_hash_ref,
                        result_type: Some("bytes".to_string()),
                    });
                    method_ctx.emit(ANFValue::Assert { value: eq_ref });
                } else {
                    // Single-output continuation: build raw output bytes, concat with change, hash
                    let state_script_ref = method_ctx.emit(ANFValue::GetStateScript {});
                    let preimage_ref2 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let new_amount_ref = method_ctx.emit(ANFValue::LoadParam {
                        name: "_newAmount".to_string(),
                    });
                    let contract_output_ref = method_ctx.emit(ANFValue::Call {
                        func: "computeStateOutput".to_string(),
                        args: vec![preimage_ref2.clone(), state_script_ref, new_amount_ref],
                    });
                    let all_outputs = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![contract_output_ref, change_output_ref],
                    });
                    let hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "hash256".to_string(),
                        args: vec![all_outputs],
                    });
                    let preimage_ref4 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let output_hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "extractOutputHash".to_string(),
                        args: vec![preimage_ref4],
                    });
                    let eq_ref = method_ctx.emit(ANFValue::BinOp {
                        op: "===".to_string(),
                        left: hash_ref,
                        right: output_hash_ref,
                        result_type: Some("bytes".to_string()),
                    });
                    method_ctx.emit(ANFValue::Assert { value: eq_ref });
                }
            }

            // Build augmented params list for ABI
            let mut augmented_params = lower_params(&method.params);
            if needs_change_output {
                augmented_params.push(ANFParam {
                    name: "_changePKH".to_string(),
                    param_type: "Ripemd160".to_string(),
                });
                augmented_params.push(ANFParam {
                    name: "_changeAmount".to_string(),
                    param_type: "bigint".to_string(),
                });
            }
            if needs_new_amount {
                augmented_params.push(ANFParam {
                    name: "_newAmount".to_string(),
                    param_type: "bigint".to_string(),
                });
            }
            augmented_params.push(ANFParam {
                name: "txPreimage".to_string(),
                param_type: "SigHashPreimage".to_string(),
            });

            result.push(ANFMethod {
                name: method.name.clone(),
                params: augmented_params,
                body: method_ctx.bindings,
                is_public: true,
            });
        } else {
            lower_statements(&method.body, &mut method_ctx);
            result.push(ANFMethod {
                name: method.name.clone(),
                params: lower_params(&method.params),
                body: method_ctx.bindings,
                is_public: method.visibility == Visibility::Public,
            });
        }
    }

    result
}

fn lower_params(params: &[ParamNode]) -> Vec<ANFParam> {
    params
        .iter()
        .map(|p| ANFParam {
            name: p.name.clone(),
            param_type: type_node_to_string(&p.param_type),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Lowering context
//
// Mirrors the TypeScript LoweringContext class exactly:
// - No parameter pre-loading (params are loaded lazily on first reference)
// - addParam is never called (matching TS where addParam exists but is unused)
// - Local variables are tracked via localNames set
// - Properties are checked against the contract
// ---------------------------------------------------------------------------

struct LoweringContext<'a> {
    bindings: Vec<ANFBinding>,
    counter: usize,
    contract: &'a ContractNode,
    param_names: HashSet<String>,
    local_names: HashSet<String>,
    add_output_refs: Vec<String>,
    /// Maps local variable names to their current ANF binding name.
    /// Updated after if-statements that reassign locals in both branches.
    local_aliases: HashMap<String, String>,
    /// Tracks local variables known to be byte-typed.
    local_byte_vars: HashSet<String>,
}

impl<'a> LoweringContext<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        LoweringContext {
            bindings: Vec::new(),
            counter: 0,
            contract,
            param_names: HashSet::new(),
            local_names: HashSet::new(),
            add_output_refs: Vec::new(),
            local_aliases: HashMap::new(),
            local_byte_vars: HashSet::new(),
        }
    }

    /// Generate a fresh temporary name.
    fn fresh_temp(&mut self) -> String {
        let name = format!("t{}", self.counter);
        self.counter += 1;
        name
    }

    /// Emit a binding and return the bound name.
    fn emit(&mut self, value: ANFValue) -> String {
        let name = self.fresh_temp();
        self.bindings.push(ANFBinding {
            name: name.clone(),
            value,
        });
        name
    }

    /// Emit a binding with a specific name (for named variables).
    fn emit_named(&mut self, name: &str, value: ANFValue) {
        self.bindings.push(ANFBinding {
            name: name.to_string(),
            value,
        });
    }

    /// Record a parameter name so we know to use load_param for it.
    fn add_param(&mut self, name: &str) {
        self.param_names.insert(name.to_string());
    }

    fn is_param(&self, name: &str) -> bool {
        self.param_names.contains(name)
    }

    /// Record a local variable name.
    fn add_local(&mut self, name: &str) {
        self.local_names.insert(name.to_string());
    }

    fn is_local(&self, name: &str) -> bool {
        self.local_names.contains(name)
    }

    /// Set the current ANF binding for a local variable (after if-statement reassignment).
    fn set_local_alias(&mut self, local_name: &str, binding_name: &str) {
        self.local_aliases
            .insert(local_name.to_string(), binding_name.to_string());
    }

    /// Get the current ANF binding for a local variable, or None if not aliased.
    fn get_local_alias(&self, name: &str) -> Option<&String> {
        self.local_aliases.get(name)
    }

    fn is_property(&self, name: &str) -> bool {
        self.contract.properties.iter().any(|p| p.name == name)
    }

    /// Create a sub-context for nested blocks (if/else, loops).
    /// The counter continues from the parent. Local names, param names, and aliases are shared.
    fn sub_context(&self) -> LoweringContext<'a> {
        let mut sub = LoweringContext::new(self.contract);
        sub.counter = self.counter;
        sub.param_names = self.param_names.clone();
        sub.local_names = self.local_names.clone();
        sub.local_aliases = self.local_aliases.clone();
        sub.local_byte_vars = self.local_byte_vars.clone();
        // Note: add_output_refs is NOT propagated to sub-contexts
        // because addOutput calls in sub-blocks should flow up to
        // the parent context via explicit tracking.
        sub
    }

    /// Sync the counter back from a sub-context.
    fn sync_counter(&mut self, sub: &LoweringContext) {
        if sub.counter > self.counter {
            self.counter = sub.counter;
        }
    }
}

// ---------------------------------------------------------------------------
// Statement lowering
// ---------------------------------------------------------------------------

fn lower_statements(stmts: &[Statement], ctx: &mut LoweringContext) {
    for i in 0..stmts.len() {
        let stmt = &stmts[i];
        // When an if-statement has no else, the then-block ends with return,
        // and there are remaining statements: nest the remaining statements
        // into the else branch. This handles early-return patterns in private methods.
        if let Statement::IfStatement {
            condition,
            then_branch,
            else_branch: None,
            source_location,
        } = stmt
        {
            if i + 1 < stmts.len() && branch_ends_with_return(then_branch) {
                let remaining = stmts[i + 1..].to_vec();
                let modified_if = Statement::IfStatement {
                    condition: condition.clone(),
                    then_branch: then_branch.clone(),
                    else_branch: Some(remaining),
                    source_location: source_location.clone(),
                };
                lower_statement(&modified_if, ctx);
                return;
            }
        }
        lower_statement(stmt, ctx);
    }
}

/// Check if a branch (slice of statements) ends with a return statement,
/// or with an if-statement where both branches end with a return.
fn branch_ends_with_return(stmts: &[Statement]) -> bool {
    if stmts.is_empty() {
        return false;
    }
    let last = &stmts[stmts.len() - 1];
    match last {
        Statement::ReturnStatement { .. } => true,
        Statement::IfStatement {
            then_branch,
            else_branch: Some(else_branch),
            ..
        } => branch_ends_with_return(then_branch) && branch_ends_with_return(else_branch),
        _ => false,
    }
}

fn lower_statement(stmt: &Statement, ctx: &mut LoweringContext) {
    match stmt {
        Statement::VariableDecl {
            name, init, ..
        } => {
            lower_variable_decl(name, init, ctx);
        }
        Statement::Assignment { target, value, .. } => {
            lower_assignment(target, value, ctx);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            lower_if_statement(condition, then_branch, else_branch.as_deref(), ctx);
        }
        Statement::ForStatement {
            init,
            condition,
            body,
            ..
        } => {
            lower_for_statement(init, condition, body, ctx);
        }
        Statement::ExpressionStatement { expression, .. } => {
            lower_expr_to_ref(expression, ctx);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                let ref_name = lower_expr_to_ref(v, ctx);
                // If the returned ref is not the name of the last emitted binding,
                // emit an explicit @ref: alias so the return value is the last
                // (top-of-stack) binding. This matters when a local variable is
                // returned after control flow (e.g., `let count = 0n; if (...) {
                // count += 1n; } return count;`). Without this, the last binding
                // is the if, not `count`, so inline_method_call in stack lowering
                // can't find the return value.
                if let Some(last) = ctx.bindings.last() {
                    if last.name != ref_name {
                        ctx.emit(ANFValue::LoadConst {
                            value: serde_json::Value::String(format!("@ref:{}", ref_name)),
                        });
                    }
                }
            }
        }
    }
}

/// Lower a variable declaration. Matches the TS reference:
/// Lower the init expression, register the variable as local, then emit
/// a named binding that aliases the variable to the computed value via @ref.
fn lower_variable_decl(name: &str, init: &Expression, ctx: &mut LoweringContext) {
    let value_ref = lower_expr_to_ref(init, ctx);
    ctx.add_local(name);
    if is_byte_typed_expr(init, ctx) {
        ctx.local_byte_vars.insert(name.to_string());
    }
    ctx.emit_named(
        name,
        ANFValue::LoadConst {
            value: serde_json::Value::String(format!("@ref:{}", value_ref)),
        },
    );
}

/// Lower an assignment. Matches the TS reference:
/// For this.x = expr -> emit update_prop
/// For local = expr -> emit named binding with @ref alias
fn lower_assignment(target: &Expression, value: &Expression, ctx: &mut LoweringContext) {
    let value_ref = lower_expr_to_ref(value, ctx);

    // this.x = expr -> update_prop
    if let Expression::PropertyAccess { property } = target {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: value_ref,
        });
        return;
    }

    // local = expr -> re-bind (emit a new named binding with @ref)
    if let Expression::Identifier { name } = target {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", value_ref)),
            },
        );
        return;
    }

    // For other targets, lower them
    lower_expr_to_ref(target, ctx);
}

fn lower_if_statement(
    condition: &Expression,
    then_branch: &[Statement],
    else_branch: Option<&[Statement]>,
    ctx: &mut LoweringContext,
) {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    // Lower then-block into sub-context
    let mut then_ctx = ctx.sub_context();
    lower_statements(then_branch, &mut then_ctx);
    ctx.sync_counter(&then_ctx);

    // Lower else-block into sub-context
    let mut else_ctx = ctx.sub_context();
    if let Some(else_stmts) = else_branch {
        lower_statements(else_stmts, &mut else_ctx);
    }
    ctx.sync_counter(&else_ctx);

    let then_bindings = then_ctx.bindings;
    let else_bindings = else_ctx.bindings;

    // If both branches end by reassigning the same local variable,
    // alias that variable to the if-expression result so that subsequent
    // references resolve to the branch output, not the dead initial value.
    let then_last = then_bindings.last();
    let else_last = else_bindings.last();
    let alias_local = match (then_last, else_last) {
        (Some(tl), Some(el)) if tl.name == el.name && ctx.is_local(&tl.name) => {
            Some(tl.name.clone())
        }
        _ => None,
    };

    // Propagate addOutput refs from sub-contexts: when either branch produces
    // addOutput calls, the if-expression result represents each addOutput
    // (only one branch executes at runtime).
    let then_has_outputs = !then_ctx.add_output_refs.is_empty();
    let else_has_outputs = !else_ctx.add_output_refs.is_empty();

    let if_name = ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_bindings,
        else_branch: else_bindings,
    });

    if then_has_outputs || else_has_outputs {
        ctx.add_output_refs.push(if_name.clone());
    }

    if let Some(local_name) = alias_local {
        ctx.set_local_alias(&local_name, &if_name);
    }
}

fn lower_for_statement(
    init: &Statement,
    condition: &Expression,
    body: &[Statement],
    ctx: &mut LoweringContext,
) {
    // Extract the loop count from the for-statement.
    let count = extract_loop_count(init, condition);

    // Extract the iterator variable name
    let iter_var = if let Statement::VariableDecl { name, .. } = init {
        name.clone()
    } else {
        "_i".to_string()
    };

    // Lower body into sub-context
    let mut body_ctx = ctx.sub_context();
    lower_statements(body, &mut body_ctx);
    ctx.sync_counter(&body_ctx);

    ctx.emit(ANFValue::Loop {
        count,
        body: body_ctx.bindings,
        iter_var,
    });
}

/// Extract a compile-time loop count from a for statement.
fn extract_loop_count(init: &Statement, condition: &Expression) -> usize {
    let start_val = if let Statement::VariableDecl { init: init_expr, .. } = init {
        extract_bigint_value(init_expr)
    } else {
        None
    };

    if let Expression::BinaryExpr { op, right, .. } = condition {
        let bound_val = extract_bigint_value(right);

        if let (Some(start), Some(bound)) = (start_val, bound_val) {
            match op {
                BinaryOp::Lt => return (bound - start).max(0) as usize,
                BinaryOp::Le => return (bound - start + 1).max(0) as usize,
                BinaryOp::Gt => return (start - bound).max(0) as usize,
                BinaryOp::Ge => return (start - bound + 1).max(0) as usize,
                _ => {}
            }
        }

        // If we can at least get the bound, assume start = 0
        if let Some(bound) = bound_val {
            match op {
                BinaryOp::Lt => return bound as usize,
                BinaryOp::Le => return (bound + 1) as usize,
                _ => {}
            }
        }
    }

    0
}

fn extract_bigint_value(expr: &Expression) -> Option<i64> {
    match expr {
        Expression::BigIntLiteral { value } => Some(*value),
        Expression::UnaryExpr { op, operand } if *op == UnaryOp::Neg => {
            extract_bigint_value(operand).map(|v| -v)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Expression lowering -- the heart of ANF conversion
//
// Matches the TypeScript lowerExprToRef exactly.
// ---------------------------------------------------------------------------

/// Lower an expression to ANF form and return the name of the temp variable
/// holding its value.
fn lower_expr_to_ref(expr: &Expression, ctx: &mut LoweringContext) -> String {
    match expr {
        Expression::BigIntLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::Number(serde_json::Number::from(*value)),
        }),

        Expression::BoolLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::Bool(*value),
        }),

        Expression::ByteStringLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String(value.clone()),
        }),

        Expression::Identifier { name } => lower_identifier(name, ctx),

        Expression::PropertyAccess { property } => {
            // this.txPreimage in StatefulSmartContract -> load_param (it's an implicit param, not a stored property)
            if ctx.is_param(property) {
                return ctx.emit(ANFValue::LoadParam {
                    name: property.clone(),
                });
            }
            // this.x -> load_prop
            ctx.emit(ANFValue::LoadProp {
                name: property.clone(),
            })
        }

        Expression::MemberExpr { object, property } => lower_member_expr(object, property, ctx),

        Expression::BinaryExpr { op, left, right } => lower_binary_expr(op, left, right, ctx),

        Expression::UnaryExpr { op, operand } => lower_unary_expr(op, operand, ctx),

        Expression::CallExpr { callee, args } => lower_call_expr(callee, args, ctx),

        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => lower_ternary_expr(condition, consequent, alternate, ctx),

        Expression::IndexAccess { object, index } => lower_index_access(object, index, ctx),

        Expression::IncrementExpr { operand, prefix } => {
            lower_increment_expr(operand, *prefix, ctx)
        }

        Expression::DecrementExpr { operand, prefix } => {
            lower_decrement_expr(operand, *prefix, ctx)
        }
    }
}

/// Lower an identifier. Matches the TS reference's lowerIdentifier exactly:
/// 1. 'this' -> load_const "@this"
/// 2. isParam(name) -> load_param (but isParam always false since addParam never called)
/// 3. isLocal(name) -> return name directly (reference the local variable)
/// 4. isProperty(name) -> load_prop
/// 5. default -> load_param (emitted EVERY time, no caching)
fn lower_identifier(name: &str, ctx: &mut LoweringContext) -> String {
    // 'this' is not a value in ANF
    if name == "this" {
        return ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String("@this".to_string()),
        });
    }

    // Check if it's a registered parameter (e.g. txPreimage for StatefulSmartContract)
    if ctx.is_param(name) {
        return ctx.emit(ANFValue::LoadParam {
            name: name.to_string(),
        });
    }

    // Check if it's a local variable -- reference it directly
    // (or use its alias if reassigned by an if-statement)
    if ctx.is_local(name) {
        return ctx
            .get_local_alias(name)
            .cloned()
            .unwrap_or_else(|| name.to_string());
    }

    // Check if it's a contract property
    if ctx.is_property(name) {
        return ctx.emit(ANFValue::LoadProp {
            name: name.to_string(),
        });
    }

    // Default: treat as parameter (this is how params get loaded lazily)
    // Emitted EVERY time, no caching
    ctx.emit(ANFValue::LoadParam {
        name: name.to_string(),
    })
}

fn lower_member_expr(
    object: &Expression,
    property: &str,
    ctx: &mut LoweringContext,
) -> String {
    // this.x -> load_prop (or load_param for implicit params like txPreimage)
    if let Expression::Identifier { name } = object {
        if name == "this" {
            if ctx.is_param(property) {
                return ctx.emit(ANFValue::LoadParam {
                    name: property.to_string(),
                });
            }
            return ctx.emit(ANFValue::LoadProp {
                name: property.to_string(),
            });
        }
    }

    // SigHash.ALL etc. -> load constant
    if let Expression::Identifier { name } = object {
        if name == "SigHash" {
            let val = match property {
                "ALL" => 0x01i64,
                "NONE" => 0x02,
                "SINGLE" => 0x03,
                "FORKID" => 0x40,
                "ANYONECANPAY" => 0x80,
                _ => 0,
            };
            return ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(val)),
            });
        }
    }

    // General member access
    let obj_ref = lower_expr_to_ref(object, ctx);
    ctx.emit(ANFValue::MethodCall {
        object: obj_ref,
        method: property.to_string(),
        args: Vec::new(),
    })
}

fn lower_binary_expr(
    op: &BinaryOp,
    left: &Expression,
    right: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let left_ref = lower_expr_to_ref(left, ctx);
    let right_ref = lower_expr_to_ref(right, ctx);

    // For equality operators, annotate with operand type so stack lowering
    // can choose OP_EQUAL vs OP_NUMEQUAL.
    // For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
    // For bitwise &, |, ^, annotate byte-typed operands.
    let result_type = if op.as_str() == "===" || op.as_str() == "!==" {
        if is_byte_typed_expr(left, ctx) || is_byte_typed_expr(right, ctx) {
            Some("bytes".to_string())
        } else {
            None
        }
    } else if op.as_str() == "&" || op.as_str() == "|" || op.as_str() == "^" {
        if is_byte_typed_expr(left, ctx) || is_byte_typed_expr(right, ctx) {
            Some("bytes".to_string())
        } else {
            None
        }
    } else {
        None
    };

    ctx.emit(ANFValue::BinOp {
        op: op.as_str().to_string(),
        left: left_ref,
        right: right_ref,
        result_type,
    })
}

fn lower_unary_expr(
    op: &UnaryOp,
    operand: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    // For ~, annotate byte-typed operands so downstream passes know the result is bytes.
    let result_type = if op.as_str() == "~" && is_byte_typed_expr(operand, ctx) {
        Some("bytes".to_string())
    } else {
        None
    };
    ctx.emit(ANFValue::UnaryOp {
        op: op.as_str().to_string(),
        operand: operand_ref,
        result_type,
    })
}

fn lower_call_expr(
    callee: &Expression,
    args: &[Expression],
    ctx: &mut LoweringContext,
) -> String {
    // super(...) call
    if let Expression::Identifier { name } = callee {
        if name == "super" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            return ctx.emit(ANFValue::Call {
                func: "super".to_string(),
                args: arg_refs,
            });
        }
    }

    // assert(expr) -> assert value
    if let Expression::Identifier { name } = callee {
        if name == "assert" {
            if !args.is_empty() {
                let value_ref = lower_expr_to_ref(&args[0], ctx);
                return ctx.emit(ANFValue::Assert { value: value_ref });
            }
            let false_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Bool(false),
            });
            return ctx.emit(ANFValue::Assert { value: false_ref });
        }
    }

    // checkPreimage(preimage) -> special node
    if let Expression::Identifier { name } = callee {
        if name == "checkPreimage" {
            if !args.is_empty() {
                let preimage_ref = lower_expr_to_ref(&args[0], ctx);
                return ctx.emit(ANFValue::CheckPreimage {
                    preimage: preimage_ref,
                });
            }
        }
    }

    // this.addOutput(satoshis, val1, val2, ...) -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "addOutput" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
            let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage: String::new() });
            ctx.add_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addOutput(satoshis, val1, val2, ...) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addOutput" {
                let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
                let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage: String::new() });
                ctx.add_output_refs.push(r.clone());
                return r;
            }
        }
    }

    // this.addRawOutput(satoshis, scriptBytes) -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "addRawOutput" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
            let r = ctx.emit(ANFValue::AddRawOutput { satoshis, script_bytes });
            ctx.add_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addRawOutput(satoshis, scriptBytes) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addRawOutput" {
                let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
                let r = ctx.emit(ANFValue::AddRawOutput { satoshis, script_bytes });
                ctx.add_output_refs.push(r.clone());
                return r;
            }
        }
    }

    // this.getStateScript() -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "getStateScript" {
            return ctx.emit(ANFValue::GetStateScript {});
        }
    }
    // this.getStateScript() -> special node (via MemberExpr)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "getStateScript" {
                return ctx.emit(ANFValue::GetStateScript {});
            }
        }
    }

    // this.method(...) -> method_call (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
        let this_ref = ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String("@this".to_string()),
        });
        return ctx.emit(ANFValue::MethodCall {
            object: this_ref,
            method: property.clone(),
            args: arg_refs,
        });
    }

    // this.method(...) -> method_call (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" {
                let arg_refs: Vec<String> =
                    args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let this_ref = ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::String("@this".to_string()),
                });
                return ctx.emit(ANFValue::MethodCall {
                    object: this_ref,
                    method: property.clone(),
                    args: arg_refs,
                });
            }
        }
    }

    // Direct function call: sha256(x), checkSig(sig, pk), etc.
    if let Expression::Identifier { name } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
        return ctx.emit(ANFValue::Call {
            func: name.clone(),
            args: arg_refs,
        });
    }

    // General call expression
    let callee_ref = lower_expr_to_ref(callee, ctx);
    let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
    ctx.emit(ANFValue::MethodCall {
        object: callee_ref,
        method: "call".to_string(),
        args: arg_refs,
    })
}

fn lower_ternary_expr(
    condition: &Expression,
    consequent: &Expression,
    alternate: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    let mut then_ctx = ctx.sub_context();
    lower_expr_to_ref(consequent, &mut then_ctx);
    ctx.sync_counter(&then_ctx);

    let mut else_ctx = ctx.sub_context();
    lower_expr_to_ref(alternate, &mut else_ctx);
    ctx.sync_counter(&else_ctx);

    ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_ctx.bindings,
        else_branch: else_ctx.bindings,
    })
}

fn lower_index_access(
    object: &Expression,
    index: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let obj_ref = lower_expr_to_ref(object, ctx);
    let index_ref = lower_expr_to_ref(index, ctx);

    ctx.emit(ANFValue::Call {
        func: "__array_access".to_string(),
        args: vec![obj_ref, index_ref],
    })
}

fn lower_increment_expr(
    operand: &Expression,
    prefix: bool,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    let one_ref = ctx.emit(ANFValue::LoadConst {
        value: serde_json::Value::Number(serde_json::Number::from(1i64)),
    });
    let result = ctx.emit(ANFValue::BinOp {
        op: "+".to_string(),
        left: operand_ref.clone(),
        right: one_ref,
        result_type: None,
    });

    // If the operand is a named variable, update it
    if let Expression::Identifier { name } = operand {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", result)),
            },
        );
    }
    if let Expression::PropertyAccess { property } = operand {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: result.clone(),
        });
    }

    if prefix {
        result
    } else {
        operand_ref
    }
}

fn lower_decrement_expr(
    operand: &Expression,
    prefix: bool,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    let one_ref = ctx.emit(ANFValue::LoadConst {
        value: serde_json::Value::Number(serde_json::Number::from(1i64)),
    });
    let result = ctx.emit(ANFValue::BinOp {
        op: "-".to_string(),
        result_type: None,
        left: operand_ref.clone(),
        right: one_ref,
    });

    // If the operand is a named variable, update it
    if let Expression::Identifier { name } = operand {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", result)),
            },
        );
    }
    if let Expression::PropertyAccess { property } = operand {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: result.clone(),
        });
    }

    if prefix {
        result
    } else {
        operand_ref
    }
}

// ---------------------------------------------------------------------------
// Type inference helpers for equality semantics
// ---------------------------------------------------------------------------

/// Byte-typed primitive names -- values that are already byte sequences.
const BYTE_TYPES: &[&str] = &[
    "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160", "Addr", "SigHashPreimage",
    "RabinSig", "RabinPubKey", "Point",
];

/// Builtin functions that return byte-typed values.
const BYTE_RETURNING_FUNCTIONS: &[&str] = &[
    "sha256", "ripemd160", "hash160", "hash256", "cat", "num2bin", "int2str",
    "reverseBytes", "substr", "left", "right",
    "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecMakePoint", "ecEncodeCompressed",
    "sha256Compress", "sha256Finalize", "blake3Compress", "blake3Hash",
];

/// Determine whether an expression is byte-typed (ByteString, PubKey, Sig, etc.).
/// This is a best-effort heuristic used to annotate equality operators.
fn is_byte_typed_expr(expr: &Expression, ctx: &LoweringContext) -> bool {
    match expr {
        Expression::ByteStringLiteral { .. } => true,

        Expression::Identifier { name } => {
            // Check if it's a parameter or property with a byte type
            if let Some(t) = get_param_type(name, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            if let Some(t) = get_property_type(name, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            if ctx.local_byte_vars.contains(name.as_str()) {
                return true;
            }
            false
        }

        Expression::PropertyAccess { property } => {
            if let Some(t) = get_property_type(property, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            false
        }

        Expression::MemberExpr { object, property } => {
            if let Expression::Identifier { name } = object.as_ref() {
                if name == "this" {
                    if let Some(t) = get_property_type(property, ctx) {
                        if BYTE_TYPES.contains(&t.as_str()) {
                            return true;
                        }
                    }
                }
            }
            false
        }

        Expression::CallExpr { callee, .. } => {
            if let Expression::Identifier { name } = callee.as_ref() {
                if BYTE_RETURNING_FUNCTIONS.contains(&name.as_str()) {
                    return true;
                }
            }
            false
        }

        _ => false,
    }
}

/// Look up the type of a method parameter by name across all contract methods.
fn get_param_type(name: &str, ctx: &LoweringContext) -> Option<String> {
    // Check constructor params
    for p in &ctx.contract.constructor.params {
        if p.name == name {
            return Some(type_node_to_string(&p.param_type));
        }
    }
    // Check method params
    for method in &ctx.contract.methods {
        for p in &method.params {
            if p.name == name {
                return Some(type_node_to_string(&p.param_type));
            }
        }
    }
    None
}

/// Look up the type of a contract property by name.
fn get_property_type(name: &str, ctx: &LoweringContext) -> Option<String> {
    for p in &ctx.contract.properties {
        if p.name == name {
            return Some(type_node_to_string(&p.prop_type));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn type_node_to_string(node: &TypeNode) -> String {
    match node {
        TypeNode::Primitive(name) => name.as_str().to_string(),
        TypeNode::FixedArray { element, length } => {
            format!("FixedArray<{}, {}>", type_node_to_string(element), length)
        }
        TypeNode::Custom(name) => name.clone(),
    }
}

// ---------------------------------------------------------------------------
// State mutation analysis for StatefulSmartContract
// ---------------------------------------------------------------------------

/// Determine whether a method mutates any mutable (non-readonly) property.
/// Conservative: if ANY code path can mutate state, returns true.
fn method_mutates_state(method: &MethodNode, contract: &ContractNode) -> bool {
    let mutable_prop_names: HashSet<String> = contract
        .properties
        .iter()
        .filter(|p| !p.readonly)
        .map(|p| p.name.clone())
        .collect();
    if mutable_prop_names.is_empty() {
        return false;
    }
    body_mutates_state(&method.body, &mutable_prop_names)
}

fn body_mutates_state(stmts: &[Statement], mutable_props: &HashSet<String>) -> bool {
    for stmt in stmts {
        if stmt_mutates_state(stmt, mutable_props) {
            return true;
        }
    }
    false
}

fn stmt_mutates_state(stmt: &Statement, mutable_props: &HashSet<String>) -> bool {
    match stmt {
        Statement::Assignment { target, .. } => {
            if let Expression::PropertyAccess { property } = target {
                if mutable_props.contains(property) {
                    return true;
                }
            }
            false
        }
        Statement::ExpressionStatement { expression, .. } => {
            expr_mutates_state(expression, mutable_props)
        }
        Statement::IfStatement {
            then_branch,
            else_branch,
            ..
        } => {
            body_mutates_state(then_branch, mutable_props)
                || else_branch
                    .as_ref()
                    .map_or(false, |e| body_mutates_state(e, mutable_props))
        }
        Statement::ForStatement { body, .. } => body_mutates_state(body, mutable_props),
        _ => false,
    }
}

fn expr_mutates_state(expr: &Expression, mutable_props: &HashSet<String>) -> bool {
    match expr {
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            if let Expression::PropertyAccess { property } = operand.as_ref() {
                if mutable_props.contains(property) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// addOutput detection for determining change output necessity
// ---------------------------------------------------------------------------

/// Check if a method body contains any this.addOutput() calls.
fn method_has_add_output(method: &MethodNode) -> bool {
    body_has_add_output(&method.body)
}

fn body_has_add_output(stmts: &[Statement]) -> bool {
    for stmt in stmts {
        if stmt_has_add_output(stmt) {
            return true;
        }
    }
    false
}

fn stmt_has_add_output(stmt: &Statement) -> bool {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => expr_has_add_output(expression),
        Statement::IfStatement {
            then_branch,
            else_branch,
            ..
        } => {
            body_has_add_output(then_branch)
                || else_branch
                    .as_ref()
                    .map_or(false, |e| body_has_add_output(e))
        }
        Statement::ForStatement { body, .. } => body_has_add_output(body),
        _ => false,
    }
}

fn expr_has_add_output(expr: &Expression) -> bool {
    if let Expression::CallExpr { callee, .. } = expr {
        if let Expression::PropertyAccess { property } = callee.as_ref() {
            if property == "addOutput" || property == "addRawOutput" {
                return true;
            }
        }
        if let Expression::MemberExpr { object, property } = callee.as_ref() {
            if let Expression::Identifier { name } = object.as_ref() {
                if name == "this" && (property == "addOutput" || property == "addRawOutput") {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// liftBranchUpdateProps — flatten nested if-else chains with update_prop
// ---------------------------------------------------------------------------
//
// Mirrors the TypeScript reference compiler's `liftBranchUpdateProps` function
// in 04-anf-lower.ts. When an if-else chain has update_prop as the last binding
// in each branch (e.g., placeMove dispatching by position), this transform
// flattens the nesting into a flat series of conditional if-expressions +
// top-level update_prop calls. This is critical for the stack lowering pass,
// which cannot handle deeply nested if-else with update_prop correctly.

struct UpdateBranch {
    cond_setup_bindings: Vec<ANFBinding>,
    cond_ref: Option<String>,
    prop_name: String,
    value_bindings: Vec<ANFBinding>,
    #[allow(dead_code)]
    value_ref: String,
}

/// Find the max temp index (e.g. t47 → 47) in a binding tree.
fn max_temp_index(bindings: &[ANFBinding]) -> i64 {
    let mut max = -1i64;
    for b in bindings {
        if b.name.starts_with('t') {
            if let Ok(n) = b.name[1..].parse::<i64>() {
                if n > max {
                    max = n;
                }
            }
        }
        match &b.value {
            ANFValue::If { then, else_branch, .. } => {
                let t = max_temp_index(then);
                if t > max { max = t; }
                let e = max_temp_index(else_branch);
                if e > max { max = e; }
            }
            ANFValue::Loop { body, .. } => {
                let l = max_temp_index(body);
                if l > max { max = l; }
            }
            _ => {}
        }
    }
    max
}

/// Check if a binding's value is side-effect-free.
fn is_side_effect_free(value: &ANFValue) -> bool {
    matches!(
        value,
        ANFValue::LoadProp { .. }
            | ANFValue::LoadParam { .. }
            | ANFValue::LoadConst { .. }
            | ANFValue::BinOp { .. }
            | ANFValue::UnaryOp { .. }
    )
}

fn all_bindings_side_effect_free(bindings: &[ANFBinding]) -> bool {
    bindings.iter().all(|b| is_side_effect_free(&b.value))
}

/// Extract the update_prop target from a branch's bindings.
/// Returns (prop_name, value_bindings_before_update, value_ref) if the last
/// binding is update_prop and all preceding bindings are side-effect-free.
fn extract_branch_update(bindings: &[ANFBinding]) -> Option<(String, Vec<ANFBinding>, String)> {
    if bindings.is_empty() {
        return None;
    }
    let last = &bindings[bindings.len() - 1];
    if let ANFValue::UpdateProp { name: prop_name, value: val_ref } = &last.value {
        let value_bindings = bindings[..bindings.len() - 1].to_vec();
        if !all_bindings_side_effect_free(&value_bindings) {
            return None;
        }
        Some((prop_name.clone(), value_bindings, val_ref.clone()))
    } else {
        None
    }
}

/// Check if an else branch is just `assert(false)` — unreachable dead code.
fn is_assert_false_else(bindings: &[ANFBinding]) -> bool {
    if bindings.is_empty() {
        return false;
    }
    let last = &bindings[bindings.len() - 1];
    if let ANFValue::Assert { value: assert_ref } = &last.value {
        // Find the binding that assert_ref references
        for b in bindings {
            if b.name == *assert_ref {
                if let ANFValue::LoadConst { value: v } = &b.value {
                    return v == &serde_json::Value::Bool(false);
                }
            }
        }
    }
    false
}

/// Recursively collect update branches from a nested if-else chain.
fn collect_update_branches(
    if_cond: &str,
    then_bindings: &[ANFBinding],
    else_bindings: &[ANFBinding],
) -> Option<Vec<UpdateBranch>> {
    let then_update = extract_branch_update(then_bindings)?;

    let mut branches = vec![UpdateBranch {
        cond_setup_bindings: Vec::new(),
        cond_ref: Some(if_cond.to_string()),
        prop_name: then_update.0,
        value_bindings: then_update.1,
        value_ref: then_update.2,
    }];

    if else_bindings.is_empty() {
        return None;
    }

    // Check if else is another if (else-if chain)
    let last_else = &else_bindings[else_bindings.len() - 1];
    if let ANFValue::If { cond, then, else_branch } = &last_else.value {
        let cond_setup = &else_bindings[..else_bindings.len() - 1];
        if !all_bindings_side_effect_free(cond_setup) {
            return None;
        }

        let mut inner_branches = collect_update_branches(cond, then, else_branch)?;

        // Prepend condition setup to first inner branch
        let mut new_setup = cond_setup.to_vec();
        new_setup.extend(inner_branches[0].cond_setup_bindings.drain(..));
        inner_branches[0].cond_setup_bindings = new_setup;

        branches.extend(inner_branches);
        return Some(branches);
    }

    // Otherwise, else branch should end with update_prop (final else)
    if let Some(else_update) = extract_branch_update(else_bindings) {
        branches.push(UpdateBranch {
            cond_setup_bindings: Vec::new(),
            cond_ref: None,
            prop_name: else_update.0,
            value_bindings: else_update.1,
            value_ref: else_update.2,
        });
        return Some(branches);
    }

    // Handle unreachable else: assert(false)
    if is_assert_false_else(else_bindings) {
        return Some(branches);
    }

    None
}

/// Remap temp references in an ANF value according to a name mapping.
fn remap_value_refs(value: &ANFValue, map: &HashMap<String, String>) -> ANFValue {
    let r = |s: &str| -> String { map.get(s).cloned().unwrap_or_else(|| s.to_string()) };
    match value {
        ANFValue::LoadParam { .. } | ANFValue::LoadProp { .. } | ANFValue::GetStateScript {} => {
            value.clone()
        }
        ANFValue::LoadConst { value: v } => {
            if let Some(s) = v.as_str() {
                if s.starts_with("@ref:") {
                    let target = &s[5..];
                    if let Some(remapped) = map.get(target) {
                        return ANFValue::LoadConst {
                            value: serde_json::Value::String(format!("@ref:{}", remapped)),
                        };
                    }
                }
            }
            value.clone()
        }
        ANFValue::BinOp { op, left, right, result_type } => ANFValue::BinOp {
            op: op.clone(),
            left: r(left),
            right: r(right),
            result_type: result_type.clone(),
        },
        ANFValue::UnaryOp { op, operand, result_type } => ANFValue::UnaryOp {
            op: op.clone(),
            operand: r(operand),
            result_type: result_type.clone(),
        },
        ANFValue::Call { func, args } => ANFValue::Call {
            func: func.clone(),
            args: args.iter().map(|a| r(a)).collect(),
        },
        ANFValue::MethodCall { object, method, args } => ANFValue::MethodCall {
            object: r(object),
            method: method.clone(),
            args: args.iter().map(|a| r(a)).collect(),
        },
        ANFValue::Assert { value: v } => ANFValue::Assert { value: r(v) },
        ANFValue::UpdateProp { name, value: v } => ANFValue::UpdateProp {
            name: name.clone(),
            value: r(v),
        },
        ANFValue::CheckPreimage { preimage } => ANFValue::CheckPreimage {
            preimage: r(preimage),
        },
        ANFValue::DeserializeState { preimage } => ANFValue::DeserializeState {
            preimage: r(preimage),
        },
        ANFValue::AddOutput { satoshis, state_values, preimage } => ANFValue::AddOutput {
            satoshis: r(satoshis),
            state_values: state_values.iter().map(|a| r(a)).collect(),
            preimage: r(preimage),
        },
        ANFValue::AddRawOutput { satoshis, script_bytes } => ANFValue::AddRawOutput {
            satoshis: r(satoshis),
            script_bytes: r(script_bytes),
        },
        ANFValue::ArrayLiteral { elements } => ANFValue::ArrayLiteral {
            elements: elements.iter().map(|e| r(e)).collect(),
        },
        ANFValue::If { cond, then, else_branch } => ANFValue::If {
            cond: r(cond),
            then: then.clone(),
            else_branch: else_branch.clone(),
        },
        ANFValue::Loop { count, body, iter_var } => ANFValue::Loop {
            count: *count,
            body: body.clone(),
            iter_var: iter_var.clone(),
        },
    }
}

/// Transform if-bindings whose branches all end with update_prop into
/// flat conditional assignments. Mirrors TS liftBranchUpdateProps.
fn lift_branch_update_props(bindings: Vec<ANFBinding>) -> Vec<ANFBinding> {
    let mut next_idx = (max_temp_index(&bindings) + 1) as usize;
    let mut fresh = || -> String {
        let name = format!("t{}", next_idx);
        next_idx += 1;
        name
    };

    let mut result: Vec<ANFBinding> = Vec::new();

    for binding in &bindings {
        let if_val = match &binding.value {
            ANFValue::If { cond, then, else_branch } => Some((cond, then, else_branch)),
            _ => None,
        };

        if if_val.is_none() {
            result.push(binding.clone());
            continue;
        }

        let (cond, then_bindings, else_bindings) = if_val.unwrap();

        let branches = collect_update_branches(cond, then_bindings, else_bindings);

        if branches.is_none() || branches.as_ref().map_or(true, |b| b.len() < 2) {
            result.push(binding.clone());
            continue;
        }

        let branches = branches.unwrap();

        // --- Transform: flatten into conditional assignments ---

        // 1. Hoist condition setup bindings with fresh names
        let mut name_map: HashMap<String, String> = HashMap::new();
        let mut cond_refs: Vec<Option<String>> = Vec::new();

        for branch in &branches {
            for csb in &branch.cond_setup_bindings {
                let new_name = fresh();
                name_map.insert(csb.name.clone(), new_name.clone());
                result.push(ANFBinding {
                    name: new_name,
                    value: remap_value_refs(&csb.value, &name_map),
                });
            }
            cond_refs.push(
                branch.cond_ref.as_ref().map(|cr| {
                    name_map.get(cr).cloned().unwrap_or_else(|| cr.clone())
                }),
            );
        }

        // 2. Compute effective condition for each branch
        let mut effective_conds: Vec<String> = Vec::new();
        let mut negated_conds: Vec<String> = Vec::new();

        for i in 0..branches.len() {
            if i == 0 {
                effective_conds.push(cond_refs[0].clone().unwrap());
                continue;
            }

            // Negate any prior conditions not yet negated
            for j in negated_conds.len()..i {
                if cond_refs[j].is_none() {
                    continue;
                }
                let neg_name = fresh();
                result.push(ANFBinding {
                    name: neg_name.clone(),
                    value: ANFValue::UnaryOp {
                        op: "!".to_string(),
                        operand: cond_refs[j].clone().unwrap(),
                        result_type: None,
                    },
                });
                negated_conds.push(neg_name);
            }

            // AND all negated conditions together
            let mut and_ref = negated_conds[0].clone();
            for j in 1..std::cmp::min(i, negated_conds.len()) {
                let and_name = fresh();
                result.push(ANFBinding {
                    name: and_name.clone(),
                    value: ANFValue::BinOp {
                        op: "&&".to_string(),
                        left: and_ref,
                        right: negated_conds[j].clone(),
                        result_type: None,
                    },
                });
                and_ref = and_name;
            }

            if cond_refs[i].is_some() {
                // Middle branch: AND with own condition
                let final_name = fresh();
                result.push(ANFBinding {
                    name: final_name.clone(),
                    value: ANFValue::BinOp {
                        op: "&&".to_string(),
                        left: and_ref,
                        right: cond_refs[i].clone().unwrap(),
                        result_type: None,
                    },
                });
                effective_conds.push(final_name);
            } else {
                // Final else: just the AND of negations
                effective_conds.push(and_ref);
            }
        }

        // 3. For each branch, emit: load_old, conditional if-expression, update_prop
        for (i, branch) in branches.iter().enumerate() {
            // Load old property value
            let old_prop_ref = fresh();
            result.push(ANFBinding {
                name: old_prop_ref.clone(),
                value: ANFValue::LoadProp {
                    name: branch.prop_name.clone(),
                },
            });

            // Remap value bindings for the then-branch
            let mut branch_map = name_map.clone();
            let mut then_bindings: Vec<ANFBinding> = Vec::new();
            for vb in &branch.value_bindings {
                let new_name = fresh();
                branch_map.insert(vb.name.clone(), new_name.clone());
                then_bindings.push(ANFBinding {
                    name: new_name,
                    value: remap_value_refs(&vb.value, &branch_map),
                });
            }

            // Else branch: keep old property value
            let keep_name = fresh();
            let else_bindings = vec![ANFBinding {
                name: keep_name,
                value: ANFValue::LoadConst {
                    value: serde_json::Value::String(format!("@ref:{}", old_prop_ref)),
                },
            }];

            // Emit conditional if-expression
            let cond_if_ref = fresh();
            result.push(ANFBinding {
                name: cond_if_ref.clone(),
                value: ANFValue::If {
                    cond: effective_conds[i].clone(),
                    then: then_bindings,
                    else_branch: else_bindings,
                },
            });

            // Emit update_prop
            result.push(ANFBinding {
                name: fresh(),
                value: ANFValue::UpdateProp {
                    name: branch.prop_name.clone(),
                    value: cond_if_ref,
                },
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::parse_source;
    use crate::frontend::typecheck::typecheck;
    use crate::frontend::validator::validate;

    /// Helper: parse → validate → typecheck → return ContractNode.
    fn must_lower_to_anf(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(
            result.errors.is_empty(),
            "parse errors: {:?}",
            result.errors
        );
        let contract = result.contract.expect("expected a contract from parse");

        let val_result = validate(&contract);
        assert!(
            val_result.errors.is_empty(),
            "validation errors: {:?}",
            val_result.errors
        );

        let tc_result = typecheck(&contract);
        assert!(
            tc_result.errors.is_empty(),
            "type check errors: {:?}",
            tc_result.errors
        );

        contract
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_has_properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_has_properties() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        assert_eq!(program.contract_name, "P2PKH");

        assert_eq!(
            program.properties.len(),
            1,
            "expected 1 property, got {}",
            program.properties.len()
        );
        let prop = &program.properties[0];
        assert_eq!(
            prop.name, "pubKeyHash",
            "expected property name 'pubKeyHash', got '{}'",
            prop.name
        );
        assert_eq!(
            prop.prop_type, "Addr",
            "expected property type 'Addr', got '{}'",
            prop.prop_type
        );
        assert!(prop.readonly, "expected property to be readonly");
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_unlock_has_bindings
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_unlock_has_bindings() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let unlock = program
            .methods
            .iter()
            .find(|m| m.name == "unlock")
            .expect("could not find 'unlock' method in ANF output");

        assert!(unlock.is_public, "expected unlock method to be public");

        assert_eq!(
            unlock.params.len(),
            2,
            "expected 2 params (sig, pubKey), got {}",
            unlock.params.len()
        );
        assert_eq!(unlock.params[0].name, "sig");
        assert_eq!(unlock.params[0].param_type, "Sig");
        assert_eq!(unlock.params[1].name, "pubKey");
        assert_eq!(unlock.params[1].param_type, "PubKey");

        // Count binding kinds — must have at least: 2 load_param, 2 call, 1
        // load_prop, 1 bin_op, 2 assert.
        let mut load_param_count = 0usize;
        let mut call_count = 0usize;
        let mut load_prop_count = 0usize;
        let mut bin_op_count = 0usize;
        let mut assert_count = 0usize;

        for b in &unlock.body {
            match &b.value {
                ANFValue::LoadParam { .. } => load_param_count += 1,
                ANFValue::LoadProp { .. } => load_prop_count += 1,
                ANFValue::Call { .. } => call_count += 1,
                ANFValue::BinOp { .. } => bin_op_count += 1,
                ANFValue::Assert { .. } => assert_count += 1,
                _ => {}
            }
        }

        assert!(
            load_param_count >= 2,
            "expected at least 2 load_param bindings, got {}",
            load_param_count
        );
        assert!(
            call_count >= 2,
            "expected at least 2 call bindings (hash160, checkSig), got {}",
            call_count
        );
        assert!(
            load_prop_count >= 1,
            "expected at least 1 load_prop binding (pubKeyHash), got {}",
            load_prop_count
        );
        assert!(
            bin_op_count >= 1,
            "expected at least 1 bin_op binding (===), got {}",
            bin_op_count
        );
        assert!(
            assert_count >= 2,
            "expected at least 2 assert bindings, got {}",
            assert_count
        );
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_binding_details
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_binding_details() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let unlock = program
            .methods
            .iter()
            .find(|m| m.name == "unlock")
            .expect("could not find 'unlock' method");

        // Verify call to hash160 with 1 argument
        let hash160_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::Call { func, .. } if func == "hash160")
        });
        assert!(
            hash160_binding.is_some(),
            "expected a call to hash160 in unlock method bindings"
        );
        if let Some(b) = hash160_binding {
            if let ANFValue::Call { args, .. } = &b.value {
                assert_eq!(
                    args.len(),
                    1,
                    "hash160 should have 1 arg, got {}",
                    args.len()
                );
            }
        }

        // Verify call to checkSig with 2 arguments
        let checksig_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::Call { func, .. } if func == "checkSig")
        });
        assert!(
            checksig_binding.is_some(),
            "expected a call to checkSig in unlock method bindings"
        );
        if let Some(b) = checksig_binding {
            if let ANFValue::Call { args, .. } = &b.value {
                assert_eq!(
                    args.len(),
                    2,
                    "checkSig should have 2 args, got {}",
                    args.len()
                );
            }
        }

        // Verify bin_op === has result_type "bytes" (byte-typed equality)
        let eq_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "===")
        });
        assert!(
            eq_binding.is_some(),
            "expected a bin_op === in unlock method bindings"
        );
        if let Some(b) = eq_binding {
            if let ANFValue::BinOp { result_type, .. } = &b.value {
                assert_eq!(
                    result_type.as_deref(),
                    Some("bytes"),
                    "expected bin_op === to have result_type 'bytes' (byte-typed equality), got {:?}",
                    result_type
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // test_constructor_included
    // -----------------------------------------------------------------------

    #[test]
    fn test_constructor_included() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class Simple extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(val: bigint): void {
    assert(val === this.x);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        assert!(
            program.methods.len() >= 2,
            "expected at least 2 methods (constructor + check), got {}",
            program.methods.len()
        );

        let ctor = &program.methods[0];
        assert_eq!(
            ctor.name, "constructor",
            "expected first method to be 'constructor', got '{}'",
            ctor.name
        );
        assert!(!ctor.is_public, "constructor should not be public");
    }

    // -----------------------------------------------------------------------
    // test_arithmetic_bindings
    // -----------------------------------------------------------------------

    #[test]
    fn test_arithmetic_bindings() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class ArithTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    assert(a + b === this.target);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let verify = program
            .methods
            .iter()
            .find(|m| m.name == "verify")
            .expect("could not find 'verify' method");

        // Should have a bin_op + for a + b
        let add_binding = verify.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "+")
        });
        assert!(
            add_binding.is_some(),
            "expected bin_op + in verify method for 'a + b'"
        );

        // Should have a bin_op === for equality check
        let eq_binding = verify.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "===")
        });
        assert!(
            eq_binding.is_some(),
            "expected bin_op === in verify method"
        );
    }

    // -----------------------------------------------------------------------
    // test_if_else_lowering
    // Mirrors Python test_anf_lower_if_else
    // -----------------------------------------------------------------------

    #[test]
    fn test_if_else_lowering() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class IfElse extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public check(value: bigint, mode: boolean): void {
    let result: bigint = 0n;
    if (mode) {
      result = value + this.limit;
    } else {
      result = value - this.limit;
    }
    assert(result > 0n);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let check = program
            .methods
            .iter()
            .find(|m| m.name == "check")
            .expect("could not find 'check' method");

        // The if/else construct should produce an ANFValue::If binding
        let has_if_binding = check
            .body
            .iter()
            .any(|b| matches!(b.value, ANFValue::If { .. }));

        assert!(
            has_if_binding,
            "expected an 'if' binding in the ANF output for the if/else construct, got: {:?}",
            check.body.iter().map(|b| format!("{:?}", b.value)).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // test_stateful_has_implicit_params
    // Mirrors Python test_typecheck_valid_stateful (checks implicit params in ANF)
    // -----------------------------------------------------------------------

    #[test]
    fn test_stateful_has_implicit_params() {
        let source = r#"
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(amount: bigint): void {
    this.count = this.count + amount;
    assert(this.count > 0n);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let increment = program
            .methods
            .iter()
            .find(|m| m.name == "increment")
            .expect("could not find 'increment' method");

        // A StatefulSmartContract public method should have implicit params injected:
        // txPreimage, _changePKH, _changeAmount
        let param_names: Vec<&str> = increment.params.iter().map(|p| p.name.as_str()).collect();

        assert!(
            param_names.contains(&"txPreimage"),
            "stateful method should have 'txPreimage' as an implicit param, got: {:?}",
            param_names
        );
        assert!(
            param_names.contains(&"_changePKH"),
            "stateful method should have '_changePKH' as an implicit param, got: {:?}",
            param_names
        );
        assert!(
            param_names.contains(&"_changeAmount"),
            "stateful method should have '_changeAmount' as an implicit param, got: {:?}",
            param_names
        );
    }
}
