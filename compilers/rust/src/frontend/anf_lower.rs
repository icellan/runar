//! Pass 4: ANF Lower
//!
//! Lowers the TSOP AST to A-Normal Form (ANF) IR. This is the critical
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

use std::collections::HashSet;

use super::ast::*;
use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lower a type-checked TSOP AST to ANF IR.
pub fn lower_to_anf(contract: &ContractNode) -> ANFProgram {
    let properties = lower_properties(contract);
    let methods = lower_methods(contract);

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
            initial_value: None,
        })
        .collect()
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
        lower_statements(&method.body, &mut method_ctx);
        result.push(ANFMethod {
            name: method.name.clone(),
            params: lower_params(&method.params),
            body: method_ctx.bindings,
            is_public: method.visibility == Visibility::Public,
        });
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
    local_names: HashSet<String>,
}

impl<'a> LoweringContext<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        LoweringContext {
            bindings: Vec::new(),
            counter: 0,
            contract,
            local_names: HashSet::new(),
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

    /// Record a local variable name.
    fn add_local(&mut self, name: &str) {
        self.local_names.insert(name.to_string());
    }

    fn is_local(&self, name: &str) -> bool {
        self.local_names.contains(name)
    }

    fn is_property(&self, name: &str) -> bool {
        self.contract.properties.iter().any(|p| p.name == name)
    }

    /// Create a sub-context for nested blocks (if/else, loops).
    /// The counter continues from the parent. Local names are shared.
    fn sub_context(&self) -> LoweringContext<'a> {
        let mut sub = LoweringContext::new(self.contract);
        sub.counter = self.counter;
        sub.local_names = self.local_names.clone();
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
    for stmt in stmts {
        lower_statement(stmt, ctx);
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
                lower_expr_to_ref(v, ctx);
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

    ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_ctx.bindings,
        else_branch: else_ctx.bindings,
    });
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

    // isParam check: always false since addParam is never called (matching TS)
    // (no check needed)

    // Check if it's a local variable -- reference it directly
    if ctx.is_local(name) {
        return name.to_string();
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
    // this.x -> load_prop
    if let Expression::Identifier { name } = object {
        if name == "this" {
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
    let result_type = if op.as_str() == "===" || op.as_str() == "!==" {
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
    ctx.emit(ANFValue::UnaryOp {
        op: op.as_str().to_string(),
        operand: operand_ref,
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
    "RabinSig", "RabinPubKey",
];

/// Builtin functions that return byte-typed values.
const BYTE_RETURNING_FUNCTIONS: &[&str] = &[
    "sha256", "ripemd160", "hash160", "hash256", "cat", "num2bin", "int2str",
    "reverseBytes", "substr", "left", "right",
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
