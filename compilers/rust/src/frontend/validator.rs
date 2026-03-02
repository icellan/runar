//! Pass 2: Validate
//!
//! Validates the Rúnar AST against the language subset constraints.
//! This pass does NOT modify the AST; it only reports errors and warnings.

use std::collections::{HashMap, HashSet};

use super::ast::*;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of validation.
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate a parsed Rúnar AST against the language subset constraints.
pub fn validate(contract: &ContractNode) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    validate_properties(contract, &mut errors);
    validate_constructor(contract, &mut errors);
    validate_methods(contract, &mut errors);
    check_no_recursion(contract, &mut errors);

    ValidationResult { errors, warnings }
}

// ---------------------------------------------------------------------------
// Valid primitive types for properties
// ---------------------------------------------------------------------------

fn is_valid_property_primitive(name: &PrimitiveTypeName) -> bool {
    match name {
        PrimitiveTypeName::Bigint
        | PrimitiveTypeName::Boolean
        | PrimitiveTypeName::ByteString
        | PrimitiveTypeName::PubKey
        | PrimitiveTypeName::Sig
        | PrimitiveTypeName::Sha256
        | PrimitiveTypeName::Ripemd160
        | PrimitiveTypeName::Addr
        | PrimitiveTypeName::SigHashPreimage
        | PrimitiveTypeName::RabinSig
        | PrimitiveTypeName::RabinPubKey => true,
        PrimitiveTypeName::Void => false,
    }
}

// ---------------------------------------------------------------------------
// Property validation
// ---------------------------------------------------------------------------

fn validate_properties(contract: &ContractNode, errors: &mut Vec<String>) {
    for prop in &contract.properties {
        validate_property_type(&prop.prop_type, errors);
    }
}

fn validate_property_type(type_node: &TypeNode, errors: &mut Vec<String>) {
    match type_node {
        TypeNode::Primitive(name) => {
            if !is_valid_property_primitive(name) {
                errors.push(format!("Property type '{}' is not valid", name.as_str()));
            }
        }
        TypeNode::FixedArray { element, length } => {
            if *length == 0 {
                errors.push("FixedArray length must be a positive integer".to_string());
            }
            validate_property_type(element, errors);
        }
        TypeNode::Custom(name) => {
            errors.push(format!(
                "Unsupported type '{}' in property declaration. Use one of: bigint, boolean, ByteString, PubKey, Sig, Sha256, Ripemd160, Addr, SigHashPreimage, RabinSig, RabinPubKey, or FixedArray<T, N>",
                name
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

fn validate_constructor(contract: &ContractNode, errors: &mut Vec<String>) {
    let ctor = &contract.constructor;
    let prop_names: HashSet<String> = contract.properties.iter().map(|p| p.name.clone()).collect();

    // Check that constructor has a super() call as first statement
    if ctor.body.is_empty() {
        errors.push("Constructor must call super() as its first statement".to_string());
        return;
    }

    if !is_super_call(&ctor.body[0]) {
        errors.push("Constructor must call super() as its first statement".to_string());
    }

    // Check that all properties are assigned in constructor
    let mut assigned_props = HashSet::new();
    for stmt in &ctor.body {
        if let Statement::Assignment { target, .. } = stmt {
            if let Expression::PropertyAccess { property } = target {
                assigned_props.insert(property.clone());
            }
        }
    }

    for prop_name in &prop_names {
        if !assigned_props.contains(prop_name) {
            errors.push(format!(
                "Property '{}' must be assigned in the constructor",
                prop_name
            ));
        }
    }

    // Validate constructor params have type annotations
    for param in &ctor.params {
        if let TypeNode::Custom(ref name) = param.param_type {
            if name == "unknown" {
                errors.push(format!(
                    "Constructor parameter '{}' must have a type annotation",
                    param.name
                ));
            }
        }
    }

    // Validate statements in constructor body
    for stmt in &ctor.body {
        validate_statement(stmt, errors);
    }
}

fn is_super_call(stmt: &Statement) -> bool {
    if let Statement::ExpressionStatement { expression, .. } = stmt {
        if let Expression::CallExpr { callee, .. } = expression {
            if let Expression::Identifier { name } = callee.as_ref() {
                return name == "super";
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Method validation
// ---------------------------------------------------------------------------

fn validate_methods(contract: &ContractNode, errors: &mut Vec<String>) {
    for method in &contract.methods {
        validate_method(method, contract, errors);
    }
}

fn validate_method(method: &MethodNode, contract: &ContractNode, errors: &mut Vec<String>) {
    // All params must have type annotations
    for param in &method.params {
        if let TypeNode::Custom(ref name) = param.param_type {
            if name == "unknown" {
                errors.push(format!(
                    "Parameter '{}' in method '{}' must have a type annotation",
                    param.name, method.name
                ));
            }
        }
    }

    // Public methods must end with an assert() call (unless StatefulSmartContract,
    // where the compiler auto-injects the final assert)
    if method.visibility == Visibility::Public && contract.parent_class == "SmartContract" {
        if !ends_with_assert(&method.body) {
            errors.push(format!(
                "Public method '{}' must end with an assert() call",
                method.name
            ));
        }
    }

    // Validate all statements in method body
    for stmt in &method.body {
        validate_statement(stmt, errors);
    }
}

fn ends_with_assert(body: &[Statement]) -> bool {
    if body.is_empty() {
        return false;
    }

    let last = &body[body.len() - 1];

    // Direct assert() call as expression statement
    if let Statement::ExpressionStatement { expression, .. } = last {
        if is_assert_call(expression) {
            return true;
        }
    }

    // If/else where both branches end with assert
    if let Statement::IfStatement {
        then_branch,
        else_branch,
        ..
    } = last
    {
        let then_ends = ends_with_assert(then_branch);
        let else_ends = else_branch
            .as_ref()
            .map_or(false, |e| ends_with_assert(e));
        return then_ends && else_ends;
    }

    false
}

fn is_assert_call(expr: &Expression) -> bool {
    if let Expression::CallExpr { callee, .. } = expr {
        if let Expression::Identifier { name } = callee.as_ref() {
            return name == "assert";
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Statement validation
// ---------------------------------------------------------------------------

fn validate_statement(stmt: &Statement, errors: &mut Vec<String>) {
    match stmt {
        Statement::VariableDecl { init, .. } => {
            validate_expression(init, errors);
        }
        Statement::Assignment { target, value, .. } => {
            validate_expression(target, errors);
            validate_expression(value, errors);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            validate_expression(condition, errors);
            for s in then_branch {
                validate_statement(s, errors);
            }
            if let Some(else_stmts) = else_branch {
                for s in else_stmts {
                    validate_statement(s, errors);
                }
            }
        }
        Statement::ForStatement {
            condition,
            init,
            body,
            ..
        } => {
            validate_expression(condition, errors);

            // Check that the loop bound is a compile-time constant
            if let Expression::BinaryExpr { right, .. } = condition {
                if !is_compile_time_constant(right) {
                    errors.push(
                        "For loop bound must be a compile-time constant (literal or const variable)"
                            .to_string(),
                    );
                }
            }

            // Validate init
            if let Statement::VariableDecl { init: init_expr, .. } = init.as_ref() {
                validate_expression(init_expr, errors);
            }

            // Validate body
            for s in body {
                validate_statement(s, errors);
            }
        }
        Statement::ExpressionStatement { expression, .. } => {
            validate_expression(expression, errors);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                validate_expression(v, errors);
            }
        }
    }
}

fn is_compile_time_constant(expr: &Expression) -> bool {
    match expr {
        Expression::BigIntLiteral { .. } => true,
        Expression::BoolLiteral { .. } => true,
        Expression::Identifier { .. } => true, // Could be a const
        Expression::UnaryExpr { op, operand } if *op == UnaryOp::Neg => {
            is_compile_time_constant(operand)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Expression validation
// ---------------------------------------------------------------------------

fn validate_expression(expr: &Expression, errors: &mut Vec<String>) {
    match expr {
        Expression::BinaryExpr { left, right, .. } => {
            validate_expression(left, errors);
            validate_expression(right, errors);
        }
        Expression::UnaryExpr { operand, .. } => {
            validate_expression(operand, errors);
        }
        Expression::CallExpr { callee, args, .. } => {
            validate_expression(callee, errors);
            for arg in args {
                validate_expression(arg, errors);
            }
        }
        Expression::MemberExpr { object, .. } => {
            validate_expression(object, errors);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            validate_expression(condition, errors);
            validate_expression(consequent, errors);
            validate_expression(alternate, errors);
        }
        Expression::IndexAccess { object, index } => {
            validate_expression(object, errors);
            validate_expression(index, errors);
        }
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            validate_expression(operand, errors);
        }
        // Leaf nodes -- nothing to validate
        Expression::Identifier { .. }
        | Expression::BigIntLiteral { .. }
        | Expression::BoolLiteral { .. }
        | Expression::ByteStringLiteral { .. }
        | Expression::PropertyAccess { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// Recursion detection
// ---------------------------------------------------------------------------

fn check_no_recursion(contract: &ContractNode, errors: &mut Vec<String>) {
    // Build call graph: method name -> set of methods it calls
    let mut call_graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut method_names: HashSet<String> = HashSet::new();

    for method in &contract.methods {
        method_names.insert(method.name.clone());
        let mut calls = HashSet::new();
        collect_method_calls(&method.body, &mut calls);
        call_graph.insert(method.name.clone(), calls);
    }

    // Also add constructor
    {
        let mut calls = HashSet::new();
        collect_method_calls(&contract.constructor.body, &mut calls);
        call_graph.insert("constructor".to_string(), calls);
    }

    // Check for cycles using DFS
    for method in &contract.methods {
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();

        if has_cycle(
            &method.name,
            &call_graph,
            &method_names,
            &mut visited,
            &mut stack,
        ) {
            errors.push(format!(
                "Recursion detected: method '{}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.",
                method.name
            ));
        }
    }
}

fn collect_method_calls(stmts: &[Statement], calls: &mut HashSet<String>) {
    for stmt in stmts {
        collect_method_calls_in_statement(stmt, calls);
    }
}

fn collect_method_calls_in_statement(stmt: &Statement, calls: &mut HashSet<String>) {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => {
            collect_method_calls_in_expr(expression, calls);
        }
        Statement::VariableDecl { init, .. } => {
            collect_method_calls_in_expr(init, calls);
        }
        Statement::Assignment { target, value, .. } => {
            collect_method_calls_in_expr(target, calls);
            collect_method_calls_in_expr(value, calls);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            collect_method_calls_in_expr(condition, calls);
            collect_method_calls(then_branch, calls);
            if let Some(else_stmts) = else_branch {
                collect_method_calls(else_stmts, calls);
            }
        }
        Statement::ForStatement {
            condition, body, ..
        } => {
            collect_method_calls_in_expr(condition, calls);
            collect_method_calls(body, calls);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                collect_method_calls_in_expr(v, calls);
            }
        }
    }
}

fn collect_method_calls_in_expr(expr: &Expression, calls: &mut HashSet<String>) {
    match expr {
        Expression::CallExpr { callee, args, .. } => {
            // Check if callee is `this.methodName` (PropertyAccess variant)
            if let Expression::PropertyAccess { property } = callee.as_ref() {
                calls.insert(property.clone());
            }
            // Also check `this.method` via MemberExpr
            if let Expression::MemberExpr { object, property } = callee.as_ref() {
                if let Expression::Identifier { name } = object.as_ref() {
                    if name == "this" {
                        calls.insert(property.clone());
                    }
                }
            }
            collect_method_calls_in_expr(callee, calls);
            for arg in args {
                collect_method_calls_in_expr(arg, calls);
            }
        }
        Expression::BinaryExpr { left, right, .. } => {
            collect_method_calls_in_expr(left, calls);
            collect_method_calls_in_expr(right, calls);
        }
        Expression::UnaryExpr { operand, .. } => {
            collect_method_calls_in_expr(operand, calls);
        }
        Expression::MemberExpr { object, .. } => {
            collect_method_calls_in_expr(object, calls);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            collect_method_calls_in_expr(condition, calls);
            collect_method_calls_in_expr(consequent, calls);
            collect_method_calls_in_expr(alternate, calls);
        }
        Expression::IndexAccess { object, index } => {
            collect_method_calls_in_expr(object, calls);
            collect_method_calls_in_expr(index, calls);
        }
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            collect_method_calls_in_expr(operand, calls);
        }
        // Leaf nodes
        _ => {}
    }
}

fn has_cycle(
    method_name: &str,
    call_graph: &HashMap<String, HashSet<String>>,
    method_names: &HashSet<String>,
    visited: &mut HashSet<String>,
    stack: &mut HashSet<String>,
) -> bool {
    if stack.contains(method_name) {
        return true;
    }
    if visited.contains(method_name) {
        return false;
    }

    visited.insert(method_name.to_string());
    stack.insert(method_name.to_string());

    if let Some(calls) = call_graph.get(method_name) {
        for callee in calls {
            if method_names.contains(callee) {
                if has_cycle(callee, call_graph, method_names, visited, stack) {
                    return true;
                }
            }
        }
    }

    stack.remove(method_name);
    false
}
