//! Pass 2: Validate
//!
//! Validates the Rúnar AST against the language subset constraints.
//! This pass does NOT modify the AST; it only reports errors and warnings.

use std::collections::{HashMap, HashSet};

use super::ast::*;
use super::diagnostic::Diagnostic;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of validation.
pub struct ValidationResult {
    pub errors: Vec<Diagnostic>,
    pub warnings: Vec<Diagnostic>,
}

impl ValidationResult {
    /// Get error messages as plain strings (for backward compatibility).
    pub fn error_strings(&self) -> Vec<String> {
        self.errors.iter().map(|d| d.format_message()).collect()
    }
    /// Get warning messages as plain strings (for backward compatibility).
    pub fn warning_strings(&self) -> Vec<String> {
        self.warnings.iter().map(|d| d.format_message()).collect()
    }
}

/// Validate a parsed Rúnar AST against the language subset constraints.
pub fn validate(contract: &ContractNode) -> ValidationResult {
    let mut errors: Vec<Diagnostic> = Vec::new();
    let mut warnings: Vec<Diagnostic> = Vec::new();

    validate_properties(contract, &mut errors, &mut warnings);
    validate_constructor(contract, &mut errors);
    validate_methods(contract, &mut errors, &mut warnings);
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
        | PrimitiveTypeName::RabinPubKey
        | PrimitiveTypeName::Point => true,
        PrimitiveTypeName::Void => false,
    }
}

// ---------------------------------------------------------------------------
// Property validation
// ---------------------------------------------------------------------------

fn validate_properties(contract: &ContractNode, errors: &mut Vec<Diagnostic>, warnings: &mut Vec<Diagnostic>) {
    for prop in &contract.properties {
        validate_property_type(&prop.prop_type, &prop.source_location, errors);

        // V27: Error when any property is named `txPreimage`
        if prop.name == "txPreimage" {
            errors.push(Diagnostic::error(
                "'txPreimage' is a reserved implicit parameter name and must not be used as a property name", Some(prop.source_location.clone())
            ));
        }
    }

    // SmartContract requires all properties to be readonly
    if contract.parent_class == "SmartContract" {
        for prop in &contract.properties {
            if !prop.readonly {
                errors.push(Diagnostic::error(format!(
                    "property '{}' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.",
                    prop.name
                ), Some(prop.source_location.clone())));
            }
        }
    }

    // V26: Warn when a StatefulSmartContract has no mutable (non-readonly) properties
    if contract.parent_class == "StatefulSmartContract" {
        let has_mutable = contract.properties.iter().any(|p| !p.readonly);
        if !has_mutable {
            warnings.push(Diagnostic::warning(
                "StatefulSmartContract has no mutable properties; consider using SmartContract instead", Some(contract.constructor.source_location.clone())
            ));
        }
    }
}

fn validate_property_type(type_node: &TypeNode, loc: &SourceLocation, errors: &mut Vec<Diagnostic>) {
    match type_node {
        TypeNode::Primitive(name) => {
            if !is_valid_property_primitive(name) {
                errors.push(Diagnostic::error(format!("Property type '{}' is not valid", name.as_str()), Some(loc.clone())));
            }
        }
        TypeNode::FixedArray { element, length } => {
            if *length == 0 {
                errors.push(Diagnostic::error("FixedArray length must be a positive integer", Some(loc.clone())));
            }
            validate_property_type(element, loc, errors);
        }
        TypeNode::Custom(name) => {
            errors.push(Diagnostic::error(format!(
                "Unsupported type '{}' in property declaration. Use one of: bigint, boolean, ByteString, PubKey, Sig, Sha256, Ripemd160, Addr, SigHashPreimage, RabinSig, RabinPubKey, or FixedArray<T, N>",
                name
            ), Some(loc.clone())));
        }
    }
}

// ---------------------------------------------------------------------------
// Constructor validation
// ---------------------------------------------------------------------------

fn validate_constructor(contract: &ContractNode, errors: &mut Vec<Diagnostic>) {
    let ctor = &contract.constructor;
    let prop_names: HashSet<String> = contract.properties.iter().map(|p| p.name.clone()).collect();

    // Check that constructor has a super() call as first statement
    if ctor.body.is_empty() {
        errors.push(Diagnostic::error("Constructor must call super() as its first statement", Some(ctor.source_location.clone())));
        return;
    }

    if !is_super_call(&ctor.body[0]) {
        errors.push(Diagnostic::error("Constructor must call super() as its first statement", Some(ctor.source_location.clone())));
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

    // Properties with initializers don't need constructor assignments
    let props_with_init: HashSet<String> = contract
        .properties
        .iter()
        .filter(|p| p.initializer.is_some())
        .map(|p| p.name.clone())
        .collect();

    for prop_name in &prop_names {
        if !assigned_props.contains(prop_name) && !props_with_init.contains(prop_name) {
            errors.push(Diagnostic::error(format!(
                "Property '{}' must be assigned in the constructor",
                prop_name
            ), Some(ctor.source_location.clone())));
        }
    }

    // Validate constructor params have type annotations
    for param in &ctor.params {
        if let TypeNode::Custom(ref name) = param.param_type {
            if name == "unknown" {
                errors.push(Diagnostic::error(format!(
                    "Constructor parameter '{}' must have a type annotation",
                    param.name
                ), Some(ctor.source_location.clone())));
            }
        }
        if matches!(param.param_type, TypeNode::FixedArray { .. }) {
            errors.push(Diagnostic::error(
                format!(
                    "Constructor parameter '{}' cannot be a FixedArray. Use initialized properties or pass each element as a separate parameter.",
                    param.name
                ),
                Some(ctor.source_location.clone()),
            ));
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

fn validate_methods(contract: &ContractNode, errors: &mut Vec<Diagnostic>, warnings: &mut Vec<Diagnostic>) {
    for method in &contract.methods {
        validate_method(method, contract, errors);

        // V24, V25: Warn when StatefulSmartContract public method calls checkPreimage or getStateScript explicitly
        if contract.parent_class == "StatefulSmartContract" && method.visibility == Visibility::Public {
            warn_manual_preimage_usage(method, warnings);
        }
    }
}

fn validate_method(method: &MethodNode, contract: &ContractNode, errors: &mut Vec<Diagnostic>) {
    // All params must have type annotations
    for param in &method.params {
        if let TypeNode::Custom(ref name) = param.param_type {
            if name == "unknown" {
                errors.push(Diagnostic::error(format!(
                    "Parameter '{}' in method '{}' must have a type annotation",
                    param.name, method.name
                ), Some(method.source_location.clone())));
            }
        }
        if matches!(param.param_type, TypeNode::FixedArray { .. }) {
            errors.push(Diagnostic::error(
                format!(
                    "Parameter '{}' in method '{}' cannot be a FixedArray. Arrays are only allowed as contract properties.",
                    param.name, method.name
                ),
                Some(method.source_location.clone()),
            ));
        }
    }

    // Public methods must end with an assert() call (unless StatefulSmartContract,
    // where the compiler auto-injects the final assert)
    if method.visibility == Visibility::Public && contract.parent_class == "SmartContract" {
        if !ends_with_assert(&method.body) {
            errors.push(Diagnostic::error(format!(
                "Public method '{}' must end with an assert() call",
                method.name
            ), Some(method.source_location.clone())));
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

fn validate_statement(stmt: &Statement, errors: &mut Vec<Diagnostic>) {
    match stmt {
        Statement::VariableDecl { name, var_type, init, .. } => {
            if let Some(TypeNode::FixedArray { .. }) = var_type {
                errors.push(Diagnostic::error(
                    format!(
                        "Local variable '{}' cannot be a FixedArray. Arrays are only allowed as contract properties.",
                        name
                    ),
                    None,
                ));
            }
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
                    errors.push(Diagnostic::error(
                        "For loop bound must be a compile-time constant (literal or const variable)",
                        None,
                    ));
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

fn validate_expression(expr: &Expression, errors: &mut Vec<Diagnostic>) {
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
            // assert() message (2nd arg) is a human-readable string, not hex — skip validation
            let is_assert = matches!(callee.as_ref(), Expression::Identifier { name } if name == "assert");
            for (i, arg) in args.iter().enumerate() {
                if is_assert && i >= 1 {
                    continue;
                }
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
        Expression::ArrayLiteral { elements } => {
            for elem in elements {
                validate_expression(elem, errors);
            }
        }
        // Leaf nodes -- nothing to validate (except ByteStringLiteral)
        Expression::Identifier { .. }
        | Expression::BigIntLiteral { .. }
        | Expression::BoolLiteral { .. }
        | Expression::PropertyAccess { .. } => {}

        Expression::ByteStringLiteral { value } => {
            if !value.is_empty() {
                if value.len() % 2 != 0 {
                    errors.push(Diagnostic::error(format!(
                        "ByteString literal '{}' has odd length ({}) \u{2014} hex strings must have an even number of characters",
                        value,
                        value.len()
                    ), None));
                } else if !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    errors.push(Diagnostic::error(format!(
                        "ByteString literal '{}' contains non-hex characters \u{2014} only 0-9, a-f, A-F are allowed",
                        value
                    ), None));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Recursion detection
// ---------------------------------------------------------------------------

fn check_no_recursion(contract: &ContractNode, errors: &mut Vec<Diagnostic>) {
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
            errors.push(Diagnostic::error(format!(
                "Recursion detected: method '{}' calls itself directly or indirectly. Recursion is not allowed in Rúnar contracts.",
                method.name
            ), Some(method.source_location.clone())));
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

// ---------------------------------------------------------------------------
// V24, V25: Warn about manual use of checkPreimage / getStateScript in
// StatefulSmartContract public methods.
// ---------------------------------------------------------------------------

fn warn_manual_preimage_usage(method: &MethodNode, warnings: &mut Vec<Diagnostic>) {
    let method_loc = method.source_location.clone();
    walk_expressions_in_body(&method.body, &mut |expr| {
        // V24: Detect manual checkPreimage(...)
        if let Expression::CallExpr { callee, .. } = expr {
            if let Expression::Identifier { name } = callee.as_ref() {
                if name == "checkPreimage" {
                    warnings.push(Diagnostic::warning(format!(
                        "StatefulSmartContract auto-injects checkPreimage(); calling it manually in '{}' will cause a duplicate verification",
                        method.name
                    ), Some(method_loc.clone())));
                }
            }
            // V25: Detect manual this.getStateScript()
            if let Expression::PropertyAccess { property } = callee.as_ref() {
                if property == "getStateScript" {
                    warnings.push(Diagnostic::warning(format!(
                        "StatefulSmartContract auto-injects state continuation; calling getStateScript() manually in '{}' is redundant",
                        method.name
                    ), Some(method_loc.clone())));
                }
            }
        }
    });
}

fn walk_expressions_in_body(stmts: &[Statement], visitor: &mut impl FnMut(&Expression)) {
    for stmt in stmts {
        walk_expressions_in_statement(stmt, visitor);
    }
}

fn walk_expressions_in_statement(stmt: &Statement, visitor: &mut impl FnMut(&Expression)) {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => {
            walk_expression(expression, visitor);
        }
        Statement::VariableDecl { init, .. } => {
            walk_expression(init, visitor);
        }
        Statement::Assignment { target, value, .. } => {
            walk_expression(target, visitor);
            walk_expression(value, visitor);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            walk_expression(condition, visitor);
            walk_expressions_in_body(then_branch, visitor);
            if let Some(else_stmts) = else_branch {
                walk_expressions_in_body(else_stmts, visitor);
            }
        }
        Statement::ForStatement {
            condition, body, ..
        } => {
            walk_expression(condition, visitor);
            walk_expressions_in_body(body, visitor);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                walk_expression(v, visitor);
            }
        }
    }
}

fn walk_expression(expr: &Expression, visitor: &mut impl FnMut(&Expression)) {
    visitor(expr);
    match expr {
        Expression::CallExpr { callee, args } => {
            walk_expression(callee, visitor);
            for arg in args {
                walk_expression(arg, visitor);
            }
        }
        Expression::BinaryExpr { left, right, .. } => {
            walk_expression(left, visitor);
            walk_expression(right, visitor);
        }
        Expression::UnaryExpr { operand, .. } => {
            walk_expression(operand, visitor);
        }
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            walk_expression(condition, visitor);
            walk_expression(consequent, visitor);
            walk_expression(alternate, visitor);
        }
        Expression::MemberExpr { object, .. } => {
            walk_expression(object, visitor);
        }
        Expression::IndexAccess { object, index } => {
            walk_expression(object, visitor);
            walk_expression(index, visitor);
        }
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            walk_expression(operand, visitor);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::parse_source;

    /// Helper: parse a TypeScript source string and return the ContractNode.
    fn parse_contract(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(
            result.errors.is_empty(),
            "parse errors: {:?}",
            result.errors
        );
        result.contract.expect("expected a contract from parse")
    }

    #[test]
    fn test_valid_p2pkh_passes_validation() {
        let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

class P2PKH extends SmartContract {
    readonly pubKeyHash: Addr;

    constructor(pubKeyHash: Addr) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no validation errors, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_missing_super_in_constructor_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        this.x = x;
    }

    public check(v: bigint) {
        assert(v === this.x);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for missing super()"
        );
        let has_super_error = result
            .errors
            .iter()
            .any(|e| e.message.to_lowercase().contains("super"));
        assert!(
            has_super_error,
            "expected error about super(), got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_public_method_not_ending_with_assert_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class NoAssert extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        const sum = v + this.x;
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for missing assert at end of public method"
        );
        let has_assert_error = result
            .errors
            .iter()
            .any(|e| e.message.to_lowercase().contains("assert"));
        assert!(
            has_assert_error,
            "expected error about missing assert(), got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_direct_recursion_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Recursive extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        this.check(v);
        assert(v === this.x);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for recursion"
        );
        let has_recursion_error = result
            .errors
            .iter()
            .any(|e| e.message.to_lowercase().contains("recursion") || e.message.to_lowercase().contains("recursive"));
        assert!(
            has_recursion_error,
            "expected error about recursion, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_stateful_contract_passes_validation() {
        // StatefulSmartContract public methods don't need to end with assert
        // because the compiler auto-injects the final assert.
        let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
    count: bigint;

    constructor(count: bigint) {
        super(count);
        this.count = count;
    }

    public increment() {
        this.count++;
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no validation errors for stateful contract, got: {:?}",
            result.errors
        );
    }

    /// Alias mirroring the name used in Go/Python test suites.
    #[test]
    fn test_constructor_missing_super_fails() {
        let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

class P2PKH extends SmartContract {
    readonly pubKeyHash: Addr;

    constructor(pubKeyHash: Addr) {
        this.pubKeyHash = pubKeyHash;
    }

    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for missing super()"
        );
        assert!(
            result.errors.iter().any(|e| e.message.to_lowercase().contains("super")),
            "expected error about super(), got: {:?}",
            result.errors
        );
    }

    /// Alias mirroring the name used in Go/Python test suites.
    #[test]
    fn test_public_method_missing_final_assert_fails() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class P2PKH extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public unlock(val: bigint): void { const y = val + 1n; }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for missing assert at end of public method"
        );
        assert!(
            result.errors.iter().any(|e| e.message.to_lowercase().contains("assert")),
            "expected error about missing assert(), got: {:?}",
            result.errors
        );
    }

    /// Alias mirroring the name used in Go/Python test suites.
    #[test]
    fn test_direct_recursion_fails() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Rec extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public recurse(v: bigint) {
        this.recurse(v);
        assert(v === this.x);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected validation errors for direct recursion"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("recursion") || e.message.to_lowercase().contains("recursive")),
            "expected error about recursion, got: {:?}",
            result.errors
        );
    }
}
