//! Pass 3: Type-Check
//!
//! Type-checks the Rúnar AST. Builds type environments from properties,
//! constructor parameters, and method parameters, then verifies all
//! expressions have consistent types.

use std::collections::{HashMap, HashSet};

use super::ast::*;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of type checking.
pub struct TypeCheckResult {
    pub errors: Vec<String>,
}

/// Type-check a Rúnar AST. Returns any type errors found.
pub fn typecheck(contract: &ContractNode) -> TypeCheckResult {
    let mut errors = Vec::new();
    let mut checker = TypeChecker::new(contract, &mut errors);

    checker.check_constructor();
    for method in &contract.methods {
        checker.check_method(method);
    }

    TypeCheckResult { errors }
}

// ---------------------------------------------------------------------------
// Type representation
// ---------------------------------------------------------------------------

/// Internal type representation (simplified string-based).
type TType = String;

const VOID: &str = "void";
const BIGINT: &str = "bigint";
const BOOLEAN: &str = "boolean";
const BYTESTRING: &str = "ByteString";

// ---------------------------------------------------------------------------
// Built-in function signatures
// ---------------------------------------------------------------------------

struct FuncSig {
    params: Vec<&'static str>,
    return_type: &'static str,
}

fn builtin_functions() -> HashMap<&'static str, FuncSig> {
    let mut m = HashMap::new();

    m.insert("sha256", FuncSig { params: vec!["ByteString"], return_type: "Sha256" });
    m.insert("ripemd160", FuncSig { params: vec!["ByteString"], return_type: "Ripemd160" });
    m.insert("hash160", FuncSig { params: vec!["ByteString"], return_type: "Ripemd160" });
    m.insert("hash256", FuncSig { params: vec!["ByteString"], return_type: "Sha256" });
    m.insert("checkSig", FuncSig { params: vec!["Sig", "PubKey"], return_type: "boolean" });
    m.insert("checkMultiSig", FuncSig { params: vec!["Sig[]", "PubKey[]"], return_type: "boolean" });
    m.insert("assert", FuncSig { params: vec!["boolean"], return_type: "void" });
    m.insert("len", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("cat", FuncSig { params: vec!["ByteString", "ByteString"], return_type: "ByteString" });
    m.insert("substr", FuncSig { params: vec!["ByteString", "bigint", "bigint"], return_type: "ByteString" });
    m.insert("num2bin", FuncSig { params: vec!["bigint", "bigint"], return_type: "ByteString" });
    m.insert("bin2num", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("checkPreimage", FuncSig { params: vec!["SigHashPreimage"], return_type: "boolean" });
    m.insert("verifyRabinSig", FuncSig { params: vec!["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type: "boolean" });
    m.insert("verifyWOTS", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_128s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_128f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_192s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_192f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_256s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_256f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("ecAdd", FuncSig { params: vec!["Point", "Point"], return_type: "Point" });
    m.insert("ecMul", FuncSig { params: vec!["Point", "bigint"], return_type: "Point" });
    m.insert("ecMulGen", FuncSig { params: vec!["bigint"], return_type: "Point" });
    m.insert("ecNegate", FuncSig { params: vec!["Point"], return_type: "Point" });
    m.insert("ecOnCurve", FuncSig { params: vec!["Point"], return_type: "boolean" });
    m.insert("ecModReduce", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("ecEncodeCompressed", FuncSig { params: vec!["Point"], return_type: "ByteString" });
    m.insert("ecMakePoint", FuncSig { params: vec!["bigint", "bigint"], return_type: "Point" });
    m.insert("ecPointX", FuncSig { params: vec!["Point"], return_type: "bigint" });
    m.insert("ecPointY", FuncSig { params: vec!["Point"], return_type: "bigint" });
    m.insert("abs", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("min", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("max", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("within", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "boolean" });
    m.insert("reverseBytes", FuncSig { params: vec!["ByteString"], return_type: "ByteString" });
    m.insert("left", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });
    m.insert("right", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });
    m.insert("int2str", FuncSig { params: vec!["bigint", "bigint"], return_type: "ByteString" });
    m.insert("toByteString", FuncSig { params: vec!["ByteString"], return_type: "ByteString" });
    m.insert("exit", FuncSig { params: vec!["boolean"], return_type: "void" });
    m.insert("pack", FuncSig { params: vec!["bigint"], return_type: "ByteString" });
    m.insert("unpack", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("safediv", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("safemod", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("clamp", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("sign", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("pow", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("mulDiv", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("percentOf", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("sqrt", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("gcd", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("divmod", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("log2", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("bool", FuncSig { params: vec!["bigint"], return_type: "boolean" });

    // Preimage extractors
    m.insert("extractVersion", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractHashPrevouts", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractHashSequence", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractOutpoint", FuncSig { params: vec!["SigHashPreimage"], return_type: "ByteString" });
    m.insert("extractInputIndex", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractScriptCode", FuncSig { params: vec!["SigHashPreimage"], return_type: "ByteString" });
    m.insert("extractAmount", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractSequence", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractOutputHash", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractOutputs", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractLocktime", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractSigHashType", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });

    m
}

// ---------------------------------------------------------------------------
// Subtyping
// ---------------------------------------------------------------------------

/// ByteString subtypes -- types represented as byte strings on the stack.
fn is_bytestring_subtype(t: &str) -> bool {
    matches!(
        t,
        "ByteString" | "PubKey" | "Sig" | "Sha256" | "Ripemd160" | "Addr" | "SigHashPreimage" | "Point"
    )
}

/// Bigint subtypes -- types represented as integers on the stack.
fn is_bigint_subtype(t: &str) -> bool {
    matches!(t, "bigint" | "RabinSig" | "RabinPubKey")
}

fn is_subtype(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }

    // ByteString subtypes
    if expected == "ByteString" && is_bytestring_subtype(actual) {
        return true;
    }
    if actual == "ByteString" && is_bytestring_subtype(expected) {
        return true;
    }

    // Both in the ByteString family -> compatible (e.g. Addr and Ripemd160)
    if is_bytestring_subtype(actual) && is_bytestring_subtype(expected) {
        return true;
    }

    // bigint subtypes
    if expected == "bigint" && is_bigint_subtype(actual) {
        return true;
    }
    if actual == "bigint" && is_bigint_subtype(expected) {
        return true;
    }

    // Both in the bigint family -> compatible
    if is_bigint_subtype(actual) && is_bigint_subtype(expected) {
        return true;
    }

    // Array subtyping
    if expected.ends_with("[]") && actual.ends_with("[]") {
        return is_subtype(
            &actual[..actual.len() - 2],
            &expected[..expected.len() - 2],
        );
    }

    false
}

fn is_bigint_family(t: &str) -> bool {
    is_bigint_subtype(t)
}

// ---------------------------------------------------------------------------
// Type environment
// ---------------------------------------------------------------------------

struct TypeEnv {
    scopes: Vec<HashMap<String, TType>>,
}

impl TypeEnv {
    fn new() -> Self {
        TypeEnv {
            scopes: vec![HashMap::new()],
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn define(&mut self, name: &str, t: TType) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name.to_string(), t);
        }
    }

    fn lookup(&self, name: &str) -> Option<&TType> {
        for scope in self.scopes.iter().rev() {
            if let Some(t) = scope.get(name) {
                return Some(t);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Type checker
// ---------------------------------------------------------------------------

/// Types whose values can be consumed at most once.
fn is_affine_type(t: &str) -> bool {
    matches!(t, "Sig" | "SigHashPreimage")
}

/// Maps consuming function names to the parameter indices that consume
/// affine values.
fn consuming_param_indices(func_name: &str) -> Option<&'static [usize]> {
    match func_name {
        "checkSig" => Some(&[0]),
        "checkMultiSig" => Some(&[0]),
        "checkPreimage" => Some(&[0]),
        _ => None,
    }
}

struct TypeChecker<'a> {
    contract: &'a ContractNode,
    errors: &'a mut Vec<String>,
    prop_types: HashMap<String, TType>,
    method_sigs: HashMap<String, (Vec<TType>, TType)>,
    builtins: HashMap<&'static str, FuncSig>,
    consumed_values: HashSet<String>,
}

impl<'a> TypeChecker<'a> {
    fn new(contract: &'a ContractNode, errors: &'a mut Vec<String>) -> Self {
        let mut prop_types = HashMap::new();
        for prop in &contract.properties {
            prop_types.insert(prop.name.clone(), type_node_to_ttype(&prop.prop_type));
        }

        // For StatefulSmartContract and InductiveSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract"
            || contract.parent_class == "InductiveSmartContract"
        {
            prop_types.insert("txPreimage".to_string(), "SigHashPreimage".to_string());
        }

        let mut method_sigs = HashMap::new();
        for method in &contract.methods {
            let params: Vec<TType> = method
                .params
                .iter()
                .map(|p| type_node_to_ttype(&p.param_type))
                .collect();
            let return_type = if method.visibility == Visibility::Public {
                VOID.to_string()
            } else {
                infer_method_return_type(method)
            };
            method_sigs.insert(method.name.clone(), (params, return_type));
        }

        TypeChecker {
            contract,
            errors,
            prop_types,
            method_sigs,
            builtins: builtin_functions(),
            consumed_values: HashSet::new(),
        }
    }

    fn check_constructor(&mut self) {
        let ctor = &self.contract.constructor;
        let mut env = TypeEnv::new();

        // Reset affine tracking for this scope
        self.consumed_values.clear();

        // Add constructor params to env
        for param in &ctor.params {
            env.define(&param.name, type_node_to_ttype(&param.param_type));
        }

        // Add properties to env
        for prop in &self.contract.properties {
            env.define(&prop.name, type_node_to_ttype(&prop.prop_type));
        }

        self.check_statements(&ctor.body, &mut env);
    }

    fn check_method(&mut self, method: &MethodNode) {
        let mut env = TypeEnv::new();

        // Reset affine tracking for this method
        self.consumed_values.clear();

        // Add method params to env
        for param in &method.params {
            env.define(&param.name, type_node_to_ttype(&param.param_type));
        }

        self.check_statements(&method.body, &mut env);
    }

    fn check_statements(&mut self, stmts: &[Statement], env: &mut TypeEnv) {
        for stmt in stmts {
            self.check_statement(stmt, env);
        }
    }

    fn check_statement(&mut self, stmt: &Statement, env: &mut TypeEnv) {
        match stmt {
            Statement::VariableDecl {
                name,
                var_type,
                init,
                ..
            } => {
                let init_type = self.infer_expr_type(init, env);
                if let Some(declared) = var_type {
                    let declared_type = type_node_to_ttype(declared);
                    if !is_subtype(&init_type, &declared_type) {
                        self.errors.push(format!(
                            "Type '{}' is not assignable to type '{}'",
                            init_type, declared_type
                        ));
                    }
                    env.define(name, declared_type);
                } else {
                    env.define(name, init_type);
                }
            }

            Statement::Assignment { target, value, .. } => {
                let target_type = self.infer_expr_type(target, env);
                let value_type = self.infer_expr_type(value, env);
                if !is_subtype(&value_type, &target_type) {
                    self.errors.push(format!(
                        "Type '{}' is not assignable to type '{}'",
                        value_type, target_type
                    ));
                }
            }

            Statement::IfStatement {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.errors.push(format!(
                        "If condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                env.push_scope();
                self.check_statements(then_branch, env);
                env.pop_scope();
                if let Some(else_stmts) = else_branch {
                    env.push_scope();
                    self.check_statements(else_stmts, env);
                    env.pop_scope();
                }
            }

            Statement::ForStatement {
                init,
                condition,
                body,
                ..
            } => {
                env.push_scope();
                self.check_statement(init, env);
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.errors.push(format!(
                        "For loop condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                self.check_statements(body, env);
                env.pop_scope();
            }

            Statement::ExpressionStatement { expression, .. } => {
                self.infer_expr_type(expression, env);
            }

            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    self.infer_expr_type(v, env);
                }
            }
        }
    }

    /// Infer the type of an expression.
    fn infer_expr_type(&mut self, expr: &Expression, env: &mut TypeEnv) -> TType {
        match expr {
            Expression::BigIntLiteral { .. } => BIGINT.to_string(),

            Expression::BoolLiteral { .. } => BOOLEAN.to_string(),

            Expression::ByteStringLiteral { .. } => BYTESTRING.to_string(),

            Expression::Identifier { name } => {
                if name == "this" {
                    return "<this>".to_string();
                }
                if name == "super" {
                    return "<super>".to_string();
                }
                if name == "true" || name == "false" {
                    return BOOLEAN.to_string();
                }

                if let Some(t) = env.lookup(name) {
                    return t.clone();
                }

                // Check if it's a builtin function name
                if self.builtins.contains_key(name.as_str()) {
                    return "<builtin>".to_string();
                }

                "<unknown>".to_string()
            }

            Expression::PropertyAccess { property } => {
                if let Some(t) = self.prop_types.get(property) {
                    return t.clone();
                }

                self.errors.push(format!(
                    "Property '{}' does not exist on the contract",
                    property
                ));
                "<unknown>".to_string()
            }

            Expression::MemberExpr { object, property } => {
                let obj_type = self.infer_expr_type(object, env);

                if obj_type == "<this>" {
                    // Check if it's a property
                    if let Some(t) = self.prop_types.get(property) {
                        return t.clone();
                    }
                    // Check if it's a method
                    if self.method_sigs.contains_key(property) {
                        return "<method>".to_string();
                    }
                    // Special: getStateScript
                    if property == "getStateScript" {
                        return "<method>".to_string();
                    }

                    self.errors.push(format!(
                        "Property or method '{}' does not exist on the contract",
                        property
                    ));
                    return "<unknown>".to_string();
                }

                // SigHash.ALL, SigHash.FORKID, etc.
                if let Expression::Identifier { name } = object.as_ref() {
                    if name == "SigHash" {
                        return BIGINT.to_string();
                    }
                }

                "<unknown>".to_string()
            }

            Expression::BinaryExpr { op, left, right } => {
                self.check_binary_expr(op, left, right, env)
            }

            Expression::UnaryExpr { op, operand } => self.check_unary_expr(op, operand, env),

            Expression::CallExpr { callee, args } => self.check_call_expr(callee, args, env),

            Expression::TernaryExpr {
                condition,
                consequent,
                alternate,
            } => {
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.errors.push(format!(
                        "Ternary condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                let cons_type = self.infer_expr_type(consequent, env);
                let alt_type = self.infer_expr_type(alternate, env);

                if cons_type != alt_type {
                    if is_subtype(&alt_type, &cons_type) {
                        return cons_type;
                    }
                    if is_subtype(&cons_type, &alt_type) {
                        return alt_type;
                    }
                    self.errors.push(format!(
                        "Ternary branches have incompatible types: '{}' and '{}'",
                        cons_type, alt_type
                    ));
                }
                cons_type
            }

            Expression::IndexAccess { object, index } => {
                let obj_type = self.infer_expr_type(object, env);
                let index_type = self.infer_expr_type(index, env);

                if !is_bigint_family(&index_type) {
                    self.errors.push(format!(
                        "Array index must be bigint, got '{}'",
                        index_type
                    ));
                }

                if obj_type.ends_with("[]") {
                    return obj_type[..obj_type.len() - 2].to_string();
                }

                "<unknown>".to_string()
            }

            Expression::IncrementExpr { operand, .. }
            | Expression::DecrementExpr { operand, .. } => {
                let operand_type = self.infer_expr_type(operand, env);
                if !is_bigint_family(&operand_type) {
                    let op_str = if matches!(expr, Expression::IncrementExpr { .. }) {
                        "++"
                    } else {
                        "--"
                    };
                    self.errors.push(format!(
                        "{} operator requires bigint, got '{}'",
                        op_str, operand_type
                    ));
                }
                BIGINT.to_string()
            }
        }
    }

    fn check_binary_expr(
        &mut self,
        op: &BinaryOp,
        left: &Expression,
        right: &Expression,
        env: &mut TypeEnv,
    ) -> TType {
        let left_type = self.infer_expr_type(left, env);
        let right_type = self.infer_expr_type(right, env);

        match op {
            // Arithmetic: bigint x bigint -> bigint
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                if !is_bigint_family(&left_type) {
                    self.errors.push(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.errors.push(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }

            // Comparison: bigint x bigint -> boolean
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if !is_bigint_family(&left_type) {
                    self.errors.push(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.errors.push(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BOOLEAN.to_string()
            }

            // Equality: T x T -> boolean
            BinaryOp::StrictEq | BinaryOp::StrictNe => {
                if !is_subtype(&left_type, &right_type)
                    && !is_subtype(&right_type, &left_type)
                {
                    if left_type != "<unknown>" && right_type != "<unknown>" {
                        self.errors.push(format!(
                            "Cannot compare '{}' and '{}' with '{}'",
                            left_type,
                            right_type,
                            op.as_str()
                        ));
                    }
                }
                BOOLEAN.to_string()
            }

            // Logical: boolean x boolean -> boolean
            BinaryOp::And | BinaryOp::Or => {
                if left_type != BOOLEAN && left_type != "<unknown>" {
                    self.errors.push(format!(
                        "Left operand of '{}' must be boolean, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if right_type != BOOLEAN && right_type != "<unknown>" {
                    self.errors.push(format!(
                        "Right operand of '{}' must be boolean, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BOOLEAN.to_string()
            }

            // Bitwise &, |, ^: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                if is_bytestring_subtype(&left_type) && is_bytestring_subtype(&right_type) {
                    return BYTESTRING.to_string();
                }
                if !is_bigint_family(&left_type) {
                    self.errors.push(format!(
                        "Left operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.errors.push(format!(
                        "Right operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }

            // Shift: bigint x bigint -> bigint
            BinaryOp::Shl | BinaryOp::Shr => {
                if !is_bigint_family(&left_type) {
                    self.errors.push(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.errors.push(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }
        }
    }

    fn check_unary_expr(
        &mut self,
        op: &UnaryOp,
        operand: &Expression,
        env: &mut TypeEnv,
    ) -> TType {
        let operand_type = self.infer_expr_type(operand, env);

        match op {
            UnaryOp::Not => {
                if operand_type != BOOLEAN && operand_type != "<unknown>" {
                    self.errors.push(format!(
                        "Operand of '!' must be boolean, got '{}'",
                        operand_type
                    ));
                }
                BOOLEAN.to_string()
            }
            UnaryOp::Neg => {
                if !is_bigint_family(&operand_type) {
                    self.errors.push(format!(
                        "Operand of unary '-' must be bigint, got '{}'",
                        operand_type
                    ));
                }
                BIGINT.to_string()
            }
            UnaryOp::BitNot => {
                if is_bytestring_subtype(&operand_type) {
                    return BYTESTRING.to_string();
                }
                if !is_bigint_family(&operand_type) {
                    self.errors.push(format!(
                        "Operand of '~' must be bigint or ByteString, got '{}'",
                        operand_type
                    ));
                }
                BIGINT.to_string()
            }
        }
    }

    fn check_call_expr(
        &mut self,
        callee: &Expression,
        args: &[Expression],
        env: &mut TypeEnv,
    ) -> TType {
        // super() call in constructor
        if let Expression::Identifier { name } = callee {
            if name == "super" {
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return VOID.to_string();
            }
        }

        // Direct builtin call: assert(...), checkSig(...), sha256(...), etc.
        if let Expression::Identifier { name } = callee {
            if let Some(sig) = self.builtins.get(name.as_str()) {
                let sig_params = sig.params.clone();
                let sig_return_type = sig.return_type;
                return self.check_call_args(name, &sig_params, sig_return_type, args, env);
            }

            // Check if it's a known contract method
            if let Some((params, return_type)) = self.method_sigs.get(name).cloned() {
                let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                return self.check_call_args(name, &param_strs, &return_type, args, env);
            }

            // Check if it's a local variable
            if env.lookup(name).is_some() {
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return "<unknown>".to_string();
            }

            self.errors.push(format!(
                "unknown function '{}' — only Rúnar built-in functions and contract methods are allowed",
                name
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // this.method(...) via PropertyAccess
        if let Expression::PropertyAccess { property } = callee {
            if property == "getStateScript" {
                if !args.is_empty() {
                    self.errors
                        .push("getStateScript() takes no arguments".to_string());
                }
                return BYTESTRING.to_string();
            }

            if property == "addOutput" || property == "addRawOutput" {
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return VOID.to_string();
            }

            // Check contract method signatures
            if let Some((params, return_type)) = self.method_sigs.get(property).cloned() {
                let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                return self.check_call_args(property, &param_strs, &return_type, args, env);
            }

            self.errors.push(format!(
                "unknown method 'self.{}' — only Rúnar built-in methods and contract methods are allowed",
                property
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // member_expr call: obj.method(...)
        if let Expression::MemberExpr { object, property } = callee {
            // .clone() is a Rust idiom — allow it as a no-op
            if property == "clone" {
                return self.infer_expr_type(object, env);
            }

            let obj_type = self.infer_expr_type(object, env);

            if obj_type == "<this>"
                || matches!(object.as_ref(), Expression::Identifier { name } if name == "this")
            {
                if property == "getStateScript" {
                    return BYTESTRING.to_string();
                }

                if let Some((params, return_type)) = self.method_sigs.get(property).cloned() {
                    let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                    return self.check_call_args(
                        property,
                        &param_strs,
                        &return_type,
                        args,
                        env,
                    );
                }
            }

            // Not this.method — reject (e.g. std::process::exit)
            let obj_name = match object.as_ref() {
                Expression::Identifier { name } => name.clone(),
                _ => "<expr>".to_string(),
            };
            self.errors.push(format!(
                "unknown function '{}.{}' — only Rúnar built-in functions and contract methods are allowed",
                obj_name, property
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // Fallback — unknown callee shape
        self.errors.push(
            "unsupported function call expression — only Rúnar built-in functions and contract methods are allowed".to_string()
        );
        self.infer_expr_type(callee, env);
        for arg in args {
            self.infer_expr_type(arg, env);
        }
        "<unknown>".to_string()
    }

    fn check_call_args(
        &mut self,
        func_name: &str,
        sig_params: &[&str],
        return_type: &str,
        args: &[Expression],
        env: &mut TypeEnv,
    ) -> TType {
        // Special case: assert can take 1 or 2 args
        if func_name == "assert" {
            if args.is_empty() || args.len() > 2 {
                self.errors.push(format!(
                    "assert() expects 1 or 2 arguments, got {}",
                    args.len()
                ));
            }
            if !args.is_empty() {
                let cond_type = self.infer_expr_type(&args[0], env);
                if cond_type != BOOLEAN && cond_type != "<unknown>" {
                    self.errors.push(format!(
                        "assert() condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
            }
            if args.len() >= 2 {
                self.infer_expr_type(&args[1], env);
            }
            return return_type.to_string();
        }

        // Special case: checkMultiSig
        if func_name == "checkMultiSig" {
            if args.len() != 2 {
                self.errors.push(format!(
                    "checkMultiSig() expects 2 arguments, got {}",
                    args.len()
                ));
            }
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            self.check_affine_consumption(func_name, args, env);
            return return_type.to_string();
        }

        // Standard argument count check
        if args.len() != sig_params.len() {
            self.errors.push(format!(
                "{}() expects {} argument(s), got {}",
                func_name,
                sig_params.len(),
                args.len()
            ));
        }

        let count = args.len().min(sig_params.len());
        for i in 0..count {
            let arg_type = self.infer_expr_type(&args[i], env);
            let expected = sig_params[i];

            if !is_subtype(&arg_type, expected) && arg_type != "<unknown>" {
                self.errors.push(format!(
                    "Argument {} of {}(): expected '{}', got '{}'",
                    i + 1,
                    func_name,
                    expected,
                    arg_type
                ));
            }
        }

        // Infer remaining args even if count mismatches
        for i in count..args.len() {
            self.infer_expr_type(&args[i], env);
        }

        // Affine type enforcement
        self.check_affine_consumption(func_name, args, env);

        return_type.to_string()
    }

    /// Check affine type constraints: Sig and SigHashPreimage values may
    /// only be consumed once by a consuming function.
    fn check_affine_consumption(
        &mut self,
        func_name: &str,
        args: &[Expression],
        env: &mut TypeEnv,
    ) {
        let indices = match consuming_param_indices(func_name) {
            Some(indices) => indices,
            None => return,
        };

        for &param_index in indices {
            if param_index >= args.len() {
                continue;
            }

            let arg = &args[param_index];
            if let Expression::Identifier { name } = arg {
                if let Some(arg_type) = env.lookup(name) {
                    let arg_type = arg_type.clone();
                    if !is_affine_type(&arg_type) {
                        continue;
                    }

                    if self.consumed_values.contains(name) {
                        self.errors.push(format!(
                            "affine value '{}' has already been consumed",
                            name
                        ));
                    } else {
                        self.consumed_values.insert(name.clone());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Private method return type inference
// ---------------------------------------------------------------------------

/// Infer a private method's return type by walking all return statements
/// and inferring the type of their expressions. Returns "void" if no
/// return statements with values are found.
fn infer_method_return_type(method: &MethodNode) -> TType {
    let return_types = collect_return_types(&method.body);

    if return_types.is_empty() {
        return VOID.to_string();
    }

    let first = &return_types[0];
    let all_same = return_types.iter().all(|t| t == first);
    if all_same {
        return first.clone();
    }

    // Check if all are in the bigint family
    if return_types.iter().all(|t| is_bigint_subtype(t)) {
        return BIGINT.to_string();
    }

    // Check if all are in the ByteString family
    if return_types.iter().all(|t| is_bytestring_subtype(t)) {
        return BYTESTRING.to_string();
    }

    // Check if all are boolean
    if return_types.iter().all(|t| t == BOOLEAN) {
        return BOOLEAN.to_string();
    }

    // Mixed types -- return the first as a best effort
    first.clone()
}

/// Recursively collect inferred types from return statements.
fn collect_return_types(stmts: &[Statement]) -> Vec<TType> {
    let mut types = Vec::new();
    for stmt in stmts {
        match stmt {
            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    types.push(infer_expr_type_static(v));
                }
            }
            Statement::IfStatement {
                then_branch,
                else_branch,
                ..
            } => {
                types.extend(collect_return_types(then_branch));
                if let Some(else_stmts) = else_branch {
                    types.extend(collect_return_types(else_stmts));
                }
            }
            Statement::ForStatement { body, .. } => {
                types.extend(collect_return_types(body));
            }
            _ => {}
        }
    }
    types
}

/// Lightweight static expression type inference without a type environment.
/// Used for inferring return types of private methods before the full
/// type-check pass runs.
fn infer_expr_type_static(expr: &Expression) -> TType {
    match expr {
        Expression::BigIntLiteral { .. } => BIGINT.to_string(),
        Expression::BoolLiteral { .. } => BOOLEAN.to_string(),
        Expression::ByteStringLiteral { .. } => BYTESTRING.to_string(),
        Expression::Identifier { name } => {
            if name == "true" || name == "false" {
                BOOLEAN.to_string()
            } else {
                "<unknown>".to_string()
            }
        }
        Expression::BinaryExpr { op, .. } => match op {
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Mod
            | BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor
            | BinaryOp::Shl
            | BinaryOp::Shr => BIGINT.to_string(),
            _ => BOOLEAN.to_string(),
        },
        Expression::UnaryExpr { op, .. } => match op {
            UnaryOp::Not => BOOLEAN.to_string(),
            _ => BIGINT.to_string(),
        },
        Expression::CallExpr { callee, .. } => {
            let builtins = builtin_functions();
            if let Expression::Identifier { name } = callee.as_ref() {
                if let Some(sig) = builtins.get(name.as_str()) {
                    return sig.return_type.to_string();
                }
            }
            if let Expression::PropertyAccess { property } = callee.as_ref() {
                if let Some(sig) = builtins.get(property.as_str()) {
                    return sig.return_type.to_string();
                }
            }
            "<unknown>".to_string()
        }
        Expression::TernaryExpr {
            consequent,
            alternate,
            ..
        } => {
            let cons_type = infer_expr_type_static(consequent);
            if cons_type != "<unknown>" {
                cons_type
            } else {
                infer_expr_type_static(alternate)
            }
        }
        Expression::IncrementExpr { .. } | Expression::DecrementExpr { .. } => {
            BIGINT.to_string()
        }
        _ => "<unknown>".to_string(),
    }
}

fn type_node_to_ttype(node: &TypeNode) -> TType {
    match node {
        TypeNode::Primitive(name) => name.as_str().to_string(),
        TypeNode::FixedArray { element, .. } => {
            format!("{}[]", type_node_to_ttype(element))
        }
        TypeNode::Custom(name) => name.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::parse_source;
    use crate::frontend::validator;

    /// Helper: parse and validate a TypeScript source string, then return the ContractNode.
    fn parse_and_validate(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(
            result.errors.is_empty(),
            "parse errors: {:?}",
            result.errors
        );
        let contract = result.contract.expect("expected a contract from parse");
        let validation = validator::validate(&contract);
        assert!(
            validation.errors.is_empty(),
            "validation errors: {:?}",
            validation.errors
        );
        contract
    }

    #[test]
    fn test_valid_p2pkh_passes_typecheck() {
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
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_unknown_function_call_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        const y = Math.floor(v);
        assert(y === this.x);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for unknown function Math.floor"
        );
        let has_unknown_error = result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("unknown"));
        assert!(
            has_unknown_error,
            "expected error about unknown function, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_builtin_with_wrong_arg_count_produces_error() {
        let source = r#"
import { SmartContract, PubKey, Sig } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        assert(min(v));
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for wrong arg count"
        );
        let has_arg_count_error = result
            .errors
            .iter()
            .any(|e| e.contains("expects") && e.contains("argument"));
        assert!(
            has_arg_count_error,
            "expected error about wrong argument count, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_arithmetic_on_boolean_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint, flag: boolean) {
        const sum = v + flag;
        assert(sum === this.x);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for arithmetic on boolean"
        );
        let has_type_error = result
            .errors
            .iter()
            .any(|e| e.contains("bigint") || e.contains("boolean"));
        assert!(
            has_type_error,
            "expected type mismatch error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_valid_stateful_contract_passes_typecheck() {
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
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors for stateful contract, got: {:?}",
            result.errors
        );
    }
}
