//! Pass 2: Validate
//!
//! Validates the Rúnar AST against the language subset constraints.
//! This pass does NOT modify the AST; it only reports errors and warnings.

use std::collections::{BTreeSet, HashMap, HashSet};

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

    // Issue #123: reject preimage-field reads / output bindings that are
    // unsound under a method's declared @sighash mode (security core). This
    // pass emits both errors (unsound usages) and warnings (e.g. an explicit
    // single-output SINGLE covenant whose same-index value cannot be pinned
    // statically), so route each diagnostic to the matching bucket.
    for d in super::sighash_validate::validate_sighash_usage(contract) {
        match d.severity {
            super::diagnostic::Severity::Warning => warnings.push(d),
            _ => errors.push(d),
        }
    }

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
        | PrimitiveTypeName::Point
        | PrimitiveTypeName::P256Point
        | PrimitiveTypeName::P384Point => true,
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

        // Validate initializer if present. FixedArray properties accept an
        // array literal of literal elements (recursively, for nested arrays);
        // other properties accept a plain literal value. Mirrors the TS
        // validator in `02-validate.ts` and the Go peer in `validator.go`.
        if let Some(init) = &prop.initializer {
            if matches!(prop.prop_type, TypeNode::FixedArray { .. }) {
                if !is_array_literal_of_literals(init) {
                    errors.push(Diagnostic::error(
                        format!(
                            "property '{}' initializer must be an array literal of literal values",
                            prop.name
                        ),
                        Some(prop.source_location.clone()),
                    ));
                }
            } else if !is_literal_expression(init) {
                errors.push(Diagnostic::error(
                    format!(
                        "property '{}' initializer must be a literal value",
                        prop.name
                    ),
                    Some(prop.source_location.clone()),
                ));
            }
        }
    }

    // SmartContract (and the asm-escape-hatch UnsafeSmartContract) require all
    // properties to be readonly.
    if contract.parent_class == "SmartContract" || contract.parent_class == "UnsafeSmartContract" {
        for prop in &contract.properties {
            if !prop.readonly {
                errors.push(Diagnostic::error(format!(
                    "property '{}' in {} must be readonly. Use StatefulSmartContract for mutable state.",
                    prop.name, contract.parent_class
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

/// Reports whether the expression is a literal allowed as a property
/// initializer (bigint, bool, bytestring, or a negated bigint literal).
/// Mirrors the TS/Go validator helpers.
fn is_literal_expression(expr: &Expression) -> bool {
    match expr {
        Expression::BigIntLiteral { .. }
        | Expression::BoolLiteral { .. }
        | Expression::ByteStringLiteral { .. } => true,
        Expression::UnaryExpr { op, operand } => {
            *op == UnaryOp::Neg && matches!(operand.as_ref(), Expression::BigIntLiteral { .. })
        }
        _ => false,
    }
}

/// Reports whether the expression is an array literal whose elements are all
/// literal values (recursively, for nested FixedArray initializers).
fn is_array_literal_of_literals(expr: &Expression) -> bool {
    let Expression::ArrayLiteral { elements } = expr else {
        return false;
    };
    elements.iter().all(|el| match el {
        Expression::ArrayLiteral { .. } => is_array_literal_of_literals(el),
        _ => is_literal_expression(el),
    })
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
                "Unsupported type '{}' in property declaration. Use one of: bigint, boolean, ByteString, PubKey, Sig, Sha256, Ripemd160, Addr, SigHashPreimage, RabinSig, RabinPubKey, Point, P256Point, P384Point, or FixedArray<T, N>",
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

    validate_constructor_slot_bijection(contract, errors);
}

/// Enforce the NEW-002 invariant: every constructor parameter initialises
/// exactly one property that needs a deploy-time value, and the i-th parameter
/// initialises the i-th such property.
///
/// A property's deploy-time value comes from a constructor ARGUMENT, and the
/// artifact addresses those arguments POSITIONALLY: the ABI constructor params
/// come from the constructor SIGNATURE while a constructor slot's `paramIndex`
/// is an index into the properties with no `initial_value`, and the SDK splices
/// `constructorArgs[slot.paramIndex]` into the slot's bytes. Two independently
/// built lists, assumed to line up. Where they disagree a deploy argument lands
/// in ANOTHER property's slot, silently — a deployed contract authorising a
/// value the developer never passed for that property.
///
/// "Needs a deploy-time value" mirrors `constructor_assigned_properties` in
/// `anf_lower.rs` exactly: a property carries a compile-time `initial_value`
/// iff it has an initializer the constructor does NOT override by assigning it
/// a bare parameter.
fn validate_constructor_slot_bijection(contract: &ContractNode, errors: &mut Vec<Diagnostic>) {
    let ctor = &contract.constructor;
    let param_index: HashMap<&str, usize> = ctor
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    // property -> distinct bare parameters assigned to it; a property with any
    // non-parameter assignment is recorded with an EMPTY set.
    let mut prop_to_params: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut param_to_props: HashMap<String, BTreeSet<String>> = HashMap::new();
    for stmt in &ctor.body {
        let Statement::Assignment { target, value, .. } = stmt else {
            continue;
        };
        let Expression::PropertyAccess { property } = target else {
            continue;
        };
        match value {
            Expression::Identifier { name } if param_index.contains_key(name.as_str()) => {
                prop_to_params
                    .entry(property.clone())
                    .or_default()
                    .insert(name.clone());
                param_to_props
                    .entry(name.clone())
                    .or_default()
                    .insert(property.clone());
            }
            _ => {
                prop_to_params.entry(property.clone()).or_default();
            }
        }
    }

    let before = errors.len();

    // (a) One parameter feeding several properties: only one of them could own
    // the argument, so the rest keep a default or deploy undefined.
    for param in &ctor.params {
        let props = param_to_props.get(&param.name);
        if props.map(BTreeSet::len).unwrap_or(0) > 1 {
            let names: Vec<&str> = props.unwrap().iter().map(String::as_str).collect();
            errors.push(Diagnostic::error(
                format!(
                    "Constructor parameter '{}' initialises more than one property ({}). \
                     Each constructor parameter is spliced into exactly one property's \
                     deploy-time slot, so only the first would receive the argument. \
                     Declare one parameter per property.",
                    param.name,
                    names.join(", ")
                ),
                Some(ctor.source_location.clone()),
            ));
        }
    }

    // (b) One property fed by several parameters — no single argument owns it.
    for prop in &contract.properties {
        let params = prop_to_params.get(&prop.name);
        if params.map(BTreeSet::len).unwrap_or(0) > 1 {
            let names: Vec<&str> = params.unwrap().iter().map(String::as_str).collect();
            errors.push(Diagnostic::error(
                format!(
                    "Property '{}' is assigned more than one constructor parameter ({}). \
                     Each property that needs a deploy-time value corresponds to exactly \
                     one constructor parameter.",
                    prop.name,
                    names.join(", ")
                ),
                Some(ctor.source_location.clone()),
            ));
        }
    }

    // (c) A property that needs a deploy-time value but whose constructor
    // assignment is not a parameter. A property assigned NOTHING is already
    // reported above, so it is skipped here rather than double-reported.
    for prop in &contract.properties {
        if prop.initializer.is_some() {
            continue;
        }
        match prop_to_params.get(&prop.name) {
            Some(params) if params.is_empty() => {
                errors.push(Diagnostic::error(
                    format!(
                        "Property '{}' has no initializer and is not assigned a constructor \
                         parameter, so it has no deploy-time value. The constructor body is \
                         not compiled into the locking script — give the property a literal \
                         initializer or assign it a constructor parameter (this.{} = {}).",
                        prop.name, prop.name, prop.name
                    ),
                    Some(ctor.source_location.clone()),
                ));
            }
            _ => {}
        }
    }

    // (d) A parameter that initialises nothing: its argument is dropped and,
    // because slots are positional, every later argument lands in the wrong slot.
    for param in &ctor.params {
        if param_to_props.contains_key(&param.name) {
            continue;
        }
        errors.push(Diagnostic::error(
            format!(
                "Constructor parameter '{}' does not initialise any property. Constructor \
                 arguments are spliced into property slots positionally, so an unused \
                 parameter drops its own argument and shifts every later one into the wrong \
                 property's slot. Assign it (this.{} = {}) or remove the parameter.",
                param.name, param.name, param.name
            ),
            Some(ctor.source_location.clone()),
        ));
    }

    // (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions
    // being compared are themselves the thing that is broken.
    if errors.len() != before {
        return;
    }
    let mut slot = 0usize;
    for prop in &contract.properties {
        let params = prop_to_params.get(&prop.name);
        let single = params.filter(|p| p.len() == 1).map(|p| p.iter().next().unwrap());
        if prop.initializer.is_some() && single.is_none() {
            continue; // initializer survives: not a deploy-time property
        }
        if let Some(param) = single {
            let declared = param_index[param.as_str()];
            if declared != slot {
                let abi_name = ctor
                    .params
                    .get(slot)
                    .map(|p| p.name.as_str())
                    .unwrap_or("?");
                errors.push(Diagnostic::error(
                    format!(
                        "Property '{}' occupies deploy-time slot {}, but the constructor \
                         parameter that initialises it ('{}') is declared at position {}. \
                         Constructor arguments are spliced positionally, so the deployed \
                         script would carry argument {} — advertised by the ABI as parameter \
                         '{}' — in this property's slot. Declare the parameters in the same \
                         order as the properties they initialise.",
                        prop.name, slot, param, declared, slot, abi_name
                    ),
                    Some(ctor.source_location.clone()),
                ));
            }
        }
        slot += 1;
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
    // A contract with no public methods has no spending entry points and
    // compiles to an empty script — never what the author meant (usually a
    // missing `public` modifier; methods default to private).
    if !contract.methods.iter().any(|m| m.visibility == Visibility::Public) {
        errors.push(Diagnostic::error(
            format!(
                "Contract '{}' has no public methods — no spending entry points; add 'public' to at least one method",
                contract.name
            ),
            None,
        ));
    }

    for method in &contract.methods {
        validate_method(method, contract, errors);

        // V24, V25: Warn when StatefulSmartContract public method calls checkPreimage or getStateScript explicitly
        if contract.parent_class == "StatefulSmartContract" && method.visibility == Visibility::Public {
            warn_manual_preimage_usage(method, warnings);
        }

        // #131: warn when a public method gates on extractLocktime but never
        // asserts the spending tx is non-final (extractSequence < 0xffffffff).
        // Advisory only.
        if method.visibility == Visibility::Public {
            warn_locktime_without_sequence_guard(method, contract, warnings);
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

    // `return` is a PRIVATE-helper construct only (NEW-012).
    if method.visibility == Visibility::Public {
        reject_return_in_public_method(method, errors);
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

    // UnsafeSmartContract public methods must end with either an assert() call
    // or a terminal asm({..., out_arity: 1}) — either way the script has to
    // leave a truthy value on the stack.
    if method.visibility == Visibility::Public && contract.parent_class == "UnsafeSmartContract" {
        if !ends_with_assert(&method.body) && !ends_with_terminal_asm(&method.body) {
            errors.push(Diagnostic::error(format!(
                "public method '{}' must end with an assert() call or a terminal asm({{...}}) with out_arity 1",
                method.name
            ), Some(method.source_location.clone())));
        }
    }

    // Gate asm({...}) calls on UnsafeSmartContract and check the structural args.
    validate_asm_usage(method, contract, errors);

    // readonly properties may only be assigned in the constructor.
    check_readonly_writes(method, contract, errors);

    // Validate all statements in method body
    for stmt in &method.body {
        validate_statement(stmt, errors);
    }
}

// ---------------------------------------------------------------------------
// Readonly property writes
// ---------------------------------------------------------------------------

/// Resolve the contract property an assignment target writes to, if any.
/// Unwraps `IndexAccess` chains so `this.grid[i][j] = v` resolves to `grid`.
fn written_property(target: &Expression) -> Option<&str> {
    let mut node = target;
    while let Expression::IndexAccess { object, .. } = node {
        node = object.as_ref();
    }
    match node {
        Expression::PropertyAccess { property } => Some(property.as_str()),
        _ => None,
    }
}

/// `spec/semantics.md`:
///   `<this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property`
///
/// The constructor is exempt — that is where every contract initialises its
/// readonly properties — so this runs per METHOD only (`validate_constructor`
/// never calls in here).
///
/// Three AST shapes reach `update_prop` in ANF lowering and are all covered:
/// `this.p = e`, `this.p++` / `this.p--`, and `this.arr[i] = e`.
fn check_readonly_writes(
    method: &MethodNode,
    contract: &ContractNode,
    errors: &mut Vec<Diagnostic>,
) {
    let readonly: HashSet<&str> = contract
        .properties
        .iter()
        .filter(|p| p.readonly)
        .map(|p| p.name.as_str())
        .collect();
    if readonly.is_empty() {
        return;
    }

    let mut hits: Vec<(String, SourceLocation)> = Vec::new();

    fn visit_expr(
        expr: &Expression,
        loc: &SourceLocation,
        readonly: &HashSet<&str>,
        hits: &mut Vec<(String, SourceLocation)>,
    ) {
        walk_expression(expr, &mut |e| {
            let operand = match e {
                Expression::IncrementExpr { operand, .. } => operand.as_ref(),
                Expression::DecrementExpr { operand, .. } => operand.as_ref(),
                _ => return,
            };
            if let Some(name) = written_property(operand) {
                if readonly.contains(name) {
                    hits.push((name.to_string(), loc.clone()));
                }
            }
        });
    }

    fn visit_statements(
        stmts: &[Statement],
        readonly: &HashSet<&str>,
        hits: &mut Vec<(String, SourceLocation)>,
    ) {
        for stmt in stmts {
            match stmt {
                Statement::Assignment {
                    target,
                    value,
                    source_location,
                } => {
                    if let Some(name) = written_property(target) {
                        if readonly.contains(name) {
                            hits.push((name.to_string(), source_location.clone()));
                        }
                    }
                    visit_expr(target, source_location, readonly, hits);
                    visit_expr(value, source_location, readonly, hits);
                }
                Statement::VariableDecl {
                    init,
                    source_location,
                    ..
                } => visit_expr(init, source_location, readonly, hits),
                Statement::ExpressionStatement {
                    expression,
                    source_location,
                } => visit_expr(expression, source_location, readonly, hits),
                Statement::ReturnStatement {
                    value,
                    source_location,
                } => {
                    if let Some(v) = value {
                        visit_expr(v, source_location, readonly, hits);
                    }
                }
                Statement::IfStatement {
                    condition,
                    then_branch,
                    else_branch,
                    source_location,
                } => {
                    visit_expr(condition, source_location, readonly, hits);
                    visit_statements(then_branch, readonly, hits);
                    if let Some(else_body) = else_branch {
                        visit_statements(else_body, readonly, hits);
                    }
                }
                Statement::ForStatement {
                    init,
                    condition,
                    update,
                    body,
                    source_location,
                } => {
                    visit_statements(std::slice::from_ref(init.as_ref()), readonly, hits);
                    visit_statements(std::slice::from_ref(update.as_ref()), readonly, hits);
                    visit_expr(condition, source_location, readonly, hits);
                    visit_statements(body, readonly, hits);
                }
            }
        }
    }

    visit_statements(&method.body, &readonly, &mut hits);

    for (name, loc) in hits {
        errors.push(Diagnostic::error(
            format!(
                "cannot assign to readonly property '{}' in method '{}'. readonly properties may only be assigned in the constructor.",
                name, method.name
            ),
            Some(loc),
        ));
    }
}


/// Enforces `spec/grammar.md:161` ("Public methods MUST return `void`") and
/// `:162` ("Public methods MUST end with an `assert(...)` call as their final
/// statement").
///
/// `spec/semantics.md` gives `return` no early-exit meaning at all: §4.6 defines
/// it ONLY as "the value of this method is v" (the private-helper inlining
/// semantics), while §4.7 sequences statements UNCONDITIONALLY — there is no
/// rule under which the statements after a `return` are skipped.
///
/// Lowering it as if it were the tail of an inlined helper produced two
/// different broken scripts (NEW-012):
///
///   - `return;`      the enclosing branch had no result to contribute, so its
///                    arm yielded OP_0 and the whole script evaluated FALSE —
///                    an unspendable UTXO from source that compiled clean.
///   - `return expr;` the returned value became the branch result and hence the
///                    script's final truthiness, so any truthy expr spent the
///                    contract WITHOUT reaching the guarding assert. Fail-OPEN.
///
/// The Java tier has always rejected the valued form; this brings the rule to
/// every tier and covers the bare form too.
fn reject_return_in_public_method(method: &MethodNode, errors: &mut Vec<Diagnostic>) {
    let mut found: Vec<SourceLocation> = Vec::new();
    collect_return_statements(&method.body, &mut found);
    for loc in found {
        errors.push(Diagnostic::error(
            format!(
                "public method '{}' must not use `return`: public methods are spending \
                 entry points, they return void (spec/grammar.md:161) and must end with \
                 an assert() that encodes the spending condition (spec/grammar.md:162). \
                 Rúnar has no early exit — restructure the guard as an if/else, or move \
                 the logic into a private helper, where `return` is allowed.",
                method.name
            ),
            Some(loc),
        ));
    }
}

/// Collects every `return` in `body`, at any nesting depth (if/else arms, loop
/// bodies).
fn collect_return_statements(body: &[Statement], out: &mut Vec<SourceLocation>) {
    for stmt in body {
        match stmt {
            Statement::ReturnStatement { source_location, .. } => {
                out.push(source_location.clone());
            }
            Statement::IfStatement { then_branch, else_branch, .. } => {
                collect_return_statements(then_branch, out);
                if let Some(else_body) = else_branch {
                    collect_return_statements(else_body, out);
                }
            }
            Statement::ForStatement { body, .. } => collect_return_statements(body, out),
            _ => {}
        }
    }
}

/// Reports whether `expr` is a call to the `asm` compiler intrinsic.
fn is_asm_call(expr: &Expression) -> bool {
    if let Expression::CallExpr { callee, .. } = expr {
        if let Expression::Identifier { name } = callee.as_ref() {
            return name == "asm";
        }
    }
    false
}

/// Reports whether the last statement of `body` is an asm({...}) call with the
/// parser-normalised positional args (body, in_arity, out_arity) and an
/// out_arity literal equal to 1.
///
/// If/else branches that both terminate in a terminal asm (or assert) also
/// count, mirroring the asserts-on-both-branches rule.
fn ends_with_terminal_asm(body: &[Statement]) -> bool {
    if body.is_empty() {
        return false;
    }
    let last = &body[body.len() - 1];

    if let Statement::ExpressionStatement { expression, .. } = last {
        if !is_asm_call(expression) {
            return false;
        }
        if let Expression::CallExpr { args, .. } = expression {
            // The parser always rewrites asm({...}) into positional
            // (body, in_arity, out_arity).
            if args.len() == 3 {
                if let Expression::BigIntLiteral { value } = &args[2] {
                    use num_traits::One;
                    return value.is_one();
                }
            }
        }
        return false;
    }

    if let Statement::IfStatement {
        then_branch,
        else_branch,
        ..
    } = last
    {
        let then_ends = ends_with_terminal_asm(then_branch) || ends_with_assert(then_branch);
        let else_ends = else_branch
            .as_ref()
            .map_or(false, |e| ends_with_terminal_asm(e) || ends_with_assert(e));
        return then_ends && else_ends;
    }

    false
}

/// Walks a method body and validates every asm({...}) call:
///
///   - Reject any asm() outside an UnsafeSmartContract.
///   - Confirm the parser-normalised arg shape: (body, in_arity, out_arity)
///     where body is a ByteString literal with even-length hex and the arities
///     are non-negative bigint literals.
///   - Expression-form asm<T>({...}) must have out_arity 1.
///
/// The parser already pushes most hex diagnostics; this pass is the back-stop
/// that runs even when the parser shape is well-formed and is the only layer
/// that knows about the contract's parentClass.
fn validate_asm_usage(
    method: &MethodNode,
    contract: &ContractNode,
    errors: &mut Vec<Diagnostic>,
) {
    walk_expressions_in_body(&method.body, &mut |expr| {
        if !is_asm_call(expr) {
            return;
        }
        let (args, asm_return_type) = match expr {
            Expression::CallExpr {
                args,
                asm_return_type,
                ..
            } => (args, asm_return_type),
            _ => return,
        };

        if contract.parent_class != "UnsafeSmartContract" {
            errors.push(Diagnostic::error(format!(
                "'asm' is only available in contracts extending UnsafeSmartContract; got {}. Move the call into a class that extends UnsafeSmartContract (and import {{ UnsafeSmartContract }} from 'runar-lang').",
                contract.parent_class
            ), None));
            return;
        }

        if args.len() != 3 {
            errors.push(Diagnostic::error(
                "asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }",
                None,
            ));
            return;
        }

        match &args[0] {
            Expression::ByteStringLiteral { value } => {
                if value.is_empty() {
                    errors.push(Diagnostic::error(
                        "asm() body must be a non-empty hex string literal",
                        None,
                    ));
                } else if value.len() % 2 != 0 {
                    errors.push(Diagnostic::error(format!(
                        "asm() body has odd hex length ({}); each opcode byte requires two hex characters",
                        value.len()
                    ), None));
                } else if !is_hex_string(value) {
                    errors.push(Diagnostic::error(
                        "asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed",
                        None,
                    ));
                }
            }
            _ => {
                errors.push(Diagnostic::error(
                    "asm() body must be a hex string literal",
                    None,
                ));
                return;
            }
        }

        use num_traits::{Signed, ToPrimitive};
        match &args[1] {
            Expression::BigIntLiteral { value } if !value.is_negative() => {}
            _ => errors.push(Diagnostic::error(
                "asm() in_arity must be a non-negative integer literal",
                None,
            )),
        }

        let out_arity_val: Option<i128> = match &args[2] {
            Expression::BigIntLiteral { value } if !value.is_negative() => value.to_i128(),
            _ => {
                errors.push(Diagnostic::error(
                    "asm() out_arity must be a non-negative integer literal",
                    None,
                ));
                None
            }
        };

        // Expression-form asm<T>({...}) returns a value that flows into a
        // let-binding — exactly ONE stack value, so out_arity must be 1.
        if let (Some(ret), Some(out)) = (asm_return_type.as_deref(), out_arity_val) {
            if out != 1 {
                errors.push(Diagnostic::error(format!(
                    "Expression-form asm<{}>() must have out_arity 1 (got {}); only a single stack value can be bound to the result variable.",
                    ret, out
                ), None));
            }
        }
    });
}

/// Reports whether `s` contains only hex digits (0-9, a-f, A-F).
fn is_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
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

            // Check that the loop bound is a compile-time constant. Non-zero
            // starts and countdown loops (`i--` with `>`/`>=`) are supported:
            // the ANF loop node carries an explicit start value and step
            // direction (issue #121), so lowering binds `iterVar = start +
            // i*step` on each unrolled iteration.
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
    // Only integer literals (and their negation) can be unrolled into fixed
    // Bitcoin Script by anf-lower. A bare identifier bound (e.g. `const N`) or a
    // runtime member access (`this.x`) is NOT resolvable and must be rejected
    // here with a graceful diagnostic — anf-lower's `extract_loop_shape` would
    // otherwise panic. This mirrors the reference TS compiler's observable
    // behavior: only literal loop bounds compile.
    match expr {
        Expression::BigIntLiteral { .. } => true,
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

// ---------------------------------------------------------------------------
// #131: locktime soundness — extractLocktime needs an extractSequence guard
// ---------------------------------------------------------------------------

/// Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value.
const SEQUENCE_FINAL: u64 = 0xffff_ffff;

/// True when `expr` is a direct call to the named intrinsic, e.g. `f(...)`.
fn is_call_to_named(expr: &Expression, name: &str) -> bool {
    if let Expression::CallExpr { callee, .. } = expr {
        if let Expression::Identifier { name: callee_name } = callee.as_ref() {
            return callee_name == name;
        }
    }
    false
}

/// True when `expr` reads the transaction locktime. Both the raw intrinsic
/// `extractLocktime(preimage)` and its ergonomic sugar `currentBlockHeight()`
/// (which the ANF pass desugars to `extractLocktime(txPreimage)`) count —
/// either read is unsound without a sequence-finality guard.
fn is_locktime_read(expr: &Expression) -> bool {
    is_call_to_named(expr, "extractLocktime") || is_call_to_named(expr, "currentBlockHeight")
}

/// True when `expr` is an `extractSequence(...) < <final>`-style comparison
/// (the guard that makes a locktime gate consensus-enforced). Accepts the two
/// natural spellings: `extractSequence(pre) < N` / `<= N`, and the reversed
/// `N > extractSequence(pre)` / `>= ...`. `N` must be a bigint literal no
/// greater than the finality sentinel, so the guard genuinely forces
/// non-finality.
fn is_sequence_finality_guard(expr: &Expression) -> bool {
    let Expression::BinaryExpr { op, left, right } = expr else {
        return false;
    };
    let bound_ok = |e: &Expression| -> bool {
        matches!(
            e,
            Expression::BigIntLiteral { value }
                if *value <= num_bigint::BigInt::from(SEQUENCE_FINAL)
        )
    };
    match op {
        BinaryOp::Lt | BinaryOp::Le => is_call_to_named(left, "extractSequence") && bound_ok(right),
        BinaryOp::Gt | BinaryOp::Ge => is_call_to_named(right, "extractSequence") && bound_ok(left),
        _ => false,
    }
}

/// #131: warn when `method` (transitively, through the private-helper call
/// graph) reads the tx locktime but never asserts the tx is non-final. A
/// locktime gate is not consensus-enforced unless `extractSequence < 0xffffffff`
/// is also asserted — otherwise an all-final-sequence spend bypasses it.
/// Advisory (warning) only — no effect on emitted bytecode.
fn warn_locktime_without_sequence_guard(
    method: &MethodNode,
    contract: &ContractNode,
    warnings: &mut Vec<Diagnostic>,
) {
    // Map of private helper methods by name (BFS follows calls into these).
    let private_methods: HashMap<&str, &MethodNode> = contract
        .methods
        .iter()
        .filter(|m| m.visibility == Visibility::Private)
        .map(|m| (m.name.as_str(), m))
        .collect();

    let mut reads_locktime = false;
    let mut has_sequence_guard = false;
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(method.name.clone());
    let mut queue: std::collections::VecDeque<&MethodNode> = std::collections::VecDeque::new();
    queue.push_back(method);

    while let Some(current) = queue.pop_front() {
        walk_expressions_in_body(&current.body, &mut |expr| {
            if is_locktime_read(expr) {
                reads_locktime = true;
            }
            if is_sequence_finality_guard(expr) {
                has_sequence_guard = true;
            }
        });
        // Follow calls into private helpers so a guard (or locktime read)
        // supplied by an inlined helper is seen by the public entry point.
        // Reuses the shared `collect_method_calls` recursion-detection helper.
        let mut calls = HashSet::new();
        collect_method_calls(&current.body, &mut calls);
        for callee in calls {
            if !visited.contains(&callee) {
                if let Some(m) = private_methods.get(callee.as_str()) {
                    visited.insert(callee.clone());
                    queue.push_back(m);
                }
            }
        }
    }

    if reads_locktime && !has_sequence_guard {
        warnings.push(Diagnostic::warning(
            format!(
                "method '{}' reads extractLocktime but does not assert \
                 extractSequence < 0xffffffff; a locktime gate is not \
                 consensus-enforced unless the tx is non-final — add \
                 assert(extractSequence(this.txPreimage) < 0xffffffffn)",
                method.name
            ),
            Some(method.source_location.clone()),
        ));
    }
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
        Expression::CallExpr { callee, args, .. } => {
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

    // -----------------------------------------------------------------------
    // #126: contract with no public methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_public_methods_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class NoPub extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    private helper(v: bigint): bigint {
        return v + this.x;
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("no public methods")),
            "expected 'no public methods' error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_public_method_passes_no_public_methods_check() {
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
            !result
                .errors
                .iter()
                .any(|e| e.message.contains("no public methods")),
            "did not expect 'no public methods' error, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // #121: non-zero-start and countdown loops are now accepted (were rejected
    // under the earlier count-only ANF loop node).
    // -----------------------------------------------------------------------

    #[test]
    fn test_countdown_loop_gt_accepted() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Countdown extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 3n; i > 0n; i--) {
            sum = sum + i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.message.contains("countdown loops are not supported")
                    || e.message.contains("must start at 0")),
            "countdown loop should be accepted (#121), got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_countdown_loop_ge_accepted() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Countdown extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 3n; i >= 1n; i--) {
            sum = sum + i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.message.contains("countdown loops are not supported")
                    || e.message.contains("must start at 0")),
            "countdown loop should be accepted (#121), got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_non_zero_start_loop_accepted() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class NonZeroStart extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 1n; i < 3n; i++) {
            sum = sum + i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.message.contains("countdown loops are not supported")
                    || e.message.contains("must start at 0")),
            "non-zero-start loop should be accepted (#121), got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_zero_start_count_up_loop_passes() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class ZeroStart extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 0n; i < 3n; i++) {
            sum += i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_contract(source);
        let result = validate(&contract);
        assert!(
            !result.errors.iter().any(|e| {
                e.message.contains("countdown loops are not supported")
                    || e.message.contains("must start at 0")
            }),
            "zero-start counting-up loop should not trigger loop-shape errors, got: {:?}",
            result.errors
        );
    }
}
