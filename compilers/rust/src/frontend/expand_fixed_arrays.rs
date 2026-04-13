//! Pass 3b: Expand fixed-size array properties into scalar sibling fields.
//!
//! Runs after typecheck and before ANF lowering. Mirrors the TypeScript
//! reference at `packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts`.
//!
//! Semantics:
//!   - Expand every `FixedArray<T, N>` property into N scalar siblings
//!     `<base>__<i>`, recursively for nested arrays.
//!   - Attach a `synthetic_array_chain` marker (outermost first) to each
//!     leaf PropertyNode so the assembler can re-group them.
//!   - Distribute array-literal initializers; length mismatch is a compile
//!     error.
//!   - Rewrite `index_access`:
//!       - Literal index -> direct property access; out-of-range is an
//!         error.
//!       - Runtime index read at statement level -> if/else chain that
//!         reassigns `target`, using `board__{N-1}` as the fallback.
//!       - Runtime index read in expression context -> nested ternary chain
//!         terminating in the last slot (no bounds check, matches v1
//!         TicTacToe semantics).
//!       - Runtime index write -> if/else chain with `assert(false)` final
//!         else.
//!       - Nested literal-index chain (`self.grid[0][1]`) -> resolve to a
//!         single synthetic leaf.
//!       - Runtime index on nested FixedArray -> compile error.
//!   - Non-pure index/value expressions are hoisted to fresh
//!     `__idx_K` / `__val_K` bindings.

use std::collections::HashMap;

use super::ast::*;
use super::diagnostic::Diagnostic;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub struct ExpandResult {
    pub contract: ContractNode,
    pub errors: Vec<Diagnostic>,
}

/// Expand fixed-array properties in `contract` into scalar siblings and
/// rewrite every `index_access` on such properties into direct-access or
/// dispatch form. Pure AST -> AST.
pub fn expand_fixed_arrays(contract: &ContractNode) -> ExpandResult {
    let mut ctx = ExpandContext::new(contract);

    if !ctx.collect_arrays() {
        return ExpandResult {
            contract: contract.clone(),
            errors: ctx.errors,
        };
    }
    if !ctx.errors.is_empty() {
        return ExpandResult {
            contract: contract.clone(),
            errors: ctx.errors,
        };
    }
    if ctx.array_map.is_empty() {
        return ExpandResult {
            contract: contract.clone(),
            errors: Vec::new(),
        };
    }

    let new_properties = ctx.rewrite_properties();
    if !ctx.errors.is_empty() {
        return ExpandResult {
            contract: contract.clone(),
            errors: ctx.errors,
        };
    }

    let new_constructor = ctx.rewrite_method(&contract.constructor);
    let new_methods: Vec<MethodNode> = contract
        .methods
        .iter()
        .map(|m| ctx.rewrite_method(m))
        .collect();

    if !ctx.errors.is_empty() {
        return ExpandResult {
            contract: contract.clone(),
            errors: ctx.errors,
        };
    }

    let rewritten = ContractNode {
        name: contract.name.clone(),
        parent_class: contract.parent_class.clone(),
        properties: new_properties,
        constructor: new_constructor,
        methods: new_methods,
        source_file: contract.source_file.clone(),
    };

    ExpandResult {
        contract: rewritten,
        errors: ctx.errors,
    }
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ArrayMeta {
    root_name: String,
    /// The outermost FixedArray element type (primitive or nested).
    element_type: TypeNode,
    /// Outer length.
    length: usize,
    /// One entry per outer slot: `<root>__<i>`.
    slot_names: Vec<String>,
    /// `true` if each outer slot is itself a FixedArray.
    slot_is_array: bool,
    /// Nested metadata, keyed by slot name. Present iff `slot_is_array`.
    nested: HashMap<String, ArrayMeta>,
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

struct ExpandContext<'a> {
    contract: &'a ContractNode,
    errors: Vec<Diagnostic>,
    /// Top-level array properties by original name.
    array_map: HashMap<String, ArrayMeta>,
    /// Every synthetic intermediate array (nested levels), keyed by
    /// synthetic name (e.g. `Grid__0`).
    synthetic_arrays: HashMap<String, ArrayMeta>,
    temp_counter: usize,
}

impl<'a> ExpandContext<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        Self {
            contract,
            errors: Vec::new(),
            array_map: HashMap::new(),
            synthetic_arrays: HashMap::new(),
            temp_counter: 0,
        }
    }

    fn fresh_idx_name(&mut self) -> String {
        let n = self.temp_counter;
        self.temp_counter += 1;
        format!("__idx_{}", n)
    }

    fn fresh_val_name(&mut self) -> String {
        let n = self.temp_counter;
        self.temp_counter += 1;
        format!("__val_{}", n)
    }

    /// Scan top-level properties for `fixed_array_type` entries and
    /// populate the array and synthetic maps.
    fn collect_arrays(&mut self) -> bool {
        for prop in &self.contract.properties {
            if !matches!(prop.prop_type, TypeNode::FixedArray { .. }) {
                continue;
            }
            let meta =
                match self.build_array_meta(&prop.name, &prop.prop_type, &prop.source_location) {
                    Some(m) => m,
                    None => return false,
                };
            self.array_map.insert(prop.name.clone(), meta);
        }
        true
    }

    fn build_array_meta(
        &mut self,
        root_name: &str,
        ty: &TypeNode,
        loc: &SourceLocation,
    ) -> Option<ArrayMeta> {
        let (element, length) = match ty {
            TypeNode::FixedArray { element, length } => (element.as_ref(), *length),
            _ => return None,
        };

        if let TypeNode::Primitive(PrimitiveTypeName::Void) = element {
            self.errors.push(Diagnostic::error(
                format!(
                    "FixedArray element type cannot be 'void' (property '{}')",
                    root_name
                ),
                Some(loc.clone()),
            ));
            return None;
        }
        if length == 0 {
            self.errors.push(Diagnostic::error(
                format!(
                    "FixedArray length must be a positive integer (property '{}')",
                    root_name
                ),
                Some(loc.clone()),
            ));
            return None;
        }

        let slot_names: Vec<String> = (0..length).map(|i| format!("{}__{}", root_name, i)).collect();

        let elem_is_array = matches!(element, TypeNode::FixedArray { .. });
        let mut nested: HashMap<String, ArrayMeta> = HashMap::new();
        if elem_is_array {
            for slot in &slot_names {
                let sub = self.build_array_meta(slot, element, loc)?;
                self.synthetic_arrays.insert(slot.clone(), sub.clone());
                nested.insert(slot.clone(), sub);
            }
        }

        Some(ArrayMeta {
            root_name: root_name.to_string(),
            element_type: element.clone(),
            length,
            slot_names,
            slot_is_array: elem_is_array,
            nested,
        })
    }

    // -----------------------------------------------------------------------
    // Property rewriting
    // -----------------------------------------------------------------------

    fn rewrite_properties(&mut self) -> Vec<PropertyNode> {
        let mut out: Vec<PropertyNode> = Vec::new();
        // Collect roots we are expanding so we can look up metas before the
        // iteration mutates `self.errors`.
        let props = self.contract.properties.clone();
        for prop in &props {
            if !matches!(prop.prop_type, TypeNode::FixedArray { .. }) {
                out.push(prop.clone());
                continue;
            }
            // Distribute initializer.
            let meta = match self.array_map.get(&prop.name).cloned() {
                Some(m) => m,
                None => continue,
            };
            let init_elems = match self.extract_array_literal_elements(prop, &meta) {
                ElementsResult::Error => return out,
                ElementsResult::Some(elems) => Some(elems),
                ElementsResult::None => None,
            };
            let expanded =
                self.expand_array_meta(&meta, prop.readonly, &prop.source_location, init_elems, Vec::new());
            out.extend(expanded);
        }
        out
    }

    fn extract_array_literal_elements(
        &mut self,
        prop: &PropertyNode,
        meta: &ArrayMeta,
    ) -> ElementsResult {
        let init = match &prop.initializer {
            Some(e) => e,
            None => return ElementsResult::None,
        };
        match init {
            Expression::ArrayLiteral { elements } => {
                if elements.len() != meta.length {
                    self.errors.push(Diagnostic::error(
                        format!(
                            "Initializer length {} does not match FixedArray length {} for property '{}'",
                            elements.len(),
                            meta.length,
                            prop.name
                        ),
                        Some(prop.source_location.clone()),
                    ));
                    return ElementsResult::Error;
                }
                ElementsResult::Some(elements.clone())
            }
            _ => {
                self.errors.push(Diagnostic::error(
                    format!(
                        "Property '{}' of type FixedArray must use an array literal initializer",
                        prop.name
                    ),
                    Some(prop.source_location.clone()),
                ));
                ElementsResult::Error
            }
        }
    }

    fn expand_array_meta(
        &mut self,
        meta: &ArrayMeta,
        readonly: bool,
        loc: &SourceLocation,
        initializer: Option<Vec<Expression>>,
        parent_chain: Vec<SyntheticArrayLevel>,
    ) -> Vec<PropertyNode> {
        let mut out: Vec<PropertyNode> = Vec::new();
        for i in 0..meta.length {
            let slot = &meta.slot_names[i];
            let slot_init: Option<Expression> = initializer
                .as_ref()
                .and_then(|elems| elems.get(i).cloned());

            let mut chain_here = parent_chain.clone();
            chain_here.push(SyntheticArrayLevel {
                base: meta.root_name.clone(),
                index: i,
                length: meta.length,
            });

            if meta.slot_is_array {
                let nested_meta = meta
                    .nested
                    .get(slot)
                    .cloned()
                    .expect("nested array meta must exist");
                let nested_init: Option<Vec<Expression>> = match slot_init {
                    None => None,
                    Some(Expression::ArrayLiteral { elements }) => {
                        if elements.len() != nested_meta.length {
                            self.errors.push(Diagnostic::error(
                                format!(
                                    "Nested FixedArray initializer length {} does not match expected length {}",
                                    elements.len(),
                                    nested_meta.length
                                ),
                                Some(loc.clone()),
                            ));
                            continue;
                        }
                        Some(elements)
                    }
                    Some(_) => {
                        self.errors.push(Diagnostic::error(
                            "Nested FixedArray element must be an array literal",
                            Some(loc.clone()),
                        ));
                        continue;
                    }
                };
                let nested_expanded =
                    self.expand_array_meta(&nested_meta, readonly, loc, nested_init, chain_here);
                out.extend(nested_expanded);
            } else {
                out.push(PropertyNode {
                    name: slot.clone(),
                    prop_type: meta.element_type.clone(),
                    readonly,
                    initializer: slot_init,
                    source_location: loc.clone(),
                    synthetic_array_chain: Some(chain_here),
                });
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Method rewriting
    // -----------------------------------------------------------------------

    fn rewrite_method(&mut self, method: &MethodNode) -> MethodNode {
        let new_body = self.rewrite_statements(&method.body);
        MethodNode {
            name: method.name.clone(),
            params: method.params.clone(),
            body: new_body,
            visibility: method.visibility.clone(),
            source_location: method.source_location.clone(),
        }
    }

    fn rewrite_statements(&mut self, stmts: &[Statement]) -> Vec<Statement> {
        let mut out: Vec<Statement> = Vec::new();
        for s in stmts {
            let produced = self.rewrite_statement(s);
            out.extend(produced);
        }
        out
    }

    fn rewrite_statement(&mut self, stmt: &Statement) -> Vec<Statement> {
        match stmt {
            Statement::VariableDecl { .. } => self.rewrite_variable_decl(stmt),
            Statement::Assignment { .. } => self.rewrite_assignment(stmt),
            Statement::IfStatement { .. } => self.rewrite_if_statement(stmt),
            Statement::ForStatement { .. } => self.rewrite_for_statement(stmt),
            Statement::ReturnStatement { .. } => self.rewrite_return_statement(stmt),
            Statement::ExpressionStatement { .. } => self.rewrite_expression_statement(stmt),
        }
    }

    fn rewrite_variable_decl(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (name, var_type, _mutable, init, loc) = match stmt {
            Statement::VariableDecl {
                name,
                var_type,
                mutable,
                init,
                source_location,
            } => (
                name.clone(),
                var_type.clone(),
                *mutable,
                init.clone(),
                source_location.clone(),
            ),
            _ => unreachable!(),
        };

        // Statement-form dispatch for `const v = self.board[idx]`.
        let target_expr = Expression::Identifier { name: name.clone() };
        if let Some(stmt_form) = self.try_rewrite_read_as_statements(&init, &target_expr, &loc) {
            let mut out: Vec<Statement> = Vec::new();
            out.extend(stmt_form.prelude);
            out.push(Statement::VariableDecl {
                name,
                var_type,
                mutable: true,
                init: stmt_form.fallback_init,
                source_location: loc,
            });
            out.extend(stmt_form.dispatch);
            return out;
        }

        let mut prelude: Vec<Statement> = Vec::new();
        let new_init = self.rewrite_expression(&init, &mut prelude);
        let mut out: Vec<Statement> = Vec::new();
        out.extend(prelude);
        out.push(Statement::VariableDecl {
            name,
            var_type,
            mutable: _mutable,
            init: new_init,
            source_location: loc,
        });
        out
    }

    fn rewrite_assignment(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (target, value, loc) = match stmt {
            Statement::Assignment {
                target,
                value,
                source_location,
            } => (target.clone(), value.clone(), source_location.clone()),
            _ => unreachable!(),
        };

        let mut prelude: Vec<Statement> = Vec::new();

        // Writes to `self.Board[...]`
        if let Expression::IndexAccess { object, index } = &target {
            // Try to resolve a nested literal-index chain.
            let chain = Expression::IndexAccess {
                object: object.clone(),
                index: index.clone(),
            };
            match self.try_resolve_literal_index_chain(&chain) {
                ChainResolve::Error => return prelude,
                ChainResolve::Leaf(name) => {
                    let rewritten_value = self.rewrite_expression(&value, &mut prelude);
                    let mut out = prelude;
                    out.push(Statement::Assignment {
                        target: Expression::PropertyAccess { property: name },
                        value: rewritten_value,
                        source_location: loc,
                    });
                    return out;
                }
                ChainResolve::None => {}
            }

            if let Expression::PropertyAccess { property } = object.as_ref() {
                if self.array_map.contains_key(property) {
                    return self.rewrite_array_write(
                        property.clone(),
                        index.as_ref().clone(),
                        value,
                        loc,
                    );
                }
            }
            // Not a fixed-array index write — rewrite sub-expressions.
            let new_index = self.rewrite_expression(index, &mut prelude);
            let new_obj = self.rewrite_expression(object, &mut prelude);
            let new_value = self.rewrite_expression(&value, &mut prelude);
            let mut out = prelude;
            out.push(Statement::Assignment {
                target: Expression::IndexAccess {
                    object: Box::new(new_obj),
                    index: Box::new(new_index),
                },
                value: new_value,
                source_location: loc,
            });
            return out;
        }

        // Statement-form dispatch for `target = self.board[idx]`.
        if matches!(
            target,
            Expression::Identifier { .. } | Expression::PropertyAccess { .. }
        ) {
            if let Some(stmt_form) = self.try_rewrite_read_as_statements(&value, &target, &loc) {
                let mut out: Vec<Statement> = Vec::new();
                out.extend(stmt_form.prelude);
                out.push(Statement::Assignment {
                    target: target.clone(),
                    value: stmt_form.fallback_init,
                    source_location: loc.clone(),
                });
                out.extend(stmt_form.dispatch);
                return out;
            }
        }

        let new_target = self.rewrite_expression(&target, &mut prelude);
        let new_value = self.rewrite_expression(&value, &mut prelude);
        let mut out = prelude;
        out.push(Statement::Assignment {
            target: new_target,
            value: new_value,
            source_location: loc,
        });
        out
    }

    fn rewrite_if_statement(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (condition, then_branch, else_branch, loc) = match stmt {
            Statement::IfStatement {
                condition,
                then_branch,
                else_branch,
                source_location,
            } => (
                condition.clone(),
                then_branch.clone(),
                else_branch.clone(),
                source_location.clone(),
            ),
            _ => unreachable!(),
        };
        let mut prelude: Vec<Statement> = Vec::new();
        let new_cond = self.rewrite_expression(&condition, &mut prelude);
        let new_then = self.rewrite_statements(&then_branch);
        let new_else = else_branch.as_ref().map(|e| self.rewrite_statements(e));
        let mut out = prelude;
        out.push(Statement::IfStatement {
            condition: new_cond,
            then_branch: new_then,
            else_branch: new_else,
            source_location: loc,
        });
        out
    }

    fn rewrite_for_statement(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (init, condition, update, body, loc) = match stmt {
            Statement::ForStatement {
                init,
                condition,
                update,
                body,
                source_location,
            } => (
                init.clone(),
                condition.clone(),
                update.clone(),
                body.clone(),
                source_location.clone(),
            ),
            _ => unreachable!(),
        };

        let mut prelude: Vec<Statement> = Vec::new();
        let new_cond = self.rewrite_expression(&condition, &mut prelude);

        let mut init_prelude: Vec<Statement> = Vec::new();
        let new_init_stmt = match init.as_ref() {
            Statement::VariableDecl {
                name,
                var_type,
                mutable,
                init: init_expr,
                source_location,
            } => {
                let new_init_expr = self.rewrite_expression(init_expr, &mut init_prelude);
                Statement::VariableDecl {
                    name: name.clone(),
                    var_type: var_type.clone(),
                    mutable: *mutable,
                    init: new_init_expr,
                    source_location: source_location.clone(),
                }
            }
            other => other.clone(),
        };
        if !init_prelude.is_empty() {
            prelude.extend(init_prelude);
        }

        let new_update_list = self.rewrite_statement(update.as_ref());
        let mut new_body = self.rewrite_statements(&body);
        let new_update: Statement = if new_update_list.len() == 1 {
            new_update_list.into_iter().next().unwrap()
        } else {
            let mut list = new_update_list;
            let tail = list.pop().expect("non-empty list");
            new_body.extend(list);
            tail
        };

        let mut out = prelude;
        out.push(Statement::ForStatement {
            init: Box::new(new_init_stmt),
            condition: new_cond,
            update: Box::new(new_update),
            body: new_body,
            source_location: loc,
        });
        out
    }

    fn rewrite_return_statement(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (value, loc) = match stmt {
            Statement::ReturnStatement {
                value,
                source_location,
            } => (value.clone(), source_location.clone()),
            _ => unreachable!(),
        };
        match value {
            None => vec![Statement::ReturnStatement {
                value: None,
                source_location: loc,
            }],
            Some(v) => {
                let mut prelude: Vec<Statement> = Vec::new();
                let new_v = self.rewrite_expression(&v, &mut prelude);
                let mut out = prelude;
                out.push(Statement::ReturnStatement {
                    value: Some(new_v),
                    source_location: loc,
                });
                out
            }
        }
    }

    fn rewrite_expression_statement(&mut self, stmt: &Statement) -> Vec<Statement> {
        let (expression, loc) = match stmt {
            Statement::ExpressionStatement {
                expression,
                source_location,
            } => (expression.clone(), source_location.clone()),
            _ => unreachable!(),
        };
        let mut prelude: Vec<Statement> = Vec::new();
        let new_expr = self.rewrite_expression(&expression, &mut prelude);
        let mut out = prelude;
        out.push(Statement::ExpressionStatement {
            expression: new_expr,
            source_location: loc,
        });
        out
    }

    // -----------------------------------------------------------------------
    // Expression rewriting
    // -----------------------------------------------------------------------

    fn rewrite_expression(&mut self, expr: &Expression, prelude: &mut Vec<Statement>) -> Expression {
        match expr {
            Expression::IndexAccess { object, index } => {
                self.rewrite_index_access(object, index, prelude)
            }
            Expression::BinaryExpr { op, left, right } => {
                let l = self.rewrite_expression(left, prelude);
                let r = self.rewrite_expression(right, prelude);
                Expression::BinaryExpr {
                    op: op.clone(),
                    left: Box::new(l),
                    right: Box::new(r),
                }
            }
            Expression::UnaryExpr { op, operand } => {
                let o = self.rewrite_expression(operand, prelude);
                Expression::UnaryExpr {
                    op: op.clone(),
                    operand: Box::new(o),
                }
            }
            Expression::CallExpr { callee, args } => {
                let c = self.rewrite_expression(callee, prelude);
                let new_args: Vec<Expression> = args
                    .iter()
                    .map(|a| self.rewrite_expression(a, prelude))
                    .collect();
                Expression::CallExpr {
                    callee: Box::new(c),
                    args: new_args,
                }
            }
            Expression::MemberExpr { object, property } => {
                let o = self.rewrite_expression(object, prelude);
                Expression::MemberExpr {
                    object: Box::new(o),
                    property: property.clone(),
                }
            }
            Expression::TernaryExpr {
                condition,
                consequent,
                alternate,
            } => {
                let c = self.rewrite_expression(condition, prelude);
                let t = self.rewrite_expression(consequent, prelude);
                let e = self.rewrite_expression(alternate, prelude);
                Expression::TernaryExpr {
                    condition: Box::new(c),
                    consequent: Box::new(t),
                    alternate: Box::new(e),
                }
            }
            Expression::IncrementExpr { operand, prefix } => {
                let o = self.rewrite_expression(operand, prelude);
                Expression::IncrementExpr {
                    operand: Box::new(o),
                    prefix: *prefix,
                }
            }
            Expression::DecrementExpr { operand, prefix } => {
                let o = self.rewrite_expression(operand, prelude);
                Expression::DecrementExpr {
                    operand: Box::new(o),
                    prefix: *prefix,
                }
            }
            Expression::ArrayLiteral { elements } => {
                let new_elements: Vec<Expression> = elements
                    .iter()
                    .map(|e| self.rewrite_expression(e, prelude))
                    .collect();
                Expression::ArrayLiteral {
                    elements: new_elements,
                }
            }
            Expression::Identifier { .. }
            | Expression::BigIntLiteral { .. }
            | Expression::BoolLiteral { .. }
            | Expression::ByteStringLiteral { .. }
            | Expression::PropertyAccess { .. } => expr.clone(),
        }
    }

    fn rewrite_index_access(
        &mut self,
        object: &Expression,
        index: &Expression,
        prelude: &mut Vec<Statement>,
    ) -> Expression {
        // Nested literal chain?
        let whole = Expression::IndexAccess {
            object: Box::new(object.clone()),
            index: Box::new(index.clone()),
        };
        match self.try_resolve_literal_index_chain(&whole) {
            ChainResolve::Error => return Expression::BigIntLiteral { value: 0 },
            ChainResolve::Leaf(name) => {
                return Expression::PropertyAccess { property: name };
            }
            ChainResolve::None => {}
        }

        let base_name = self.try_resolve_array_base(object);
        if base_name.is_none() {
            let new_obj = self.rewrite_expression(object, prelude);
            let new_idx = self.rewrite_expression(index, prelude);
            return Expression::IndexAccess {
                object: Box::new(new_obj),
                index: Box::new(new_idx),
            };
        }
        let base_name = base_name.unwrap();
        let meta = self
            .array_map
            .get(&base_name)
            .cloned()
            .or_else(|| self.synthetic_arrays.get(&base_name).cloned());
        let meta = match meta {
            Some(m) => m,
            None => {
                let new_obj = self.rewrite_expression(object, prelude);
                let new_idx = self.rewrite_expression(index, prelude);
                return Expression::IndexAccess {
                    object: Box::new(new_obj),
                    index: Box::new(new_idx),
                };
            }
        };

        // Literal index?
        if let Some(literal) = as_literal_index(index) {
            if literal < 0 || literal >= meta.length as i128 {
                self.errors.push(Diagnostic::error(
                    format!(
                        "Index {} is out of range for FixedArray of length {}",
                        literal, meta.length
                    ),
                    None,
                ));
                return Expression::BigIntLiteral { value: 0 };
            }
            let slot = meta.slot_names[literal as usize].clone();
            return Expression::PropertyAccess { property: slot };
        }

        // Runtime index — rewrite sub-expressions, hoist if impure, build
        // nested ternary chain.
        let rewritten_index = self.rewrite_expression(index, prelude);
        let index_ref = self.hoist_if_impure(rewritten_index, prelude, HoistTag::Idx);

        if meta.slot_is_array {
            self.errors.push(Diagnostic::error(
                "Runtime index access on a nested FixedArray is not supported",
                None,
            ));
            return Expression::BigIntLiteral { value: 0 };
        }

        self.build_read_dispatch_ternary(&meta, &index_ref)
    }

    fn try_rewrite_read_as_statements(
        &mut self,
        init_expr: &Expression,
        target: &Expression,
        _loc: &SourceLocation,
    ) -> Option<StmtForm> {
        let (object, index) = match init_expr {
            Expression::IndexAccess { object, index } => (object.as_ref(), index.as_ref()),
            _ => return None,
        };
        let base_name = self.try_resolve_array_base(object)?;
        let meta = self
            .array_map
            .get(&base_name)
            .cloned()
            .or_else(|| self.synthetic_arrays.get(&base_name).cloned())?;

        if as_literal_index(index).is_some() {
            return None;
        }
        if meta.slot_is_array {
            return None;
        }

        let mut prelude: Vec<Statement> = Vec::new();
        let rewritten_index = self.rewrite_expression(index, &mut prelude);
        let index_ref = self.hoist_if_impure(rewritten_index, &mut prelude, HoistTag::Idx);

        let n = meta.length;
        if n < 2 {
            let fallback_init = Expression::PropertyAccess {
                property: meta.slot_names[0].clone(),
            };
            return Some(StmtForm {
                prelude,
                fallback_init,
                dispatch: Vec::new(),
            });
        }

        let fallback_init = Expression::PropertyAccess {
            property: meta.slot_names[n - 1].clone(),
        };

        let mut tail_else: Option<Vec<Statement>> = None;
        let loc = default_loc();
        let mut i = (n - 1) as isize - 1;
        while i >= 0 {
            let slot = &meta.slot_names[i as usize];
            let cond = Expression::BinaryExpr {
                op: BinaryOp::StrictEq,
                left: Box::new(index_ref.clone()),
                right: Box::new(Expression::BigIntLiteral { value: i as i128 }),
            };
            let assign = Statement::Assignment {
                target: target.clone(),
                value: Expression::PropertyAccess {
                    property: slot.clone(),
                },
                source_location: loc.clone(),
            };
            let if_stmt = Statement::IfStatement {
                condition: cond,
                then_branch: vec![assign],
                else_branch: tail_else.take(),
                source_location: loc.clone(),
            };
            tail_else = Some(vec![if_stmt]);
            i -= 1;
        }
        let dispatch = tail_else.unwrap_or_default();
        Some(StmtForm {
            prelude,
            fallback_init,
            dispatch,
        })
    }

    fn build_read_dispatch_ternary(
        &mut self,
        meta: &ArrayMeta,
        index_ref: &Expression,
    ) -> Expression {
        let mut chain = Expression::PropertyAccess {
            property: meta.slot_names[meta.length - 1].clone(),
        };
        let mut i = (meta.length - 1) as isize - 1;
        while i >= 0 {
            let slot = &meta.slot_names[i as usize];
            let cond = Expression::BinaryExpr {
                op: BinaryOp::StrictEq,
                left: Box::new(index_ref.clone()),
                right: Box::new(Expression::BigIntLiteral { value: i as i128 }),
            };
            let branch = Expression::PropertyAccess {
                property: slot.clone(),
            };
            let ternary = Expression::TernaryExpr {
                condition: Box::new(cond),
                consequent: Box::new(branch),
                alternate: Box::new(chain),
            };
            chain = ternary;
            i -= 1;
        }
        chain
    }

    fn rewrite_array_write(
        &mut self,
        base_name: String,
        index: Expression,
        value: Expression,
        loc: SourceLocation,
    ) -> Vec<Statement> {
        let mut prelude: Vec<Statement> = Vec::new();
        let meta = match self.array_map.get(&base_name).cloned() {
            Some(m) => m,
            None => return Vec::new(),
        };

        let rewritten_value = self.rewrite_expression(&value, &mut prelude);
        let rewritten_index = self.rewrite_expression(&index, &mut prelude);

        if let Some(literal) = as_literal_index(&rewritten_index) {
            if literal < 0 || literal >= meta.length as i128 {
                self.errors.push(Diagnostic::error(
                    format!(
                        "Index {} is out of range for FixedArray of length {}",
                        literal, meta.length
                    ),
                    Some(loc.clone()),
                ));
                return prelude;
            }
            if meta.slot_is_array {
                self.errors.push(Diagnostic::error(
                    "Cannot assign to a nested FixedArray sub-array as a whole",
                    Some(loc.clone()),
                ));
                return prelude;
            }
            let slot = meta.slot_names[literal as usize].clone();
            let mut out = prelude;
            out.push(Statement::Assignment {
                target: Expression::PropertyAccess { property: slot },
                value: rewritten_value,
                source_location: loc,
            });
            return out;
        }

        if meta.slot_is_array {
            self.errors.push(Diagnostic::error(
                "Runtime index assignment on a nested FixedArray is not supported",
                Some(loc),
            ));
            return prelude;
        }

        let index_ref = self.hoist_if_impure(rewritten_index, &mut prelude, HoistTag::Idx);
        let value_ref = self.hoist_if_impure(rewritten_value, &mut prelude, HoistTag::Val);
        let branches = self.build_write_dispatch_if(&meta, &index_ref, &value_ref, &loc);
        let mut out = prelude;
        out.push(branches);
        out
    }

    fn build_write_dispatch_if(
        &self,
        meta: &ArrayMeta,
        index_ref: &Expression,
        value_ref: &Expression,
        loc: &SourceLocation,
    ) -> Statement {
        let assert_false = Statement::ExpressionStatement {
            expression: Expression::CallExpr {
                callee: Box::new(Expression::Identifier {
                    name: "assert".to_string(),
                }),
                args: vec![Expression::BoolLiteral { value: false }],
            },
            source_location: loc.clone(),
        };
        let mut tail: Vec<Statement> = vec![assert_false];
        let mut i = (meta.length - 1) as isize;
        while i >= 0 {
            let slot = &meta.slot_names[i as usize];
            let cond = Expression::BinaryExpr {
                op: BinaryOp::StrictEq,
                left: Box::new(index_ref.clone()),
                right: Box::new(Expression::BigIntLiteral { value: i as i128 }),
            };
            let branch_assign = Statement::Assignment {
                target: Expression::PropertyAccess {
                    property: slot.clone(),
                },
                value: value_ref.clone(),
                source_location: loc.clone(),
            };
            let if_stmt = Statement::IfStatement {
                condition: cond,
                then_branch: vec![branch_assign],
                else_branch: Some(tail),
                source_location: loc.clone(),
            };
            tail = vec![if_stmt];
            i -= 1;
        }
        tail.into_iter().next().expect("non-empty tail")
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Try to resolve a fully-literal-indexed chain `self.grid[0][1]`
    /// into a flat synthetic leaf name `grid__0__1`.
    fn try_resolve_literal_index_chain(&mut self, expr: &Expression) -> ChainResolve {
        let mut literal_indices: Vec<i128> = Vec::new();
        let mut cursor = expr;
        loop {
            match cursor {
                Expression::IndexAccess { object, index } => {
                    let lit = match as_literal_index(index) {
                        Some(v) => v,
                        None => return ChainResolve::None,
                    };
                    literal_indices.push(lit);
                    cursor = object.as_ref();
                }
                _ => break,
            }
        }
        let root_name = match cursor {
            Expression::PropertyAccess { property } => property.clone(),
            _ => return ChainResolve::None,
        };
        let root_meta = match self.array_map.get(&root_name).cloned() {
            Some(m) => m,
            None => return ChainResolve::None,
        };
        literal_indices.reverse();

        let mut meta = root_meta;
        for (level, idx) in literal_indices.iter().enumerate() {
            if *idx < 0 || *idx >= meta.length as i128 {
                self.errors.push(Diagnostic::error(
                    format!(
                        "Index {} is out of range for FixedArray of length {}",
                        idx, meta.length
                    ),
                    None,
                ));
                return ChainResolve::Error;
            }
            let slot = meta.slot_names[*idx as usize].clone();
            if level == literal_indices.len() - 1 {
                if meta.slot_is_array {
                    return ChainResolve::None;
                }
                return ChainResolve::Leaf(slot);
            }
            if !meta.slot_is_array {
                return ChainResolve::None;
            }
            meta = meta
                .nested
                .get(&slot)
                .cloned()
                .expect("nested meta must exist");
        }
        ChainResolve::None
    }

    /// If `obj` is a `self.<name>` access referring to a known top-level
    /// or synthetic-intermediate array property, return the base name.
    fn try_resolve_array_base(&self, obj: &Expression) -> Option<String> {
        match obj {
            Expression::PropertyAccess { property }
                if self.array_map.contains_key(property)
                    || self.synthetic_arrays.contains_key(property) =>
            {
                Some(property.clone())
            }
            _ => None,
        }
    }

    fn hoist_if_impure(
        &mut self,
        expr: Expression,
        prelude: &mut Vec<Statement>,
        tag: HoistTag,
    ) -> Expression {
        if is_pure_reference(&expr) {
            return expr;
        }
        let name = match tag {
            HoistTag::Idx => self.fresh_idx_name(),
            HoistTag::Val => self.fresh_val_name(),
        };
        let loc = default_loc();
        let decl = Statement::VariableDecl {
            name: name.clone(),
            var_type: None,
            mutable: false,
            init: expr,
            source_location: loc,
        };
        prelude.push(decl);
        Expression::Identifier { name }
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

enum ElementsResult {
    None,
    Some(Vec<Expression>),
    Error,
}

enum ChainResolve {
    Leaf(String),
    Error,
    None,
}

enum HoistTag {
    Idx,
    Val,
}

struct StmtForm {
    prelude: Vec<Statement>,
    fallback_init: Expression,
    dispatch: Vec<Statement>,
}

fn as_literal_index(expr: &Expression) -> Option<i128> {
    match expr {
        Expression::BigIntLiteral { value } => Some(*value),
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => {
            if let Expression::BigIntLiteral { value } = operand.as_ref() {
                Some(-*value)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_pure_reference(expr: &Expression) -> bool {
    match expr {
        Expression::Identifier { .. }
        | Expression::BigIntLiteral { .. }
        | Expression::BoolLiteral { .. }
        | Expression::ByteStringLiteral { .. }
        | Expression::PropertyAccess { .. } => true,
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => matches!(operand.as_ref(), Expression::BigIntLiteral { .. }),
        _ => false,
    }
}

fn default_loc() -> SourceLocation {
    SourceLocation {
        file: "<synthetic>".to_string(),
        line: 0,
        column: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser;

    fn parse_contract(source: &str) -> ContractNode {
        let res = parser::parse_source(source, Some("t.runar.ts"));
        assert!(
            res.errors.is_empty(),
            "parse errors: {:?}",
            res.error_strings()
        );
        res.contract.expect("contract")
    }

    fn expand_source(source: &str) -> ExpandResult {
        let c = parse_contract(source);
        expand_fixed_arrays(&c)
    }

    const BASIC_ARRAY: &str = r#"
class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public setZero(v: bigint) {
    this.board[0] = v;
    assert(true);
  }

  public setRuntime(idx: bigint, v: bigint) {
    this.board[idx] = v;
    assert(true);
  }
}
"#;

    const NESTED_ARRAY: &str = r#"
class Grid extends StatefulSmartContract {
  g: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public tick(v: bigint) {
    this.g[0][1] = v;
    assert(true);
  }
}
"#;

    const OUT_OF_RANGE_LIT: &str = r#"
class Oor extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public bad() {
    this.board[5] = 9n;
    assert(true);
  }
}
"#;

    const BAD_LENGTH_INIT: &str = r#"
class BadInit extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n];

  constructor() {
    super();
  }

  public m() {
    assert(true);
  }
}
"#;

    const SIDE_EFFECT_INDEX: &str = r#"
class SE extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public doStuff(base: bigint) {
    this.board[base + 1n] = 5n;
    assert(true);
  }
}
"#;

    fn find_method_body<'a>(c: &'a ContractNode, name: &str) -> &'a Vec<Statement> {
        &c.methods
            .iter()
            .find(|m| m.name == name)
            .expect("method")
            .body
    }

    // -----------------------------------------------------------------------
    // Property expansion
    // -----------------------------------------------------------------------

    #[test]
    fn expands_flat_fixed_array_into_three_scalars() {
        let res = expand_source(BASIC_ARRAY);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let names: Vec<&str> = res.contract.properties.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["board__0", "board__1", "board__2"]);
        for p in &res.contract.properties {
            assert!(matches!(
                &p.prop_type,
                TypeNode::Primitive(PrimitiveTypeName::Bigint)
            ));
        }
    }

    #[test]
    fn distributes_array_literal_initializers() {
        let src = r#"
class Init extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [1n, 2n, 3n];
  constructor() { super(); }
  public m() { assert(true); }
}
"#;
        let res = expand_source(src);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let vals: Vec<i128> = res
            .contract
            .properties
            .iter()
            .map(|p| match &p.initializer {
                Some(Expression::BigIntLiteral { value }) => *value,
                _ => -1,
            })
            .collect();
        assert_eq!(vals, vec![1, 2, 3]);
    }

    #[test]
    fn rejects_initializer_length_mismatch() {
        let res = expand_source(BAD_LENGTH_INIT);
        assert!(res.errors.iter().any(|e| e.format_message().contains("does not match")));
    }

    #[test]
    fn expands_nested_fixed_array_recursively() {
        let res = expand_source(NESTED_ARRAY);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let names: Vec<&str> = res.contract.properties.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["g__0__0", "g__0__1", "g__1__0", "g__1__1"]
        );
    }

    // -----------------------------------------------------------------------
    // Literal index access
    // -----------------------------------------------------------------------

    #[test]
    fn rewrites_literal_index_write_to_direct_member() {
        let res = expand_source(BASIC_ARRAY);
        assert!(res.errors.is_empty());
        let body = find_method_body(&res.contract, "setZero");
        let assign = body.iter().find_map(|s| match s {
            Statement::Assignment { target, .. } => Some(target),
            _ => None,
        });
        let target = assign.expect("assignment");
        match target {
            Expression::PropertyAccess { property } => assert_eq!(property, "board__0"),
            _ => panic!("expected property_access"),
        }
    }

    #[test]
    fn errors_on_out_of_range_literal_index() {
        let res = expand_source(OUT_OF_RANGE_LIT);
        assert!(res.errors.iter().any(|e| e.format_message().contains("out of range")));
    }

    // -----------------------------------------------------------------------
    // Runtime index write
    // -----------------------------------------------------------------------

    #[test]
    fn rewrites_runtime_index_write_to_if_chain() {
        let res = expand_source(BASIC_ARRAY);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let body = find_method_body(&res.contract, "setRuntime");
        let first = &body[0];
        assert!(matches!(first, Statement::IfStatement { .. }));
        // Walk else chain; expect 3 branches ending in assert(false).
        let mut node: Option<&Statement> = Some(first);
        let mut branches = 0;
        while let Some(Statement::IfStatement { else_branch, .. }) = node {
            branches += 1;
            node = else_branch.as_ref().and_then(|list| list.first());
        }
        assert_eq!(branches, 3);
    }

    #[test]
    fn hoists_impure_index_expressions() {
        let res = expand_source(SIDE_EFFECT_INDEX);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let body = find_method_body(&res.contract, "doStuff");
        let first = &body[0];
        match first {
            Statement::VariableDecl { name, .. } => assert!(name.starts_with("__idx_")),
            _ => panic!("expected variable_decl for hoisted idx"),
        }
    }

    // -----------------------------------------------------------------------
    // Runtime index read (statement form)
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_index_read_statement_form() {
        let src = r#"
class R extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  constructor() { super(); }
  public m(idx: bigint) {
    const v = this.board[idx];
    assert(v == 0n);
  }
}
"#;
        let res = expand_source(src);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let body = find_method_body(&res.contract, "m");
        match &body[0] {
            Statement::VariableDecl { name, init, .. } => {
                assert_eq!(name, "v");
                match init {
                    Expression::PropertyAccess { property } => assert_eq!(property, "board__2"),
                    _ => panic!("expected fallback property access"),
                }
            }
            _ => panic!("expected variable_decl"),
        }
        let second = &body[1];
        let mut node: Option<&Statement> = Some(second);
        let mut branches = 0;
        while let Some(Statement::IfStatement { else_branch, .. }) = node {
            branches += 1;
            node = else_branch.as_ref().and_then(|list| list.first());
        }
        assert_eq!(branches, 2);
    }

    // -----------------------------------------------------------------------
    // Synthetic-array chain
    // -----------------------------------------------------------------------

    #[test]
    fn attaches_single_element_chain_on_flat_leaves() {
        let res = expand_source(BASIC_ARRAY);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        for (i, p) in res.contract.properties.iter().enumerate() {
            let chain = p.synthetic_array_chain.as_ref().expect("chain");
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].base, "board");
            assert_eq!(chain[0].index, i);
            assert_eq!(chain[0].length, 3);
        }
    }

    #[test]
    fn attaches_two_element_chain_on_2d_leaves() {
        let res = expand_source(NESTED_ARRAY);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        // Leaves in order: g__0__0, g__0__1, g__1__0, g__1__1
        let expected = [
            ("g__0__0", 0usize, 0usize),
            ("g__0__1", 0usize, 1usize),
            ("g__1__0", 1usize, 0usize),
            ("g__1__1", 1usize, 1usize),
        ];
        for (prop, (name, outer, inner)) in res.contract.properties.iter().zip(expected.iter()) {
            assert_eq!(prop.name, *name);
            let chain = prop.synthetic_array_chain.as_ref().expect("chain");
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].base, "g");
            assert_eq!(chain[0].index, *outer);
            assert_eq!(chain[0].length, 2);
            assert_eq!(chain[1].base, format!("g__{}", outer));
            assert_eq!(chain[1].index, *inner);
            assert_eq!(chain[1].length, 2);
        }
    }

    #[test]
    fn attaches_three_element_chain_on_3d_leaves() {
        let src = r#"
class Cube extends StatefulSmartContract {
  c: FixedArray<FixedArray<FixedArray<bigint, 2>, 2>, 2> = [
    [[0n, 0n], [0n, 0n]],
    [[0n, 0n], [0n, 0n]]
  ];
  constructor() { super(); }
  public m() { assert(true); }
}
"#;
        let res = expand_source(src);
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(res.contract.properties.len(), 8);
        let leaf = res
            .contract
            .properties
            .iter()
            .find(|p| p.name == "c__1__0__1")
            .expect("leaf");
        let chain = leaf.synthetic_array_chain.as_ref().expect("chain");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].base, "c");
        assert_eq!(chain[0].index, 1);
        assert_eq!(chain[0].length, 2);
        assert_eq!(chain[1].base, "c__1");
        assert_eq!(chain[1].index, 0);
        assert_eq!(chain[1].length, 2);
        assert_eq!(chain[2].base, "c__1__0");
        assert_eq!(chain[2].index, 1);
        assert_eq!(chain[2].length, 2);
    }
}
