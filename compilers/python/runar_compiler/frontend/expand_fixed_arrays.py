"""Pass 3b: Expand fixed-size array properties into scalar sibling fields.

Runs after typecheck and before ANF lowering. Takes a :class:`ContractNode`
whose properties may contain :class:`FixedArrayType` declarations like
``board: FixedArray[bigint, 9]`` and rewrites the AST so that every downstream
pass sees an equivalent contract with 9 scalar siblings ``board__0 .. board__8``
and all ``self.board[i]`` reads/writes replaced by direct member access (literal
index) or if/else dispatch (runtime index).

Scope & rules:

* Only properties on the contract may have :class:`FixedArrayType`. Array
  types are not allowed as method parameters or local variables; the
  validator rejects those, and this pass does not attempt to rewrite
  anything but top-level property declarations.
* Nested arrays (``FixedArray[FixedArray[bigint, 3], 3]``) expand
  recursively. Names use double underscore to avoid colliding with
  user-written ``board_0`` identifiers: ``board__0``, ``board__0__0`` etc.
* Literal index access (``self.board[3]`` where 3 is a :class:`BigIntLiteral`,
  possibly wrapped in unary ``-``) is rewritten to a direct ``self.board__3``
  property access. Out-of-range literal indices produce a hard compile error.
* Runtime index read in an expression context becomes a nested ternary
  chain: ``(idx == 0) ? board__0 : ((idx == 1) ? board__1 : ... : board__{N-1})``.
  The terminal branch reads the last slot without any bounds check — this
  matches the TS spike semantics by design.
* Runtime index read at statement level (``v = self.board[i]``) emits a
  fallback ``v = board__{N-1}`` initializer followed by an if/else-if chain
  assigning in-range slots. Out-of-range indices fall through to the
  fallback.
* Runtime index write (``self.board[i] = v``) emits a full if/else-if chain
  with an explicit final ``assert(False)`` out-of-range guard.
* Nested runtime indexing is rejected with a diagnostic — only literal
  index chains (``self.grid[0][1]``) are supported on nested arrays.
* Side-effectful index or value expressions are hoisted to fresh synthetic
  ``__idx_K`` / ``__val_K`` bindings before the containing statement.
* Array literal initializers are distributed pairwise; length mismatches
  are compile errors.
* ``FixedArray[void, N]`` is rejected.

This is a direct port of ``packages/runar-compiler/src/passes/03b-expand-fixed-arrays.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    BoolLiteral,
    ByteStringLiteral,
    CallExpr,
    ContractNode,
    CustomType,
    DecrementExpr,
    Expression,
    ExpressionStmt,
    FixedArrayType,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    IndexAccessExpr,
    MemberExpr,
    MethodNode,
    PrimitiveType,
    PropertyAccessExpr,
    PropertyNode,
    ReturnStmt,
    SourceLocation,
    Statement,
    SyntheticArrayChainEntry,
    TernaryExpr,
    TypeNode,
    UnaryExpr,
    VariableDeclStmt,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ExpandFixedArraysResult:
    """Output of :func:`expand_fixed_arrays`."""

    contract: ContractNode
    errors: list[Diagnostic] = field(default_factory=list)


def expand_fixed_arrays(contract: ContractNode) -> ExpandFixedArraysResult:
    """Expand FixedArray properties into scalar siblings and rewrite indexing.

    Pure AST-to-AST. On any error, returns the original contract unchanged
    with the accumulated diagnostics.
    """
    ctx = _ExpandContext(contract=contract)
    if not ctx.collect_arrays():
        return ExpandFixedArraysResult(contract=contract, errors=ctx.errors)

    if ctx.errors:
        return ExpandFixedArraysResult(contract=contract, errors=ctx.errors)

    if not ctx.array_map:
        # No FixedArray properties — return unchanged.
        return ExpandFixedArraysResult(contract=contract, errors=[])

    new_properties = ctx.rewrite_properties()
    if ctx.errors:
        return ExpandFixedArraysResult(contract=contract, errors=ctx.errors)

    new_constructor = ctx.rewrite_method(contract.constructor)
    new_methods = [ctx.rewrite_method(m) for m in contract.methods]

    if ctx.errors:
        return ExpandFixedArraysResult(contract=contract, errors=ctx.errors)

    rewritten = ContractNode(
        name=contract.name,
        parent_class=contract.parent_class,
        properties=new_properties,
        constructor=new_constructor,
        methods=new_methods,
        source_file=contract.source_file,
    )
    return ExpandFixedArraysResult(contract=rewritten, errors=[])


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------


@dataclass
class _ArrayMeta:
    """Metadata for one level of an expanded FixedArray tree."""

    root_name: str
    type: FixedArrayType
    slot_names: list[str]
    slot_is_array: bool
    element_type: TypeNode
    nested: dict[str, "_ArrayMeta"] = field(default_factory=dict)


@dataclass
class _ExpandContext:
    contract: ContractNode
    errors: list[Diagnostic] = field(default_factory=list)
    array_map: dict[str, _ArrayMeta] = field(default_factory=dict)
    synthetic_scalars: dict[str, TypeNode] = field(default_factory=dict)
    synthetic_arrays: dict[str, _ArrayMeta] = field(default_factory=dict)
    _temp_counter: int = 0

    def _add_error(self, msg: str, loc: SourceLocation) -> None:
        self.errors.append(
            Diagnostic(message=msg, severity=Severity.ERROR, loc=loc)
        )

    def fresh_idx_name(self) -> str:
        n = self._temp_counter
        self._temp_counter += 1
        return f"__idx_{n}"

    def fresh_val_name(self) -> str:
        n = self._temp_counter
        self._temp_counter += 1
        return f"__val_{n}"

    # ------------------------------------------------------------------
    # Collect phase
    # ------------------------------------------------------------------

    def collect_arrays(self) -> bool:
        for prop in self.contract.properties:
            if not isinstance(prop.type, FixedArrayType):
                continue
            meta = self._build_array_meta(
                prop.name, prop.type, prop.source_location
            )
            if meta is None:
                return False
            self.array_map[prop.name] = meta
        return True

    def _build_array_meta(
        self,
        root_name: str,
        ty: FixedArrayType,
        loc: SourceLocation,
    ) -> Optional[_ArrayMeta]:
        # Reject FixedArray[void, N]
        if isinstance(ty.element, PrimitiveType) and ty.element.name == "void":
            self._add_error(
                f"FixedArray element type cannot be 'void' (property '{root_name}')",
                loc,
            )
            return None
        if ty.length <= 0:
            self._add_error(
                f"FixedArray length must be a positive integer (property '{root_name}')",
                loc,
            )
            return None

        slot_names = [f"{root_name}__{i}" for i in range(ty.length)]
        elem_is_array = isinstance(ty.element, FixedArrayType)
        meta = _ArrayMeta(
            root_name=root_name,
            type=ty,
            slot_names=slot_names,
            slot_is_array=elem_is_array,
            element_type=ty.element,
        )

        if elem_is_array:
            elem_type: FixedArrayType = ty.element  # type: ignore[assignment]
            for slot in slot_names:
                nested_meta = self._build_array_meta(slot, elem_type, loc)
                if nested_meta is None:
                    return None
                meta.nested[slot] = nested_meta
                self.synthetic_arrays[slot] = nested_meta
        else:
            for slot in slot_names:
                self.synthetic_scalars[slot] = ty.element

        return meta

    # ------------------------------------------------------------------
    # Property rewriting
    # ------------------------------------------------------------------

    def rewrite_properties(self) -> list[PropertyNode]:
        out: list[PropertyNode] = []
        for prop in self.contract.properties:
            if not isinstance(prop.type, FixedArrayType):
                out.append(prop)
                continue
            meta = self.array_map.get(prop.name)
            if meta is None:
                continue
            expanded = self._expand_property_root(prop, meta)
            out.extend(expanded)
        return out

    def _expand_property_root(
        self, prop: PropertyNode, meta: _ArrayMeta
    ) -> list[PropertyNode]:
        initializer_elements = self._extract_array_literal_elements(prop, meta)
        if initializer_elements == "error":
            return []
        return self._expand_array_meta(
            meta, prop.readonly, prop.source_location, initializer_elements, []
        )

    def _extract_array_literal_elements(
        self, prop: PropertyNode, meta: _ArrayMeta
    ):
        """Return element list, None if no initializer, or sentinel 'error'."""
        if prop.initializer is None:
            return None
        if not isinstance(prop.initializer, ArrayLiteralExpr):
            self._add_error(
                f"Property '{prop.name}' of type FixedArray must use an array literal initializer",
                prop.source_location,
            )
            return "error"
        elements = prop.initializer.elements
        if len(elements) != meta.type.length:
            self._add_error(
                f"Initializer length {len(elements)} does not match FixedArray length {meta.type.length} for property '{prop.name}'",
                prop.source_location,
            )
            return "error"
        return elements

    def _expand_array_meta(
        self,
        meta: _ArrayMeta,
        readonly: bool,
        loc: SourceLocation,
        initializer,
        parent_chain: list[SyntheticArrayChainEntry],
    ) -> list[PropertyNode]:
        out: list[PropertyNode] = []
        for i, slot in enumerate(meta.slot_names):
            slot_init = None
            if initializer is not None:
                slot_init = initializer[i]
            chain_here = list(parent_chain) + [
                SyntheticArrayChainEntry(
                    base=meta.root_name, index=i, length=len(meta.slot_names)
                )
            ]
            if meta.slot_is_array:
                nested_meta = meta.nested[slot]
                nested_init = None
                if slot_init is not None:
                    if not isinstance(slot_init, ArrayLiteralExpr):
                        self._add_error(
                            "Nested FixedArray element must be an array literal",
                            loc,
                        )
                        continue
                    if len(slot_init.elements) != nested_meta.type.length:
                        self._add_error(
                            f"Nested FixedArray initializer length {len(slot_init.elements)} does not match expected length {nested_meta.type.length}",
                            loc,
                        )
                        continue
                    nested_init = slot_init.elements
                out.extend(
                    self._expand_array_meta(
                        nested_meta, readonly, loc, nested_init, chain_here
                    )
                )
            else:
                out.append(
                    PropertyNode(
                        name=slot,
                        type=meta.element_type,
                        readonly=readonly,
                        initializer=slot_init,
                        source_location=loc,
                        synthetic_array_chain=chain_here,
                    )
                )
        return out

    # ------------------------------------------------------------------
    # Method rewriting
    # ------------------------------------------------------------------

    def rewrite_method(self, method: MethodNode) -> MethodNode:
        new_body = self._rewrite_statements(method.body)
        return MethodNode(
            name=method.name,
            params=method.params,
            body=new_body,
            visibility=method.visibility,
            source_location=method.source_location,
        )

    def _rewrite_statements(self, stmts: list[Statement]) -> list[Statement]:
        out: list[Statement] = []
        for stmt in stmts:
            out.extend(self._rewrite_statement(stmt))
        return out

    def _rewrite_statement(self, stmt: Statement) -> list[Statement]:
        if isinstance(stmt, VariableDeclStmt):
            return self._rewrite_variable_decl(stmt)
        if isinstance(stmt, AssignmentStmt):
            return self._rewrite_assignment(stmt)
        if isinstance(stmt, IfStmt):
            return self._rewrite_if_statement(stmt)
        if isinstance(stmt, ForStmt):
            return self._rewrite_for_statement(stmt)
        if isinstance(stmt, ReturnStmt):
            return self._rewrite_return_statement(stmt)
        if isinstance(stmt, ExpressionStmt):
            return self._rewrite_expression_statement(stmt)
        return [stmt]

    def _rewrite_variable_decl(self, stmt: VariableDeclStmt) -> list[Statement]:
        # Statement-form dispatch: `v = self.board[i]` where `i` is a runtime
        # index. Produces a shorter Script because each branch only
        # materialises one field.
        target: Expression = Identifier(name=stmt.name)
        stmt_form = self._try_rewrite_read_as_statements(
            stmt.init, target, stmt.source_location
        )
        if stmt_form is not None:
            prelude, fallback_init, dispatch = stmt_form
            # Replace original with [prelude..., let v = fallback, if-chain...]
            new_decl = VariableDeclStmt(
                name=stmt.name,
                type=stmt.type,
                mutable=True,
                init=fallback_init,
                source_location=stmt.source_location,
            )
            return [*prelude, new_decl, *dispatch]

        prelude: list[Statement] = []
        new_init = self._rewrite_expression(stmt.init, prelude) if stmt.init is not None else None
        new_decl = VariableDeclStmt(
            name=stmt.name,
            type=stmt.type,
            mutable=stmt.mutable,
            init=new_init,
            source_location=stmt.source_location,
        )
        return [*prelude, new_decl]

    def _rewrite_assignment(self, stmt: AssignmentStmt) -> list[Statement]:
        prelude: list[Statement] = []

        if isinstance(stmt.target, IndexAccessExpr):
            # Try to resolve a fully literal chain (nested or flat).
            resolved = self._try_resolve_literal_index_chain(stmt.target)
            if resolved == "error":
                return list(prelude)
            if resolved is not None:
                rewritten_value = self._rewrite_expression(stmt.value, prelude)
                return [
                    *prelude,
                    AssignmentStmt(
                        target=PropertyAccessExpr(property=resolved),
                        value=rewritten_value,
                        source_location=stmt.source_location,
                    ),
                ]

            target_object = stmt.target.object
            if (
                isinstance(target_object, PropertyAccessExpr)
                and target_object.property in self.array_map
            ):
                return self._rewrite_array_write(stmt, prelude)

            # Non-fixed-array index target — rewrite subexprs only.
            new_index = self._rewrite_expression(stmt.target.index, prelude)
            new_obj = self._rewrite_expression(target_object, prelude)
            new_value = self._rewrite_expression(stmt.value, prelude)
            return [
                *prelude,
                AssignmentStmt(
                    target=IndexAccessExpr(object=new_obj, index=new_index),
                    value=new_value,
                    source_location=stmt.source_location,
                ),
            ]

        # Statement-form dispatch for `target = self.board[i]`.
        if isinstance(stmt.target, (Identifier, PropertyAccessExpr)):
            stmt_form = self._try_rewrite_read_as_statements(
                stmt.value, stmt.target, stmt.source_location
            )
            if stmt_form is not None:
                prelude_local, fallback_init, dispatch = stmt_form
                fallback_assign = AssignmentStmt(
                    target=stmt.target,
                    value=fallback_init,
                    source_location=stmt.source_location,
                )
                return [*prelude_local, fallback_assign, *dispatch]

        new_target = self._rewrite_expression(stmt.target, prelude)
        new_value = self._rewrite_expression(stmt.value, prelude)
        return [
            *prelude,
            AssignmentStmt(
                target=new_target,
                value=new_value,
                source_location=stmt.source_location,
            ),
        ]

    def _rewrite_if_statement(self, stmt: IfStmt) -> list[Statement]:
        prelude: list[Statement] = []
        new_cond = self._rewrite_expression(stmt.condition, prelude)
        new_then = self._rewrite_statements(stmt.then)
        new_else = self._rewrite_statements(stmt.else_) if stmt.else_ else []
        return [
            *prelude,
            IfStmt(
                condition=new_cond,
                then=new_then,
                else_=new_else,
                source_location=stmt.source_location,
            ),
        ]

    def _rewrite_for_statement(self, stmt: ForStmt) -> list[Statement]:
        prelude: list[Statement] = []
        new_cond = self._rewrite_expression(stmt.condition, prelude)

        init_prelude: list[Statement] = []
        new_init_init = None
        if stmt.init is not None:
            new_init_init = self._rewrite_expression(stmt.init.init, init_prelude) if stmt.init.init is not None else None
        if init_prelude:
            prelude.extend(init_prelude)

        new_update_list = self._rewrite_statement(stmt.update) if stmt.update is not None else []
        new_body = self._rewrite_statements(stmt.body)
        new_update: Statement | None = None
        if len(new_update_list) == 1:
            new_update = new_update_list[0]
        elif new_update_list:
            new_update = new_update_list[-1]
            new_body.extend(new_update_list[:-1])

        new_init_stmt: VariableDeclStmt | None = None
        if stmt.init is not None:
            new_init_stmt = VariableDeclStmt(
                name=stmt.init.name,
                type=stmt.init.type,
                mutable=stmt.init.mutable,
                init=new_init_init,
                source_location=stmt.init.source_location,
            )

        return [
            *prelude,
            ForStmt(
                init=new_init_stmt,
                condition=new_cond,
                update=new_update,
                body=new_body,
                source_location=stmt.source_location,
            ),
        ]

    def _rewrite_return_statement(self, stmt: ReturnStmt) -> list[Statement]:
        if stmt.value is None:
            return [stmt]
        prelude: list[Statement] = []
        new_value = self._rewrite_expression(stmt.value, prelude)
        return [
            *prelude,
            ReturnStmt(value=new_value, source_location=stmt.source_location),
        ]

    def _rewrite_expression_statement(
        self, stmt: ExpressionStmt
    ) -> list[Statement]:
        prelude: list[Statement] = []
        new_expr = self._rewrite_expression(stmt.expr, prelude) if stmt.expr is not None else None
        return [
            *prelude,
            ExpressionStmt(expr=new_expr, source_location=stmt.source_location),
        ]

    # ------------------------------------------------------------------
    # Expression rewriting
    # ------------------------------------------------------------------

    def _rewrite_expression(
        self, expr: Expression, prelude: list[Statement]
    ) -> Expression:
        if isinstance(expr, IndexAccessExpr):
            return self._rewrite_index_access(expr, prelude)
        if isinstance(expr, BinaryExpr):
            left = self._rewrite_expression(expr.left, prelude)
            right = self._rewrite_expression(expr.right, prelude)
            return BinaryExpr(op=expr.op, left=left, right=right)
        if isinstance(expr, UnaryExpr):
            operand = self._rewrite_expression(expr.operand, prelude)
            return UnaryExpr(op=expr.op, operand=operand)
        if isinstance(expr, CallExpr):
            callee = self._rewrite_expression(expr.callee, prelude)
            args = [self._rewrite_expression(a, prelude) for a in expr.args]
            return CallExpr(callee=callee, args=args)
        if isinstance(expr, MemberExpr):
            obj = self._rewrite_expression(expr.object, prelude)
            return MemberExpr(object=obj, property=expr.property)
        if isinstance(expr, TernaryExpr):
            cond = self._rewrite_expression(expr.condition, prelude)
            cons = self._rewrite_expression(expr.consequent, prelude)
            alt = self._rewrite_expression(expr.alternate, prelude)
            return TernaryExpr(condition=cond, consequent=cons, alternate=alt)
        if isinstance(expr, IncrementExpr):
            operand = self._rewrite_expression(expr.operand, prelude)
            return IncrementExpr(operand=operand, prefix=expr.prefix)
        if isinstance(expr, DecrementExpr):
            operand = self._rewrite_expression(expr.operand, prelude)
            return DecrementExpr(operand=operand, prefix=expr.prefix)
        if isinstance(expr, ArrayLiteralExpr):
            elements = [
                self._rewrite_expression(e, prelude) for e in expr.elements
            ]
            return ArrayLiteralExpr(elements=elements)
        # Leaf expressions: Identifier, BigIntLiteral, BoolLiteral,
        # ByteStringLiteral, PropertyAccessExpr — no rewriting needed.
        return expr

    def _rewrite_index_access(
        self, expr: IndexAccessExpr, prelude: list[Statement]
    ) -> Expression:
        # Nested fully literal chains collapse in a single hop.
        nested = self._try_resolve_literal_index_chain(expr)
        if nested == "error":
            return BigIntLiteral(value=0)
        if nested is not None:
            return PropertyAccessExpr(property=nested)

        base_name = self._try_resolve_array_base(expr.object)
        if base_name is None:
            # Not a fixed-array property — recurse into sub-expressions.
            obj = self._rewrite_expression(expr.object, prelude)
            idx = self._rewrite_expression(expr.index, prelude)
            return IndexAccessExpr(object=obj, index=idx)

        meta = self.array_map.get(base_name) or self.synthetic_arrays.get(base_name)
        if meta is None:
            obj = self._rewrite_expression(expr.object, prelude)
            idx = self._rewrite_expression(expr.index, prelude)
            return IndexAccessExpr(object=obj, index=idx)

        loc = SourceLocation()  # expression source loc unavailable in Python AST
        literal = self._as_literal_index(expr.index)
        if literal is not None:
            if literal < 0 or literal >= meta.type.length:
                self._add_error(
                    f"Index {literal} is out of range for FixedArray of length {meta.type.length}",
                    loc,
                )
                return BigIntLiteral(value=0)
            slot = meta.slot_names[literal]
            return PropertyAccessExpr(property=slot)

        # Runtime index — nested arrays rejected.
        if meta.slot_is_array:
            self._add_error(
                "Runtime index access on a nested FixedArray is not supported",
                loc,
            )
            return BigIntLiteral(value=0)

        rewritten_index = self._rewrite_expression(expr.index, prelude)
        index_ref = self._hoist_if_impure(
            rewritten_index, prelude, loc, "idx"
        )
        return self._build_read_dispatch_ternary(meta, index_ref, loc)

    # ------------------------------------------------------------------
    # Statement-form read rewriter
    # ------------------------------------------------------------------

    def _try_rewrite_read_as_statements(
        self,
        init_expr: Expression | None,
        target: Expression,
        loc: SourceLocation,
    ):
        """Return (prelude, fallback_init, dispatch) or None.

        Matches the TS ``tryRewriteReadAsStatements``. Runtime reads do NOT
        bounds-check — the fallback is the last slot, and out-of-range
        indices fall through, matching the ternary form.
        """
        if not isinstance(init_expr, IndexAccessExpr):
            return None
        base_name = self._try_resolve_array_base(init_expr.object)
        if base_name is None:
            return None
        meta = self.array_map.get(base_name) or self.synthetic_arrays.get(base_name)
        if meta is None:
            return None
        if self._as_literal_index(init_expr.index) is not None:
            return None
        if meta.slot_is_array:
            return None

        prelude: list[Statement] = []
        rewritten_index = self._rewrite_expression(init_expr.index, prelude)
        index_ref = self._hoist_if_impure(rewritten_index, prelude, loc, "idx")

        n = len(meta.slot_names)
        if n < 2:
            fallback_init = PropertyAccessExpr(property=meta.slot_names[0])
            return prelude, fallback_init, []

        fallback_init = PropertyAccessExpr(property=meta.slot_names[n - 1])

        dispatch: list[Statement] = []
        tail_else: list[Statement] | None = None
        for i in range(n - 2, -1, -1):
            slot = meta.slot_names[i]
            cond = BinaryExpr(
                op="===",
                left=_clone_expr(index_ref),
                right=BigIntLiteral(value=i),
            )
            assign = AssignmentStmt(
                target=_clone_expr(target),
                value=PropertyAccessExpr(property=slot),
                source_location=loc,
            )
            if_stmt = IfStmt(
                condition=cond,
                then=[assign],
                else_=tail_else if tail_else is not None else [],
                source_location=loc,
            )
            tail_else = [if_stmt]
        if tail_else:
            dispatch.extend(tail_else)

        return prelude, fallback_init, dispatch

    # ------------------------------------------------------------------
    # Dispatch builders
    # ------------------------------------------------------------------

    def _build_read_dispatch_ternary(
        self,
        meta: _ArrayMeta,
        index_ref: Expression,
        loc: SourceLocation,
    ) -> Expression:
        # Terminal = last legal slot (runtime reads do NOT bounds-check).
        chain: Expression = PropertyAccessExpr(
            property=meta.slot_names[-1]
        )
        for i in range(len(meta.slot_names) - 2, -1, -1):
            slot = meta.slot_names[i]
            cond = BinaryExpr(
                op="===",
                left=_clone_expr(index_ref),
                right=BigIntLiteral(value=i),
            )
            chain = TernaryExpr(
                condition=cond,
                consequent=PropertyAccessExpr(property=slot),
                alternate=chain,
            )
        return chain

    def _rewrite_array_write(
        self, stmt: AssignmentStmt, prelude: list[Statement]
    ) -> list[Statement]:
        index_access = stmt.target
        assert isinstance(index_access, IndexAccessExpr)
        obj = index_access.object
        assert isinstance(obj, PropertyAccessExpr)
        base_name = obj.property
        meta = self.array_map.get(base_name)
        if meta is None:
            return [stmt]

        rewritten_value = self._rewrite_expression(stmt.value, prelude)
        rewritten_index = self._rewrite_expression(index_access.index, prelude)
        loc = stmt.source_location

        literal = self._as_literal_index(rewritten_index)
        if literal is not None:
            if literal < 0 or literal >= meta.type.length:
                self._add_error(
                    f"Index {literal} is out of range for FixedArray of length {meta.type.length}",
                    loc,
                )
                return list(prelude)
            if meta.slot_is_array:
                self._add_error(
                    "Cannot assign to a nested FixedArray sub-array as a whole",
                    loc,
                )
                return list(prelude)
            slot = meta.slot_names[literal]
            return [
                *prelude,
                AssignmentStmt(
                    target=PropertyAccessExpr(property=slot),
                    value=rewritten_value,
                    source_location=loc,
                ),
            ]

        if meta.slot_is_array:
            self._add_error(
                "Runtime index assignment on a nested FixedArray is not supported",
                loc,
            )
            return list(prelude)

        index_ref = self._hoist_if_impure(rewritten_index, prelude, loc, "idx")
        value_ref = self._hoist_if_impure(rewritten_value, prelude, loc, "val")
        branches = self._build_write_dispatch_if(meta, index_ref, value_ref, loc)
        return [*prelude, branches]

    def _build_write_dispatch_if(
        self,
        meta: _ArrayMeta,
        index_ref: Expression,
        value_ref: Expression,
        loc: SourceLocation,
    ) -> IfStmt:
        # Final fallthrough = assert(False)
        assert_false = ExpressionStmt(
            expr=CallExpr(
                callee=Identifier(name="assert"),
                args=[BoolLiteral(value=False)],
            ),
            source_location=loc,
        )
        tail: list[Statement] = [assert_false]
        for i in range(len(meta.slot_names) - 1, -1, -1):
            slot = meta.slot_names[i]
            cond = BinaryExpr(
                op="===",
                left=_clone_expr(index_ref),
                right=BigIntLiteral(value=i),
            )
            branch_assign = AssignmentStmt(
                target=PropertyAccessExpr(property=slot),
                value=_clone_expr(value_ref),
                source_location=loc,
            )
            if_stmt = IfStmt(
                condition=cond,
                then=[branch_assign],
                else_=tail,
                source_location=loc,
            )
            tail = [if_stmt]
        assert isinstance(tail[0], IfStmt)
        return tail[0]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _try_resolve_literal_index_chain(self, expr: IndexAccessExpr):
        """Resolve a fully literal nested index chain to a leaf name.

        Returns the leaf name on success, ``'error'`` with diagnostic on a
        known out-of-range literal, or ``None`` if the chain doesn't match.
        """
        literal_indices: list[int] = []
        cursor: Expression = expr
        while isinstance(cursor, IndexAccessExpr):
            lit = self._as_literal_index(cursor.index)
            if lit is None:
                return None
            literal_indices.append(lit)
            cursor = cursor.object
        if not isinstance(cursor, PropertyAccessExpr):
            return None
        root_name = cursor.property
        root_meta = self.array_map.get(root_name)
        if root_meta is None:
            return None

        literal_indices.reverse()
        meta = root_meta
        for level, idx in enumerate(literal_indices):
            if idx < 0 or idx >= meta.type.length:
                self._add_error(
                    f"Index {idx} is out of range for FixedArray of length {meta.type.length}",
                    SourceLocation(),
                )
                return "error"
            slot = meta.slot_names[idx]
            if level == len(literal_indices) - 1:
                if meta.slot_is_array:
                    return None
                return slot
            if not meta.slot_is_array:
                return None
            meta = meta.nested[slot]
        return None

    def _try_resolve_array_base(self, obj: Expression) -> str | None:
        if isinstance(obj, PropertyAccessExpr):
            if obj.property in self.array_map:
                return obj.property
            if obj.property in self.synthetic_arrays:
                return obj.property
        return None

    def _as_literal_index(self, index: Expression) -> int | None:
        if isinstance(index, BigIntLiteral):
            return index.value
        if (
            isinstance(index, UnaryExpr)
            and index.op == "-"
            and isinstance(index.operand, BigIntLiteral)
        ):
            return -index.operand.value
        return None

    def _hoist_if_impure(
        self,
        expr: Expression,
        prelude: list[Statement],
        loc: SourceLocation,
        tag: str,
    ) -> Expression:
        if _is_pure_reference(expr):
            return expr
        name = self.fresh_idx_name() if tag == "idx" else self.fresh_val_name()
        decl = VariableDeclStmt(
            name=name,
            type=None,
            mutable=False,
            init=expr,
            source_location=loc,
        )
        prelude.append(decl)
        return Identifier(name=name)


# ---------------------------------------------------------------------------
# Stateless helpers
# ---------------------------------------------------------------------------


def _is_pure_reference(expr: Expression) -> bool:
    if isinstance(
        expr,
        (
            Identifier,
            BigIntLiteral,
            BoolLiteral,
            ByteStringLiteral,
            PropertyAccessExpr,
        ),
    ):
        return True
    if (
        isinstance(expr, UnaryExpr)
        and expr.op == "-"
        and isinstance(expr.operand, BigIntLiteral)
    ):
        return True
    return False


def _clone_expr(expr: Expression) -> Expression:
    if isinstance(expr, BigIntLiteral):
        return BigIntLiteral(value=expr.value)
    if isinstance(expr, BoolLiteral):
        return BoolLiteral(value=expr.value)
    if isinstance(expr, ByteStringLiteral):
        return ByteStringLiteral(value=expr.value)
    if isinstance(expr, Identifier):
        return Identifier(name=expr.name)
    if isinstance(expr, PropertyAccessExpr):
        return PropertyAccessExpr(property=expr.property)
    if isinstance(expr, BinaryExpr):
        return BinaryExpr(
            op=expr.op,
            left=_clone_expr(expr.left),
            right=_clone_expr(expr.right),
        )
    if isinstance(expr, UnaryExpr):
        return UnaryExpr(op=expr.op, operand=_clone_expr(expr.operand))
    if isinstance(expr, CallExpr):
        return CallExpr(
            callee=_clone_expr(expr.callee),
            args=[_clone_expr(a) for a in expr.args],
        )
    if isinstance(expr, MemberExpr):
        return MemberExpr(object=_clone_expr(expr.object), property=expr.property)
    if isinstance(expr, TernaryExpr):
        return TernaryExpr(
            condition=_clone_expr(expr.condition),
            consequent=_clone_expr(expr.consequent),
            alternate=_clone_expr(expr.alternate),
        )
    if isinstance(expr, IndexAccessExpr):
        return IndexAccessExpr(
            object=_clone_expr(expr.object), index=_clone_expr(expr.index)
        )
    if isinstance(expr, IncrementExpr):
        return IncrementExpr(operand=_clone_expr(expr.operand), prefix=expr.prefix)
    if isinstance(expr, DecrementExpr):
        return DecrementExpr(operand=_clone_expr(expr.operand), prefix=expr.prefix)
    if isinstance(expr, ArrayLiteralExpr):
        return ArrayLiteralExpr(elements=[_clone_expr(e) for e in expr.elements])
    return expr
