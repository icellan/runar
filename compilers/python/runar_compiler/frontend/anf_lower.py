"""ANF lowering pass for the Runar compiler.

Lowers a type-checked Runar AST to A-Normal Form IR.
Direct port of ``compilers/go/frontend/anf_lower.go``.

This is the most complex frontend pass. Every expression is recursively
flattened into a sequence of let-bindings (``ANFBinding``) with fresh temp
names (``t0``, ``t1``, ...).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

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
    PrimitiveType,
    PropertyAccessExpr,
    ReturnStmt,
    SourceLocation as ASTSourceLocation,
    Statement,
    TernaryExpr,
    TypeNode,
    UnaryExpr,
    VariableDeclStmt,
)
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
    SourceLocation,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lower_to_anf(contract: ContractNode) -> ANFProgram:
    """Lower a type-checked Runar AST to ANF IR.

    Matches the TypeScript reference compiler's ``04-anf-lower.ts`` exactly.
    """
    properties = _lower_properties(contract)
    methods = _lower_methods(contract)

    # Post-pass: lift update_prop from if-else branches into flat conditionals.
    # Mirrors the TS reference compiler's liftBranchUpdateProps
    # (04-anf-lower.ts) and the Go port (anf_lower.go). This prevents phantom
    # stack entries in stack lowering for patterns like position dispatch,
    # where different properties get updated in different branches.
    for method in methods:
        method.body = _lift_branch_update_props(method.body)

    return ANFProgram(
        contract_name=contract.name,
        properties=properties,
        methods=methods,
    )


# ---------------------------------------------------------------------------
# Byte-typed expression detection
# ---------------------------------------------------------------------------

_BYTE_TYPES: frozenset[str] = frozenset({
    "ByteString",
    "PubKey",
    "Sig",
    "Sha256",
    "Ripemd160",
    "Addr",
    "SigHashPreimage",
    "RabinSig",
    "RabinPubKey",
    "Point",
})

_BYTE_RETURNING_FUNCTIONS: frozenset[str] = frozenset({
    "sha256",
    "ripemd160",
    "hash160",
    "hash256",
    "cat",
    "substr",
    "num2bin",
    "reverseBytes",
    "left",
    "right",
    "int2str",
    "toByteString",
    "pack",
    "ecAdd",
    "ecMul",
    "ecMulGen",
    "ecNegate",
    "ecMakePoint",
    "ecEncodeCompressed",
    "blake3Compress",
    "blake3Hash",
})


def _is_byte_typed_expr(expr: Expression | None, ctx: _LowerCtx) -> bool:
    """Return True if *expr* is known to produce a byte-typed value."""
    if expr is None:
        return False

    if isinstance(expr, ByteStringLiteral):
        return True

    if isinstance(expr, Identifier):
        t = ctx.get_param_type(expr.name)
        if t is not None and t in _BYTE_TYPES:
            return True
        t = ctx.get_property_type(expr.name)
        if t is not None and t in _BYTE_TYPES:
            return True
        if expr.name in ctx._local_byte_vars:
            return True
        return False

    if isinstance(expr, PropertyAccessExpr):
        t = ctx.get_property_type(expr.property)
        if t is not None and t in _BYTE_TYPES:
            return True
        return False

    if isinstance(expr, MemberExpr):
        if isinstance(expr.object, Identifier) and expr.object.name == "this":
            t = ctx.get_property_type(expr.property)
            if t is not None and t in _BYTE_TYPES:
                return True
        return False

    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, Identifier):
            if expr.callee.name in _BYTE_RETURNING_FUNCTIONS:
                return True
            if len(expr.callee.name) >= 7 and expr.callee.name[:7] == "extract":
                return True
        return False

    return False


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

def _lower_properties(contract: ContractNode) -> list[ANFProperty]:
    result = []
    for prop in contract.properties:
        anf_prop = ANFProperty(
            name=prop.name,
            type=_type_node_to_string(prop.type),
            readonly=prop.readonly,
        )
        if prop.initializer is not None:
            anf_prop.initial_value = _extract_literal_value(prop.initializer)
        # Propagate synthetic FixedArray chain (set by expand_fixed_arrays)
        # so the artifact assembler can iteratively re-group synthetic runs.
        chain = getattr(prop, "synthetic_array_chain", None)
        if chain:
            anf_prop.synthetic_array_chain = [
                {"base": c.base, "index": c.index, "length": c.length}
                for c in chain
            ]
        result.append(anf_prop)
    return result


def _extract_literal_value(expr: Expression) -> str | int | bool | None:
    """Extract a literal value from an expression for property initializers."""
    if isinstance(expr, BigIntLiteral):
        return expr.value
    if isinstance(expr, BoolLiteral):
        return expr.value
    if isinstance(expr, ByteStringLiteral):
        return expr.value
    if isinstance(expr, UnaryExpr) and expr.op == "-":
        if isinstance(expr.operand, BigIntLiteral):
            return -expr.operand.value
    return None


# ---------------------------------------------------------------------------
# Methods
# ---------------------------------------------------------------------------

def _lower_methods(contract: ContractNode) -> list[ANFMethod]:
    result: list[ANFMethod] = []

    # Lower constructor
    ctor_ctx = _LowerCtx(contract)
    ctor_ctx.lower_statements(contract.constructor.body)
    result.append(ANFMethod(
        name="constructor",
        params=_lower_params(contract.constructor.params),
        body=ctor_ctx.bindings,
        is_public=False,
    ))

    # Lower each method
    for method in contract.methods:
        method_ctx = _LowerCtx(contract)

        if contract.parent_class == "StatefulSmartContract" and method.visibility == "public":
            # Determine if this method verifies hashOutputs (needs change output support).
            # Methods that use addOutput or mutate state need hashOutputs verification.
            # Non-mutating methods (like close/destroy) don't verify outputs.
            needs_change_output = (
                _method_mutates_state(method, contract)
                or _method_has_add_output(method)
            )

            # Register implicit parameters
            if needs_change_output:
                method_ctx.add_param("_changePKH")
                method_ctx.add_param("_changeAmount")
            # Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
            # Multi-output (addOutput) methods already specify amounts explicitly per output.
            needs_new_amount = _method_mutates_state(method, contract) and not _method_has_add_output(method)
            if needs_new_amount:
                method_ctx.add_param("_newAmount")
            method_ctx.add_param("txPreimage")

            # Inject checkPreimage(txPreimage) at the start
            preimage_ref = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
            check_result = method_ctx.emit(ANFValue(kind="check_preimage", preimage=preimage_ref))
            method_ctx.emit(_make_assert(check_result))

            # Deserialize mutable state from the preimage's scriptCode
            has_state_prop = any(not p.readonly for p in contract.properties)
            if has_state_prop:
                preimage_ref3 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                method_ctx.emit(ANFValue(kind="deserialize_state", preimage=preimage_ref3))

            # Lower the developer's method body
            method_ctx.lower_statements(method.body)

            # Determine state continuation type
            add_output_refs = method_ctx.get_add_output_refs()
            if add_output_refs or _method_mutates_state(method, contract):
                # Build the P2PKH change output for hashOutputs verification
                change_pkh_ref = method_ctx.emit(ANFValue(kind="load_param", name="_changePKH"))
                change_amount_ref = method_ctx.emit(ANFValue(kind="load_param", name="_changeAmount"))
                change_output_ref = method_ctx.emit(_make_call("buildChangeOutput", [change_pkh_ref, change_amount_ref]))

                if add_output_refs:
                    # Multi-output continuation: concat all outputs + change output, hash
                    accumulated = add_output_refs[0]
                    for i in range(1, len(add_output_refs)):
                        accumulated = method_ctx.emit(_make_call("cat", [accumulated, add_output_refs[i]]))
                    accumulated = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
                    hash_ref = method_ctx.emit(_make_call("hash256", [accumulated]))
                    preimage_ref2 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref2]))
                    eq_ref = method_ctx.emit(ANFValue(
                        kind="bin_op", op="===",
                        left=hash_ref, right=output_hash_ref,
                        result_type="bytes",
                    ))
                    method_ctx.emit(_make_assert(eq_ref))
                else:
                    # Single-output continuation: build raw output bytes, concat with change, hash
                    state_script_ref = method_ctx.emit(ANFValue(kind="get_state_script"))
                    preimage_ref2 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    new_amount_ref = method_ctx.emit(ANFValue(kind="load_param", name="_newAmount"))
                    contract_output_ref = method_ctx.emit(_make_call("computeStateOutput", [preimage_ref2, state_script_ref, new_amount_ref]))
                    all_outputs = method_ctx.emit(_make_call("cat", [contract_output_ref, change_output_ref]))
                    hash_ref = method_ctx.emit(_make_call("hash256", [all_outputs]))
                    preimage_ref4 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref4]))
                    eq_ref = method_ctx.emit(ANFValue(
                        kind="bin_op", op="===",
                        left=hash_ref, right=output_hash_ref,
                        result_type="bytes",
                    ))
                    method_ctx.emit(_make_assert(eq_ref))

            # Build augmented params list for ABI
            augmented_params = _lower_params(method.params)
            if needs_change_output:
                augmented_params += [
                    ANFParam(name="_changePKH", type="Ripemd160"),
                    ANFParam(name="_changeAmount", type="bigint"),
                ]
            if needs_new_amount:
                augmented_params.append(ANFParam(name="_newAmount", type="bigint"))
            augmented_params.append(ANFParam(name="txPreimage", type="SigHashPreimage"))

            result.append(ANFMethod(
                name=method.name,
                params=augmented_params,
                body=method_ctx.bindings,
                is_public=True,
            ))
        else:
            method_ctx.lower_statements(method.body)
            result.append(ANFMethod(
                name=method.name,
                params=_lower_params(method.params),
                body=method_ctx.bindings,
                is_public=method.visibility == "public",
            ))

    return result


def _lower_params(params: list) -> list[ANFParam]:
    return [
        ANFParam(name=p.name, type=_type_node_to_string(p.type))
        for p in params
    ]


# ---------------------------------------------------------------------------
# Lowering context
# ---------------------------------------------------------------------------

class _LowerCtx:
    """Manages temp variable generation and binding emission.

    Mirrors the Go ``lowerCtx`` struct exactly.
    """

    def __init__(self, contract: ContractNode) -> None:
        self.bindings: list[ANFBinding] = []
        self._counter: int = 0
        self._contract: ContractNode = contract
        self._local_names: set[str] = set()
        self._param_names: set[str] = set()
        self._add_output_refs: list[str] = []
        self._local_aliases: dict[str, str] = {}
        self._local_byte_vars: set[str] = set()
        self.current_source_loc: SourceLocation | None = None

    def fresh_temp(self) -> str:
        name = f"t{self._counter}"
        self._counter += 1
        return name

    def emit(self, value: ANFValue) -> str:
        name = self.fresh_temp()
        binding = ANFBinding(name=name, value=value)
        if self.current_source_loc:
            binding.source_loc = self.current_source_loc
        self.bindings.append(binding)
        return name

    def emit_named(self, name: str, value: ANFValue) -> None:
        binding = ANFBinding(name=name, value=value)
        if self.current_source_loc:
            binding.source_loc = self.current_source_loc
        self.bindings.append(binding)

    def add_local(self, name: str) -> None:
        self._local_names.add(name)

    def is_local(self, name: str) -> bool:
        return name in self._local_names

    def add_param(self, name: str) -> None:
        self._param_names.add(name)

    def is_param(self, name: str) -> bool:
        return name in self._param_names

    def set_local_alias(self, local_name: str, binding_name: str) -> None:
        self._local_aliases[local_name] = binding_name

    def get_local_alias(self, local_name: str) -> str:
        return self._local_aliases.get(local_name, "")

    def add_output_ref(self, ref: str) -> None:
        self._add_output_refs.append(ref)

    def get_add_output_refs(self) -> list[str]:
        return self._add_output_refs

    def is_property(self, name: str) -> bool:
        return any(p.name == name for p in self._contract.properties)

    def _is_private_method(self, name: str) -> bool:
        """Whether ``name`` is a private (non-public) method on the contract.
        Used to route bare-identifier calls through the method_call inlining
        path so Move's free-function helpers match TypeScript's ``this.foo()``
        lowering."""
        for m in self._contract.methods:
            if m.name == name and m.name != "constructor" and m.visibility != "public":
                return True
        return False

    def get_param_type(self, name: str) -> str | None:
        for p in self._contract.constructor.params:
            if p.name == name:
                return _type_node_to_string(p.type)
        for method in self._contract.methods:
            for p in method.params:
                if p.name == name:
                    return _type_node_to_string(p.type)
        return None

    def get_property_type(self, name: str) -> str | None:
        for p in self._contract.properties:
            if p.name == name:
                return _type_node_to_string(p.type)
        return None

    def sub_context(self) -> _LowerCtx:
        """Create a sub-context for nested blocks (if/else, loops).

        The counter continues from the parent. Local names and param names
        are shared (copied).
        """
        sub = _LowerCtx(self._contract)
        sub._counter = self._counter
        sub._local_names = set(self._local_names)
        sub._param_names = set(self._param_names)
        sub._local_aliases = dict(self._local_aliases)
        sub._local_byte_vars = set(self._local_byte_vars)
        return sub

    def sync_counter(self, sub: _LowerCtx) -> None:
        if sub._counter > self._counter:
            self._counter = sub._counter

    # -------------------------------------------------------------------
    # Statement lowering
    # -------------------------------------------------------------------

    def lower_statements(self, stmts: list[Statement]) -> None:
        for i, stmt in enumerate(stmts):
            # Early-return nesting: when an if-statement's then-block ends with a
            # return and there is no else-branch, the remaining statements after the
            # if logically belong in the else-branch (they only execute when the
            # condition is false).
            if (
                isinstance(stmt, IfStmt)
                and not stmt.else_
                and i + 1 < len(stmts)
                and _branch_ends_with_return(stmt.then)
            ):
                remaining = stmts[i + 1:]
                modified_if = IfStmt(
                    condition=stmt.condition,
                    then=stmt.then,
                    else_=remaining,
                )
                self.lower_statement(modified_if)
                return
            self.lower_statement(stmt)

    def lower_statement(self, stmt: Statement) -> None:
        # Propagate source location to emitted ANF bindings
        stmt_loc = getattr(stmt, "source_location", None)
        if stmt_loc is not None:
            self.current_source_loc = SourceLocation(
                file=stmt_loc.file, line=stmt_loc.line, column=stmt_loc.column,
            )

        if isinstance(stmt, VariableDeclStmt):
            self._lower_variable_decl(stmt)
        elif isinstance(stmt, AssignmentStmt):
            self._lower_assignment(stmt)
        elif isinstance(stmt, IfStmt):
            self._lower_if_statement(stmt)
        elif isinstance(stmt, ForStmt):
            self._lower_for_statement(stmt)
        elif isinstance(stmt, ExpressionStmt):
            self.lower_expr_to_ref(stmt.expr)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                ref = self.lower_expr_to_ref(stmt.value)
                # If the returned ref is not the name of the last emitted binding,
                # emit an explicit load so the return value is the last (top-of-stack)
                # binding.  This matters when a local variable is returned after
                # control flow (e.g., `let count = 0n; if (...) { count += 1n; }
                # return count;`).  Without this, the last binding is the if, not
                # `count`, so _inline_method_call in stack lowering can't find the
                # return value.
                if self.bindings and self.bindings[-1].name != ref:
                    self.emit(_make_load_const_string(f"@ref:{ref}"))

        self.current_source_loc = None

    def _lower_variable_decl(self, stmt: VariableDeclStmt) -> None:
        value_ref = self.lower_expr_to_ref(stmt.init)
        self.add_local(stmt.name)
        if _is_byte_typed_expr(stmt.init, self):
            self._local_byte_vars.add(stmt.name)
        self.emit_named(stmt.name, _make_load_const_string("@ref:" + value_ref))

    def _lower_assignment(self, stmt: AssignmentStmt) -> None:
        value_ref = self.lower_expr_to_ref(stmt.value)

        # this.x = expr -> update_prop
        if isinstance(stmt.target, PropertyAccessExpr):
            self.emit(_make_update_prop(stmt.target.property, value_ref))
            return

        # local = expr -> re-bind
        if isinstance(stmt.target, Identifier):
            self.emit_named(stmt.target.name, _make_load_const_string("@ref:" + value_ref))
            return

        # For other targets, lower the target expression
        self.lower_expr_to_ref(stmt.target)

    def _lower_if_statement(self, stmt: IfStmt) -> None:
        cond_ref = self.lower_expr_to_ref(stmt.condition)

        # Lower then-block into sub-context
        then_ctx = self.sub_context()
        then_ctx.lower_statements(stmt.then)
        self.sync_counter(then_ctx)

        # Lower else-block into sub-context
        else_ctx = self.sub_context()
        if stmt.else_:
            else_ctx.lower_statements(stmt.else_)
        self.sync_counter(else_ctx)

        # Propagate addOutput refs from sub-contexts: when either branch produces
        # addOutput calls, the if-expression result represents each addOutput
        # (only one branch executes at runtime).
        then_has_outputs = bool(then_ctx.get_add_output_refs())
        else_has_outputs = bool(else_ctx.get_add_output_refs())

        if_name = self.emit(ANFValue(
            kind="if",
            cond=cond_ref,
            then=then_ctx.bindings,
            else_=else_ctx.bindings,
        ))

        if then_has_outputs or else_has_outputs:
            self.add_output_ref(if_name)

        # If both branches end by reassigning the same local variable,
        # alias that variable to the if-expression result
        if then_ctx.bindings and else_ctx.bindings:
            then_last = then_ctx.bindings[-1]
            else_last = else_ctx.bindings[-1]
            if then_last.name == else_last.name and self.is_local(then_last.name):
                self.set_local_alias(then_last.name, if_name)

    def _lower_for_statement(self, stmt: ForStmt) -> None:
        count = _extract_loop_count(stmt)

        # Lower body into sub-context
        body_ctx = self.sub_context()
        body_ctx.lower_statements(stmt.body)
        self.sync_counter(body_ctx)

        self.emit(ANFValue(
            kind="loop",
            count=count,
            body=body_ctx.bindings,
            iter_var=stmt.init.name if stmt.init else "",
        ))

    # -------------------------------------------------------------------
    # Expression lowering (the core ANF conversion)
    # -------------------------------------------------------------------

    def lower_expr_to_ref(self, expr: Expression | None) -> str:
        if expr is None:
            return self.emit(_make_load_const_int(0))

        if isinstance(expr, BigIntLiteral):
            return self.emit(_make_load_const_int(expr.value))

        if isinstance(expr, BoolLiteral):
            return self.emit(_make_load_const_bool(expr.value))

        if isinstance(expr, ByteStringLiteral):
            return self.emit(_make_load_const_string(expr.value))

        if isinstance(expr, Identifier):
            return self._lower_identifier(expr)

        if isinstance(expr, PropertyAccessExpr):
            # this.txPreimage in StatefulSmartContract -> load_param
            if self.is_param(expr.property):
                return self.emit(ANFValue(kind="load_param", name=expr.property))
            # this.x -> load_prop
            return self.emit(ANFValue(kind="load_prop", name=expr.property))

        if isinstance(expr, MemberExpr):
            return self._lower_member_expr(expr)

        if isinstance(expr, BinaryExpr):
            left_ref = self.lower_expr_to_ref(expr.left)
            right_ref = self.lower_expr_to_ref(expr.right)

            result_type: str | None = None
            if (expr.op in ("===", "!==")) and (
                _is_byte_typed_expr(expr.left, self) or _is_byte_typed_expr(expr.right, self)
            ):
                result_type = "bytes"
            # For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
            if expr.op == "+" and (
                _is_byte_typed_expr(expr.left, self) or _is_byte_typed_expr(expr.right, self)
            ):
                result_type = "bytes"
            # For bitwise &, |, ^, annotate byte-typed operands.
            if expr.op in ("&", "|", "^") and (
                _is_byte_typed_expr(expr.left, self) or _is_byte_typed_expr(expr.right, self)
            ):
                result_type = "bytes"

            return self.emit(ANFValue(
                kind="bin_op", op=expr.op,
                left=left_ref, right=right_ref,
                result_type=result_type,
            ))

        if isinstance(expr, UnaryExpr):
            operand_ref = self.lower_expr_to_ref(expr.operand)
            unary_val = ANFValue(kind="unary_op", op=expr.op, operand=operand_ref)
            # For ~, annotate byte-typed operands so downstream passes know the result is bytes.
            if expr.op == "~" and _is_byte_typed_expr(expr.operand, self):
                unary_val.result_type = "bytes"
            return self.emit(unary_val)

        if isinstance(expr, CallExpr):
            return self._lower_call_expr(expr)

        if isinstance(expr, TernaryExpr):
            return self._lower_ternary_expr(expr)

        if isinstance(expr, IndexAccessExpr):
            obj_ref = self.lower_expr_to_ref(expr.object)
            index_ref = self.lower_expr_to_ref(expr.index)
            return self.emit(_make_call("__array_access", [obj_ref, index_ref]))

        if isinstance(expr, IncrementExpr):
            return self._lower_increment_expr(expr)

        if isinstance(expr, DecrementExpr):
            return self._lower_decrement_expr(expr)

        if isinstance(expr, ArrayLiteralExpr):
            element_refs = [self.lower_expr_to_ref(elem) for elem in expr.elements]
            return self.emit(ANFValue(kind="array_literal", elements=element_refs))

        return self.emit(_make_load_const_int(0))

    def _lower_identifier(self, id_node: Identifier) -> str:
        name = id_node.name

        # 'this' is not a value in ANF
        if name == "this":
            return self.emit(_make_load_const_string("@this"))

        # Check if it's a registered parameter (e.g. txPreimage)
        if self.is_param(name):
            return self.emit(ANFValue(kind="load_param", name=name))

        # Check if it's a local variable -- reference it directly
        # (or use its alias if reassigned by an if-statement)
        if self.is_local(name):
            alias = self.get_local_alias(name)
            if alias:
                return alias
            return name

        # Check if it's a contract property
        if self.is_property(name):
            return self.emit(ANFValue(kind="load_prop", name=name))

        # Default: treat as parameter (this is how params get loaded lazily)
        return self.emit(ANFValue(kind="load_param", name=name))

    def _lower_member_expr(self, e: MemberExpr) -> str:
        # this.x -> load_prop
        if isinstance(e.object, Identifier) and e.object.name == "this":
            return self.emit(ANFValue(kind="load_prop", name=e.property))

        # SigHash.ALL etc. -> load constant
        if isinstance(e.object, Identifier) and e.object.name == "SigHash":
            sig_hash_values: dict[str, int] = {
                "ALL":          0x01,
                "NONE":         0x02,
                "SINGLE":       0x03,
                "FORKID":       0x40,
                "ANYONECANPAY": 0x80,
            }
            val = sig_hash_values.get(e.property)
            if val is not None:
                return self.emit(_make_load_const_int(val))

        # General member access
        obj_ref = self.lower_expr_to_ref(e.object)
        return self.emit(ANFValue(kind="method_call", object=obj_ref, method=e.property))

    def _lower_call_expr(self, e: CallExpr) -> str:
        callee = e.callee

        # super(...) call — accepts both Identifier("super") and MemberExpr(super, "")
        is_super = (isinstance(callee, Identifier) and callee.name == "super") or (
            isinstance(callee, MemberExpr) and isinstance(callee.object, Identifier)
            and callee.object.name == "super"
        )
        if is_super:
            arg_refs = self._lower_args(e.args)
            return self.emit(_make_call("super", arg_refs))

        # assert(expr)
        if isinstance(callee, Identifier) and callee.name == "assert":
            if len(e.args) >= 1:
                value_ref = self.lower_expr_to_ref(e.args[0])
                return self.emit(_make_assert(value_ref))
            false_ref = self.emit(_make_load_const_bool(False))
            return self.emit(_make_assert(false_ref))

        # checkPreimage(preimage)
        if isinstance(callee, Identifier) and callee.name == "checkPreimage":
            if len(e.args) >= 1:
                preimage_ref = self.lower_expr_to_ref(e.args[0])
                return self.emit(ANFValue(kind="check_preimage", preimage=preimage_ref))

        # this.addOutput(satoshis, val1, val2, ...) via PropertyAccessExpr
        if isinstance(callee, PropertyAccessExpr) and callee.property == "addOutput":
            arg_refs = self._lower_args(e.args)
            satoshis = arg_refs[0]
            state_values = arg_refs[1:]
            ref = self.emit(ANFValue(kind="add_output", satoshis=satoshis, state_values=state_values, preimage=""))
            self.add_output_ref(ref)
            return ref

        # this.addRawOutput(satoshis, scriptBytes) via PropertyAccessExpr
        if isinstance(callee, PropertyAccessExpr) and callee.property == "addRawOutput":
            arg_refs = self._lower_args(e.args)
            satoshis = arg_refs[0]
            script_bytes_ref = arg_refs[1]
            ref = self.emit(ANFValue(kind="add_raw_output", satoshis=satoshis, script_bytes=script_bytes_ref))
            self.add_output_ref(ref)
            return ref

        # this.addOutput(satoshis, val1, val2, ...) via MemberExpr
        if isinstance(callee, MemberExpr):
            if (
                isinstance(callee.object, Identifier)
                and callee.object.name == "this"
                and callee.property == "addOutput"
            ):
                arg_refs = self._lower_args(e.args)
                satoshis = arg_refs[0]
                state_values = arg_refs[1:]
                ref = self.emit(ANFValue(kind="add_output", satoshis=satoshis, state_values=state_values, preimage=""))
                self.add_output_ref(ref)
                return ref

        # this.addRawOutput(satoshis, scriptBytes) via MemberExpr
        if isinstance(callee, MemberExpr):
            if (
                isinstance(callee.object, Identifier)
                and callee.object.name == "this"
                and callee.property == "addRawOutput"
            ):
                arg_refs = self._lower_args(e.args)
                satoshis = arg_refs[0]
                script_bytes_ref = arg_refs[1]
                ref = self.emit(ANFValue(kind="add_raw_output", satoshis=satoshis, script_bytes=script_bytes_ref))
                self.add_output_ref(ref)
                return ref

        # this.getStateScript() via PropertyAccessExpr
        if isinstance(callee, PropertyAccessExpr) and callee.property == "getStateScript":
            return self.emit(ANFValue(kind="get_state_script"))

        # this.getStateScript() via MemberExpr
        if isinstance(callee, MemberExpr):
            if (
                isinstance(callee.object, Identifier)
                and callee.object.name == "this"
                and callee.property == "getStateScript"
            ):
                return self.emit(ANFValue(kind="get_state_script"))

        # this.method(...) via PropertyAccessExpr
        if isinstance(callee, PropertyAccessExpr):
            arg_refs = self._lower_args(e.args)
            this_ref = self.emit(_make_load_const_string("@this"))
            return self.emit(ANFValue(
                kind="method_call", object=this_ref,
                method=callee.property, args=arg_refs,
            ))

        # this.method(...) via MemberExpr
        if isinstance(callee, MemberExpr):
            if isinstance(callee.object, Identifier) and callee.object.name == "this":
                arg_refs = self._lower_args(e.args)
                this_ref = self.emit(_make_load_const_string("@this"))
                return self.emit(ANFValue(
                    kind="method_call", object=this_ref,
                    method=callee.property, args=arg_refs,
                ))

        # Direct function call: sha256(x), checkSig(sig, pk), etc.
        if isinstance(callee, Identifier):
            arg_refs = self._lower_args(e.args)
            # Bare identifier calls that match a private method on the contract
            # (e.g. Move's `require_owner(contract, sig)` which the parser
            # strips to `requireOwner(sig)`) must be routed through the same
            # inlining path as `this.requireOwner(sig)` so downstream stack
            # lowering can inline the body. Keeps .runar.move in sync with
            # .runar.ts across all formats.
            if self._is_private_method(callee.name):
                this_ref = self.emit(_make_load_const_string("@this"))
                return self.emit(ANFValue(
                    kind="method_call", object=this_ref,
                    method=callee.name, args=arg_refs,
                ))
            return self.emit(_make_call(callee.name, arg_refs))

        # General call
        callee_ref = self.lower_expr_to_ref(callee)
        arg_refs = self._lower_args(e.args)
        return self.emit(ANFValue(
            kind="method_call", object=callee_ref,
            method="call", args=arg_refs,
        ))

    def _lower_args(self, args: list[Expression]) -> list[str]:
        return [self.lower_expr_to_ref(arg) for arg in args]

    def _lower_ternary_expr(self, e: TernaryExpr) -> str:
        cond_ref = self.lower_expr_to_ref(e.condition)

        then_ctx = self.sub_context()
        then_ctx.lower_expr_to_ref(e.consequent)
        self.sync_counter(then_ctx)

        else_ctx = self.sub_context()
        else_ctx.lower_expr_to_ref(e.alternate)
        self.sync_counter(else_ctx)

        return self.emit(ANFValue(
            kind="if",
            cond=cond_ref,
            then=then_ctx.bindings,
            else_=else_ctx.bindings,
        ))

    def _lower_increment_expr(self, e: IncrementExpr) -> str:
        operand_ref = self.lower_expr_to_ref(e.operand)
        one_ref = self.emit(_make_load_const_int(1))
        result = self.emit(ANFValue(kind="bin_op", op="+", left=operand_ref, right=one_ref))

        # If the operand is a named variable, update it
        if isinstance(e.operand, Identifier):
            self.emit_named(e.operand.name, _make_load_const_string("@ref:" + result))
        if isinstance(e.operand, PropertyAccessExpr):
            self.emit(_make_update_prop(e.operand.property, result))

        if e.prefix:
            return result
        return operand_ref

    def _lower_decrement_expr(self, e: DecrementExpr) -> str:
        operand_ref = self.lower_expr_to_ref(e.operand)
        one_ref = self.emit(_make_load_const_int(1))
        result = self.emit(ANFValue(kind="bin_op", op="-", left=operand_ref, right=one_ref))

        # If the operand is a named variable, update it
        if isinstance(e.operand, Identifier):
            self.emit_named(e.operand.name, _make_load_const_string("@ref:" + result))
        if isinstance(e.operand, PropertyAccessExpr):
            self.emit(_make_update_prop(e.operand.property, result))

        if e.prefix:
            return result
        return operand_ref


# ---------------------------------------------------------------------------
# ANFValue constructors
# ---------------------------------------------------------------------------

def _make_load_const_int(val: int) -> ANFValue:
    raw = json.dumps(val)
    return ANFValue(
        kind="load_const",
        raw_value=raw,
        const_big_int=val,
        const_int=val,
    )


def _make_load_const_bool(val: bool) -> ANFValue:
    raw = json.dumps(val)
    return ANFValue(
        kind="load_const",
        raw_value=raw,
        const_bool=val,
    )


def _make_load_const_string(val: str) -> ANFValue:
    raw = json.dumps(val)
    return ANFValue(
        kind="load_const",
        raw_value=raw,
        const_string=val,
    )


def _make_call(func_name: str, args: list[str]) -> ANFValue:
    return ANFValue(
        kind="call",
        func=func_name,
        args=args,
    )


def _make_assert(value_ref: str) -> ANFValue:
    raw = json.dumps(value_ref)
    return ANFValue(
        kind="assert",
        raw_value=raw,
        value_ref=value_ref,
    )


def _make_update_prop(name: str, value_ref: str) -> ANFValue:
    raw = json.dumps(value_ref)
    return ANFValue(
        kind="update_prop",
        name=name,
        raw_value=raw,
        value_ref=value_ref,
    )


# ---------------------------------------------------------------------------
# State mutation analysis
# ---------------------------------------------------------------------------

def _method_mutates_state(method, contract: ContractNode) -> bool:
    """Determine whether a method mutates any mutable (non-readonly) property.

    Conservative: if ANY code path can mutate state, returns True.
    """
    mutable_props: set[str] = {
        p.name for p in contract.properties if not p.readonly
    }
    if not mutable_props:
        return False
    return _body_mutates_state(method.body, mutable_props)


def _body_mutates_state(stmts: list[Statement], mutable_props: set[str]) -> bool:
    return any(_stmt_mutates_state(stmt, mutable_props) for stmt in stmts)


def _stmt_mutates_state(stmt: Statement, mutable_props: set[str]) -> bool:
    if isinstance(stmt, AssignmentStmt):
        if isinstance(stmt.target, PropertyAccessExpr):
            return stmt.target.property in mutable_props
        return False

    if isinstance(stmt, ExpressionStmt):
        return _expr_mutates_state(stmt.expr, mutable_props)

    if isinstance(stmt, IfStmt):
        if _body_mutates_state(stmt.then, mutable_props):
            return True
        if stmt.else_ and _body_mutates_state(stmt.else_, mutable_props):
            return True
        return False

    if isinstance(stmt, ForStmt):
        if stmt.update is not None and _stmt_mutates_state(stmt.update, mutable_props):
            return True
        return _body_mutates_state(stmt.body, mutable_props)

    return False


def _expr_mutates_state(expr: Expression | None, mutable_props: set[str]) -> bool:
    if expr is None:
        return False
    if isinstance(expr, IncrementExpr):
        if isinstance(expr.operand, PropertyAccessExpr):
            return expr.operand.property in mutable_props
    if isinstance(expr, DecrementExpr):
        if isinstance(expr.operand, PropertyAccessExpr):
            return expr.operand.property in mutable_props
    return False


# ---------------------------------------------------------------------------
# addOutput detection for determining change output necessity
# ---------------------------------------------------------------------------

def _method_has_add_output(method) -> bool:
    """Check if a method body contains any this.addOutput() calls."""
    return _body_has_add_output(method.body)


def _body_has_add_output(stmts: list[Statement]) -> bool:
    return any(_stmt_has_add_output(stmt) for stmt in stmts)


def _stmt_has_add_output(stmt: Statement) -> bool:
    if isinstance(stmt, ExpressionStmt):
        return _expr_has_add_output(stmt.expr)
    if isinstance(stmt, IfStmt):
        if _body_has_add_output(stmt.then):
            return True
        if stmt.else_ and _body_has_add_output(stmt.else_):
            return True
        return False
    if isinstance(stmt, ForStmt):
        return _body_has_add_output(stmt.body)
    return False


def _expr_has_add_output(expr: Expression | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, CallExpr):
        callee = expr.callee
        if isinstance(callee, PropertyAccessExpr) and callee.property in ("addOutput", "addRawOutput"):
            return True
        if isinstance(callee, MemberExpr):
            if isinstance(callee.object, Identifier) and callee.object.name == "this" and callee.property in ("addOutput", "addRawOutput"):
                return True
    return False


# ---------------------------------------------------------------------------
# Loop count extraction
# ---------------------------------------------------------------------------

def _extract_loop_count(stmt: ForStmt) -> int:
    start_val = _extract_bigint_value(stmt.init.init if stmt.init else None)

    if isinstance(stmt.condition, BinaryExpr):
        bound_val = _extract_bigint_value(stmt.condition.right)

        if start_val is not None and bound_val is not None:
            start = start_val
            bound = bound_val
            op = stmt.condition.op
            if op == "<":
                return max(0, bound - start)
            if op == "<=":
                return max(0, bound - start + 1)
            if op == ">":
                return max(0, start - bound)
            if op == ">=":
                return max(0, start - bound + 1)

        if bound_val is not None:
            op = stmt.condition.op
            if op == "<":
                return bound_val
            if op == "<=":
                return bound_val + 1

    return 0


def _extract_bigint_value(expr: Expression | None) -> int | None:
    if expr is None:
        return None
    if isinstance(expr, BigIntLiteral):
        return expr.value
    if isinstance(expr, UnaryExpr) and expr.op == "-":
        inner = _extract_bigint_value(expr.operand)
        if inner is not None:
            return -inner
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _branch_ends_with_return(stmts: list[Statement]) -> bool:
    """Check whether a statement list always terminates with a return_statement."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, ReturnStmt):
        return True
    # Also handle if-else where both branches return
    if isinstance(last, IfStmt) and last.else_:
        return _branch_ends_with_return(last.then) and _branch_ends_with_return(last.else_)
    return False


def _type_node_to_string(node: TypeNode | None) -> str:
    """Convert a type node to its string representation."""
    if node is None:
        return "<unknown>"
    if isinstance(node, PrimitiveType):
        return node.name
    if isinstance(node, FixedArrayType):
        return _type_node_to_string(node.element) + "[]"
    if isinstance(node, CustomType):
        return node.name
    return "<unknown>"


# ---------------------------------------------------------------------------
# Post-ANF pass: lift update_prop from if-else branches
# ---------------------------------------------------------------------------
#
# Mirrors the TypeScript reference compiler's ``liftBranchUpdateProps`` (see
# packages/runar-compiler/src/passes/04-anf-lower.ts) and the Go port
# (compilers/go/frontend/anf_lower.go).
#
# Transforms if-else chains where each branch ends with ``update_prop`` into
# flat conditional assignments. This prevents phantom stack entries in stack
# lowering for patterns like position dispatch where each branch updates a
# different property.
#
# Before:
#   if (pos === 0) { this.c0 = turn; }
#   else if (pos === 1) { this.c1 = turn; }
#   else { this.c4 = turn; }
#
# After:
#   this.c0 = (pos === 0) ? turn : this.c0;
#   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;
#   this.c4 = (!cond0 && !cond1) ? turn : this.c4;


@dataclass
class _UpdateBranch:
    """A single branch of a flattened if-else update-prop chain."""

    cond_setup_bindings: list[ANFBinding]
    cond_ref: str | None  # None for the final else
    prop_name: str
    value_bindings: list[ANFBinding]
    value_ref: str


def _max_temp_index(bindings: list[ANFBinding]) -> int:
    """Find the maximum temp index (e.g. t47 -> 47) in a binding tree."""
    max_idx = -1
    for b in bindings:
        if b.name.startswith("t") and len(b.name) > 1 and b.name[1:].isdigit():
            n = int(b.name[1:])
            if n > max_idx:
                max_idx = n
        if b.value.kind == "if":
            if b.value.then is not None:
                t = _max_temp_index(b.value.then)
                if t > max_idx:
                    max_idx = t
            if b.value.else_ is not None:
                e = _max_temp_index(b.value.else_)
                if e > max_idx:
                    max_idx = e
        elif b.value.kind == "loop":
            if b.value.body is not None:
                l = _max_temp_index(b.value.body)
                if l > max_idx:
                    max_idx = l
    return max_idx


def _is_side_effect_free(v: ANFValue) -> bool:
    return v.kind in ("load_prop", "load_param", "load_const", "bin_op", "unary_op")


def _all_bindings_side_effect_free(bindings: list[ANFBinding]) -> bool:
    return all(_is_side_effect_free(b.value) for b in bindings)


def _extract_branch_update(
    bindings: list[ANFBinding],
) -> tuple[str, list[ANFBinding], str] | None:
    """If *bindings* ends with ``update_prop``, return (prop_name, value_bindings, value_ref)."""
    if not bindings:
        return None
    last = bindings[-1]
    if last.value.kind != "update_prop":
        return None
    value_bindings = bindings[:-1]
    if not _all_bindings_side_effect_free(value_bindings):
        return None
    return last.value.name or "", value_bindings, last.value.value_ref or ""


def _is_assert_false_else(bindings: list[ANFBinding]) -> bool:
    """Check if an else branch is just ``assert(false)`` -- unreachable dead code."""
    if not bindings:
        return False
    last = bindings[-1]
    if last.value.kind != "assert":
        return False
    assert_ref = last.value.value_ref
    for b in bindings:
        if (
            b.name == assert_ref
            and b.value.kind == "load_const"
            and b.value.const_bool is False
        ):
            return True
    return False


def _collect_update_branches(
    if_cond: str,
    then_bindings: list[ANFBinding],
    else_bindings: list[ANFBinding],
) -> list[_UpdateBranch] | None:
    """Recursively collect branches from a nested if-else chain where every
    branch ends with exactly one ``update_prop``."""
    then_update = _extract_branch_update(then_bindings)
    if then_update is None:
        return None
    prop_name, val_bindings, val_ref = then_update

    branches: list[_UpdateBranch] = [
        _UpdateBranch(
            cond_setup_bindings=[],
            cond_ref=if_cond,
            prop_name=prop_name,
            value_bindings=val_bindings,
            value_ref=val_ref,
        )
    ]

    if not else_bindings:
        return None

    # Check if else is another if (else-if chain)
    last_else = else_bindings[-1]
    if last_else.value.kind == "if":
        cond_setup = else_bindings[:-1]
        if not _all_bindings_side_effect_free(cond_setup):
            return None

        inner_branches = _collect_update_branches(
            last_else.value.cond or "",
            last_else.value.then or [],
            last_else.value.else_ or [],
        )
        if inner_branches is None:
            return None

        # Prepend condition setup to first inner branch
        inner_branches[0].cond_setup_bindings = (
            list(cond_setup) + inner_branches[0].cond_setup_bindings
        )
        branches.extend(inner_branches)
        return branches

    # Otherwise, else branch should end with update_prop (final else)
    else_update = _extract_branch_update(else_bindings)
    if else_update is not None:
        e_prop_name, e_val_bindings, e_val_ref = else_update
        branches.append(
            _UpdateBranch(
                cond_setup_bindings=[],
                cond_ref=None,
                prop_name=e_prop_name,
                value_bindings=e_val_bindings,
                value_ref=e_val_ref,
            )
        )
        return branches

    # Handle unreachable else: assert(false) as the final else is dead code.
    # Each preceding branch's condition fully guards its update; the else
    # path never executes.
    if _is_assert_false_else(else_bindings):
        return branches

    return None


def _remap_value_refs(value: ANFValue, name_map: dict[str, str]) -> ANFValue:
    """Return a copy of *value* with temp references remapped via *name_map*."""
    def r(s: str | None) -> str | None:
        if s is None:
            return None
        return name_map.get(s, s)

    new_v = ANFValue(kind=value.kind)
    new_v.name = value.name
    new_v.raw_value = value.raw_value
    new_v.const_string = value.const_string
    new_v.const_big_int = value.const_big_int
    new_v.const_bool = value.const_bool
    new_v.const_int = value.const_int
    new_v.op = value.op
    new_v.left = r(value.left)
    new_v.right = r(value.right)
    new_v.result_type = value.result_type
    new_v.operand = r(value.operand)
    new_v.func = value.func
    new_v.args = [r(a) or "" for a in value.args] if value.args is not None else None
    new_v.object = r(value.object)
    new_v.method = value.method
    new_v.cond = r(value.cond)
    new_v.then = value.then
    new_v.else_ = value.else_
    new_v.count = value.count
    new_v.iter_var = value.iter_var
    new_v.body = value.body
    new_v.value_ref = r(value.value_ref)
    new_v.preimage = r(value.preimage)
    new_v.satoshis = r(value.satoshis)
    new_v.state_values = (
        [r(s) or "" for s in value.state_values] if value.state_values is not None else None
    )
    new_v.script_bytes = r(value.script_bytes)
    new_v.elements = (
        [r(e) or "" for e in value.elements] if value.elements is not None else None
    )

    # Special-case load_const "@ref:..." strings: also remap and refresh raw_value
    if value.kind == "load_const" and value.const_string is not None:
        s = value.const_string
        if s.startswith("@ref:"):
            target = s[5:]
            mapped = name_map.get(target)
            if mapped is not None:
                new_ref = "@ref:" + mapped
                new_v.const_string = new_ref
                new_v.raw_value = json.dumps(new_ref)

    # Refresh raw_value for kinds that store the value reference there
    if value.kind in ("assert", "update_prop") and new_v.value_ref is not None:
        new_v.raw_value = json.dumps(new_v.value_ref)

    return new_v


def _lift_branch_update_props(bindings: list[ANFBinding]) -> list[ANFBinding]:
    """Transform if-bindings whose branches all end with ``update_prop`` into
    flat conditional assignments."""
    next_idx = _max_temp_index(bindings) + 1

    def fresh() -> str:
        nonlocal next_idx
        name = f"t{next_idx}"
        next_idx += 1
        return name

    result: list[ANFBinding] = []

    for binding in bindings:
        if binding.value.kind != "if":
            # Recurse into nested if-bindings (loops etc. are not transformed)
            result.append(binding)
            continue

        if_val = binding.value
        branches = _collect_update_branches(
            if_val.cond or "",
            if_val.then or [],
            if_val.else_ or [],
        )

        if branches is None or len(branches) < 2:
            result.append(binding)
            continue

        # --- Transform: flatten into conditional assignments ---

        # 1. Hoist condition setup bindings with fresh names
        name_map: dict[str, str] = {}
        cond_refs: list[str | None] = []

        for branch in branches:
            for csb in branch.cond_setup_bindings:
                new_name = fresh()
                name_map[csb.name] = new_name
                result.append(ANFBinding(
                    name=new_name,
                    value=_remap_value_refs(csb.value, name_map),
                ))
            if branch.cond_ref is not None:
                cond_refs.append(name_map.get(branch.cond_ref, branch.cond_ref))
            else:
                cond_refs.append(None)

        # 2. Compute effective condition for each branch
        #    Branch 0: cond0
        #    Branch k>0: !cond0 && !cond1 && ... && !cond(k-1) && cond_k
        #    Final else: !cond0 && !cond1 && ... && !cond(N-2)
        effective_conds: list[str] = []
        negated_conds: list[str] = []

        for i in range(len(branches)):
            if i == 0:
                assert cond_refs[0] is not None
                effective_conds.append(cond_refs[0])
                continue

            # Negate any prior conditions not yet negated
            for j in range(len(negated_conds), i):
                if cond_refs[j] is None:
                    continue
                neg_name = fresh()
                result.append(ANFBinding(
                    name=neg_name,
                    value=ANFValue(
                        kind="unary_op",
                        op="!",
                        operand=cond_refs[j],
                    ),
                ))
                negated_conds.append(neg_name)

            # AND all negated conditions together
            and_ref = negated_conds[0]
            limit = min(i, len(negated_conds))
            for j in range(1, limit):
                and_name = fresh()
                result.append(ANFBinding(
                    name=and_name,
                    value=ANFValue(
                        kind="bin_op",
                        op="&&",
                        left=and_ref,
                        right=negated_conds[j],
                    ),
                ))
                and_ref = and_name

            if cond_refs[i] is not None:
                # Middle branch: AND with own condition
                final_name = fresh()
                result.append(ANFBinding(
                    name=final_name,
                    value=ANFValue(
                        kind="bin_op",
                        op="&&",
                        left=and_ref,
                        right=cond_refs[i],
                    ),
                ))
                effective_conds.append(final_name)
            else:
                # Final else: just the AND of negations
                effective_conds.append(and_ref)

        # 3. For each branch, emit: load_old, conditional if-expression, update_prop
        for i, branch in enumerate(branches):
            # Load old property value
            old_prop_ref = fresh()
            result.append(ANFBinding(
                name=old_prop_ref,
                value=ANFValue(kind="load_prop", name=branch.prop_name),
            ))

            # Remap value bindings for the then-branch
            branch_map = dict(name_map)
            then_bindings: list[ANFBinding] = []
            for vb in branch.value_bindings:
                new_name = fresh()
                branch_map[vb.name] = new_name
                then_bindings.append(ANFBinding(
                    name=new_name,
                    value=_remap_value_refs(vb.value, branch_map),
                ))

            # The branch's value_ref also needs remapping (it points into value_bindings)
            mapped_value_ref = branch_map.get(branch.value_ref, branch.value_ref)

            # Else branch: keep old property value
            keep_name = fresh()
            ref_str = "@ref:" + old_prop_ref
            else_bindings: list[ANFBinding] = [
                ANFBinding(
                    name=keep_name,
                    value=ANFValue(
                        kind="load_const",
                        raw_value=json.dumps(ref_str),
                        const_string=ref_str,
                    ),
                ),
            ]

            # Emit conditional if-expression
            # Note: mapped_value_ref is computed above for symmetry with TS/Go,
            # but the standard ANF invariant is that the last binding in
            # value_bindings produces the value the original update_prop
            # referenced, so it is already the last binding in then_bindings.
            _ = mapped_value_ref  # reserved for invariant checks in tests
            cond_if_ref = fresh()
            result.append(ANFBinding(
                name=cond_if_ref,
                value=ANFValue(
                    kind="if",
                    cond=effective_conds[i],
                    then=then_bindings,
                    else_=else_bindings,
                ),
            ))

            # Emit update_prop pointing at the if-expression
            update_name = fresh()
            result.append(ANFBinding(
                name=update_name,
                value=ANFValue(
                    kind="update_prop",
                    name=branch.prop_name,
                    raw_value=json.dumps(cond_if_ref),
                    value_ref=cond_if_ref,
                ),
            ))

    return result
