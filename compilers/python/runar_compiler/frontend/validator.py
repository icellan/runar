"""Validation pass for the Runar compiler.

Checks the AST against language subset constraints WITHOUT modifying it.
Direct port of ``compilers/go/frontend/validator.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import re

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
    SourceLocation,
    Statement,
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
class ValidationResult:
    """Output of the validation pass."""

    errors: list[Diagnostic] = field(default_factory=list)
    warnings: list[Diagnostic] = field(default_factory=list)

    def error_strings(self) -> list[str]:
        """Return formatted error messages as plain strings."""
        return [d.format_message() for d in self.errors]

    def warning_strings(self) -> list[str]:
        """Return formatted warning messages as plain strings."""
        return [d.format_message() for d in self.warnings]


def validate(contract: ContractNode) -> ValidationResult:
    """Validate a Runar AST against language subset constraints.

    Does NOT modify the AST; only reports errors and warnings.
    """
    ctx = _ValidationContext(contract=contract)

    ctx.validate_properties()
    ctx.validate_constructor()
    ctx.validate_methods()
    ctx.check_no_recursion()

    # Issue #123: reject preimage-field reads / output bindings that are unsound
    # under a method's declared @sighash mode (security core). This pass emits
    # both errors (unsound usages) and warnings (e.g. an explicit single-output
    # SINGLE covenant whose same-index value cannot be pinned statically), so
    # route each diagnostic to the matching bucket.
    from runar_compiler.frontend.sighash_validate import validate_sighash_usage
    for d in validate_sighash_usage(contract):
        (ctx.warnings if d.severity == Severity.WARNING else ctx.errors).append(d)

    return ValidationResult(errors=ctx.errors, warnings=ctx.warnings)


# ---------------------------------------------------------------------------
# Valid property types
# ---------------------------------------------------------------------------

_VALID_PROP_TYPES: frozenset[str] = frozenset({
    "bigint",
    "boolean",
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
    "P256Point",
    "P384Point",
})


# ---------------------------------------------------------------------------
# Validation context
# ---------------------------------------------------------------------------

@dataclass
class _ValidationContext:
    contract: ContractNode
    errors: list[Diagnostic] = field(default_factory=list)
    warnings: list[Diagnostic] = field(default_factory=list)

    def _add_error(self, msg: str, loc: SourceLocation | None = None) -> None:
        self.errors.append(Diagnostic(message=msg, severity=Severity.ERROR, loc=loc))

    # -------------------------------------------------------------------
    # Property validation
    # -------------------------------------------------------------------

    def validate_properties(self) -> None:
        for prop in self.contract.properties:
            self._validate_property_type(prop.type, prop.source_location)

            # V27: txPreimage is an implicit property of StatefulSmartContract
            if self.contract.parent_class == "StatefulSmartContract" and prop.name == "txPreimage":
                self._add_error(
                    "'txPreimage' is an implicit property of StatefulSmartContract "
                    "and must not be declared",
                    loc=prop.source_location,
                )

            # Validate initializer if present. FixedArray properties accept an
            # array literal of literal elements (recursively, for nested
            # arrays); other properties accept a plain literal value. Mirrors
            # the TS validator in `02-validate.ts` and the Go peer in
            # `validator.go`.
            if prop.initializer is not None:
                if isinstance(prop.type, FixedArrayType):
                    if not _is_array_literal_of_literals(prop.initializer):
                        self._add_error(
                            f"property '{prop.name}' initializer must be an "
                            f"array literal of literal values",
                            loc=prop.source_location,
                        )
                elif not _is_literal_expression(prop.initializer):
                    self._add_error(
                        f"property '{prop.name}' initializer must be a literal value",
                        loc=prop.source_location,
                    )

        # SmartContract (and the asm-escape-hatch UnsafeSmartContract) require
        # all properties to be readonly.
        if self.contract.parent_class in ("SmartContract", "UnsafeSmartContract"):
            for prop in self.contract.properties:
                if not prop.readonly:
                    self._add_error(
                        f"Property '{prop.name}' in {self.contract.parent_class} "
                        f"must be declared readonly",
                        loc=prop.source_location,
                    )

        # V26: Warn if StatefulSmartContract has no mutable properties
        if self.contract.parent_class == "StatefulSmartContract":
            has_mutable = any(not p.readonly for p in self.contract.properties)
            if not has_mutable:
                self.warnings.append(Diagnostic(
                    message="StatefulSmartContract has no mutable properties; "
                    "consider using SmartContract instead",
                    severity=Severity.WARNING,
                    loc=self.contract.constructor.source_location,
                ))

    def _validate_property_type(self, t: TypeNode | None, loc: SourceLocation) -> None:
        if t is None:
            return
        if isinstance(t, PrimitiveType):
            if t.name not in _VALID_PROP_TYPES:
                if t.name == "void":
                    self._add_error(
                        f"property type 'void' is not valid at {loc.file}:{loc.line}",
                        loc=loc,
                    )
        elif isinstance(t, FixedArrayType):
            if t.length <= 0:
                self._add_error(
                    f"FixedArray length must be a positive integer at {loc.file}:{loc.line}",
                    loc=loc,
                )
            self._validate_property_type(t.element, loc)
        elif isinstance(t, CustomType):
            self._add_error(
                f"unsupported type '{t.name}' in property declaration at {loc.file}:{loc.line}",
                loc=loc,
            )

    # -------------------------------------------------------------------
    # Constructor validation
    # -------------------------------------------------------------------

    def validate_constructor(self) -> None:
        ctor = self.contract.constructor
        prop_names: set[str] = {p.name for p in self.contract.properties}

        # FixedArray not allowed as constructor parameter.
        for param in ctor.params:
            if isinstance(param.type, FixedArrayType):
                self._add_error(
                    f"Constructor parameter '{param.name}' cannot be a FixedArray. "
                    "Use initialized properties or pass each element as a separate parameter.",
                    loc=ctor.source_location,
                )

        # Check super() as first statement
        if len(ctor.body) == 0:
            self._add_error("constructor must call super() as its first statement", loc=ctor.source_location)
            return

        if not _is_super_call(ctor.body[0]):
            self._add_error("constructor must call super() as its first statement", loc=ctor.source_location)

        # Check all properties are assigned
        assigned_props: set[str] = set()
        for stmt in ctor.body:
            if isinstance(stmt, AssignmentStmt):
                if isinstance(stmt.target, PropertyAccessExpr):
                    assigned_props.add(stmt.target.property)

        # Properties with initializers don't need constructor assignments
        props_with_init = {
            p.name for p in self.contract.properties if p.initializer is not None
        }

        for name in prop_names:
            if name not in assigned_props and name not in props_with_init:
                self._add_error(
                    f"property '{name}' must be assigned in the constructor",
                    loc=ctor.source_location,
                )

        # Validate constructor body
        for stmt in ctor.body:
            self._validate_statement(stmt)

        self._validate_constructor_slot_bijection()

    def _validate_constructor_slot_bijection(self) -> None:
        """Enforce the NEW-002 invariant.

        Every constructor parameter initialises exactly one property that needs
        a deploy-time value, and the i-th parameter initialises the i-th such
        property.

        A property's deploy-time value comes from a constructor ARGUMENT, and
        the artifact addresses those arguments POSITIONALLY: the ABI
        constructor params come from the constructor SIGNATURE while a
        constructor slot's ``paramIndex`` is an index into the properties with
        no ``initial_value``, and the SDK splices
        ``constructorArgs[slot.paramIndex]`` into the slot's bytes. Two
        independently built lists, assumed to line up. Where they disagree a
        deploy argument lands in ANOTHER property's slot, silently -- a
        deployed contract authorising a value the developer never passed for
        that property.

        "Needs a deploy-time value" mirrors
        ``_constructor_assigned_properties`` in ``anf_lower.py`` exactly: a
        property carries a compile-time ``initial_value`` iff it has an
        initializer the constructor does NOT override by assigning it a bare
        parameter.
        """
        ctor = self.contract.constructor
        param_index = {p.name: i for i, p in enumerate(ctor.params)}

        # property -> distinct bare parameters assigned to it; a property with
        # any non-parameter assignment is recorded with an EMPTY set.
        prop_to_params: dict[str, set[str]] = {}
        param_to_props: dict[str, set[str]] = {}
        for stmt in ctor.body:
            if not isinstance(stmt, AssignmentStmt):
                continue
            if not isinstance(stmt.target, PropertyAccessExpr):
                continue
            prop = stmt.target.property
            if not isinstance(stmt.value, Identifier) or stmt.value.name not in param_index:
                prop_to_params.setdefault(prop, set())
                continue
            param = stmt.value.name
            prop_to_params.setdefault(prop, set()).add(param)
            param_to_props.setdefault(param, set()).add(prop)

        before = len(self.errors)

        # (a) One parameter feeding several properties: only one of them could
        # own the argument, so the rest keep a default or deploy undefined.
        for param in ctor.params:
            props = param_to_props.get(param.name, set())
            if len(props) > 1:
                self._add_error(
                    f"constructor parameter '{param.name}' initialises more than one "
                    f"property ({', '.join(sorted(props))}). Each constructor parameter "
                    "is spliced into exactly one property's deploy-time slot, so only "
                    "the first would receive the argument. Declare one parameter per "
                    "property.",
                    loc=ctor.source_location,
                )

        # (b) One property fed by several parameters -- no single argument owns it.
        for prop_node in self.contract.properties:
            params = prop_to_params.get(prop_node.name, set())
            if len(params) > 1:
                self._add_error(
                    f"property '{prop_node.name}' is assigned more than one constructor "
                    f"parameter ({', '.join(sorted(params))}). Each property that needs "
                    "a deploy-time value corresponds to exactly one constructor parameter.",
                    loc=ctor.source_location,
                )

        # (c) A property that needs a deploy-time value but whose constructor
        # assignment is not a parameter. A property assigned NOTHING is already
        # reported above, so it is skipped here rather than double-reported.
        for prop_node in self.contract.properties:
            if prop_node.initializer is not None:
                continue
            params = prop_to_params.get(prop_node.name)
            if params is None or len(params) >= 1:
                continue
            self._add_error(
                f"property '{prop_node.name}' has no initializer and is not assigned a "
                "constructor parameter, so it has no deploy-time value. The constructor "
                "body is not compiled into the locking script — give the property a "
                "literal initializer or assign it a constructor parameter "
                f"(this.{prop_node.name} = {prop_node.name}).",
                loc=ctor.source_location,
            )

        # (d) A parameter that initialises nothing: its argument is dropped
        # and, because slots are positional, every later argument lands in the
        # wrong slot.
        for param in ctor.params:
            if param.name in param_to_props:
                continue
            self._add_error(
                f"constructor parameter '{param.name}' does not initialise any property. "
                "Constructor arguments are spliced into property slots positionally, so "
                "an unused parameter drops its own argument and shifts every later one "
                f"into the wrong property's slot. Assign it (this.{param.name} = "
                f"{param.name}) or remove the parameter.",
                loc=ctor.source_location,
            )

        # (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions
        # being compared are themselves the thing that is broken.
        if len(self.errors) != before:
            return
        slot = 0
        for prop_node in self.contract.properties:
            params = prop_to_params.get(prop_node.name, set())
            single = next(iter(params)) if len(params) == 1 else None
            if prop_node.initializer is not None and single is None:
                continue  # initializer survives: not a deploy-time property
            if single is not None:
                declared = param_index[single]
                if declared != slot:
                    abi_name = ctor.params[slot].name if slot < len(ctor.params) else "?"
                    self._add_error(
                        f"property '{prop_node.name}' occupies deploy-time slot {slot}, "
                        f"but the constructor parameter that initialises it ('{single}') "
                        f"is declared at position {declared}. Constructor arguments are "
                        "spliced positionally, so the deployed script would carry "
                        f"argument {slot} — advertised by the ABI as parameter "
                        f"'{abi_name}' — in this property's slot. Declare the parameters "
                        "in the same order as the properties they initialise.",
                        loc=ctor.source_location,
                    )
            slot += 1

    # -------------------------------------------------------------------
    # Method validation
    # -------------------------------------------------------------------

    def validate_methods(self) -> None:
        # A contract with no public methods has no spending entry points and
        # compiles to an empty script -- never what the author meant (usually a
        # missing `public` modifier; methods default to private).
        if not any(m.visibility == "public" for m in self.contract.methods):
            self._add_error(
                f"Contract '{self.contract.name}' has no public methods "
                "— no spending entry points; add 'public' to at least one method"
            )

        for method in self.contract.methods:
            self._validate_method(method)

    def _validate_method(self, method) -> None:
        # FixedArray not allowed as method parameter.
        for param in method.params:
            if isinstance(param.type, FixedArrayType):
                self._add_error(
                    f"Parameter '{param.name}' in method '{method.name}' cannot be a FixedArray. "
                    "Arrays are only allowed as contract properties.",
                    loc=method.source_location,
                )

        # `return` is a PRIVATE-helper construct only (NEW-012).
        if method.visibility == "public":
            self._reject_return_in_public_method(method)

        # Public methods must end with an assert() call (unless
        # StatefulSmartContract, where the compiler auto-injects the final
        # assert; or UnsafeSmartContract, where a terminal asm({..., out_arity:
        # 1}) provides the truthy stack value).
        if (
            method.visibility == "public"
            and self.contract.parent_class == "SmartContract"
        ):
            if not _ends_with_assert(method.body):
                self._add_error(
                    f"public method '{method.name}' must end with an assert() call",
                    loc=method.source_location,
                )

        # UnsafeSmartContract public methods must end with either an assert()
        # call or a terminal asm({..., out_arity: 1}) -- either way the script
        # has to leave a truthy value on the stack.
        if (
            method.visibility == "public"
            and self.contract.parent_class == "UnsafeSmartContract"
        ):
            if not _ends_with_assert(method.body) and not _ends_with_terminal_asm(method.body):
                self._add_error(
                    f"public method '{method.name}' must end with an assert() call "
                    f"or a terminal asm({{...}}) with out_arity 1",
                    loc=method.source_location,
                )

        # V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if self.contract.parent_class == "StatefulSmartContract" and method.visibility == "public":
            _warn_manual_preimage_usage(method, self.warnings)

        # #131: warn when a public method gates on extractLocktime but never
        # asserts the spending tx is non-final (extractSequence < 0xffffffff).
        # Advisory only.
        if method.visibility == "public":
            _warn_locktime_without_sequence_guard(method, self.contract, self.warnings)

        # Gate asm({...}) calls on UnsafeSmartContract and check the structural args.
        self._validate_asm_usage(method)

        # readonly properties may only be assigned in the constructor.
        self._check_readonly_writes(method)

        # Validate statements
        for stmt in method.body:
            self._validate_statement(stmt)

    # -------------------------------------------------------------------
    # Readonly property writes
    # -------------------------------------------------------------------

    def _check_readonly_writes(self, method) -> None:
        """Report every write to a readonly contract property in a method body.

        ``spec/semantics.md``::

            <this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property

        The constructor is exempt -- that is where every contract initialises
        its readonly properties -- so this runs per METHOD only
        (``validate_constructor`` never calls in here).

        Three AST shapes reach ``update_prop`` in ANF lowering and are all
        covered: ``this.p = e``, ``this.p++`` / ``this.p--``, and
        ``this.arr[i] = e``.
        """
        readonly = {p.name for p in self.contract.properties if p.readonly}
        if not readonly:
            return

        def report(name: str, loc: SourceLocation | None) -> None:
            self._add_error(
                f"cannot assign to readonly property '{name}' in method "
                f"'{method.name}'. readonly properties may only be assigned "
                f"in the constructor.",
                loc=loc,
            )

        def visit_expr(expr: Expression | None, loc: SourceLocation | None) -> None:
            if expr is None:
                return

            def visitor(e: Expression) -> None:
                if not isinstance(e, (IncrementExpr, DecrementExpr)):
                    return
                name = _written_property(e.operand)
                if name is not None and name in readonly:
                    report(name, loc)

            _walk_expr(expr, visitor)

        def visit_statements(stmts) -> None:
            for stmt in stmts:
                if isinstance(stmt, AssignmentStmt):
                    name = _written_property(stmt.target)
                    if name is not None and name in readonly:
                        report(name, stmt.source_location)
                    visit_expr(stmt.target, stmt.source_location)
                    visit_expr(stmt.value, stmt.source_location)
                elif isinstance(stmt, VariableDeclStmt):
                    visit_expr(stmt.init, stmt.source_location)
                elif isinstance(stmt, ExpressionStmt):
                    visit_expr(stmt.expr, stmt.source_location)
                elif isinstance(stmt, ReturnStmt):
                    visit_expr(stmt.value, stmt.source_location)
                elif isinstance(stmt, IfStmt):
                    visit_expr(stmt.condition, stmt.source_location)
                    visit_statements(stmt.then)
                    visit_statements(stmt.else_)
                elif isinstance(stmt, ForStmt):
                    visit_statements([stmt.init, stmt.update])
                    visit_expr(stmt.condition, stmt.source_location)
                    visit_statements(stmt.body)

        visit_statements(method.body)

    # -------------------------------------------------------------------
    # asm() intrinsic validation
    # -------------------------------------------------------------------


    def _reject_return_in_public_method(self, method) -> None:
        """Enforce ``spec/grammar.md:161`` and ``:162``.

        161: "Public methods MUST return ``void``."
        162: "Public methods MUST end with an ``assert(...)`` call as their
             final statement."

        ``spec/semantics.md`` gives ``return`` no early-exit meaning at all:
        §4.6 defines it ONLY as "the value of this method is v" (the
        private-helper inlining semantics), while §4.7 sequences statements
        UNCONDITIONALLY -- there is no rule under which the statements after a
        ``return`` are skipped.

        Lowering it as if it were the tail of an inlined helper produced two
        different broken scripts (NEW-012):

        * ``return;`` -- the enclosing branch had no result to contribute, so
          its arm yielded OP_0 and the whole script evaluated FALSE, an
          unspendable UTXO from source that compiled clean. In this tier it
          surfaced as an internal "stack lowering: list index out of range"
          instead.
        * ``return expr;`` -- the returned value became the branch result and
          hence the script's final truthiness, so any truthy expr spent the
          contract WITHOUT reaching the guarding assert. Fail-OPEN.

        The Java tier has always rejected the valued form; this brings the rule
        to every tier and covers the bare form too.
        """
        for ret in _find_return_statements(method.body):
            self._add_error(
                f"public method '{method.name}' must not use `return`: public "
                "methods are spending entry points, they return void "
                "(spec/grammar.md:161) and must end with an assert() that "
                "encodes the spending condition (spec/grammar.md:162). "
                "R\u00fanar has no early exit \u2014 restructure the guard as an "
                "if/else, or move the logic into a private helper, where "
                "`return` is allowed.",
                loc=ret.source_location,
            )

    def _validate_asm_usage(self, method) -> None:
        """Walk a method body and validate every asm({...}) call.

        - Reject any asm() outside an UnsafeSmartContract.
        - Confirm the parser-normalised arg shape: (body, in_arity, out_arity)
          where body is a ByteString literal with even-length hex and the
          arities are non-negative bigint literals.
        - Expression-form asm<T>({...}) must have out_arity 1.

        The parser already pushes most hex diagnostics; this pass is the
        back-stop that runs even when the parser shape is well-formed and is
        the only layer that knows about the contract's parentClass.
        """
        def visitor(expr: Expression) -> None:
            if not _is_asm_call(expr):
                return
            assert isinstance(expr, CallExpr)

            if self.contract.parent_class != "UnsafeSmartContract":
                self._add_error(
                    f"'asm' is only available in contracts extending "
                    f"UnsafeSmartContract; got {self.contract.parent_class}. "
                    f"Move the call into a class that extends "
                    f"UnsafeSmartContract (and import {{ UnsafeSmartContract }} "
                    f"from 'runar-lang')."
                )
                return

            if len(expr.args) != 3:
                self._add_error(
                    "asm() expects exactly one object-literal argument "
                    "{ body, in_arity?, out_arity? }"
                )
                return

            body_arg = expr.args[0]
            if not isinstance(body_arg, ByteStringLiteral):
                self._add_error("asm() body must be a hex string literal")
                return
            body = body_arg.value
            if len(body) == 0:
                self._add_error(
                    "asm() body must be a non-empty hex string literal"
                )
            elif len(body) % 2 != 0:
                self._add_error(
                    f"asm() body has odd hex length ({len(body)}); each "
                    f"opcode byte requires two hex characters"
                )
            elif not re.fullmatch(r"[0-9a-fA-F]*", body):
                self._add_error(
                    "asm() body contains non-hex characters; only 0-9, a-f, "
                    "A-F are allowed"
                )

            in_arity = expr.args[1]
            if not isinstance(in_arity, BigIntLiteral) or in_arity.value < 0:
                self._add_error(
                    "asm() in_arity must be a non-negative integer literal"
                )

            out_arity = expr.args[2]
            if not isinstance(out_arity, BigIntLiteral) or out_arity.value < 0:
                self._add_error(
                    "asm() out_arity must be a non-negative integer literal"
                )

            # Expression-form asm<T>({...}) returns a value that flows into a
            # let-binding -- exactly ONE stack value, so out_arity must be 1.
            if (
                expr.asm_return_type
                and isinstance(out_arity, BigIntLiteral)
                and out_arity.value != 1
            ):
                self._add_error(
                    f"Expression-form asm<{expr.asm_return_type}>() must have "
                    f"out_arity 1 (got {out_arity.value}); only a single stack "
                    f"value can be bound to the result variable."
                )

        _walk_expressions_in_body(method.body, visitor)

    # -------------------------------------------------------------------
    # Statement validation
    # -------------------------------------------------------------------

    def _validate_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, VariableDeclStmt):
            if isinstance(stmt.type, FixedArrayType):
                self._add_error(
                    f"Local variable '{stmt.name}' cannot be a FixedArray. "
                    "Arrays are only allowed as contract properties.",
                    loc=stmt.source_location,
                )
            self._validate_expression(stmt.init)
        elif isinstance(stmt, AssignmentStmt):
            self._validate_expression(stmt.target)
            self._validate_expression(stmt.value)
        elif isinstance(stmt, IfStmt):
            self._validate_expression(stmt.condition)
            for st in stmt.then:
                self._validate_statement(st)
            for st in stmt.else_:
                self._validate_statement(st)
        elif isinstance(stmt, ForStmt):
            self._validate_for_statement(stmt)
        elif isinstance(stmt, ExpressionStmt):
            self._validate_expression(stmt.expr)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                self._validate_expression(stmt.value)

    def _validate_for_statement(self, stmt: ForStmt) -> None:
        self._validate_expression(stmt.condition)

        # Check constant bounds. Non-zero starts and countdown loops (``i--``
        # with ``>``/``>=``) are supported: the ANF loop node carries an
        # explicit start value and step direction (issue #121), so lowering
        # binds ``iterVar = start + i*step`` on each unrolled iteration.
        if isinstance(stmt.condition, BinaryExpr):
            if not _is_compile_time_constant(stmt.condition.right):
                self._add_error("for loop bound must be a compile-time constant")

        self._validate_expression(stmt.init.init)
        for s in stmt.body:
            self._validate_statement(s)

    # -------------------------------------------------------------------
    # Expression validation
    # -------------------------------------------------------------------

    def _validate_expression(self, expr: Expression | None) -> None:
        if expr is None:
            return
        if isinstance(expr, BinaryExpr):
            self._validate_expression(expr.left)
            self._validate_expression(expr.right)
        elif isinstance(expr, UnaryExpr):
            self._validate_expression(expr.operand)
        elif isinstance(expr, CallExpr):
            self._validate_expression(expr.callee)
            # assert() message (2nd arg) is a human-readable string, not hex — skip validation
            is_assert = isinstance(expr.callee, Identifier) and expr.callee.name == "assert"
            for i, arg in enumerate(expr.args):
                if is_assert and i >= 1:
                    continue
                self._validate_expression(arg)
        elif isinstance(expr, MemberExpr):
            self._validate_expression(expr.object)
        elif isinstance(expr, TernaryExpr):
            self._validate_expression(expr.condition)
            self._validate_expression(expr.consequent)
            self._validate_expression(expr.alternate)
        elif isinstance(expr, IndexAccessExpr):
            self._validate_expression(expr.object)
            self._validate_expression(expr.index)
        elif isinstance(expr, IncrementExpr):
            self._validate_expression(expr.operand)
        elif isinstance(expr, DecrementExpr):
            self._validate_expression(expr.operand)
        elif isinstance(expr, ByteStringLiteral):
            val = expr.value
            if len(val) > 0:
                if len(val) % 2 != 0:
                    self._add_error(
                        f"ByteString literal '{val}' has odd length ({len(val)}) "
                        f"\u2014 hex strings must have an even number of characters"
                    )
                elif not re.fullmatch(r'[0-9a-fA-F]*', val):
                    self._add_error(
                        f"ByteString literal '{val}' contains non-hex characters "
                        f"\u2014 only 0-9, a-f, A-F are allowed"
                    )

    # -------------------------------------------------------------------
    # Recursion detection
    # -------------------------------------------------------------------

    def check_no_recursion(self) -> None:
        call_graph: dict[str, set[str]] = {}
        method_names: set[str] = set()

        for method in self.contract.methods:
            method_names.add(method.name)
            calls: set[str] = set()
            _collect_method_calls(method.body, calls)
            call_graph[method.name] = calls

        # Check for cycles using DFS
        for method in self.contract.methods:
            visited: set[str] = set()
            stack: set[str] = set()
            if _has_cycle(method.name, call_graph, method_names, visited, stack):
                self._add_error(
                    f"recursion detected: method '{method.name}' calls itself "
                    f"directly or indirectly",
                    loc=method.source_location,
                )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _is_super_call(stmt: Statement) -> bool:
    if not isinstance(stmt, ExpressionStmt):
        return False
    if not isinstance(stmt.expr, CallExpr):
        return False
    callee = stmt.expr.callee
    # Accept both Identifier("super") and MemberExpr(Identifier("super"), "")
    if isinstance(callee, Identifier):
        return callee.name == "super"
    if isinstance(callee, MemberExpr):
        return isinstance(callee.object, Identifier) and callee.object.name == "super"
    return False



def _find_return_statements(body: list[Statement]) -> list[ReturnStmt]:
    """Every ``return`` in ``body``, at any nesting depth (arms, loop bodies)."""
    found: list[ReturnStmt] = []

    def walk(stmts: list[Statement]) -> None:
        for stmt in stmts:
            if isinstance(stmt, ReturnStmt):
                found.append(stmt)
            elif isinstance(stmt, IfStmt):
                walk(stmt.then)
                walk(stmt.else_ or [])
            elif isinstance(stmt, ForStmt):
                walk(stmt.body)

    walk(body)
    return found

def _ends_with_assert(body: list[Statement]) -> bool:
    if len(body) == 0:
        return False
    last = body[-1]

    if isinstance(last, ExpressionStmt):
        return _is_assert_call(last.expr)

    if isinstance(last, IfStmt):
        then_ends = _ends_with_assert(last.then)
        else_ends = len(last.else_) > 0 and _ends_with_assert(last.else_)
        return then_ends and else_ends

    return False


def _is_assert_call(expr: Expression | None) -> bool:
    if not isinstance(expr, CallExpr):
        return False
    if not isinstance(expr.callee, Identifier):
        return False
    return expr.callee.name == "assert"


def _is_asm_call(expr: Expression | None) -> bool:
    """Return True if *expr* is a call to the asm compiler intrinsic."""
    if not isinstance(expr, CallExpr):
        return False
    if not isinstance(expr.callee, Identifier):
        return False
    return expr.callee.name == "asm"


def _ends_with_terminal_asm(body: list[Statement]) -> bool:
    """Return True if the last statement of *body* is an asm({...}) call with
    the parser-normalised positional args (body, in_arity, out_arity) and an
    out_arity literal equal to 1.

    If/else branches that both terminate in a terminal asm (or assert) also
    count, mirroring the asserts-on-both-branches rule.
    """
    if len(body) == 0:
        return False
    last = body[-1]

    if isinstance(last, ExpressionStmt):
        if not _is_asm_call(last.expr):
            return False
        call = last.expr
        assert isinstance(call, CallExpr)
        # The parser always rewrites asm({...}) into positional
        # (body, in_arity, out_arity).
        if len(call.args) == 3:
            out_arity = call.args[2]
            if isinstance(out_arity, BigIntLiteral) and out_arity.value == 1:
                return True
        return False

    if isinstance(last, IfStmt):
        then_ends = _ends_with_terminal_asm(last.then) or _ends_with_assert(last.then)
        else_ends = len(last.else_) > 0 and (
            _ends_with_terminal_asm(last.else_) or _ends_with_assert(last.else_)
        )
        return then_ends and else_ends

    return False


def _is_compile_time_constant(expr: Expression | None) -> bool:
    # Only integer literals (and their negation) can be unrolled into fixed
    # Bitcoin Script by anf-lower. A bare identifier bound (e.g. ``const N``) or
    # a runtime member access (``this.x``) is NOT resolvable and must be
    # rejected here with a graceful diagnostic — anf-lower's
    # ``_extract_loop_shape`` would otherwise raise. Mirrors the reference TS
    # compiler's observable behavior: only literal loop bounds compile.
    if expr is None:
        return False
    if isinstance(expr, BigIntLiteral):
        return True
    if isinstance(expr, UnaryExpr):
        if expr.op == "-":
            return _is_compile_time_constant(expr.operand)
    return False


# ---------------------------------------------------------------------------
# V24/V25: warn on manual preimage/state-script usage
# ---------------------------------------------------------------------------

def _warn_manual_preimage_usage(method, warnings: list[Diagnostic]) -> None:
    """Walk method body and warn on checkPreimage() or this.getStateScript() calls."""
    method_loc = method.source_location

    def visitor(expr: Expression) -> None:
        if isinstance(expr, CallExpr):
            # V24: bare checkPreimage(...) call
            if isinstance(expr.callee, Identifier) and expr.callee.name == "checkPreimage":
                warnings.append(Diagnostic(
                    message=f"StatefulSmartContract auto-injects checkPreimage(); calling it manually "
                    f"in '{method.name}' will cause a duplicate verification",
                    severity=Severity.WARNING,
                    loc=method_loc,
                ))
            # V24: this.checkPreimage(...) call via PropertyAccessExpr or MemberExpr
            callee_prop = _callee_property(expr.callee)
            if callee_prop == "checkPreimage":
                warnings.append(Diagnostic(
                    message=f"StatefulSmartContract auto-injects checkPreimage(); calling it manually "
                    f"in '{method.name}' will cause a duplicate verification",
                    severity=Severity.WARNING,
                    loc=method_loc,
                ))
            # V25: this.getStateScript() call
            if callee_prop == "getStateScript":
                warnings.append(Diagnostic(
                    message=f"StatefulSmartContract auto-injects state continuation; calling "
                    f"getStateScript() manually in '{method.name}' is redundant",
                    severity=Severity.WARNING,
                    loc=method_loc,
                ))

    _walk_expressions_in_body(method.body, visitor)


# ---------------------------------------------------------------------------
# #131: locktime soundness -- extractLocktime needs an extractSequence guard
# ---------------------------------------------------------------------------

# Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value.
_SEQUENCE_FINAL = 0xffffffff


def _is_call_to_named(expr: Expression, name: str) -> bool:
    """True when *expr* is a direct call to the named intrinsic, e.g. ``f(...)``."""
    return (
        isinstance(expr, CallExpr)
        and isinstance(expr.callee, Identifier)
        and expr.callee.name == name
    )


def _is_locktime_read(expr: Expression) -> bool:
    """True when *expr* reads the transaction locktime.

    Both the raw intrinsic ``extractLocktime(preimage)`` and its ergonomic sugar
    ``currentBlockHeight()`` (which anf-lower desugars to
    ``extractLocktime(txPreimage)``) count -- either read is unsound without a
    sequence-finality guard.
    """
    return (
        _is_call_to_named(expr, "extractLocktime")
        or _is_call_to_named(expr, "currentBlockHeight")
    )


def _is_sequence_finality_guard(expr: Expression) -> bool:
    """True when *expr* is an ``extractSequence(...) < <final>``-style comparison
    (the guard that makes a locktime gate consensus-enforced).

    Accepts the two natural spellings: ``extractSequence(pre) < N`` / ``<= N``,
    and the reversed ``N > extractSequence(pre)`` / ``>= ...``. ``N`` must be a
    bigint literal no greater than the finality sentinel, so the guard genuinely
    forces non-finality.
    """
    if not isinstance(expr, BinaryExpr):
        return False

    def bound_ok(e: Expression) -> bool:
        return isinstance(e, BigIntLiteral) and e.value <= _SEQUENCE_FINAL

    if (expr.op in ("<", "<=")
            and _is_call_to_named(expr.left, "extractSequence")
            and bound_ok(expr.right)):
        return True
    if (expr.op in (">", ">=")
            and _is_call_to_named(expr.right, "extractSequence")
            and bound_ok(expr.left)):
        return True
    return False


def _warn_locktime_without_sequence_guard(method, contract, warnings: list[Diagnostic]) -> None:
    """#131: warn when *method* (transitively, through the private-helper call
    graph) reads the tx locktime but never asserts the tx is non-final.

    A locktime gate is not consensus-enforced unless ``extractSequence <
    0xffffffff`` is also asserted -- otherwise an all-final-sequence spend
    bypasses it. Advisory (warning) only -- no effect on emitted bytecode.
    """
    private_methods = {
        m.name: m for m in contract.methods if m.visibility == "private"
    }

    reads_locktime = False
    has_sequence_guard = False

    def visitor(expr: Expression) -> None:
        nonlocal reads_locktime, has_sequence_guard
        if _is_locktime_read(expr):
            reads_locktime = True
        if _is_sequence_finality_guard(expr):
            has_sequence_guard = True

    visited: set[str] = {method.name}
    queue: list = [method]
    while queue:
        current = queue.pop(0)
        _walk_expressions_in_body(current.body, visitor)
        # Follow calls into private helpers so a guard (or locktime read)
        # supplied by an inlined helper is seen by the public entry point.
        calls: set[str] = set()
        _collect_method_calls(current.body, calls)
        for callee in calls:
            if callee not in visited and callee in private_methods:
                visited.add(callee)
                queue.append(private_methods[callee])

    if reads_locktime and not has_sequence_guard:
        warnings.append(Diagnostic(
            message=f"method '{method.name}' reads extractLocktime but does not assert "
            f"extractSequence < 0xffffffff; a locktime gate is not consensus-enforced "
            f"unless the tx is non-final — add "
            f"assert(extractSequence(this.txPreimage) < 0xffffffffn)",
            severity=Severity.WARNING,
            loc=method.source_location,
        ))


def _callee_property(callee: Expression | None) -> str | None:
    """Return the property name if callee is a property access (PropertyAccessExpr or MemberExpr)."""
    if callee is None:
        return None
    if isinstance(callee, PropertyAccessExpr):
        return callee.property
    if isinstance(callee, MemberExpr):
        return callee.property
    return None


def _written_property(target: Expression | None) -> str | None:
    """Resolve the contract property an assignment target writes to, if any.

    Unwraps ``IndexAccessExpr`` chains so ``this.grid[i][j] = v`` resolves to
    ``grid``.
    """
    node = target
    while isinstance(node, IndexAccessExpr):
        node = node.object
    if isinstance(node, PropertyAccessExpr):
        return node.property
    return None


def _is_literal_expression(expr: Expression | None) -> bool:
    """Whether the expression is a literal allowed as a property initializer.

    bigint, bool, bytestring, or a negated bigint literal. Mirrors the TS/Go
    validator helpers.
    """
    if isinstance(expr, (BigIntLiteral, BoolLiteral, ByteStringLiteral)):
        return True
    if isinstance(expr, UnaryExpr) and expr.op == "-":
        return isinstance(expr.operand, BigIntLiteral)
    return False


def _is_array_literal_of_literals(expr: Expression | None) -> bool:
    """Whether the expression is an array literal of literal values.

    Recursive, for nested FixedArray initializers.
    """
    if not isinstance(expr, ArrayLiteralExpr):
        return False
    for el in expr.elements:
        if isinstance(el, ArrayLiteralExpr):
            if not _is_array_literal_of_literals(el):
                return False
        elif not _is_literal_expression(el):
            return False
    return True


def _walk_expressions_in_body(stmts: list[Statement], visitor) -> None:
    for stmt in stmts:
        _walk_expressions_in_stmt(stmt, visitor)


def _walk_expressions_in_stmt(stmt: Statement, visitor) -> None:
    if isinstance(stmt, ExpressionStmt):
        _walk_expr(stmt.expr, visitor)
    elif isinstance(stmt, VariableDeclStmt):
        _walk_expr(stmt.init, visitor)
    elif isinstance(stmt, AssignmentStmt):
        _walk_expr(stmt.target, visitor)
        _walk_expr(stmt.value, visitor)
    elif isinstance(stmt, IfStmt):
        _walk_expr(stmt.condition, visitor)
        _walk_expressions_in_body(stmt.then, visitor)
        _walk_expressions_in_body(stmt.else_, visitor)
    elif isinstance(stmt, ForStmt):
        _walk_expr(stmt.condition, visitor)
        _walk_expressions_in_body(stmt.body, visitor)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _walk_expr(stmt.value, visitor)


def _walk_expr(expr: Expression | None, visitor) -> None:
    if expr is None:
        return
    visitor(expr)
    if isinstance(expr, BinaryExpr):
        _walk_expr(expr.left, visitor)
        _walk_expr(expr.right, visitor)
    elif isinstance(expr, UnaryExpr):
        _walk_expr(expr.operand, visitor)
    elif isinstance(expr, CallExpr):
        _walk_expr(expr.callee, visitor)
        for arg in expr.args:
            _walk_expr(arg, visitor)
    elif isinstance(expr, MemberExpr):
        _walk_expr(expr.object, visitor)
    elif isinstance(expr, TernaryExpr):
        _walk_expr(expr.condition, visitor)
        _walk_expr(expr.consequent, visitor)
        _walk_expr(expr.alternate, visitor)
    elif isinstance(expr, IndexAccessExpr):
        _walk_expr(expr.object, visitor)
        _walk_expr(expr.index, visitor)
    elif isinstance(expr, IncrementExpr):
        _walk_expr(expr.operand, visitor)
    elif isinstance(expr, DecrementExpr):
        _walk_expr(expr.operand, visitor)


# ---------------------------------------------------------------------------
# Recursion detection helpers
# ---------------------------------------------------------------------------

def _collect_method_calls(stmts: list[Statement], calls: set[str]) -> None:
    for stmt in stmts:
        _collect_method_calls_in_stmt(stmt, calls)


def _collect_method_calls_in_stmt(stmt: Statement, calls: set[str]) -> None:
    if isinstance(stmt, ExpressionStmt):
        _collect_method_calls_in_expr(stmt.expr, calls)
    elif isinstance(stmt, VariableDeclStmt):
        _collect_method_calls_in_expr(stmt.init, calls)
    elif isinstance(stmt, AssignmentStmt):
        _collect_method_calls_in_expr(stmt.target, calls)
        _collect_method_calls_in_expr(stmt.value, calls)
    elif isinstance(stmt, IfStmt):
        _collect_method_calls_in_expr(stmt.condition, calls)
        _collect_method_calls(stmt.then, calls)
        _collect_method_calls(stmt.else_, calls)
    elif isinstance(stmt, ForStmt):
        _collect_method_calls_in_expr(stmt.condition, calls)
        _collect_method_calls(stmt.body, calls)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _collect_method_calls_in_expr(stmt.value, calls)


def _collect_method_calls_in_expr(expr: Expression | None, calls: set[str]) -> None:
    if expr is None:
        return
    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, PropertyAccessExpr):
            calls.add(expr.callee.property)
        if isinstance(expr.callee, MemberExpr):
            if isinstance(expr.callee.object, Identifier) and expr.callee.object.name == "this":
                calls.add(expr.callee.property)
        _collect_method_calls_in_expr(expr.callee, calls)
        for arg in expr.args:
            _collect_method_calls_in_expr(arg, calls)
    elif isinstance(expr, BinaryExpr):
        _collect_method_calls_in_expr(expr.left, calls)
        _collect_method_calls_in_expr(expr.right, calls)
    elif isinstance(expr, UnaryExpr):
        _collect_method_calls_in_expr(expr.operand, calls)
    elif isinstance(expr, MemberExpr):
        _collect_method_calls_in_expr(expr.object, calls)
    elif isinstance(expr, TernaryExpr):
        _collect_method_calls_in_expr(expr.condition, calls)
        _collect_method_calls_in_expr(expr.consequent, calls)
        _collect_method_calls_in_expr(expr.alternate, calls)
    elif isinstance(expr, IndexAccessExpr):
        _collect_method_calls_in_expr(expr.object, calls)
        _collect_method_calls_in_expr(expr.index, calls)
    elif isinstance(expr, IncrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls)
    elif isinstance(expr, DecrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls)


def _has_cycle(
    name: str,
    call_graph: dict[str, set[str]],
    method_names: set[str],
    visited: set[str],
    stack: set[str],
) -> bool:
    if name in stack:
        return True
    if name in visited:
        return False
    visited.add(name)
    stack.add(name)

    for callee in call_graph.get(name, set()):
        if callee in method_names:
            if _has_cycle(callee, call_graph, method_names, visited, stack):
                return True

    stack.discard(name)
    return False
