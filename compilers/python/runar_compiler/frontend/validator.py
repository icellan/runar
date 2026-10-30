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
    MethodNode,
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
from runar_compiler.frontend.input_limits import MAX_CALL_DEPTH, call_depth_message


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#: The cross-tier loop-START sentence (shared verbatim with the other six
#: tiers, which raise it from ANF lowering).
LOOP_START_DIAGNOSTIC = (
    "Cannot determine loop start at compile time. "
    "For-loop iterators must start at an integer literal."
)


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
    call_depth_exceeded = ctx.check_no_recursion()
    ctx.check_reserved_names()
    # N-180: the Rabin-provenance and sighash passes walk the private-method
    # call graph; past MAX_CALL_DEPTH that walk is the very depth the limit
    # refuses, so stop here.
    if call_depth_exceeded:
        return ValidationResult(errors=ctx.errors, warnings=ctx.warnings)
    _check_rabin_pubkey_provenance(ctx)

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

def loop_output_intrinsic_msg(intrinsic: str, via: str | None = None) -> str:
    """Build the R-127 rejection.

    Shared verbatim with the other six tiers and with the pass-4 backstop in
    ``anf_lower._lower_for_statement`` (N-006).
    """
    via_clause = f" (reached through private method '{via}')" if via else ""
    return (
        f"Output intrinsic '{intrinsic}'{via_clause} cannot be called inside a loop "
        "body. A loop body lowers into its own scope whose declared outputs never "
        "reach the method's output list, so the continuation hash would commit to "
        "fewer outputs than the transaction actually creates: the spend is rejected "
        "by every shipped SDK and any successor it produces is unspendable. Move the "
        "call out of the loop."
    )


def ternary_output_intrinsic_msg(intrinsic: str, via: str | None = None) -> str:
    """Build the N-049 rejection.

    Shared verbatim with the other six tiers (TS reference:
    ``ternaryOutputIntrinsicDiagnostic`` in 02-validate.ts) and with the pass-4
    backstop in ``anf_lower._lower_ternary_expr``.
    """
    via_clause = f" (reached through private method '{via}')" if via else ""
    return (
        f"Output intrinsic '{intrinsic}'{via_clause} cannot be called inside a "
        "conditional (ternary) expression arm. A ternary arm lowers into its own "
        "scope whose declared outputs never reach the method's output list, so the "
        "continuation hash would commit to fewer outputs than the transaction "
        "actually creates: a spender can drop the output and the honest spend is "
        "rejected. Use an if/else statement instead."
    )


@dataclass
class _ValidationContext:
    contract: ContractNode
    errors: list[Diagnostic] = field(default_factory=list)
    warnings: list[Diagnostic] = field(default_factory=list)
    #: Location of the statement currently being validated (R-149).
    #:
    #: ``typecheck.py`` auto-attaches a location to every error it raises, so
    #: the same contract produced located TYPE errors and unlocated VALIDATION
    #: errors. Eleven ``_add_error`` calls here passed none -- the whole
    #: ``asm()``-usage family among them -- because they are reached from
    #: EXPRESSION validation, and Python's ``Expression`` nodes carry no
    #: ``SourceLocation`` at all (``ast_nodes.py``). The enclosing statement
    #: does, so ``_validate_statement`` publishes it here and ``_add_error``
    #: falls back to it. Statement granularity is the difference between
    #: "somewhere in your contract" and "line 14"; expression granularity needs
    #: the AST change R-142 made on the TypeScript side.
    current_stmt_loc: SourceLocation | None = None

    def _add_error(self, msg: str, loc: SourceLocation | None = None) -> None:
        self.errors.append(
            Diagnostic(message=msg, severity=Severity.ERROR, loc=loc or self.current_stmt_loc)
        )

    # -------------------------------------------------------------------
    # N-065 / N-060: compiler-reserved names
    # -------------------------------------------------------------------

    def check_reserved_names(self) -> None:
        """Refuse a declared identifier spelled like a name a compiler pass
        mints (see reserved_names.py). Checks properties, method names,
        constructor and method parameters, locals and loop variables. A
        stateful ``txPreimage`` PROPERTY keeps its older, dedicated diagnostic.
        """
        from runar_compiler.frontend.reserved_names import (
            is_reserved_source_name,
            reserved_name_message,
        )

        stateful = self.contract.parent_class == "StatefulSmartContract"

        def check(name: str, loc: SourceLocation | None) -> None:
            if is_reserved_source_name(name, stateful):
                self._add_error(reserved_name_message(name), loc=loc)

        def walk(stmts: list[Statement]) -> None:
            for s in stmts:
                if isinstance(s, VariableDeclStmt):
                    check(s.name, s.source_location)
                elif isinstance(s, IfStmt):
                    walk(s.then)
                    walk(s.else_ or [])
                elif isinstance(s, ForStmt):
                    if s.init is not None:
                        check(s.init.name, s.init.source_location)
                    walk(s.body)

        for prop in self.contract.properties:
            if stateful and prop.name == "txPreimage":
                continue
            check(prop.name, prop.source_location)
        for method in [self.contract.constructor, *self.contract.methods]:
            if method.name != "constructor":
                check(method.name, method.source_location)
            for p in method.params:
                check(p.name, method.source_location)
            walk(method.body)

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

                # N-414 (peer of TS F-265): the shape checks above never validate
                # a ByteStringLiteral's HEX FORMAT; that lives in
                # _validate_expression, which a property initializer never
                # reached. An odd-length literal used to surface two passes later
                # as an opaque stack-lowering error.
                self._validate_expression(prop.initializer)

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
                else:
                    # R-246: any other unrecognised primitive name used to fall
                    # through in silence, while the identical name arriving as a
                    # CustomType is refused below. One property, two spellings,
                    # two answers. No parser in this tier produces a
                    # PrimitiveType with an unknown name today — they all map an
                    # unrecognised name to CustomType — but validate() takes an
                    # AST, and a pass that synthesises a property (the
                    # fixed-array expansion synthesises several) is one refactor
                    # away from building the node this branch dropped.
                    self._add_error(
                        f"unsupported type '{t.name}' in property declaration "
                        f"at {loc.file}:{loc.line}",
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

    def _reject_unknown_param_type(self, param, where: str, loc) -> None:
        # N-325: a parameter whose type is a name that is not a Rúnar type.
        # "unknown" is the missing-annotation case, diagnosed by the parser;
        # StatefulContext is the explicit context parameter of the Zig/Go/Move
        # stateful surfaces, dropped by ANF lowering.
        t = param.type
        if isinstance(t, CustomType) and t.name not in ("unknown", "StatefulContext"):
            self._add_error(
                f"type '{t.name}' of parameter '{param.name}' in {where} "
                "is not a Rúnar type",
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
            self._reject_unknown_param_type(param, "constructor", ctor.source_location)

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
            # R-149: a class-level complaint, so anchor it at the constructor's
            # declaration rather than letting it fall back to wherever
            # validation happened to be — which would be the constructor's LAST
            # statement, a line that has nothing to do with the problem.
            # `ContractNode` carries no location of its own in this tier.
            self._add_error(
                f"Contract '{self.contract.name}' has no public methods "
                "— no spending entry points; add 'public' to at least one method",
                self.contract.constructor.source_location,
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
            self._reject_unknown_param_type(
                param, f"method '{method.name}'", method.source_location
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
        # asserts the spending tx is non-final (extractSequence !== 0xffffffff).
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

        # R-149: walk one statement at a time so `current_stmt_loc` is the
        # statement the asm() call sits in. This pass runs BEFORE the statement
        # loop in `_validate_method`, so without this the fallback would be
        # stale (the previous method's last statement) or absent entirely.
        for stmt in method.body:
            loc = getattr(stmt, "source_location", None)
            if loc is not None and getattr(loc, "line", 0):
                self.current_stmt_loc = loc
            _walk_expressions_in_body([stmt], visitor)

    # -------------------------------------------------------------------
    # Statement validation
    # -------------------------------------------------------------------

    def _validate_statement(self, stmt: Statement) -> None:
        # R-149: publish where we are, so a diagnostic raised from inside
        # expression validation still reports a line.
        loc = getattr(stmt, "source_location", None)
        if loc is not None and getattr(loc, "line", 0):
            self.current_stmt_loc = loc
        if isinstance(stmt, VariableDeclStmt):
            if isinstance(stmt.type, FixedArrayType):
                self._add_error(
                    f"Local variable '{stmt.name}' cannot be a FixedArray. "
                    "Arrays are only allowed as contract properties.",
                    loc=stmt.source_location,
                )
            self._validate_expression(stmt.init)
        elif isinstance(stmt, AssignmentStmt):
            # F-013: only a FixedArray property is index-writable. Any other
            # index target (a ByteString property, a local, a parameter) is
            # left alone by expand_fixed_arrays and anf_lower lowers it as a
            # READ, dropping the write -- a deployable script whose state
            # never changes. Reject it here with a location instead.
            if isinstance(stmt.target, IndexAccessExpr):
                root = stmt.target
                while isinstance(root, IndexAccessExpr):
                    root = root.object
                fixed_array_props = {
                    p.name for p in self.contract.properties
                    if isinstance(p.type, FixedArrayType)
                }
                if not (
                    isinstance(root, PropertyAccessExpr)
                    and root.property in fixed_array_props
                ):
                    self._add_error(
                        "index assignment is only supported on FixedArray "
                        "contract properties; the target here is not a "
                        "FixedArray property",
                        loc=stmt.source_location,
                    )
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
                self._add_error(_for_loop_bound_diagnostic(stmt.condition.right))

        # R-148: the START, checked the same way and for the same reason. Until
        # now only the BOUND was validated here; a non-literal start reached
        # ``anf_lower._extract_loop_shape``, which raises a bare ``ValueError``
        # with no location. That escapes ``compile_from_source`` -- the tier's
        # public API, which every other failure exits through as a
        # ``CompilationError`` carrying located diagnostics -- so a caller
        # written against that contract got an exception type it does not catch.
        # Only the CLI was unaffected, because it wraps the call in a generic
        # ``except Exception``.
        #
        # The message is the other six tiers' sentence, word for word; the raise
        # in ``_extract_loop_shape`` stays as the backstop for ``--ir`` inputs,
        # which run no frontend at all.
        if stmt.init is not None and not _is_compile_time_constant(stmt.init.init):
            self._add_error(LOOP_START_DIAGNOSTIC, stmt.source_location)

        self._validate_for_condition_tests_iterator(stmt)

        if stmt.init is not None:
            self._validate_expression(stmt.init.init)
        self._validate_for_update(stmt)
        self._validate_no_output_intrinsic_in_loop(stmt)
        for s in stmt.body:
            self._validate_statement(s)

    def _validate_for_condition_tests_iterator(self, stmt: ForStmt) -> None:
        """Reject a for-loop whose condition does not test the iterator (W4).

        The bound check above reads only ``condition.right``. Nothing required
        ``condition.left`` to BE the iterator, and ``_extract_loop_shape``
        ignores left entirely: it computes ``count = bound - start``. So::

            for (let i = 0n; i + 1n < 2n; i++) { ... }

        runs ONCE in the source language and TWICE in the emitted script
        (count = 2 - 0). The extra lap executes the ``else`` arm the source can
        never reach. Measured on ``@bsv/sdk`` ``Spend.validate()`` with a vault
        whose signature check sits in the first lap and whose second lap sets
        ``authorized = true``: the phantom-lap loop ACCEPTED an empty signature,
        while the semantically identical ``i < 1n`` rejected it.

        Refusal rather than lowering: evaluating a general condition per
        iteration means unrolling against a real interpreter at ANF time, a
        language extension with no golden behind it. The diagnostic text is
        shared verbatim with the other six tiers.
        """
        iter_name = stmt.init.name if stmt.init is not None else ""
        cond = stmt.condition
        if (
            isinstance(cond, BinaryExpr)
            and isinstance(cond.left, Identifier)
            and cond.left.name == iter_name
        ):
            return

        self._add_error(
            f"For loop condition must compare the loop variable '{iter_name}' to a "
            f"compile-time constant (`{iter_name} < 10n`). The unrolled loop binds the "
            "iterator as `start + k*step` and takes its trip count from the bound alone, "
            "so a condition whose left-hand side is anything else -- a computed "
            "expression, or a different variable -- is not the condition the loop "
            "actually evaluates",
            stmt.source_location,
        )

    # R-127 -- output intrinsics inside a loop body
    # ------------------------------------------------------------------

    #: The three intrinsics that register an output ref.
    _OUTPUT_INTRINSIC_NAMES = frozenset({"addOutput", "addRawOutput", "addDataOutput"})

    @staticmethod
    def _loop_output_intrinsic_msg(intrinsic: str, via: str | None) -> str:
        """Build the R-127 rejection.

        Shared verbatim with the other six tiers.
        """
        return loop_output_intrinsic_msg(intrinsic, via)

    def _validate_no_output_intrinsic_in_loop(self, stmt: ForStmt) -> None:
        """Reject an output intrinsic called inside a loop body (R-127).

        ``anf_lower`` lowers a loop body into its own sub-context, which starts
        with a fresh empty add-output ref list, and nothing propagates that list
        back to the method context -- unlike the if-statement lowering, which
        concatenates each arm's outputs into one ref precisely so the parent
        sees them. The continuation hash is then built from whatever
        ``addOutput`` calls sit at the method's TOP level while the loop's
        outputs are still emitted into the transaction. Measured on a
        two-iteration loop before this check existed:

        * loop only -- ts/go/rust/python blew up inside stack lowering ("method
          parameter '_newAmount' is not on the stack at a post-consumption
          reference"), zig/ruby emitted a covenant over the WRONG output set,
          java emitted none.
        * loop + one top-level call -- compiled clean in every tier, and the ANF
          continuation hashed exactly ONE leaf while three outputs were built.

        A continuation committing to fewer outputs than the transaction creates
        is spendable only by a hand-crafted transaction, is rejected by every
        shipped SDK, and the successor it produces is permanently unspendable
        (CL-BUG-164).

        Refusal rather than lowering: propagating the refs cannot work by name,
        because the loop is unrolled at stack-lowering time and one body binding
        name denotes N physical slots. A correct lowering means unrolling at ANF
        time, a language feature with no golden behind it; refusing removes
        nothing that works today.
        """
        found = self._find_output_intrinsic(stmt.body, set())
        if found is None:
            return
        intrinsic, via, loc = found
        self._add_error(
            self._loop_output_intrinsic_msg(intrinsic, via),
            loc or stmt.source_location,
        )

    @staticmethod
    def _callee_property(expr) -> str | None:
        """The property/function name a call names, if any."""
        if not isinstance(expr, CallExpr):
            return None
        callee = expr.callee
        if isinstance(callee, PropertyAccessExpr):
            return callee.property
        if isinstance(callee, MemberExpr):
            return callee.property
        if isinstance(callee, Identifier):
            return callee.name
        return None

    def _private_method_named(self, name: str) -> MethodNode | None:
        for m in self.contract.methods:
            if m.name == name and m.visibility == "private":
                return m
        return None

    def _find_output_intrinsic(self, stmts, seen: set[str]):
        """First output intrinsic reachable from ``stmts``.

        Follows calls to private methods: a public method that delegates
        ``addOutput`` to a private helper has that helper INLINED at ANF time,
        so a helper called in a loop lands its outputs in the loop's
        sub-context exactly as a direct call would.
        """
        for stmt in stmts:
            found = self._find_output_intrinsic_in_statement(stmt, seen)
            if found is not None:
                return found
        return None

    def _find_output_intrinsic_in_statement(self, stmt, seen: set[str]):
        if isinstance(stmt, ExpressionStmt):
            return self._find_output_intrinsic_in_expr(stmt.expr, stmt.source_location, seen)
        if isinstance(stmt, VariableDeclStmt):
            return self._find_output_intrinsic_in_expr(stmt.init, stmt.source_location, seen)
        if isinstance(stmt, AssignmentStmt):
            return self._find_output_intrinsic_in_expr(stmt.value, stmt.source_location, seen)
        if isinstance(stmt, ReturnStmt):
            return self._find_output_intrinsic_in_expr(stmt.value, stmt.source_location, seen)
        if isinstance(stmt, IfStmt):
            found = self._find_output_intrinsic_in_expr(
                stmt.condition, stmt.source_location, seen
            )
            if found is not None:
                return found
            return self._find_output_intrinsic(list(stmt.then) + list(stmt.else_), seen)
        if isinstance(stmt, ForStmt):
            if stmt.init is not None:
                found = self._find_output_intrinsic_in_statement(stmt.init, seen)
                if found is not None:
                    return found
            found = self._find_output_intrinsic_in_expr(
                stmt.condition, stmt.source_location, seen
            )
            if found is not None:
                return found
            if stmt.update is not None:
                found = self._find_output_intrinsic_in_statement(stmt.update, seen)
                if found is not None:
                    return found
            return self._find_output_intrinsic(stmt.body, seen)
        return None

    def _find_output_intrinsic_in_expr(self, expr, loc, seen: set[str]):
        if expr is None:
            return None
        name = self._callee_property(expr)
        if name is not None:
            if name in self._OUTPUT_INTRINSIC_NAMES:
                return (name, None, loc)
            helper = self._private_method_named(name)
            if helper is not None and name not in seen:
                seen.add(name)
                nested = self._find_output_intrinsic(helper.body, seen)
                if nested is not None:
                    return (nested[0], name, loc)
        for child in _sub_expressions(expr):
            found = self._find_output_intrinsic_in_expr(child, loc, seen)
            if found is not None:
                return found
        return None

    def _validate_no_output_intrinsic_in_ternary_arm(self, expr: TernaryExpr) -> None:
        """Reject an output intrinsic in either arm of a ternary (N-049).

        ``anf_lower._lower_ternary_expr`` lowers each arm into a sub-context
        whose output refs are dropped -- unlike the if-statement lowering, which
        merges each arm's refs into the parent -- so the continuation hash would
        omit the arm's output (EXT-2 TernaryToll: a spend dropping the payout
        was accepted on every tier). Private helpers are followed because they
        are inlined into the arm. A ternary that only selects values is
        untouched.
        """
        for arm in (expr.consequent, expr.alternate):
            found = self._find_output_intrinsic_in_expr(arm, None, set())
            if found is not None:
                intrinsic, via, _ = found
                self._add_error(ternary_output_intrinsic_msg(intrinsic, via))
                return

    def _validate_for_update(self, stmt: ForStmt) -> None:
        """Reject any for-loop update clause the loop model cannot represent
        (R-065).

        The ANF ``loop`` node carries exactly ``{count, iterVar, start, step,
        body}`` and synthesizes the iterator on unrolled iteration k as
        ``start + k*step``. There is no slot for an arbitrary update statement,
        and ``_extract_loop_step`` only ever understood a unit step —
        everything else was silently coerced to ``+1`` (or ``-1`` from the
        comparison direction) and the clause itself was discarded. That made
        three distinct failures indistinguishable from a correct compile:

        * ``for (let i = 0n; i < 3n; undefinedFn())`` produced byte-identical
          output. A nonexistent function name raised nothing.
        * ``for (let i = 0n; i < 3n; this.count++)`` dropped the state write.
        * ``while (i < 5) : (i += 2)`` unrolled 5 times over i = 0..4 instead
          of 3 times over i = 0,2,4.

        ``spec/grammar.md``'s ForStatement production admits only
        ``Identifier ('++' | '--')``, and its Statement Restrictions say "The
        loop variable MUST use simple increment (``++``) or decrement
        (``--``)". So rejecting is the fix rather than lowering: appending the
        update's lowering to the loop body would re-emit ``i++`` as a dead
        binding on every loop that already compiles correctly, moving bytes
        across the whole corpus to express nothing.

        The accepted set is every shape the nine frontends actually
        synthesize: ``i++``/``i--``/``++i``/``--i``; the assignment spelling
        ``i = i + 1`` / ``i = i - 1`` / ``i = 1 + i`` that ``i += 1`` becomes in
        the Solidity, Zig and Java parsers; and the effect-free no-op sentinel
        (a literal or a bare identifier) that the while-shaped parsers
        synthesize when the source has no continue expression at all -- but
        only on a loop whose condition does not test its declared iterator
        (already refused by the condition rule). On a real iterator a no-op
        update never advances it: ``var i = 3; while (i < 5) : (i)`` compiled
        two laps over i = 3, 4 (N-116).

        The advanced variable must be the declared iterator or the identifier
        the condition tests. Both are needed: the Zig parser only folds
        ``var i = 0; while (i < N) : (i += 1)`` into a single ForStmt when the
        declaration is the immediately preceding statement, so an unfolded loop
        carries a placeholder init while the update advances the real ``i``
        named in the condition.
        """
        allowed: list[str] = []
        if stmt.init is not None:
            allowed.append(stmt.init.name)
        if isinstance(stmt.condition, BinaryExpr) and isinstance(
            stmt.condition.left, Identifier
        ):
            allowed.append(stmt.condition.left.name)

        # N-116: the no-op sentinel is tolerated only on a loop the condition
        # rule already refuses (placeholder iterator). On a real iterator it
        # never advances, yet the unrolled loop would still step by one.
        cond_tests_iter = (
            stmt.init is not None
            and isinstance(stmt.condition, BinaryExpr)
            and isinstance(stmt.condition.left, Identifier)
            and stmt.condition.left.name == stmt.init.name
        )

        if _is_representable_for_update(allowed, stmt.update, not cond_tests_iter):
            return

        self._add_error(LOOP_UPDATE_DIAGNOSTIC, stmt.source_location)

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
            self._validate_no_output_intrinsic_in_ternary_arm(expr)
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
        elif isinstance(expr, ArrayLiteralExpr):
            for el in expr.elements:
                self._validate_expression(el)
        elif isinstance(expr, ByteStringLiteral):
            val = expr.value
            if len(val) > 0:
                # N-436: TS counts UTF-16 code units; len(val) counts code points.
                units = len(val.encode("utf-16-le", "surrogatepass")) // 2
                if units % 2 != 0:
                    self._add_error(
                        f"ByteString literal '{val}' has odd length ({units}) "
                        f"\u2014 hex strings must have an even number of characters",
                        expr.source_location,
                    )
                elif not re.fullmatch(r'[0-9a-fA-F]*', val):
                    self._add_error(
                        f"ByteString literal '{val}' contains non-hex characters "
                        f"\u2014 only 0-9, a-f, A-F are allowed",
                        expr.source_location,
                    )

    # -------------------------------------------------------------------
    # Recursion detection
    # -------------------------------------------------------------------

    def check_no_recursion(self) -> bool:
        """Report recursion and the N-180 call depth; True iff MAX_CALL_DEPTH was exceeded."""
        call_graph: dict[str, set[str]] = {}
        method_names: set[str] = set()

        for method in self.contract.methods:
            method_names.add(method.name)
            calls: set[str] = set()
            _collect_method_calls(method.body, calls, bare=True)
            call_graph[method.name] = calls

        # N-180: one iterative pass answers, for every method, whether it
        # reaches a cycle and how deep its call chain is, in O(methods + calls).
        # The old per-method DFS restarted for each method (quadratic on a
        # chain) and recursed once per link.
        reaches_cycle, depth = _analyze_call_graph(self.contract.methods, call_graph, method_names)

        for method in self.contract.methods:
            if reaches_cycle[method.name]:
                self._add_error(
                    f"recursion detected: method '{method.name}' calls itself "
                    f"directly or indirectly",
                    loc=method.source_location,
                )

        # N-180: private methods are inlined at every call site, so the call
        # depth is the inlining depth. Report the first method (declaration
        # order) past it.
        for method in self.contract.methods:
            if not reaches_cycle[method.name] and depth[method.name] > MAX_CALL_DEPTH:
                self._add_error(call_depth_message(method.name), loc=method.source_location)
                return True
        return False


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


# Shared verbatim with the other six tiers. Per-tier diagnostic drift on the
# same rejection is a recurring defect in this repo, so the string is mirrored,
# character for character, in
# packages/runar-compiler/src/passes/02-validate.ts,
# compilers/go/frontend/validator.go, compilers/rust/src/frontend/validator.rs,
# compilers/zig/src/frontend/validator.zig,
# compilers/ruby/lib/frontend/validator.rb and
# compilers/java/src/main/java/runar/compiler/passes/Validate.java.
LOOP_UPDATE_DIAGNOSTIC = (
    "For loop update must advance the loop variable by one (`i++`, `i--`, "
    "`i = i + 1n`, `i = i - 1n`). The unrolled loop carries only a start value and a "
    "unit step, so any other update clause -- a function call, a state mutation, or a "
    "non-unit step such as `i += 2` -- cannot be represented and would be discarded"
)


def _is_allowed_loop_var(allowed: list[str], expr: Expression | None) -> bool:
    """True when ``expr`` names one of the identifiers the update may advance.

    A property access, an index access or anything else is never accepted:
    those are the side effects that used to be dropped.
    """
    return isinstance(expr, Identifier) and expr.name in allowed


def _is_literal_one(expr: Expression | None) -> bool:
    return isinstance(expr, BigIntLiteral) and expr.value == 1


def _is_representable_for_update(
    allowed: list[str], update: Statement | None, accept_no_op_sentinel: bool
) -> bool:
    if isinstance(update, ExpressionStmt):
        e = update.expr
        if isinstance(e, (IncrementExpr, DecrementExpr)):
            return _is_allowed_loop_var(allowed, e.operand)
        # The no-op sentinel a while-shaped frontend synthesizes when the source
        # carries no continue expression: zig's ``while (c) {}``, move's
        # ``while (c) {}``, go's ``for c {}``. Reading a literal or a bare
        # identifier has no effect, so discarding it loses nothing -- on a loop
        # the condition rule already refuses (N-116).
        return accept_no_op_sentinel and isinstance(
            e, (BigIntLiteral, BoolLiteral, Identifier)
        )

    if isinstance(update, AssignmentStmt):
        # ``i += 1`` / ``i -= 1`` arrive here as ``i = i + 1`` / ``i = i - 1``.
        if not _is_allowed_loop_var(allowed, update.target):
            return False
        v = update.value
        if not isinstance(v, BinaryExpr):
            return False
        if v.op == "+":
            return (
                _is_allowed_loop_var(allowed, v.left) and _is_literal_one(v.right)
            ) or (_is_literal_one(v.left) and _is_allowed_loop_var(allowed, v.right))
        if v.op == "-":
            return _is_allowed_loop_var(allowed, v.left) and _is_literal_one(v.right)
        return False

    return False


def _for_loop_bound_diagnostic(bound: Expression | None) -> str:
    # The reference (TypeScript) tier's sentence for a for-loop bound that is not
    # an integer literal. The reference's validator trusts a bare identifier (or
    # boolean literal, or a negation of one) as "could be a const" and lets ANF
    # lowering refuse it with the "Cannot determine" sentence; every other
    # non-literal shape (``this.x``, an expression) is refused by its validator
    # with the "must be a compile-time constant" sentence. Both sentences are
    # shared verbatim by all seven tiers (N-026).
    while isinstance(bound, UnaryExpr) and bound.op == "-":
        bound = bound.operand
    if isinstance(bound, (Identifier, BoolLiteral)):
        return (
            "Cannot determine loop bound at compile time. "
            "For-loop bounds must be integer literals."
        )
    return "For loop bound must be a compile-time constant (literal or const variable)"


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
    """True when *expr* is a comparison on ``extractSequence(...)`` that
    genuinely EXCLUDES the finality sentinel ``0xffffffff``, reading the field
    as the unsigned 32-bit wire value it is (see ``_emit_unsigned_bin2num`` in
    ``codegen/stack.py``).

    Accepted::

        extractSequence(pre) !== 0xffffffff   # and the reversed spelling
        extractSequence(pre) <  N, 0 < N <= 0xffffffff   # reversed: N > ...
        extractSequence(pre) <= N, N <  0xffffffff   # reversed: N >= ...

    Deliberately NOT accepted: ``<= 0xffffffff`` and ``>= 0xffffffff``.
    nSequence cannot exceed 0xffffffff, so those are true for every transaction
    including the final one -- a tautology that used to silence this warning on
    a contract with no guard at all (W1 / FinalCountdown).

    Also NOT accepted: ``extractSequence(pre) < 0``. Unsigned nSequence is
    never negative, so that comparison is vacuous.
    """
    if not isinstance(expr, BinaryExpr):
        return False

    def is_final_sentinel(e: Expression) -> bool:
        return isinstance(e, BigIntLiteral) and e.value == _SEQUENCE_FINAL

    def strict_bound_ok(e: Expression) -> bool:
        return isinstance(e, BigIntLiteral) and e.value > 0 and e.value <= _SEQUENCE_FINAL

    def non_strict_bound_ok(e: Expression) -> bool:
        return isinstance(e, BigIntLiteral) and e.value < _SEQUENCE_FINAL

    if expr.op == "!==":
        return (
            (_is_call_to_named(expr.left, "extractSequence") and is_final_sentinel(expr.right))
            or (_is_call_to_named(expr.right, "extractSequence") and is_final_sentinel(expr.left))
        )
    if expr.op == "<":
        return _is_call_to_named(expr.left, "extractSequence") and strict_bound_ok(expr.right)
    if expr.op == "<=":
        return _is_call_to_named(expr.left, "extractSequence") and non_strict_bound_ok(expr.right)
    if expr.op == ">":
        return _is_call_to_named(expr.right, "extractSequence") and strict_bound_ok(expr.left)
    if expr.op == ">=":
        return _is_call_to_named(expr.right, "extractSequence") and non_strict_bound_ok(expr.left)
    return False


def _assertion_implies_sequence_guard(expr: Expression) -> bool:
    """True when asserting *expr* logically implies a sequence-finality guard.

    A matching comparison nested under ``!`` (or ``||``) does not count:
    ``assert(not (extract_sequence !== 0xffffffff))`` requires a FINAL sequence.
    ``&&`` implies each conjunct.
    """
    if _is_sequence_finality_guard(expr):
        return True
    if isinstance(expr, BinaryExpr) and expr.op == "&&":
        return _assertion_implies_sequence_guard(expr.left) or _assertion_implies_sequence_guard(
            expr.right
        )
    return False


def _warn_locktime_without_sequence_guard(method, contract, warnings: list[Diagnostic]) -> None:
    """#131: warn when *method* (transitively, through the private-helper call
    graph) reads the tx locktime but never asserts the tx is non-final.

    A locktime gate is not consensus-enforced unless ``extractSequence !==
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
        if _is_assert_call(expr) and isinstance(expr, CallExpr):
            for arg in expr.args:
                if _assertion_implies_sequence_guard(arg):
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
            f"extractSequence is not 0xffffffff; a locktime gate is not consensus-enforced "
            f"unless the tx is non-final — add "
            f"assert(extractSequence(this.txPreimage) !== 0xffffffffn)",
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
    # `toByteString('<hex>')` IS the ByteStringLiteral production -- see
    # spec/grammar.md section 11:
    #
    #     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
    #
    # 0e192af6 folded it in ANF lowering, which covers every EXPRESSION
    # position. This check runs on the AST, BEFORE ANF lowering, so an
    # initializer still arrives here as a call node and was refused -- in the
    # one position the `.runar.rs` surface needs it, since the Rust DSL writes
    # initializers as assignments inside `init()` that the parser LIFTS into
    # `PropertyNode.initializer`, and a bare `"1976a914"` is a `&str` that
    # cannot be assigned to a `ByteString` (`Vec<u8>`).
    #
    # Accepting it here is only half the job: `_extract_literal_value` in
    # anf_lower.py must UNWRAP the same shape, or the property validates and
    # then loses its default entirely.
    return is_to_byte_string_literal(expr)


def is_to_byte_string_literal(expr: Expression | None) -> bool:
    """Whether the expression is the ``toByteString(<literal>)`` production.

    Literal argument ONLY. ``toByteString(x)`` for a non-literal ``x`` is not
    this production and stays a non-literal initializer. Peer of the TS helper
    of the same name in ``02-validate.ts``.
    """
    return (
        isinstance(expr, CallExpr)
        and isinstance(expr.callee, Identifier)
        and expr.callee.name == "toByteString"
        and len(expr.args) == 1
        and isinstance(expr.args[0], ByteStringLiteral)
    )


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
        if stmt.init is not None:
            _walk_expressions_in_stmt(stmt.init, visitor)
        _walk_expr(stmt.condition, visitor)
        if stmt.update is not None:
            _walk_expressions_in_stmt(stmt.update, visitor)
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
    elif isinstance(expr, ArrayLiteralExpr):
        for el in expr.elements:
            _walk_expr(el, visitor)


# ---------------------------------------------------------------------------
# F-286: verifyRabinSig's public key must not be chosen by the spender
# ---------------------------------------------------------------------------

#: The one diagnostic every tier emits for F-286 (user decision R78).
RABIN_PUBKEY_PROVENANCE_MESSAGE = (
    "verifyRabinSig public key (4th argument) must be a contract property or a literal; "
    "a spender-supplied Rabin modulus lets anyone forge a signature"
)


def rabin_key_write_message(prop: str) -> str:
    """N-205 (a): the diagnostic every tier emits when a mutable key property is
    written, outside the constructor, with a value the F-286 rule does not trust."""
    return (
        f"verifyRabinSig public key property '{prop}' may only be assigned a contract property or a literal "
        "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
    )


class _RabinScope:
    """Per-method view: params, every value bound to each local, ++/-- names."""

    def __init__(self, method: MethodNode) -> None:
        self.method = method
        self.params: list[str] = [p.name for p in method.params]
        self.bindings: dict[str, list[Expression]] = {}
        self.mutated: set[str] = set()
        # N-205: names declared as locals (a bare property write also lands in
        # ``bindings``).
        self.declared: set[str] = set()
        self._visit(method.body)

    def _bind(self, name: str, value: Expression | None) -> None:
        # A missing value cannot be shown trusted: record it as untrusted.
        self.bindings.setdefault(name, []).append(value)  # type: ignore[arg-type]

    def _visit_expr(self, expr: Expression | None) -> None:
        def visitor(e: Expression) -> None:
            if isinstance(e, (IncrementExpr, DecrementExpr)) and isinstance(e.operand, Identifier):
                self.mutated.add(e.operand.name)
        _walk_expr(expr, visitor)

    def _visit(self, stmts: list[Statement]) -> None:
        for stmt in stmts:
            if stmt is None:
                continue
            if isinstance(stmt, VariableDeclStmt):
                self.declared.add(stmt.name)
                self._bind(stmt.name, stmt.init)
                self._visit_expr(stmt.init)
            elif isinstance(stmt, AssignmentStmt):
                if isinstance(stmt.target, Identifier):
                    self._bind(stmt.target.name, stmt.value)
                self._visit_expr(stmt.target)
                self._visit_expr(stmt.value)
            elif isinstance(stmt, ExpressionStmt):
                self._visit_expr(stmt.expr)
            elif isinstance(stmt, IfStmt):
                self._visit_expr(stmt.condition)
                self._visit(stmt.then)
                self._visit(stmt.else_)
            elif isinstance(stmt, ForStmt):
                self._visit([stmt.init] if stmt.init is not None else [])
                self._visit_expr(stmt.condition)
                self._visit([stmt.update] if stmt.update is not None else [])
                self._visit(stmt.body)
            elif isinstance(stmt, ReturnStmt):
                self._visit_expr(stmt.value)


def _walk_expressions_in_body_deep(stmts: list[Statement], visitor) -> None:
    """Like ``_walk_expressions_in_body``, but also visits every ``for`` loop's
    init and update, at any nesting depth."""
    for stmt in stmts:
        if stmt is None:
            continue
        if isinstance(stmt, IfStmt):
            _walk_expr(stmt.condition, visitor)
            _walk_expressions_in_body_deep(stmt.then, visitor)
            _walk_expressions_in_body_deep(stmt.else_, visitor)
        elif isinstance(stmt, ForStmt):
            _walk_expressions_in_body_deep([stmt.init] if stmt.init is not None else [], visitor)
            _walk_expr(stmt.condition, visitor)
            _walk_expressions_in_body_deep([stmt.update] if stmt.update is not None else [], visitor)
            _walk_expressions_in_body_deep(stmt.body, visitor)
        else:
            _walk_expressions_in_stmt(stmt, visitor)


def _check_rabin_pubkey_provenance(ctx: "_ValidationContext") -> None:
    """F-286: the 4th argument of ``verifyRabinSig`` must be fixed by the deployer.

    Port of ``checkRabinPubKeyProvenance`` (TS 02-validate.ts). Trusted: a
    property read (``this.x`` / member on ``this``, or a bare identifier naming
    a property no param/local shadows); a bigint literal; a local whose init AND
    every assignment are trusted (never if ++/--); a PRIVATE method's parameter
    that every call site (at least one) binds to a trusted value -- least fixed
    point. Public and constructor parameters, arithmetic, ternaries and calls
    are refused.
    """
    contract = ctx.contract
    property_names = {p.name for p in contract.properties}
    private_methods: dict[str, MethodNode] = {
        m.name: m for m in contract.methods if m.visibility == "private"
    }
    all_methods = [contract.constructor, *contract.methods]
    scopes = [_RabinScope(m) for m in all_methods]
    trusted_params: dict[str, set[int]] = {name: set() for name in private_methods}

    def is_trusted(expr: Expression | None, scope: _RabinScope, visiting: set[str]) -> bool:
        if isinstance(expr, PropertyAccessExpr):
            return True
        if isinstance(expr, MemberExpr):
            return isinstance(expr.object, Identifier) and expr.object.name == "this"
        if isinstance(expr, BigIntLiteral):
            return True
        if isinstance(expr, Identifier):
            name = expr.name
            is_param = name in scope.params
            local_values = scope.bindings.get(name)
            if not is_param and local_values is None:
                return name in property_names
            if name in scope.mutated:
                return False
            if is_param:
                method = scope.method
                if method.visibility != "private" or method is contract.constructor:
                    return False
                idx = scope.params.index(name)
                if idx not in trusted_params.get(method.name, set()):
                    return False
            if local_values is not None:
                if name in visiting:
                    return False
                visiting.add(name)
                ok = all(is_trusted(v, scope, visiting) for v in local_values)
                visiting.discard(name)
                if not ok:
                    return False
            return True
        return False

    def private_callee(expr: Expression) -> str | None:
        if not isinstance(expr, CallExpr):
            return None
        c = expr.callee
        name: str | None = None
        if isinstance(c, PropertyAccessExpr):
            name = c.property
        elif isinstance(c, MemberExpr) and isinstance(c.object, Identifier) and c.object.name == "this":
            name = c.property
        return name if name is not None and name in private_methods else None

    call_sites: dict[str, list[tuple[list[Expression], _RabinScope]]] = {
        name: [] for name in private_methods
    }
    for scope in scopes:
        def collect(e: Expression, scope: _RabinScope = scope) -> None:
            callee = private_callee(e)
            if callee is not None:
                call_sites[callee].append((e.args, scope))
        _walk_expressions_in_body_deep(scope.method.body, collect)

    # Least fixed point: monotone, so it terminates.
    changed = True
    while changed:
        changed = False
        for name, method in private_methods.items():
            sites = call_sites[name]
            if not sites:
                continue
            trusted = trusted_params[name]
            for i in range(len(method.params)):
                if i in trusted:
                    continue
                if all(i < len(args) and is_trusted(args[i], sc, set()) for args, sc in sites):
                    trusted.add(i)
                    changed = True

    for scope in scopes:
        def check(e: Expression, scope: _RabinScope = scope) -> None:
            if (
                isinstance(e, CallExpr)
                and isinstance(e.callee, Identifier)
                and e.callee.name == "verifyRabinSig"
                and len(e.args) >= 4
                and not is_trusted(e.args[3], scope, set())
            ):
                ctx._add_error(RABIN_PUBKEY_PROVENANCE_MESSAGE, scope.method.source_location)
        _walk_expressions_in_body_deep(scope.method.body, check)

    # N-205 (a): a MUTABLE property used as the key is state the previous spend
    # chose, so outside the constructor it may only be written with a value
    # ``is_trusted`` accepts. KEY properties: those whose value reaches a 4th
    # argument, closed under "is written into a key property".
    def sources_of(expr: Expression | None, scope: _RabinScope, out: set[str], visiting: set[str]) -> None:
        if isinstance(expr, PropertyAccessExpr):
            out.add(expr.property)
            return
        if isinstance(expr, MemberExpr):
            if isinstance(expr.object, Identifier) and expr.object.name == "this":
                out.add(expr.property)
            return
        if not isinstance(expr, Identifier):
            return
        name = expr.name
        is_param = name in scope.params
        local_values = scope.bindings.get(name)
        if not is_param and local_values is None:
            if name in property_names:
                out.add(name)
            return
        key = f"{scope.method.name}\0{name}"
        if key in visiting:
            return
        visiting.add(key)
        for v in local_values or []:
            sources_of(v, scope, out, visiting)
        method = scope.method
        if is_param and method.visibility == "private" and method is not contract.constructor:
            idx = scope.params.index(name)
            for args, site_scope in call_sites.get(method.name, []):
                if idx < len(args):
                    sources_of(args[idx], site_scope, out, visiting)

    key_props: set[str] = set()
    for scope in scopes:
        def collect_key(e: Expression, scope: _RabinScope = scope) -> None:
            if (
                isinstance(e, CallExpr)
                and isinstance(e.callee, Identifier)
                and e.callee.name == "verifyRabinSig"
                and len(e.args) >= 4
            ):
                sources_of(e.args[3], scope, key_props, set())
        _walk_expressions_in_body_deep(scope.method.body, collect_key)

    # Every write to a property outside the constructor: (prop, value, scope,
    # loc). ``value`` is None for ++/--, which no value makes trusted.
    mutable_props = [p.name for p in contract.properties if not p.readonly]
    writes: list[tuple[str, Expression | None, _RabinScope, object]] = []

    def written_prop(target: Expression | None, scope: _RabinScope) -> str | None:
        if isinstance(target, PropertyAccessExpr):
            return target.property
        if isinstance(target, MemberExpr) and isinstance(target.object, Identifier) and target.object.name == "this":
            return target.property
        if (
            isinstance(target, Identifier)
            and target.name in property_names
            and target.name not in scope.params
            and target.name not in scope.declared
        ):
            return target.name
        return None

    def collect_assignments(stmts: list[Statement], scope: _RabinScope) -> None:
        for stmt in stmts:
            if stmt is None:
                continue
            if isinstance(stmt, AssignmentStmt):
                prop = written_prop(stmt.target, scope)
                if prop is not None:
                    writes.append((prop, stmt.value, scope, stmt.source_location))
            elif isinstance(stmt, IfStmt):
                collect_assignments(stmt.then, scope)
                collect_assignments(stmt.else_, scope)
            elif isinstance(stmt, ForStmt):
                collect_assignments([s for s in (stmt.init, stmt.update) if s is not None], scope)
                collect_assignments(stmt.body, scope)

    def output_callee(expr: Expression) -> str | None:
        if not isinstance(expr, CallExpr):
            return None
        c = expr.callee
        if isinstance(c, (PropertyAccessExpr, MemberExpr)):
            return c.property
        return None

    for scope in scopes:
        if scope.method is contract.constructor:
            continue
        collect_assignments(scope.method.body, scope)

        def collect_writes(e: Expression, scope: _RabinScope = scope) -> None:
            loc = scope.method.source_location
            if isinstance(e, (IncrementExpr, DecrementExpr)):
                prop = written_prop(e.operand, scope)
                if prop is not None:
                    writes.append((prop, None, scope, loc))
            elif output_callee(e) == "addOutput":
                # addOutput(satoshis, ...values): values are positional over
                # the mutable properties in declaration order. A single
                # array-literal value list (the Zig tuple form) is unpacked,
                # as ANF lowering's _flatten_add_output_args does.
                values = e.args[1].elements if len(e.args) == 2 and isinstance(e.args[1], ArrayLiteralExpr) else e.args[1:]
                for i, value in enumerate(values):
                    if i < len(mutable_props):
                        writes.append((mutable_props[i], value, scope, loc))
        _walk_expressions_in_body_deep(scope.method.body, collect_writes)

    grew = True
    while grew:
        before = len(key_props)
        for prop, value, sc, _loc in writes:
            if prop in key_props and value is not None and is_trusted(value, sc, set()):
                sources_of(value, sc, key_props, set())
        grew = len(key_props) != before

    mutable = set(mutable_props)
    for prop, value, sc, loc in writes:
        if prop not in key_props or prop not in mutable:
            continue
        if value is not None and is_trusted(value, sc, set()):
            continue
        ctx._add_error(rabin_key_write_message(prop), loc)


# ---------------------------------------------------------------------------
# Recursion detection helpers
# ---------------------------------------------------------------------------

def _collect_method_calls(stmts: list[Statement], calls: set[str], bare: bool = False) -> None:
    for stmt in stmts:
        _collect_method_calls_in_stmt(stmt, calls, bare)


def _collect_method_calls_in_stmt(stmt: Statement, calls: set[str], bare: bool = False) -> None:
    if isinstance(stmt, ExpressionStmt):
        _collect_method_calls_in_expr(stmt.expr, calls, bare)
    elif isinstance(stmt, VariableDeclStmt):
        _collect_method_calls_in_expr(stmt.init, calls, bare)
    elif isinstance(stmt, AssignmentStmt):
        _collect_method_calls_in_expr(stmt.target, calls, bare)
        _collect_method_calls_in_expr(stmt.value, calls, bare)
    elif isinstance(stmt, IfStmt):
        _collect_method_calls_in_expr(stmt.condition, calls, bare)
        _collect_method_calls(stmt.then, calls, bare)
        _collect_method_calls(stmt.else_, calls, bare)
    elif isinstance(stmt, ForStmt):
        if stmt.init is not None:
            _collect_method_calls_in_stmt(stmt.init, calls, bare)
        _collect_method_calls_in_expr(stmt.condition, calls, bare)
        if stmt.update is not None:
            _collect_method_calls_in_stmt(stmt.update, calls, bare)
        _collect_method_calls(stmt.body, calls, bare)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _collect_method_calls_in_expr(stmt.value, calls, bare)


def _collect_method_calls_in_expr(expr: Expression | None, calls: set[str], bare: bool = False) -> None:
    if expr is None:
        return
    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, PropertyAccessExpr):
            calls.add(expr.callee.property)
        if isinstance(expr.callee, MemberExpr):
            if isinstance(expr.callee.object, Identifier) and expr.callee.object.name == "this":
                calls.add(expr.callee.property)
        # N-180: the Solidity, Move and Java surfaces may call a helper as a
        # bare ``m(...)``. Counted only for the recursion / call-depth graph
        # (``bare``), and only names of contract methods count there
        # (_analyze_call_graph filters by method_names), so builtins are
        # unaffected.
        if bare and isinstance(expr.callee, Identifier):
            calls.add(expr.callee.name)
        _collect_method_calls_in_expr(expr.callee, calls, bare)
        for arg in expr.args:
            _collect_method_calls_in_expr(arg, calls, bare)
    elif isinstance(expr, BinaryExpr):
        _collect_method_calls_in_expr(expr.left, calls, bare)
        _collect_method_calls_in_expr(expr.right, calls, bare)
    elif isinstance(expr, UnaryExpr):
        _collect_method_calls_in_expr(expr.operand, calls, bare)
    elif isinstance(expr, MemberExpr):
        _collect_method_calls_in_expr(expr.object, calls, bare)
    elif isinstance(expr, TernaryExpr):
        _collect_method_calls_in_expr(expr.condition, calls, bare)
        _collect_method_calls_in_expr(expr.consequent, calls, bare)
        _collect_method_calls_in_expr(expr.alternate, calls, bare)
    elif isinstance(expr, IndexAccessExpr):
        _collect_method_calls_in_expr(expr.object, calls, bare)
        _collect_method_calls_in_expr(expr.index, calls, bare)
    elif isinstance(expr, IncrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls, bare)
    elif isinstance(expr, DecrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls, bare)
    elif isinstance(expr, ArrayLiteralExpr):
        for el in expr.elements:
            _collect_method_calls_in_expr(el, calls, bare)


def _analyze_call_graph(
    methods: list,
    call_graph: dict[str, set[str]],
    method_names: set[str],
) -> tuple[dict[str, bool], dict[str, int]]:
    """N-180: for every method, whether it reaches a call cycle, and (when it
    does not) its call depth: 0 if it calls no contract method, else 1 + the
    largest call depth among the contract methods it calls. Iterative
    three-colour DFS with memoisation: O(methods + calls), no recursion.
    ``reaches_cycle`` matches what a fresh DFS from each method reports."""
    reaches_cycle: dict[str, bool] = {}
    depth: dict[str, int] = {}
    on_stack: set[str] = set()

    for root in methods:
        if root.name in reaches_cycle:
            continue
        # frame: [name, callees, next, cyc, depth]
        stack: list[list] = [[root.name, list(call_graph.get(root.name, ())), 0, False, 0]]
        on_stack.add(root.name)
        while stack:
            top = stack[-1]
            if top[2] < len(top[1]):
                callee = top[1][top[2]]
                top[2] += 1
                if callee not in method_names:
                    continue
                if callee in on_stack:
                    top[3] = True
                elif callee in reaches_cycle:
                    if reaches_cycle[callee]:
                        top[3] = True
                    else:
                        top[4] = max(top[4], 1 + depth[callee])
                else:
                    on_stack.add(callee)
                    stack.append([callee, list(call_graph.get(callee, ())), 0, False, 0])
                continue
            stack.pop()
            name, _, _, cyc, d = top
            on_stack.discard(name)
            reaches_cycle[name] = cyc
            depth[name] = d
            if stack:
                parent = stack[-1]
                if cyc:
                    parent[3] = True
                else:
                    parent[4] = max(parent[4], 1 + d)
    return reaches_cycle, depth


def _sub_expressions(expr):
    """Direct sub-expressions of ``expr``, for the R-127 intrinsic search.

    An intrinsic can sit inside an argument list or an operand, not only as a
    bare expression statement.
    """
    if isinstance(expr, CallExpr):
        return list(expr.args)
    if isinstance(expr, BinaryExpr):
        return [expr.left, expr.right]
    if isinstance(expr, UnaryExpr):
        return [expr.operand]
    if isinstance(expr, TernaryExpr):
        return [expr.condition, expr.consequent, expr.alternate]
    if isinstance(expr, IndexAccessExpr):
        return [expr.object, expr.index]
    if isinstance(expr, ArrayLiteralExpr):
        return list(expr.elements)
    return []
