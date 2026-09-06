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
    MERGED_LOCAL_TEMP_PREFIX,
    SourceLocation,
    bigint_json_value,
)
from runar_compiler.frontend.side_effect_summary import (
    MethodEffects,
    compute_side_effect_summary,
    continuation_shape_for,
)
from runar_compiler.frontend.sighash_directive import SIGHASH_DEFAULT


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
        parent_class=contract.parent_class,
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
    "P256Point",
    "P384Point",
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
    # P-256 point-returning functions
    "p256Add",
    "p256Mul",
    "p256MulGen",
    "p256Negate",
    "p256EncodeCompressed",
    # P-384 point-returning functions
    "p384Add",
    "p384Mul",
    "p384MulGen",
    "p384Negate",
    "p384EncodeCompressed",
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
            # Expression-form asm<ByteString>({...}) yields a byte value.
            if expr.callee.name == "asm":
                return expr.asm_return_type == "ByteString"
            if expr.callee.name in _BYTE_RETURNING_FUNCTIONS:
                return True
            if len(expr.callee.name) >= 7 and expr.callee.name[:7] == "extract":
                return True
        return False

    return False


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

def _constructor_assigned_properties(contract: ContractNode) -> set[str]:
    """Properties the constructor assigns a constructor PARAMETER to.

    These get their value from the deploy-time argument, so any initializer on
    them is a default the argument overrides -- carrying it into
    ``initial_value`` would bake the default into the artifact and silently
    discard the argument (NEW-001). The property must instead stay in the
    constructor slot list (``initial_value is None``) so the SDK writes the
    argument.

    Deliberately narrow in three ways.

    1. Only a BARE parameter reference counts. ``this.a = 5n`` assigns a
       literal, not an argument, and keeps its initializer.
    2. The property<->parameter mapping must be ONE-TO-ONE. The artifact model
       is positional, so a parameter feeding two properties has no
       representation -- that shape is already undeployable today when written
       without initializers, and belongs to NEW-002.
    3. A property assigned more than once in the constructor is skipped, for
       the same reason.
    """
    ctor = contract.constructor
    if ctor is None:
        return set()
    params = {p.name for p in ctor.params}
    prop_to_params: dict[str, set[str]] = {}
    param_to_props: dict[str, set[str]] = {}

    for stmt in ctor.body:
        if not isinstance(stmt, AssignmentStmt):
            continue
        if not isinstance(stmt.target, PropertyAccessExpr):
            continue
        prop = stmt.target.property
        if not isinstance(stmt.value, Identifier) or stmt.value.name not in params:
            # Not a constructor argument: never strip this property.
            prop_to_params.setdefault(prop, set())
            continue
        param = stmt.value.name
        prop_to_params.setdefault(prop, set()).add(param)
        param_to_props.setdefault(param, set()).add(prop)

    out: set[str] = set()
    for prop, ps in prop_to_params.items():
        if len(ps) != 1:
            continue
        (param,) = ps
        if len(param_to_props[param]) == 1:
            out.add(prop)
    return out


def _lower_properties(contract: ContractNode) -> list[ANFProperty]:
    ctor_assigned = _constructor_assigned_properties(contract)
    result = []
    for prop in contract.properties:
        anf_prop = ANFProperty(
            name=prop.name,
            type=_type_node_to_string(prop.type),
            readonly=prop.readonly,
        )
        if prop.initializer is not None and prop.name not in ctor_assigned:
            anf_prop.initial_value = _extract_literal_value(prop.initializer)
            _check_state_bigint_magnitude(anf_prop)
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


# Magnitude a bigint state field gets: ``num2bin-le8`` is a fixed 8-byte
# little-endian SIGN-MAGNITUDE word, so bytes 0..6 plus the low 7 bits of byte
# 7 carry the magnitude and 0x80 of byte 7 carries the sign.
_STATE_BIGINT_MAGNITUDE_LIMIT = 1 << 63


def _check_state_bigint_magnitude(prop: ANFProperty) -> None:
    """Reject a MUTABLE bigint property initialised beyond the 8-byte state word.

    The state section writes every bigint field with OP_NUM2BIN 8, which cannot
    represent a magnitude of 2**63 or more. Nothing used to check: the compiler
    stamped ``encoding: "num2bin-le8"`` on the field and carried the initializer
    verbatim, the SDK wrote the low 8 bytes of it into the deployed state
    section, and the covenant then rebuilt the continuation with its own
    OP_NUM2BIN 8 -- which produces different bytes -- so hash256(outputs) never
    matched and the UTXO was permanently unspendable. It deployed cleanly, with
    no diagnostic at compile time or deploy time.

    This catches the statically-known half. Values that only exist at call time
    are stopped by the SDK serializer (packages/runar-py/runar/sdk/state.py).

    READONLY properties are deliberately exempt: they are baked into the locking
    script as script-number pushes, never into the state section, and BSV script
    numbers are arbitrary-precision after Genesis.
    """
    if prop.readonly or prop.type not in ("bigint", "int"):
        return
    value = prop.initial_value
    if not isinstance(value, int) or isinstance(value, bool):
        return
    if -_STATE_BIGINT_MAGNITUDE_LIMIT < value < _STATE_BIGINT_MAGNITUDE_LIMIT:
        return
    raise ValueError(
        f"Cannot compile state property '{prop.name}' initialised to {value}: it "
        "does not fit the fixed 8-byte sign-magnitude state word (magnitude must "
        "be < 2^63). Reduce the value, or make the property readonly if it is a "
        "constant rather than state."
    )


def _flatten_add_output_args(args: list[Expression]) -> list[Expression]:
    """Mirror flattenAddOutputArgs in 04-anf-lower.ts: when this.addOutput is
    called as ``this.addOutput(satoshis, .{ v1, v2, ... })`` (the surface
    form Zig / Move tuple syntax produce), unwrap the trailing array
    literal so each element becomes an individual state value.
    """
    if len(args) == 2 and isinstance(args[1], ArrayLiteralExpr):
        return [args[0], *args[1].elements]
    return args


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

    # Single source of truth for "does this method (transitively)
    # mutate state, emit outputs, or use the preimage?" Shared across
    # the lowering pass so every public method's auto-injection sees
    # private-helper effects, not just direct ones.
    side_effects = compute_side_effect_summary(contract)

    # Issue #109: readonly fields carrying a ``/** @embedAlways */`` directive
    # must survive DCE into the locking script. A readonly field no method
    # references lowers to no ``load_prop``, so no constructor slot is emitted
    # and the field's deploy-time bytes vanish. We inject a ``load_prop`` + a
    # ``@ref:`` alias (the exact shape ``const _bind = this.field;`` produces)
    # into the first public method's body — the alias keeps the ``load_prop``
    # alive through dead-binding DCE, and stack lowering threads the pushed
    # value through and cleans it up (OP_NIP) at method end. One slot in the
    # deployed script suffices; every spending branch shares it.
    embed_fields = [p for p in contract.properties if p.readonly and p.embed_always]
    embed_injected = False

    # Lower constructor
    ctor_ctx = _LowerCtx(contract, side_effects)
    for p in contract.constructor.params:
        ctor_ctx.register_param_type(p.name, _type_node_to_string(p.type))
    ctor_ctx.lower_statements(contract.constructor.body)
    result.append(ANFMethod(
        name="constructor",
        params=_lower_params(contract.constructor.params),
        body=ctor_ctx.bindings,
        is_public=False,
    ))

    # Lower each method
    for method in contract.methods:
        method_ctx = _LowerCtx(contract, side_effects)
        # Issue #123: non-default @sighash mode drives the OP_PUSH_TX binding
        # flag for any checkPreimage (auto-injected below, or a manual call) in
        # this method.
        if method.sighash_type is not None and method.sighash_type != SIGHASH_DEFAULT:
            method_ctx.sighash_flag = method.sighash_type
        for p in method.params:
            method_ctx.register_param_type(p.name, _type_node_to_string(p.type))

        # Register the declared param NAMES so a bare identifier resolves to
        # ``load_param`` before falling through to ``load_prop`` (issue #130).
        # Without this, a param whose name collides with a mutable state
        # property lowered to the stale deserialized property value instead of
        # the witness param. Explicit ``this.x`` is unaffected: it lowers via
        # the property_access / member paths, which prefer a real property.
        for p in method.params:
            method_ctx.add_param(p.name)

        if contract.parent_class == "StatefulSmartContract" and method.visibility == "public":
            # Continuation requirements come from the side-effect
            # summary, which walks the private-method call graph. A
            # public method that calls a private helper which mutates
            # state or emits an output must therefore inject the same
            # continuation params as if the public body did so directly.
            eff = side_effects.get(method.name, MethodEffects())
            shape = continuation_shape_for(eff)
            needs_change_output = shape.needs_change
            needs_new_amount = shape.needs_new_amount

            # Register implicit parameters
            if needs_change_output:
                method_ctx.add_param("_changePKH")
                method_ctx.add_param("_changeAmount")
                method_ctx.register_param_type("_changePKH", "Ripemd160")
                method_ctx.register_param_type("_changeAmount", "bigint")
            if needs_new_amount:
                method_ctx.add_param("_newAmount")
                method_ctx.register_param_type("_newAmount", "bigint")
            method_ctx.add_param("txPreimage")
            method_ctx.register_param_type("txPreimage", "SigHashPreimage")

            # Issue #123: the declared per-method sighash mode (default
            # ALL|FORKID). Drives BOTH the OP_PUSH_TX binding flag (so the
            # derived sig re-computes the tx sighash under this mode) AND the
            # runtime preimage-type assert.
            sighash_mode = method.sighash_type if method.sighash_type is not None else SIGHASH_DEFAULT
            is_default_sighash = sighash_mode == SIGHASH_DEFAULT

            # Inject checkPreimage(txPreimage) at the start
            preimage_ref = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
            check_pre_value = ANFValue(kind="check_preimage", preimage=preimage_ref)
            # Omit for the default so the ANF (and pinned binding blob) is unchanged.
            if not is_default_sighash:
                check_pre_value.sighash_flag = sighash_mode
            check_result = method_ctx.emit(check_pre_value)
            method_ctx.emit(_make_assert(check_result))

            # GAP-302 / #123: pin the sighash type to the declared mode. The
            # auto-injected covenant verifies a real tx preimage, but without
            # this check the spend could use a DIFFERENT sighash flag than
            # declared that zeroes out preimage fields the contract (or its
            # continuation) relies on (hashOutputs / hashPrevouts / hashSequence).
            # The value defaults to 0x41 (SIGHASH_ALL|FORKID) so existing
            # contracts emit byte-identical ANF.
            sig_hash_preimage_ref = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
            sig_hash_type_ref = method_ctx.emit(_make_call("extractSigHashType", [sig_hash_preimage_ref]))
            expected_sig_hash_ref = method_ctx.emit(_make_load_const_int(sighash_mode))
            sig_hash_ok_ref = method_ctx.emit(ANFValue(
                kind="bin_op", op="===",
                left=sig_hash_type_ref, right=expected_sig_hash_ref,
            ))
            method_ctx.emit(_make_assert(sig_hash_ok_ref))

            # Deserialize mutable state from the preimage's scriptCode
            has_state_prop = any(not p.readonly for p in contract.properties)
            if has_state_prop:
                preimage_ref3 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                method_ctx.emit(ANFValue(kind="deserialize_state", preimage=preimage_ref3))

            # Issue #109: preserve @embedAlways fields at the first user-statement
            # position (after the checkPreimage/deserialize preamble), mirroring
            # where a ``const _bind = this.field;`` idiom would sit.
            if not embed_injected and embed_fields:
                _emit_embed_always_preservation(method_ctx, embed_fields)
                embed_injected = True

            # Lower the developer's method body
            method_ctx.lower_statements(method.body)

            # Determine state continuation type.
            #
            # === Continuation-hash construction ===
            #
            # Outputs are concatenated in the following order before hashing
            # with hash256:
            #   1. state outputs  (addOutput / addRawOutput, via addOutputRef)
            #   2. data outputs   (addDataOutput, via addDataOutputRef)
            #   3. change output  (P2PKH to _changePKH, value = _changeAmount)
            #
            # For the "single-output" fast path (no addOutput, but state mutates
            # or a data output is emitted), the state output is computed on the
            # fly from (preimage, stateScript, _newAmount); data outputs are
            # inserted BETWEEN the single state output and the change output.
            add_output_refs = method_ctx.get_add_output_refs()
            add_data_output_refs = method_ctx.get_add_data_output_refs()
            # Gate the continuation assertion on the same shape used
            # for param injection. Both must agree or the deployed
            # locking script will not match the auto-injected parameter
            # list.
            if needs_change_output:
                # Build the P2PKH change output for hashOutputs verification.
                #
                # Issue #116: the SDK's build_call_transaction OMITS the change
                # output when ``change <= 0`` (an exact-cover call) and passes
                # ``_changeAmount = 0``. Gate the change segment on
                # ``_changeAmount != 0`` at runtime so the hashed output set
                # matches the SDK at the exact-zero boundary -- the segment is
                # the P2PKH change output when non-zero, and empty bytes (cat
                # with empty is a no-op) when zero, reproducing the omission.
                # For any change > 0 the hashed bytes are unchanged; only the
                # emitted script gains the guard.
                change_pkh_ref = method_ctx.emit(ANFValue(kind="load_param", name="_changePKH"))
                change_amount_ref = method_ctx.emit(ANFValue(kind="load_param", name="_changeAmount"))
                zero_ref = method_ctx.emit(_make_load_const_int(0))
                change_non_zero_ref = method_ctx.emit(ANFValue(
                    kind="bin_op", op="!==",
                    left=change_amount_ref, right=zero_ref,
                ))
                change_then_ctx = method_ctx.sub_context()
                change_then_ctx.emit(_make_call("buildChangeOutput", [change_pkh_ref, change_amount_ref]))
                method_ctx.sync_counter(change_then_ctx)
                change_else_ctx = method_ctx.sub_context()
                change_else_ctx.emit(_make_load_const_string(""))
                method_ctx.sync_counter(change_else_ctx)
                change_output_ref = method_ctx.emit(ANFValue(
                    kind="if",
                    cond=change_non_zero_ref,
                    then=change_then_ctx.bindings,
                    else_=change_else_ctx.bindings,
                ))

                if add_output_refs:
                    # Multi-output continuation: concat all state outputs, then
                    # all data outputs, then change output, then hash.
                    accumulated = add_output_refs[0]
                    for i in range(1, len(add_output_refs)):
                        accumulated = method_ctx.emit(_make_call("cat", [accumulated, add_output_refs[i]]))
                    for data_ref in add_data_output_refs:
                        accumulated = method_ctx.emit(_make_call("cat", [accumulated, data_ref]))
                    accumulated = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
                    hash_ref = method_ctx.emit(_make_call("hash256", [accumulated]))
                    preimage_ref2 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref2]))
                    eq_ref = method_ctx.emit(ANFValue(
                        kind="bin_op", op="===",
                        left=hash_ref, right=output_hash_ref,
                        result_type="bytes",
                    ))
                    method_ctx.emit(_make_auto_injected_state_check_assert(eq_ref))
                else:
                    # Single-output continuation: build raw output bytes, then
                    # splice in any declared data outputs, then concat with
                    # change, then hash.
                    state_script_ref = method_ctx.emit(ANFValue(kind="get_state_script"))
                    preimage_ref2 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    new_amount_ref = method_ctx.emit(ANFValue(kind="load_param", name="_newAmount"))
                    contract_output_ref = method_ctx.emit(_make_call("computeStateOutput", [preimage_ref2, state_script_ref, new_amount_ref]))
                    accumulated = contract_output_ref
                    for data_ref in add_data_output_refs:
                        accumulated = method_ctx.emit(_make_call("cat", [accumulated, data_ref]))
                    all_outputs = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
                    hash_ref = method_ctx.emit(_make_call("hash256", [all_outputs]))
                    preimage_ref4 = method_ctx.emit(ANFValue(kind="load_param", name="txPreimage"))
                    output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref4]))
                    eq_ref = method_ctx.emit(ANFValue(
                        kind="bin_op", op="===",
                        left=hash_ref, right=output_hash_ref,
                        result_type="bytes",
                    ))
                    method_ctx.emit(_make_auto_injected_state_check_assert(eq_ref))

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

            # Intent-covenant intrinsic auto-injected witness params:
            # extractPrevOutputScript adds `_prevOutScript_<inputIndex>`
            # (one per distinct literal index referenced in the method);
            # requireOutputP2PKH adds a single `_serialisedOutputs`. Order
            # follows insertion order via method_scope.auto_injected_params.
            # Appended AFTER txPreimage so unlocking scripts push them
            # adjacent to the preimage (matches existing _changePKH /
            # _changeAmount / _newAmount convention of trailing the user
            # args before the preimage anchor).
            augmented_params += list(method_ctx.method_scope.auto_injected_params)

            result.append(ANFMethod(
                name=method.name,
                params=augmented_params,
                body=method_ctx.bindings,
                is_public=True,
                sighash_type=method.sighash_type,
            ))
        else:
            # Issue #109: stateless public methods (and stateless contracts'
            # spending entry points) are lowered here — inject @embedAlways
            # preservation into the first PUBLIC one before its body.
            if not embed_injected and embed_fields and method.visibility == "public":
                _emit_embed_always_preservation(method_ctx, embed_fields)
                embed_injected = True
            method_ctx.lower_statements(method.body)
            # Private methods can also call the intent intrinsics; capture
            # their auto-injected witness params so a public method that
            # inlines this private picks them up via the shared method_scope.
            augmented = _lower_params(method.params)
            augmented += list(method_ctx.method_scope.auto_injected_params)
            result.append(ANFMethod(
                name=method.name,
                params=augmented,
                body=method_ctx.bindings,
                is_public=method.visibility == "public",
                sighash_type=method.sighash_type,
            ))

    return result


def _lower_params(params: list) -> list[ANFParam]:
    return [
        ANFParam(name=p.name, type=_type_node_to_string(p.type))
        for p in params
    ]


def _emit_embed_always_preservation(ctx: "_LowerCtx", fields: list) -> None:
    """Issue #109: emit the DCE-surviving preservation pair for each
    ``@embedAlways`` readonly field, into the given (public) method context.

    Reproduces exactly what a hand-written ``const _bind = this.field;`` lowers
    to: a ``load_prop`` followed by a ``load_const("@ref:<t>")`` alias. The alias
    marks the ``load_prop`` as referenced (see ``collect_refs`` in the DCE pass),
    so dead-binding DCE keeps it; stack lowering then emits the field's
    constructor-slot placeholder and NIPs the unused value off the stack at
    method end. The field's bytes therefore remain in the deployed locking
    script for downstream recovery.
    """
    for field in fields:
        load_ref = ctx.emit(ANFValue(kind="load_prop", name=field.name))
        ctx.emit_named(
            f"__embedAlways_{field.name}",
            _make_load_const_string(f"@ref:{load_ref}"),
        )


# ---------------------------------------------------------------------------
# Lowering context
# ---------------------------------------------------------------------------

class _MethodScope:
    """Per-method bookkeeping shared by parent and sub-contexts.

    Tracks auto-injected witness parameters needed by intent-covenant
    intrinsics (``extractPrevOutputScript``, ``requireOutputP2PKH``)
    regardless of whether the intrinsic is called from the method's
    top-level body or from inside a nested block (if/else, ternary).
    Mirrors the Go ``methodScopeT`` struct.
    """

    def __init__(self) -> None:
        # Append-only list of auto-injected params (insertion order).
        self.auto_injected_params: list[ANFParam] = []
        # Set of names already recorded (dedup).
        self.auto_injected_set: set[str] = set()
        # requireOutputP2PKH emits its hashOutputs(preimage) check at
        # most ONCE per method body.
        self.did_emit_hash_outputs_check: bool = False

    def record_auto_injected_param(self, name: str, typ: str) -> None:
        """Idempotent: second call with the same name is a no-op."""
        if name in self.auto_injected_set:
            return
        self.auto_injected_set.add(name)
        self.auto_injected_params.append(ANFParam(name=name, type=typ))


class _LowerCtx:
    """Manages temp variable generation and binding emission.

    Mirrors the Go ``lowerCtx`` struct exactly.
    """

    def __init__(
        self,
        contract: ContractNode,
        side_effects: dict[str, MethodEffects] | None = None,
        method_scope: _MethodScope | None = None,
    ) -> None:
        self.bindings: list[ANFBinding] = []
        self._counter: int = 0
        self._contract: ContractNode = contract
        self._local_names: set[str] = set()
        self._param_names: set[str] = set()
        # Issue #123: the declared non-default @sighash flag for the method being
        # lowered, so a MANUAL ``checkPreimage(pre)`` call (stateless / explicit)
        # binds under the same mode as the method's declared sighash. ``None`` =
        # default ALL|FORKID, keeping the pinned binding blob unchanged.
        self.sighash_flag: int | None = None
        # True in every context produced by ``sub_context()`` -- inside an if
        # arm, a loop body, or an inlined helper's block -- and False only in
        # the context a method's own body is lowered into.
        self.nested: bool = False
        # Method-scoped parameter type table. Populated once per
        # method/constructor (and for auto-injected continuation params)
        # before its body is lowered. Mirrors the TS reference's
        # per-method getParamType: a local named ``x`` in one method must
        # NOT pick up a same-named parameter (e.g. ``x: ByteString``) of a
        # DIFFERENT method, which would poison byte-type analysis and emit
        # OP_CAT where OP_ADD is correct. Shared by reference into
        # sub-contexts so if/else blocks see the same scope.
        self._param_types: dict[str, str] = {}
        self._add_output_refs: list[str] = []
        self._add_data_output_refs: list[str] = []
        self._local_aliases: dict[str, str] = {}
        self._local_byte_vars: set[str] = set()
        self.current_source_loc: SourceLocation | None = None
        # Param substitution stack used when inlining a private method's
        # body into this context. When the inlined body references that
        # param, the lowered identifier resolves to the aliased ref
        # instead of emitting load_param. Stacked so nested inlines
        # compose correctly.
        self._param_alias_stack: dict[str, list[str]] = {}
        # Side-effect summary shared with auto-injection decisions. Used
        # at lowering time to decide whether a private call should be
        # inlined (so that helper's add_output / add_data_output ANF
        # nodes register on the caller's continuation hash) or remain a
        # method_call for stack lowering to inline later.
        self._side_effects: dict[str, MethodEffects] | None = side_effects
        # Per-method scope shared by parent and sub-contexts. Tracks
        # auto-injected witness params for intent-covenant intrinsics.
        # Always non-None so sub-contexts inherit the same scope and
        # auto-injection registers regardless of nesting depth.
        self.method_scope: _MethodScope = method_scope if method_scope is not None else _MethodScope()

    def push_param_alias(self, name: str, alias_ref: str) -> None:
        self._param_alias_stack.setdefault(name, []).append(alias_ref)

    def pop_param_alias(self, name: str) -> None:
        stack = self._param_alias_stack.get(name)
        if not stack:
            return
        stack.pop()
        if not stack:
            self._param_alias_stack.pop(name, None)

    def get_param_alias(self, name: str) -> str | None:
        stack = self._param_alias_stack.get(name)
        if not stack:
            return None
        return stack[-1]

    def should_inline_private(self, name: str) -> bool:
        """Whether a call to ``name`` should be ANF-inlined rather than
        emitted as a method_call. True iff ``name`` is a private method
        that (transitively) emits state outputs (addOutput /
        addRawOutput) or data outputs (addDataOutput). Those refs MUST
        appear in the caller's binding stream so they participate in
        the continuation hash.

        Mutation-only private helpers are intentionally NOT inlined —
        state mutation flows through state continuity (the
        continuation hash reads state via get_state_script after all
        mutations apply). Keeping the existing method_call +
        stack-lowering inlining path for those preserves byte-equality
        with the pre-fix corpus.
        """
        if self._side_effects is None:
            return False
        if not self._is_private_method(name):
            return False
        eff = self._side_effects.get(name)
        if eff is None:
            return False
        return eff.has_state_output or eff.has_data_output

    def get_private_method(self, name: str) -> MethodNode | None:
        for m in self._contract.methods:
            if m.name == name and m.visibility != "public":
                return m
        return None

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

    def register_param_type(self, name: str, type_str: str | None) -> None:
        """Record the type of a parameter for the CURRENT method scope."""
        if type_str is not None:
            self._param_types[name] = type_str

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

    def add_data_output_ref(self, ref: str) -> None:
        """Track an addDataOutput binding ref -- distinct from state outputs."""
        self._add_data_output_refs.append(ref)

    def get_add_data_output_refs(self) -> list[str]:
        """Get all addDataOutput refs collected during lowering."""
        return self._add_data_output_refs

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
        # Method-scoped: read ONLY the current method's parameter types.
        # Searching all methods would let a local in one method falsely
        # match a same-named param of a different method (issue #34).
        return self._param_types.get(name)

    def get_property_type(self, name: str) -> str | None:
        for p in self._contract.properties:
            if p.name == name:
                return _type_node_to_string(p.type)
        return None

    def sub_context(self) -> _LowerCtx:
        """Create a sub-context for nested blocks (if/else, loops).

        The counter continues from the parent. Local names and param names
        are shared (copied). The method_scope is *shared by reference* so
        auto-injection from intent intrinsics registers on the parent
        method's ABI augmentation regardless of nesting depth.
        """
        sub = _LowerCtx(self._contract, side_effects=self._side_effects, method_scope=self.method_scope)
        sub._counter = self._counter
        sub._local_names = set(self._local_names)
        sub._param_names = set(self._param_names)
        # Issue #123: a manual checkPreimage() inside a nested block must bind
        # under the same declared @sighash mode as the enclosing method.
        sub.sighash_flag = self.sighash_flag
        # Share the method-scoped param-type table by reference so if/else
        # sub-contexts resolve parameter types against the same method.
        sub._param_types = self._param_types
        sub._local_aliases = dict(self._local_aliases)
        sub._local_byte_vars = set(self._local_byte_vars)
        # ``_lift_branch_update_props`` walks ``method.body`` and does NOT
        # recurse, so an ``if`` its recogniser accepts is only actually
        # REWRITTEN at method top level. ``lower_if_statement`` needs the same
        # distinction before it defers to that pass.
        sub.nested = True
        return sub

    def sync_counter(self, sub: _LowerCtx) -> None:
        if sub._counter > self._counter:
            self._counter = sub._counter

    # -------------------------------------------------------------------
    # Statement lowering
    # -------------------------------------------------------------------

    def lower_statements(
        self, stmts: list[Statement], reads_after_block: frozenset[str] = frozenset()
    ) -> None:
        """Lower a statement block, threading down the set of identifiers the
        enclosing blocks still read after this block ends. Only the
        block-forming statements (if / for) consume it; see
        ``_reads_after_statement``.
        """
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
                self.lower_statement(modified_if, reads_after_block)
                return
            # Only the block-forming statements need to know what the code after
            # them still reads; computing it for every statement would be
            # quadratic for no benefit.
            reads_after: frozenset[str] = frozenset()
            if isinstance(stmt, (IfStmt, ForStmt)):
                reads_after = _reads_after_statement(stmts, i, reads_after_block)
            self.lower_statement(stmt, reads_after)

    def lower_statement(
        self, stmt: Statement, reads_after: frozenset[str] = frozenset()
    ) -> None:
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
            self._lower_if_statement(stmt, reads_after)
        elif isinstance(stmt, ForStmt):
            self._lower_for_statement(stmt, reads_after)
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

    def _lower_if_statement(
        self, stmt: IfStmt, reads_after: frozenset[str] = frozenset()
    ) -> None:
        cond_ref = self.lower_expr_to_ref(stmt.condition)

        # Lower then-block into sub-context
        then_ctx = self.sub_context()
        then_ctx.lower_statements(stmt.then, reads_after)
        self.sync_counter(then_ctx)

        # Lower else-block into sub-context
        else_ctx = self.sub_context()
        if stmt.else_:
            else_ctx.lower_statements(stmt.else_, reads_after)
        self.sync_counter(else_ctx)

        # 2026-04-30 audit finding F2: when a branch contains output
        # intrinsics, append a cat-chain inside each branch so the
        # branch's terminal value is the concat of its output bytes
        # (state then data, in declaration order). Balances runtime
        # stack effects across branches and lets the parent's
        # continuation hash see one ref per if representing the
        # chosen branch's full output set.
        branch_has_state_output = bool(
            then_ctx.get_add_output_refs() or else_ctx.get_add_output_refs()
        )
        branch_has_outputs = (
            branch_has_state_output
            or bool(then_ctx.get_add_data_output_refs() or else_ctx.get_add_data_output_refs())
        )

        then_output_bytes = ""
        else_output_bytes = ""
        if branch_has_outputs:
            then_output_bytes = _append_branch_output_concat(then_ctx)
            else_output_bytes = _append_branch_output_concat(else_ctx)

        # Branch-merged locals (2 or more). An ``if`` expression carries exactly
        # ONE value, so the alias below can only rewire post-branch references
        # for a SINGLE merged local. With two or more -- or with the arms
        # reassigning DIFFERENT locals -- every later reference kept naming the
        # pre-branch binding, i.e. the dead initial value, and stack lowering
        # then registered one stack-map slot for N physical results and resolved
        # every later operand one slot off. Reported privately 2026-08-03; see
        # packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts.
        #
        # Fix: give both arms the SAME result set in the SAME order by appending
        # an explicit rebind of every merged local to each arm.
        merged_locals = self._collect_branch_merged_locals(then_ctx, else_ctx)

        if branch_has_outputs:
            reason = _branch_output_rejection_reason(
                then_ctx, else_ctx, then_output_bytes, else_output_bytes,
                merged_locals, reads_after,
            )
            if reason is not None:
                raise ValueError(
                    "Cannot compile conditional that both declares outputs and "
                    f"{reason}. Move the addOutput/addRawOutput/addDataOutput "
                    "call after the if-statement."
                )

        # The ``if``'s multi-result contract. Locals first, in the canonical
        # merge order both arms agree on, then the properties either arm
        # writes, in contract declaration order -- so all seven tiers derive the
        # same list from the same source. ``results[0]`` is the deepest slot.
        arm_props: list[str] = []
        _collect_updated_props(then_ctx.bindings, arm_props)
        _collect_updated_props(else_ctx.bindings, arm_props)
        result_names = list(merged_locals) + [
            p.name for p in self._contract.properties if p.name in arm_props
        ]

        # The result list is keyed by NAME everywhere downstream, so a local
        # that shares a contract property's name appears TWICE and both entries
        # take the PROPERTY path -- the local's value is silently replaced by
        # the property's, and the layout assertion cannot see it because both
        # slots are legitimately named the same. Refuse the exact collision
        # only; shadowing a property is otherwise fine.
        for _name in merged_locals:
            if _name in arm_props:
                raise ValueError(
                    f"Local variable '{_name}' shadows contract property "
                    f"'this.{_name}', and the conditional assigns both. The "
                    f"branch's result slots are identified by name, so the two "
                    f"cannot be told apart and the local's value would be "
                    f"silently replaced by the property's. Rename the local."
                )

        # When to materialise the contract instead of leaving the arms to the
        # stack-lowerer's inference:
        #
        #   - two or more merged locals -- the pre-existing normalisation. Kept
        #     on exactly its old trigger so the four ``__merge$`` goldens do not
        #     move.
        #   - any result at all when the ELSE arm carries code. This is the new
        #     case, and it is where every measured miscompile lives: one arm
        #     rebinds its local IN PLACE (net depth 0) while the other pushes a
        #     fresh slot (net +1), or an arm writes a property beside a rebound
        #     local, or the two arms write the same properties in a different
        #     order. The arms then leave different LAYOUTS, which no depth or
        #     liveness predicate can see.
        #
        # An ``if`` WITHOUT an else keeps the preserve-the-old-value path in
        # ``lower_if`` (phase 3 copies each missing slot's same-named parent
        # value), which already produces exactly these results by construction
        # -- deliberately left intact. An arm that emits outputs is excluded:
        # its single value is the serialised output bytes, and
        # ``_branch_output_rejection_reason`` above already refuses every
        # combination that would need a second result.
        #
        # EXCLUDED: an ``if`` that ``_lift_branch_update_props`` will rewrite.
        # That pass (deep-review finding C20) turns a
        # conditional-property-assignment chain into one flat single-valued
        # ``if`` per property plus a top-level ``update_prop``, so the surviving
        # ``if``s carry no property result and need no declaration. Appending
        # the normalisation block first would ALSO silently disable that pass:
        # its recogniser requires the arm's last binding to be the
        # ``update_prop`` with everything before it side-effect free, and the
        # block adds a second ``update_prop`` behind it. TicTacToe's position
        # dispatch is exactly that shape, and losing the lift there produced an
        # unspendable ``move`` script.
        #
        # The exclusion must be exactly "the lift WILL rewrite this ``if``",
        # which is narrower than "the lift's recogniser accepts it" in TWO ways
        # -- both were live defects producing an unspendable UTXO: the lift only
        # rewrites chains of TWO OR MORE branches (``_collect_update_branches``
        # returns a ONE-element list for the assert-false-else guard), and it
        # only walks ``method.body``, passing loop bodies and surviving arms
        # through untouched, while ``declares_results`` is evaluated at EVERY
        # nesting depth.
        #
        # A chain's DEEPEST ``if`` is never at top level, so it now declares
        # results and carries a normalisation block -- which is why
        # ``_collect_update_branches`` strips a declared block before matching
        # (``_strip_declared_results``).
        lifted = _collect_update_branches(
            cond_ref, then_ctx.bindings, else_ctx.bindings
        )
        will_be_lifted = (
            not self.nested and lifted is not None and len(lifted) >= 2
        )
        declares_results = not branch_has_outputs and not will_be_lifted and (
            len(merged_locals) >= 2
            or (len(result_names) >= 1 and bool(else_ctx.bindings))
        )

        if declares_results:
            _append_branch_results(then_ctx, result_names, arm_props)
            self.sync_counter(then_ctx)
            _append_branch_results(else_ctx, result_names, arm_props)
            self.sync_counter(else_ctx)

        if_name = self.emit(ANFValue(
            kind="if",
            cond=cond_ref,
            then=then_ctx.bindings,
            else_=else_ctx.bindings,
            results=list(result_names) if declares_results else None,
        ))

        if branch_has_outputs:
            # Register the if's value once with the parent's continuation
            # tracker. CRITICAL: pick the right tracker. If either
            # branch produces a STATE output, the parent must take the
            # multi-output continuation path, so we register as a
            # state output ref. If neither branch produces a state
            # output and at least one branch produces a data output,
            # we register as a DATA output ref so the parent keeps
            # its single-output `computeStateOutput` continuation
            # and the data-output bytes splice in BETWEEN the state
            # output and the change output. Without this, a branch
            # with only `addDataOutput` was incorrectly forced onto
            # the multi-output path, dropping the canonical state
            # continuation.
            if branch_has_state_output:
                self.add_output_ref(if_name)
            else:
                self.add_data_output_ref(if_name)

        # If both branches end by reassigning the same single local variable,
        # alias that variable to the if-expression result.
        #
        # Skipped when the arms were normalised above: there the ``if``
        # DECLARES its results, and each one keeps its OWN name through the
        # reconcile in the stack lowerer.
        if not declares_results and then_ctx.bindings and else_ctx.bindings:
            then_last = then_ctx.bindings[-1]
            else_last = else_ctx.bindings[-1]
            if then_last.name == else_last.name and self.is_local(then_last.name):
                self.set_local_alias(then_last.name, if_name)

    def _collect_branch_merged_locals(self, then_ctx, else_ctx) -> list[str]:
        """Locals from the enclosing scope that either arm of an if-statement
        reassigns, in a canonical order both arms can agree on: the then-arm's
        reassignments in order of last rebind, then the else-only ones in the
        same order.

        Only names the PARENT already knows as locals count -- ``sub_context``
        copies the local-name set by value, so a local declared inside a branch
        never reaches the parent's set and is correctly excluded (it is not live
        after the if).
        """
        def last_rebind_order(branch) -> list[str]:
            last_index: dict[str, int] = {}
            for i, b in enumerate(branch.bindings):
                if self.is_local(b.name):
                    last_index[b.name] = i
            return [n for n, _ in sorted(last_index.items(), key=lambda kv: kv[1])]

        merged = last_rebind_order(then_ctx)
        for name in last_rebind_order(else_ctx):
            if name not in merged:
                merged.append(name)
        return merged

    def _lower_for_statement(
        self, stmt: ForStmt, reads_after: frozenset[str] = frozenset()
    ) -> None:
        # Resolve the loop's compile-time shape: start value, step direction,
        # and iteration count. Rúnar requires bounded loops, so all three must
        # be statically determinable (issue #121).
        start, step, count = _extract_loop_shape(stmt)

        # Lower body into sub-context. The body repeats, so every read anywhere
        # in it is a read that happens after any given statement inside it.
        body_reads = set(reads_after)
        for s in stmt.body:
            _collect_statement_reads(s, body_reads)

        body_ctx = self.sub_context()
        body_ctx.lower_statements(stmt.body, frozenset(body_reads))
        self.sync_counter(body_ctx)

        self.emit(ANFValue(
            kind="loop",
            count=count,
            body=body_ctx.bindings,
            iter_var=stmt.init.name if stmt.init else "",
            start=start,
            step=step,
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
            # Explicit ``this.x``: a real contract property always wins, even
            # when a method param shares the name (issue #130). Now that
            # declared params are registered, the is_param branch below must not
            # shadow a stored property.
            if self.is_property(expr.property):
                return self.emit(ANFValue(kind="load_prop", name=expr.property))
            # this.txPreimage in StatefulSmartContract -> load_param (implicit
            # injected param, not a stored property).
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

        # Param alias takes precedence over normal param lookup. Set
        # when a private method's body is being inlined into this
        # context — the private's param names map to the caller's arg
        # refs.
        alias = self.get_param_alias(name)
        if alias is not None:
            return alias

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
                cp = ANFValue(kind="check_preimage", preimage=preimage_ref)
                # Issue #123: honour the method's declared @sighash on manual calls.
                if self.sighash_flag is not None:
                    cp.sighash_flag = self.sighash_flag
                return self.emit(cp)

        # extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString.
        # extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString.
        #
        # Witness-bridge sugar (BSVM Phase 13). Auto-injects a hidden method
        # parameter named `_prevOutScript_<inputIndex>` (one per distinct index
        # in the method body), emits a hash assertion, and returns the witness
        # ref for caller substring extraction.
        #
        # 2-arg form: hash256(witness) === expectedScriptHash. Pins the full
        #   prev-output script byte-for-byte. Use when the prev-output is a
        #   single fixed-shape contract.
        # 3-arg form: hash256(substr(witness, 0, prefixLen)) ===
        #   expectedScriptPrefixHash. Pins the policy prefix only, leaving the
        #   pushdata tail free to vary. Required for the intent-template
        #   matching use case where each successor intent UTXO has a unique
        #   tail (BSVM Mode 3 permissionless step-in).
        if isinstance(callee, Identifier) and callee.name == "extractPrevOutputScript":
            if len(e.args) != 2 and len(e.args) != 3:
                return self.emit(_make_load_const_string(""))
            idx_lit = e.args[0]
            if not isinstance(idx_lit, BigIntLiteral):
                return self.emit(_make_load_const_string(""))
            idx = idx_lit.value
            param_name = f"_prevOutScript_{idx}"
            self.method_scope.record_auto_injected_param(param_name, "ByteString")
            self.add_param(param_name)
            self.register_param_type(param_name, "ByteString")
            witness_ref = self.emit(ANFValue(kind="load_param", name=param_name))
            expected_hash_ref = self.lower_expr_to_ref(e.args[1])

            # Determine which bytes to hash: full witness (2-arg) or
            # prefix (3-arg). The substr happens at script-execution time;
            # the literal prefixLen is baked into the emitted Stack-IR.
            if len(e.args) == 3:
                prefix_len_lit = e.args[2]
                if not isinstance(prefix_len_lit, BigIntLiteral):
                    return self.emit(_make_load_const_string(""))
                zero_ref = self.emit(_make_load_const_int(0))
                prefix_len_ref = self.emit(_make_load_const_int(prefix_len_lit.value))
                bytes_to_hash_ref = self.emit(
                    _make_call("substr", [witness_ref, zero_ref, prefix_len_ref])
                )
            else:
                bytes_to_hash_ref = witness_ref

            actual_hash_ref = self.emit(_make_call("hash256", [bytes_to_hash_ref]))
            eq_ref = self.emit(ANFValue(
                kind="bin_op", op="===",
                left=actual_hash_ref, right=expected_hash_ref,
                result_type="bytes",
            ))
            self.emit(_make_assert(eq_ref))
            return witness_ref

        # requireOutputP2PKH(outputIndex_literal, pubkeyHash, amount) -> void.
        # Asserts that the tx's output at outputIndex is a standard P2PKH
        # paying `amount` satoshis to `pubkeyHash`. Auto-injects
        # `_serialisedOutputs` (once per method) and emits
        # hash256(serialisedOutputs) == extractOutputHash(txPreimage) the
        # first time the intrinsic is called in a method body. Subsequent
        # calls in the same method skip the hashOutputs check (already
        # established) and emit only the per-output substring assertion.
        #
        # v1 assumes all outputs in the serialised set are exactly 34 bytes
        # (8-byte LE amount || 0x19 length || 25-byte P2PKH script). Byte
        # offset of output i is i*34.
        if isinstance(callee, Identifier) and callee.name == "requireOutputP2PKH":
            if len(e.args) != 3:
                return self.emit(_make_load_const_string(""))
            idx_lit = e.args[0]
            if not isinstance(idx_lit, BigIntLiteral):
                return self.emit(_make_load_const_string(""))
            idx = idx_lit.value

            self.method_scope.record_auto_injected_param("_serialisedOutputs", "ByteString")
            self.add_param("_serialisedOutputs")
            self.register_param_type("_serialisedOutputs", "ByteString")

            # Emit the hashOutputs(preimage) check exactly once per method.
            if not self.method_scope.did_emit_hash_outputs_check:
                self.method_scope.did_emit_hash_outputs_check = True
                serialised_ref = self.emit(ANFValue(kind="load_param", name="_serialisedOutputs"))
                actual_out_hash_ref = self.emit(_make_call("hash256", [serialised_ref]))
                preimage_ref = self.emit(ANFValue(kind="load_param", name="txPreimage"))
                expected_out_hash_ref = self.emit(_make_call("extractOutputHash", [preimage_ref]))
                hash_eq_ref = self.emit(ANFValue(
                    kind="bin_op", op="===",
                    left=actual_out_hash_ref, right=expected_out_hash_ref,
                    result_type="bytes",
                ))
                self.emit(_make_assert(hash_eq_ref))

            # Lower the user-supplied args (pubkeyHash, amount).
            pubkey_hash_ref = self.lower_expr_to_ref(e.args[1])
            amount_ref = self.lower_expr_to_ref(e.args[2])

            # Construct expected P2PKH output bytes:
            #   <amount: 8-byte LE> || 0x19 0x76 0xa9 0x14
            #     || <pubkeyHash: 20 bytes> || 0x88 0xac
            eight_ref = self.emit(_make_load_const_int(8))
            amount_bytes_ref = self.emit(_make_call("num2bin", [amount_ref, eight_ref]))
            # 0x19 0x76 0xa9 0x14 -- script length byte + OP_DUP OP_HASH160 OP_PUSH20
            prefix_ref = self.emit(_make_load_const_string("1976a914"))
            # 0x88 0xac -- OP_EQUALVERIFY OP_CHECKSIG
            suffix_ref = self.emit(_make_load_const_string("88ac"))
            cat1_ref = self.emit(_make_call("cat", [amount_bytes_ref, prefix_ref]))
            cat2_ref = self.emit(_make_call("cat", [cat1_ref, pubkey_hash_ref]))
            expected_output_ref = self.emit(_make_call("cat", [cat2_ref, suffix_ref]))

            # Substring extract at idx*34 length 34, assert equal.
            serialised_ref2 = self.emit(ANFValue(kind="load_param", name="_serialisedOutputs"))
            offset_ref = self.emit(_make_load_const_int(idx * 34))
            length_ref = self.emit(_make_load_const_int(34))
            extracted_ref = self.emit(_make_call("substr", [serialised_ref2, offset_ref, length_ref]))
            out_eq_ref = self.emit(ANFValue(
                kind="bin_op", op="===",
                left=extracted_ref, right=expected_output_ref,
                result_type="bytes",
            ))
            return self.emit(_make_assert(out_eq_ref))

        # currentBlockHeight() -> bigint. Pure source-level desugar to
        # extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
        # methods (typecheck enforces). No new ANF kind or stack codegen needed.
        if isinstance(callee, Identifier) and callee.name == "currentBlockHeight":
            preimage_ref = self.emit(ANFValue(kind="load_param", name="txPreimage"))
            return self.emit(_make_call("extractLocktime", [preimage_ref]))

        # this.addOutput(satoshis, val1, val2, ...) via PropertyAccessExpr.
        # Mirrors flattenAddOutputArgs in 04-anf-lower.ts: when addOutput is
        # called as `this.addOutput(satoshis, .{ v1, v2, ... })` (the surface
        # form Zig / Move tuple syntax produce), unwrap the trailing array
        # literal so each element becomes an individual state value.
        if isinstance(callee, PropertyAccessExpr) and callee.property == "addOutput":
            flat_args = _flatten_add_output_args(e.args)
            arg_refs = self._lower_args(flat_args)
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

        # this.addDataOutput(satoshis, scriptBytes) via PropertyAccessExpr. Like
        # addRawOutput in wire shape, but included in the continuation hash
        # AFTER state outputs and BEFORE the change output.
        if isinstance(callee, PropertyAccessExpr) and callee.property == "addDataOutput":
            arg_refs = self._lower_args(e.args)
            satoshis = arg_refs[0]
            script_bytes_ref = arg_refs[1]
            ref = self.emit(ANFValue(kind="add_data_output", satoshis=satoshis, script_bytes=script_bytes_ref))
            self.add_data_output_ref(ref)
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

        # this.addDataOutput(satoshis, scriptBytes) via MemberExpr
        if isinstance(callee, MemberExpr):
            if (
                isinstance(callee.object, Identifier)
                and callee.object.name == "this"
                and callee.property == "addDataOutput"
            ):
                arg_refs = self._lower_args(e.args)
                satoshis = arg_refs[0]
                script_bytes_ref = arg_refs[1]
                ref = self.emit(ANFValue(kind="add_data_output", satoshis=satoshis, script_bytes=script_bytes_ref))
                self.add_data_output_ref(ref)
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

        # this.method(...) via PropertyAccessExpr (or inlined if the
        # target is a private method with continuation-relevant side
        # effects).
        if isinstance(callee, PropertyAccessExpr):
            arg_refs = self._lower_args(e.args)
            if self.should_inline_private(callee.property):
                return self._inline_private_method_call(callee.property, arg_refs)
            this_ref = self.emit(_make_load_const_string("@this"))
            return self.emit(ANFValue(
                kind="method_call", object=this_ref,
                method=callee.property, args=arg_refs,
            ))

        # this.method(...) via MemberExpr
        if isinstance(callee, MemberExpr):
            if isinstance(callee.object, Identifier) and callee.object.name == "this":
                arg_refs = self._lower_args(e.args)
                if self.should_inline_private(callee.property):
                    return self._inline_private_method_call(callee.property, arg_refs)
                this_ref = self.emit(_make_load_const_string("@this"))
                return self.emit(ANFValue(
                    kind="method_call", object=this_ref,
                    method=callee.property, args=arg_refs,
                ))

        # asm({...}) compiler intrinsic -- the parser has already normalised
        # the object-literal argument into three positional args
        # (body, in_arity, out_arity). Lower it to a single opaque raw_script
        # ANF binding; the hex body passes through unchanged. Diagnostics for
        # malformed args were already pushed by the validator -- here we
        # defensively coerce missing values to safe defaults.
        if isinstance(callee, Identifier) and callee.name == "asm":
            bytes_hex = ""
            in_arity = 0
            out_arity = 1
            if len(e.args) >= 1 and isinstance(e.args[0], ByteStringLiteral):
                bytes_hex = e.args[0].value
            if len(e.args) >= 2 and isinstance(e.args[1], BigIntLiteral):
                in_arity = e.args[1].value
            if len(e.args) >= 3 and isinstance(e.args[2], BigIntLiteral):
                out_arity = e.args[2].value
            return self.emit(ANFValue(
                kind="raw_script",
                bytes=bytes_hex,
                in_arity=in_arity,
                out_arity=out_arity,
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
                if self.should_inline_private(callee.name):
                    return self._inline_private_method_call(callee.name, arg_refs)
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

    def _inline_private_method_call(self, method_name: str, arg_refs: list[str]) -> str:
        """Lower a private method's body directly into this context.

        Used when the private has continuation-relevant side effects
        (state mutation, addOutput, addRawOutput, addDataOutput) so the
        helper's emitted ANF nodes register output refs on the caller.
        Arg refs are mapped onto the private's parameter names via
        push_param_alias. While the private's body lowers, any
        identifier expression matching one of those param names
        resolves to the caller's ref. The aliases are popped afterwards
        so subsequent lowering in the caller's body sees its own scope.

        Recursion across private helpers is forbidden by validation, so
        this always terminates. Nested inlining (private A calls
        private B) works naturally.
        """
        method = self.get_private_method(method_name)
        if method is None:
            # Should not happen — caller checked should_inline_private.
            this_ref = self.emit(_make_load_const_string("@this"))
            return self.emit(ANFValue(
                kind="method_call", object=this_ref,
                method=method_name, args=arg_refs,
            ))

        aliased: list[str] = []
        for i, param in enumerate(method.params):
            if i >= len(arg_refs):
                break
            self.push_param_alias(param.name, arg_refs[i])
            aliased.append(param.name)

        start_index = len(self.bindings)
        self.lower_statements(method.body)
        end_index = len(self.bindings)

        for name in reversed(aliased):
            self.pop_param_alias(name)

        if end_index > start_index:
            return self.bindings[end_index - 1].name
        return self.emit(_make_load_const_string("@void"))

    def _lower_ternary_arm(self, e: Expression) -> None:
        """Lower one arm of a ternary so the arm ENDS with its result binding.

        NEW-016: ``lower_expr_to_ref`` returns an existing ref without emitting
        anything when the arm is a bare identifier -- ``g ? f : c === 0n``
        produced ``then: []``, an ``if`` arm with no bindings at all. Stack
        lowering reads an arm's result off its stack effect, so a +0 arm has no
        result to adopt and the depth reconcile padded the shortfall with an
        EMPTY push. The contract compiled clean, the AST interpreter accepted
        it, and the real engine rejected the spend with "OP_VERIFY requires the
        top stack value to be truthy" over a stack of ``[01, ]`` -- the arm's
        ``true`` replaced by an empty (false) value. An ordinary contract
        deployed to a permanently unspendable UTXO.

        Aliasing through ``load_const "@ref:"`` -- the same idiom ``let x = y``
        and the increment/decrement lowerings already use -- makes the arm's
        stack effect +1 and copies the parent slot instead of trying to move
        it. The alias is only emitted when the result was NOT produced inside
        the arm, so every arm that already ended on its own result keeps its
        exact bytes.
        """
        ref = self.lower_expr_to_ref(e)
        if not self.bindings or self.bindings[-1].name != ref:
            self.emit(_make_load_const_string("@ref:" + ref))

    def _lower_ternary_expr(self, e: TernaryExpr) -> str:
        cond_ref = self.lower_expr_to_ref(e.condition)

        then_ctx = self.sub_context()
        then_ctx._lower_ternary_arm(e.consequent)
        self.sync_counter(then_ctx)

        else_ctx = self.sub_context()
        else_ctx._lower_ternary_arm(e.alternate)
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
    # JSON numbers in JavaScript are IEEE-754 doubles (~53 bits of integer
    # precision). Cross-tier IR consumers (Go, Rust) round-trip JSON numbers
    # through encoding/json which silently degrades values above 2^53 into
    # scientific notation. Emit values a bare JSON number cannot carry as a
    # quoted decimal string with the canonical JS BigInt `n` suffix so
    # 256-bit constants (e.g. the secp256k1 group order used in
    # schnorr-zkp's s-bound assert) survive the JSON round-trip losslessly
    # AND so consuming IR decoders can distinguish a decimal-encoded big
    # integer from a hex-encoded ByteString literal. ``bigint_json_value``
    # owns the boundary (Number.MAX_SAFE_INTEGER, not int64).
    raw = json.dumps(bigint_json_value(val))
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


def _append_branch_results(
    branch_ctx, result_names: list[str], props: list[str]
) -> None:
    """Append the canonical result block to one arm of an if-statement: a copy
    of every declared result, in the declared order, rebound under its own
    name. This is what makes the ``if`` node's ``results`` contract true rather
    than hoped-for.

    Two passes on purpose. Pass 1 always COPIES: for a LOCAL, ``@ref:<local>``
    resolves to the arm's own new value if it rebound one, else to the
    enclosing scope's value; for a PROPERTY, ``load_prop`` picks the arm's
    updated slot when the arm wrote it and otherwise the enclosing value.
    Either way stack lowering picks (never rolls) it, because a declared result
    is outer-protected. Pass 2 always CONSUMES, because the temps are bound in
    this arm and this is their last use. The arm's stack effect is therefore
    exactly +N regardless of which of the N results it assigned.

    Semantically a no-op for the off-chain ANF interpreters: every binding is
    an ordinary read-then-write of a value the arm already holds.
    """
    for i, name in enumerate(result_names):
        temp = f"{MERGED_LOCAL_TEMP_PREFIX}{i}"
        if name in props:
            branch_ctx.emit_named(temp, ANFValue(kind="load_prop", name=name))
        else:
            branch_ctx.emit_named(temp, _make_load_const_string(f"@ref:{name}"))
    for i, name in enumerate(result_names):
        temp = f"{MERGED_LOCAL_TEMP_PREFIX}{i}"
        if name in props:
            branch_ctx.emit(_make_update_prop(name, temp))
        else:
            branch_ctx.emit_named(name, _make_load_const_string(f"@ref:{temp}"))


def _append_branch_output_concat(branch_ctx: "_LowerCtx") -> str:
    """Concatenate a branch's output refs (state then data, in
    declaration order) into a single bytes-ref appended to the
    branch's bindings. If the branch has no outputs, emits an empty
    ``load_const`` so the branch still leaves one item on the stack —
    required to balance the if's branch shapes when the OTHER branch
    has outputs. 2026-04-30 audit finding F2 fix."""
    all_refs = list(branch_ctx.get_add_output_refs())
    all_refs.extend(branch_ctx.get_add_data_output_refs())
    if not all_refs:
        return branch_ctx.emit(_make_load_const_string(""))
    if len(all_refs) == 1:
        return all_refs[0]
    accumulated = all_refs[0]
    for ref in all_refs[1:]:
        accumulated = branch_ctx.emit(_make_call("cat", [accumulated, ref]))
    return accumulated


def _reads_after_statement(
    stmts: list[Statement], index: int, reads_after_block: frozenset[str]
) -> frozenset[str]:
    """The identifiers still readable once statement ``index`` of this block has
    run: everything the following statements in this block read, plus whatever
    the enclosing blocks read after this block.

    Used by ``_lower_if_statement`` to tell a branch-merged local that is dead
    after the ``if`` (safe) from one that is still live (not representable
    alongside a branch output -- see ``_branch_output_rejection_reason``).
    """
    reads = set(reads_after_block)
    for stmt in stmts[index + 1:]:
        _collect_statement_reads(stmt, reads)
    return frozenset(reads)


def _collect_statement_reads(stmt: Statement, out: set[str]) -> None:
    """Collect every identifier a statement READS. The ``x`` in ``x = expr`` is
    a write, not a read, so a plain identifier assignment target is skipped;
    every other target form can still read locals.
    """
    if isinstance(stmt, VariableDeclStmt):
        _collect_expression_reads(stmt.init, out)
    elif isinstance(stmt, AssignmentStmt):
        if not isinstance(stmt.target, Identifier):
            _collect_expression_reads(stmt.target, out)
        _collect_expression_reads(stmt.value, out)
    elif isinstance(stmt, IfStmt):
        _collect_expression_reads(stmt.condition, out)
        for inner in stmt.then:
            _collect_statement_reads(inner, out)
        for inner in stmt.else_ or []:
            _collect_statement_reads(inner, out)
    elif isinstance(stmt, ForStmt):
        if stmt.init is not None:
            _collect_statement_reads(stmt.init, out)
        _collect_expression_reads(stmt.condition, out)
        if stmt.update is not None:
            _collect_statement_reads(stmt.update, out)
        for inner in stmt.body:
            _collect_statement_reads(inner, out)
    elif isinstance(stmt, ReturnStmt):
        _collect_expression_reads(stmt.value, out)
    elif isinstance(stmt, ExpressionStmt):
        _collect_expression_reads(stmt.expr, out)


def _collect_expression_reads(expr: Expression | None, out: set[str]) -> None:
    """Collect every identifier an expression reads."""
    if expr is None:
        return
    if isinstance(expr, Identifier):
        out.add(expr.name)
    elif isinstance(expr, BinaryExpr):
        _collect_expression_reads(expr.left, out)
        _collect_expression_reads(expr.right, out)
    elif isinstance(expr, UnaryExpr):
        _collect_expression_reads(expr.operand, out)
    elif isinstance(expr, CallExpr):
        _collect_expression_reads(expr.callee, out)
        for a in expr.args:
            _collect_expression_reads(a, out)
    elif isinstance(expr, MemberExpr):
        _collect_expression_reads(expr.object, out)
    elif isinstance(expr, TernaryExpr):
        _collect_expression_reads(expr.condition, out)
        _collect_expression_reads(expr.consequent, out)
        _collect_expression_reads(expr.alternate, out)
    elif isinstance(expr, IndexAccessExpr):
        _collect_expression_reads(expr.object, out)
        _collect_expression_reads(expr.index, out)
    elif isinstance(expr, (IncrementExpr, DecrementExpr)):
        _collect_expression_reads(expr.operand, out)
    elif isinstance(expr, ArrayLiteralExpr):
        for e in expr.elements:
            _collect_expression_reads(e, out)
    # Literals and ``this.x`` property access read no locals.


def _branch_output_rejection_reason(
    then_ctx: "_LowerCtx",
    else_ctx: "_LowerCtx",
    then_output_bytes: str,
    else_output_bytes: str,
    merged_locals: list[str],
    reads_after: frozenset[str],
) -> str | None:
    """Why an ``if`` whose arms declare outputs cannot be represented -- or
    ``None`` when it can. The result is the reason clause the diagnostic embeds.

    An ``if`` expression carries exactly ONE value, and when an arm emits an
    output that value is already spoken for: it is the output bytes the
    continuation hash consumes (``_append_branch_output_concat``). Anything ELSE
    the arm leaves behind breaks one of two invariants nothing downstream
    enforces:

    INV-A
        the parent registers the if-expression's value as the branch's
        contribution to the continuation hash, so "the branch's output bytes"
        really means "whatever the arm's LAST binding is". A binding that lands
        after the output -- a rebound local, a property write -- silently
        replaces the serialized output with an unrelated value, and the residue
        drain then physically drops the real output because it is no longer on
        top.
    INV-B
        an arm that emits an output AND leaves any other slot the parent can
        still name -- a property write anywhere in the arm, or a rebound local
        that is still read after the ``if`` -- leaves 2+ results against the ONE
        stackMap name the stack lowerer registers, desyncing the parent stack by
        a slot from there on. The residue drain cannot save it: it filters BY
        NAME and those names are all pre-``if`` names.

    Neither is visible off-chain, so both shipped as permanently unspendable
    locking scripts. Refuse at compile time rather than emit one. See
    packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
    for the real-Script-VM proof of each shape.

    The clauses are checked in a fixed order so all seven tiers report the same
    reason for a source that trips more than one.
    """
    # 1. Two or more merged locals: normalising them would need a multi-result
    #    ``if`` node, and the arms' single value is already the output concat.
    if len(merged_locals) >= 2:
        return (
            f"merges {len(merged_locals)} local variables "
            f"({', '.join(merged_locals)})"
        )

    arms = (("then", then_ctx, then_output_bytes), ("else", else_ctx, else_output_bytes))

    # 2. INV-A: the arm's terminal binding must BE its output bytes.
    for label, branch_ctx, output_bytes in arms:
        if not branch_ctx.bindings or branch_ctx.bindings[-1].name != output_bytes:
            return f"continues past its output in the {label}-branch"

    # 3. INV-B: a property write leaves a slot the parent can still name,
    #    wherever in the arm it sits.
    written_props: list[str] = []
    for _, branch_ctx, _ in arms:
        _collect_updated_props(branch_ctx.bindings, written_props)
    if written_props:
        return (
            f"assigns contract properties ({', '.join(written_props)}) "
            "inside the branch"
        )

    # 4. INV-B: a rebound local that survives the ``if`` is protected from being
    #    rolled away, so the arm ends one slot deeper than lowerIf accounts for.
    live_merged = [name for name in merged_locals if name in reads_after]
    if live_merged:
        return f"reassigns local variables read after it ({', '.join(live_merged)})"

    return None


def _collect_updated_props(bindings: list[ANFBinding], out: list[str]) -> None:
    """Append every property name an ANF binding list assigns, including the
    ones nested inside an ``if`` arm or a ``loop`` body -- a nested write is just
    as much a named slot the enclosing arm leaves behind.
    """
    for binding in bindings:
        value = binding.value
        if value.kind == "update_prop":
            if value.name not in out:
                out.append(value.name)
        elif value.kind == "if":
            _collect_updated_props(value.then or [], out)
            _collect_updated_props(value.else_ or [], out)
        elif value.kind == "loop":
            _collect_updated_props(value.body or [], out)


def _make_assert(value_ref: str) -> ANFValue:
    raw = json.dumps(value_ref)
    return ANFValue(
        kind="assert",
        raw_value=raw,
        value_ref=value_ref,
    )


def _make_auto_injected_state_check_assert(value_ref: str) -> ANFValue:
    """Build the auto-injected stateful-continuation hash-equality assert.

    Carries ``is_auto_injected_state_check=True`` so off-chain SDK
    interpreters can skip the equality check via a direct marker lookup
    instead of structural / taint heuristics that misfire on developer
    code with identical IR shape (covenant rules, e.g.
    ``examples/rust/covenant-vault``).
    """
    raw = json.dumps(value_ref)
    return ANFValue(
        kind="assert",
        raw_value=raw,
        value_ref=value_ref,
        is_auto_injected_state_check=True,
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
# addDataOutput detection (distinct from state outputs)
# ---------------------------------------------------------------------------

def _method_has_add_data_output(method) -> bool:
    """Check if a method body contains any this.addDataOutput() calls."""
    return _body_has_add_data_output(method.body)


def _body_has_add_data_output(stmts: list[Statement]) -> bool:
    return any(_stmt_has_add_data_output(stmt) for stmt in stmts)


def _stmt_has_add_data_output(stmt: Statement) -> bool:
    if isinstance(stmt, ExpressionStmt):
        return _expr_has_add_data_output(stmt.expr)
    if isinstance(stmt, IfStmt):
        if _body_has_add_data_output(stmt.then):
            return True
        if stmt.else_ and _body_has_add_data_output(stmt.else_):
            return True
        return False
    if isinstance(stmt, ForStmt):
        return _body_has_add_data_output(stmt.body)
    return False


def _expr_has_add_data_output(expr: Expression | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, CallExpr):
        callee = expr.callee
        if isinstance(callee, PropertyAccessExpr) and callee.property == "addDataOutput":
            return True
        if isinstance(callee, MemberExpr):
            if (
                isinstance(callee.object, Identifier)
                and callee.object.name == "this"
                and callee.property == "addDataOutput"
            ):
                return True
    return False


# ---------------------------------------------------------------------------
# Loop count extraction
# ---------------------------------------------------------------------------

def _extract_loop_shape(stmt: ForStmt) -> tuple[int, int, int]:
    """Resolve a for-statement's compile-time loop shape (issue #121).

    Supports counting-up and counting-down loops::

        for (let i = 0n; i < 10n; i++)     -> start 0,  step +1, count 10
        for (let i = 1n; i <= 3n; i++)     -> start 1,  step +1, count 3
        for (let i = 3n; i > 0n; i--)      -> start 3,  step -1, count 3
        for (let i = 3n; i >= 1n; i--)     -> start 3,  step -1, count 3

    The loop is unrolled ``count`` times; on iteration ``i`` the iterator holds
    ``start + i * step``. Start and bound must be compile-time integer literals.

    Returns ``(start, step, count)``.
    """
    start = _extract_bigint_value(stmt.init.init if stmt.init else None)
    if start is None:
        raise ValueError(
            "Cannot determine loop start at compile time. For-loop iterators "
            "must start at an integer literal."
        )

    if not isinstance(stmt.condition, BinaryExpr):
        raise ValueError(
            "Cannot determine loop bound at compile time. For-loop bounds must "
            "be integer literals."
        )
    op = stmt.condition.op
    bound = _extract_bigint_value(stmt.condition.right)
    if bound is None:
        raise ValueError(
            "Cannot determine loop bound at compile time. For-loop bounds must "
            "be integer literals."
        )

    step = _extract_loop_step(stmt)

    # Count = number of iterations before the condition first turns false.
    if step == 1:
        if op == "<":
            count = bound - start
        elif op == "<=":
            count = bound - start + 1
        else:
            raise ValueError(
                f"For loop counting up (i++) must use '<' or '<=' (got '{op}')."
            )
    else:
        if op == ">":
            count = start - bound
        elif op == ">=":
            count = start - bound + 1
        else:
            raise ValueError(
                f"For loop counting down (i--) must use '>' or '>=' (got '{op}')."
            )

    return start, step, max(0, count)


def _extract_loop_step(stmt: ForStmt) -> int:
    """Determine the iterator step direction (+1 / -1) from the for-statement's
    update clause, falling back to the condition direction. Only unit steps are
    supported; a non-unit update (e.g. ``i += 2``) is out of the loop model.
    """
    update = stmt.update
    if isinstance(update, ExpressionStmt):
        e = update.expr
        if isinstance(e, IncrementExpr):
            return 1
        if isinstance(e, DecrementExpr):
            return -1
    # Fall back to the comparison direction for other unit-step spellings
    # (e.g. ``i = i + 1n``): ``<``/``<=`` counts up, ``>``/``>=`` counts down.
    if isinstance(stmt.condition, BinaryExpr):
        if stmt.condition.op in (">", ">="):
            return -1
    return 1


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


def _strip_declared_results(
    bindings: list[ANFBinding], results: list[str] | None
) -> list[ANFBinding]:
    """An arm with its declared-results block removed.

    ``_append_branch_results`` adds exactly ``2 * len(results)`` trailing
    bindings to each arm of an ``if`` that declares results. They are a
    materialisation mechanism, not program logic, and they hide the arm's real
    shape from this pass. A dispatch chain's deepest ``if`` is nested by
    definition, so it declares results; without this the enclosing chain stops
    being recognised and TicTacToe's position dispatch loses the C20 lift (an
    unspendable ``move`` script).
    """
    n = len(results) if results else 0
    if n == 0:
        return bindings
    return bindings[: max(0, len(bindings) - 2 * n)]


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
            _strip_declared_results(last_else.value.then or [], last_else.value.results),
            _strip_declared_results(last_else.value.else_ or [], last_else.value.results),
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
    new_v.start = value.start
    new_v.step = value.step
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
            _strip_declared_results(if_val.then or [], if_val.results),
            _strip_declared_results(if_val.else_ or [], if_val.results),
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

        # 2b. C20 — preserve a dropped terminal `assert(false)` else.
        #
        # `_collect_update_branches` transforms a dispatch chain whose branches
        # each end in a single `update_prop` into this flat conditional-assignment
        # form. When the chain's terminal else is `assert(false)` it returns the
        # branches WITHOUT a catch-all final branch (every branch keeps a non-null
        # cond_ref), dropping the abort. But that assert(false) is the ONLY thing
        # rejecting a selector value that matches no branch: without it, an
        # unmatched selector leaves every property at its old value — a spendable
        # NO-OP state continuation instead of a failed script (a funds-safety bug).
        #
        # A real final else (`else { prop = ... }`) instead yields a catch-all
        # branch with cond_ref is None, and needs no guard because every selector
        # value maps to some branch. So the presence of a None-cond_ref terminal
        # branch exactly distinguishes the two cases.
        #
        # Re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`:
        # if no branch condition held, the OR is false and the script aborts —
        # byte-identical to the original `assert(false)` semantics for the
        # unmatched position, and a no-op (`assert(true)`) whenever a branch runs.
        has_catch_all_else = branches[-1].cond_ref is None
        if not has_catch_all_else:
            # Every branch here has a non-null cond_ref (only a catch-all final
            # else is None, and there is none), so the OR fully covers the
            # selector space.
            or_ref = cond_refs[0]
            for i in range(1, len(cond_refs)):
                or_name = fresh()
                result.append(ANFBinding(
                    name=or_name,
                    value=ANFValue(
                        kind="bin_op",
                        op="||",
                        left=or_ref,
                        right=cond_refs[i],
                    ),
                ))
                or_ref = or_name
            result.append(ANFBinding(
                name=fresh(),
                value=_make_assert(or_ref),
            ))

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
