"""Op-shape parity tests for the Python ``checkSig`` and ``checkMultiSig``
builtins.

  * ``checkSig(sig, pubkey)``      -> [OP_CHECKSIG]      (table-driven)
  * ``checkMultiSig(sigs, pks)``   -> custom lowering (``_lower_check_multi_sig``)
                                     emits [OP_0, sigs.., nSigs, pks.., nPKs,
                                            OP_CHECKMULTISIG]

For checkSig the lowering is a single OP_CHECKSIG. For checkMultiSig the
lowering must:

  1. Push OP_0 dummy first (workaround for the well-known Bitcoin off-by-one
     bug in OP_CHECKMULTISIG).
  2. Place the signature array on the stack (already laid out by
     array_literal lowering of the sigs argument).
  3. Push the count nSigs.
  4. Place the pubkey array on the stack.
  5. Push the count nPKs.
  6. Emit OP_CHECKMULTISIG.

Tests drive the lowering with hand-built ANF programs that mirror the
inputs the frontend would produce.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.stack import (
    StackMethod,
    StackOp,
    lower_to_stack,
)
from runar_compiler.codegen.emit import emit_method
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


def _is_push_int(op: StackOp, n: int) -> bool:
    return (
        op.op == "push"
        and op.value is not None
        and op.value.kind == "bigint"
        and op.value.big_int == n
    )


# ---------------------------------------------------------------------------
# checkSig: 2-arg call lowers to a single OP_CHECKSIG.
# ---------------------------------------------------------------------------

def _build_check_sig_program() -> ANFProgram:
    body: list[ANFBinding] = [
        ANFBinding(name="a0", value=ANFValue(kind="load_param", name="sig")),
        ANFBinding(name="a1", value=ANFValue(kind="load_param", name="pk")),
        ANFBinding(
            name="r",
            value=ANFValue(kind="call", func="checkSig", args=["a0", "a1"]),
        ),
        ANFBinding(name="_assert", value=ANFValue(kind="assert", value_ref="r")),
    ]
    return ANFProgram(
        contract_name="CheckSigProbe",
        properties=[],
        methods=[
            ANFMethod(
                name="unlock",
                params=[
                    ANFParam(name="sig", type="Sig"),
                    ANFParam(name="pk", type="PubKey"),
                ],
                body=body,
                is_public=True,
            )
        ],
    )


class TestCheckSig:
    def test_emits_op_checksig_as_final_opcode(self):
        methods = lower_to_stack(_build_check_sig_program())
        unlock = next(m for m in methods if m.name == "unlock")
        # The very last op must be OP_CHECKSIG (the table maps checkSig -> [OP_CHECKSIG]).
        assert _is_opcode(unlock.ops[-1], "OP_CHECKSIG"), (
            f"checkSig must end with OP_CHECKSIG; got {unlock.ops[-1]!r}"
        )

    def test_emits_exactly_one_op_checksig(self):
        methods = lower_to_stack(_build_check_sig_program())
        unlock = next(m for m in methods if m.name == "unlock")
        check_sigs = [op for op in unlock.ops if _is_opcode(op, "OP_CHECKSIG")]
        assert len(check_sigs) == 1, (
            f"expected exactly 1 OP_CHECKSIG, got {len(check_sigs)}"
        )

    def test_does_not_emit_op_checkmultisig(self):
        methods = lower_to_stack(_build_check_sig_program())
        unlock = next(m for m in methods if m.name == "unlock")
        cms = [op for op in unlock.ops if _is_opcode(op, "OP_CHECKMULTISIG")]
        assert len(cms) == 0, (
            f"checkSig must not emit OP_CHECKMULTISIG; got {len(cms)}"
        )

    def test_op_checksig_byte_value_in_emitted_hex(self):
        """OP_CHECKSIG = 0xac. The emitted hex must end with 'ac'."""
        methods = lower_to_stack(_build_check_sig_program())
        unlock = next(m for m in methods if m.name == "unlock")
        res = emit_method(unlock)
        assert res.script_hex.endswith("ac"), (
            f"emitted hex must end with 'ac' (OP_CHECKSIG); got {res.script_hex[-4:]!r}"
        )


# ---------------------------------------------------------------------------
# checkMultiSig: bespoke lowering with OP_0 dummy + counts.
# ---------------------------------------------------------------------------

def _build_check_multi_sig_program(n_sigs: int, n_pks: int) -> ANFProgram:
    """Build a minimal program::

        sig0 = load_param(s0); sig1 = load_param(s1); ...
        pk0 = load_param(k0); pk1 = load_param(k1); ...
        sigs = array_literal([sig0, sig1, ...])
        pks = array_literal([pk0, pk1, ...])
        r = checkMultiSig(sigs, pks)
        assert(r)
    """
    sig_params = [ANFParam(name=f"s{i}", type="Sig") for i in range(n_sigs)]
    pk_params = [ANFParam(name=f"k{i}", type="PubKey") for i in range(n_pks)]

    body: list[ANFBinding] = []
    for i in range(n_sigs):
        body.append(
            ANFBinding(name=f"sig{i}", value=ANFValue(kind="load_param", name=f"s{i}"))
        )
    for i in range(n_pks):
        body.append(
            ANFBinding(name=f"pk{i}", value=ANFValue(kind="load_param", name=f"k{i}"))
        )
    body.append(
        ANFBinding(
            name="sigs",
            value=ANFValue(
                kind="array_literal",
                elements=[f"sig{i}" for i in range(n_sigs)],
            ),
        )
    )
    body.append(
        ANFBinding(
            name="pks",
            value=ANFValue(
                kind="array_literal",
                elements=[f"pk{i}" for i in range(n_pks)],
            ),
        )
    )
    body.append(
        ANFBinding(
            name="r",
            value=ANFValue(kind="call", func="checkMultiSig", args=["sigs", "pks"]),
        )
    )
    body.append(ANFBinding(name="_assert", value=ANFValue(kind="assert", value_ref="r")))

    return ANFProgram(
        contract_name="CheckMultiSigProbe",
        properties=[],
        methods=[
            ANFMethod(
                name="unlock",
                params=sig_params + pk_params,
                body=body,
                is_public=True,
            )
        ],
    )


class TestCheckMultiSig:
    def test_2_of_3_emits_op_checkmultisig(self):
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        cms = [op for op in unlock.ops if _is_opcode(op, "OP_CHECKMULTISIG")]
        assert len(cms) == 1, (
            f"expected exactly 1 OP_CHECKMULTISIG, got {len(cms)}"
        )

    def test_2_of_3_emits_op_checkmultisig_as_final_opcode(self):
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        assert _is_opcode(unlock.ops[-1], "OP_CHECKMULTISIG"), (
            f"checkMultiSig must end with OP_CHECKMULTISIG; got {unlock.ops[-1]!r}"
        )

    def test_2_of_3_pushes_n_sigs_count_2(self):
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        # The nSigs count must be pushed as the literal 2.
        twos = [op for op in unlock.ops if _is_push_int(op, 2)]
        assert len(twos) >= 1, (
            f"checkMultiSig must push nSigs=2; got pushes-of-2: {len(twos)}"
        )

    def test_2_of_3_pushes_n_pks_count_3(self):
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        threes = [op for op in unlock.ops if _is_push_int(op, 3)]
        assert len(threes) >= 1, (
            f"checkMultiSig must push nPKs=3; got pushes-of-3: {len(threes)}"
        )

    def test_emits_op_0_dummy_for_off_by_one_workaround(self):
        """OP_CHECKMULTISIG has the well-known off-by-one bug: it consumes one
        extra item below the signatures. The Rúnar lowering pushes OP_0 (a 0
        bigint) as the dummy at the BASE of the sig array.
        """
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        zeros = [op for op in unlock.ops if _is_push_int(op, 0)]
        assert len(zeros) >= 1, (
            "checkMultiSig must push OP_0 dummy (workaround for off-by-one bug)"
        )

    def test_does_not_emit_op_checksig(self):
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        # OP_CHECKSIG must not appear -- the multi-sig path uses CHECKMULTISIG.
        css = [op for op in unlock.ops if _is_opcode(op, "OP_CHECKSIG")]
        assert len(css) == 0, (
            f"checkMultiSig must not emit OP_CHECKSIG; got {len(css)}"
        )

    def test_op_checkmultisig_byte_value_in_emitted_hex(self):
        """OP_CHECKMULTISIG = 0xae. The emitted hex must end with 'ae'."""
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=2, n_pks=3))
        unlock = next(m for m in methods if m.name == "unlock")
        res = emit_method(unlock)
        assert res.script_hex.endswith("ae"), (
            f"emitted hex must end with 'ae' (OP_CHECKMULTISIG); got {res.script_hex[-4:]!r}"
        )

    def test_3_of_5_changes_pushed_counts(self):
        """Bumping the threshold updates the nSigs / nPKs pushes proportionally
        -- a regression that ignored array_lengths would emit the wrong counts.
        """
        methods = lower_to_stack(_build_check_multi_sig_program(n_sigs=3, n_pks=5))
        unlock = next(m for m in methods if m.name == "unlock")
        threes = [op for op in unlock.ops if _is_push_int(op, 3)]
        fives = [op for op in unlock.ops if _is_push_int(op, 5)]
        assert len(threes) >= 1, "must push nSigs=3"
        assert len(fives) >= 1, "must push nPKs=5"
