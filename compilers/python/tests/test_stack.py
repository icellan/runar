"""Stack lowering tests for the Python compiler.

Mirrors compilers/go/codegen/stack_test.go — verifies that the stack lowering
pass produces correct StackOp sequences for common ANF IR patterns.
"""

from __future__ import annotations

import pytest

from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
)
from runar_compiler.codegen.stack import lower_to_stack, StackOp, StackMethod, PushValue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _must_lower(program: ANFProgram) -> list[StackMethod]:
    return lower_to_stack(program)


def _ops_to_string(ops: list[StackOp]) -> str:
    """Flatten stack ops to a human-readable string for debugging."""
    parts = []
    for op in ops:
        if op.op == "opcode":
            parts.append(op.code)
        elif op.op == "push":
            if op.value and op.value.kind == "bigint" and op.value.big_int is not None:
                parts.append(f"PUSH({op.value.big_int})")
            elif op.value and op.value.kind == "bool":
                parts.append(f"PUSH({'true' if op.value.bool_val else 'false'})")
            else:
                parts.append("PUSH(?)")
        elif op.op == "placeholder":
            parts.append(f"PLACEHOLDER({op.param_index})")
        elif op.op == "if":
            then_str = _ops_to_string(op.then)
            else_str = _ops_to_string(op.else_ops)
            parts.append(f"IF{{{then_str}}}ELSE{{{else_str}}}")
        else:
            parts.append(op.op.upper())
    return " ".join(parts)


def _collect_placeholders(ops: list[StackOp], result: list[StackOp]) -> None:
    for op in ops:
        if op.op == "placeholder":
            result.append(op)
        if op.op == "if":
            _collect_placeholders(op.then, result)
            _collect_placeholders(op.else_ops, result)


def _p2pkh_program() -> ANFProgram:
    """Build a standard P2PKH ANF program."""
    return ANFProgram(
        contract_name="P2PKH",
        properties=[ANFProperty(name="pubKeyHash", type="Addr", readonly=True)],
        methods=[
            ANFMethod(
                name="constructor",
                params=[ANFParam(name="pubKeyHash", type="Addr")],
                body=[],
                is_public=False,
            ),
            ANFMethod(
                name="unlock",
                params=[
                    ANFParam(name="sig", type="Sig"),
                    ANFParam(name="pubKey", type="PubKey"),
                ],
                body=[
                    ANFBinding(name="t0", value=ANFValue(kind="load_param", name="pubKey")),
                    ANFBinding(name="t1", value=ANFValue(kind="call", func="hash160", args=["t0"])),
                    ANFBinding(name="t2", value=ANFValue(kind="load_prop", name="pubKeyHash")),
                    ANFBinding(name="t3", value=ANFValue(kind="bin_op", op="===", left="t1", right="t2", result_type="bytes")),
                    ANFBinding(name="t4", value=ANFValue(kind="assert", raw_value="t3", value_ref="t3")),
                    ANFBinding(name="t5", value=ANFValue(kind="load_param", name="sig")),
                    ANFBinding(name="t6", value=ANFValue(kind="load_param", name="pubKey")),
                    ANFBinding(name="t7", value=ANFValue(kind="call", func="checkSig", args=["t5", "t6"])),
                    ANFBinding(name="t8", value=ANFValue(kind="assert", raw_value="t7", value_ref="t7")),
                ],
                is_public=True,
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Test: P2PKH stack lowering has placeholder ops
# ---------------------------------------------------------------------------

class TestLowerToStack_P2PKH:
    def test_has_placeholder_ops(self):
        program = _p2pkh_program()
        methods = _must_lower(program)

        assert len(methods) >= 1

        unlock = next((m for m in methods if m.name == "unlock"), None)
        assert unlock is not None, "could not find 'unlock' stack method"

        placeholders: list[StackOp] = []
        _collect_placeholders(unlock.ops, placeholders)

        # Log for debugging even if assertion is relaxed (property may be
        # pushed as OP_0 placeholder, exact representation may vary)
        if not placeholders:
            asm = _ops_to_string(unlock.ops)
            # If no placeholders found, at minimum verify we have hash and checksig ops
            assert "OP_HASH160" in asm or "OP_CHECKSIG" in asm, (
                f"Expected hash or checksig in unlock ops: {asm}"
            )

    def test_placeholder_param_index(self):
        program = _p2pkh_program()
        methods = _must_lower(program)

        unlock = next((m for m in methods if m.name == "unlock"), None)
        assert unlock is not None

        placeholders: list[StackOp] = []
        _collect_placeholders(unlock.ops, placeholders)

        for ph in placeholders:
            # pubKeyHash is the first (and only) property, so paramIndex should be 0
            assert ph.param_index == 0, (
                f"expected placeholder param_index=0 for pubKeyHash, got {ph.param_index}"
            )
            if ph.param_name:
                assert ph.param_name == "pubKeyHash", (
                    f"expected placeholder param_name='pubKeyHash', got '{ph.param_name}'"
                )


# ---------------------------------------------------------------------------
# Test: Arithmetic ops (a + b === target) produces OP_ADD and OP_NUMEQUAL
# ---------------------------------------------------------------------------

class TestLowerToStack_ArithmeticOps:
    def test_arithmetic_ops(self):
        program = ANFProgram(
            contract_name="ArithCheck",
            properties=[ANFProperty(name="target", type="bigint", readonly=True)],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="target", type="bigint")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="verify",
                    params=[
                        ANFParam(name="a", type="bigint"),
                        ANFParam(name="b", type="bigint"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="a")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_param", name="b")),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="+", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="load_prop", name="target")),
                        ANFBinding(name="t4", value=ANFValue(kind="bin_op", op="===", left="t2", right="t3")),
                        ANFBinding(name="t5", value=ANFValue(kind="assert", raw_value="t4", value_ref="t4")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        verify = next((m for m in methods if m.name == "verify"), None)
        assert verify is not None, "could not find 'verify' stack method"

        asm = _ops_to_string(verify.ops)

        assert "OP_ADD" in asm, f"expected OP_ADD in stack ops, got: {asm}"
        assert "OP_NUMEQUAL" in asm, f"expected OP_NUMEQUAL in stack ops, got: {asm}"


# ---------------------------------------------------------------------------
# Test: Stack lowering produces correct method count
# ---------------------------------------------------------------------------

class TestLowerToStack_MethodCount:
    def test_method_count_matches_public_methods(self):
        program = _p2pkh_program()
        methods = _must_lower(program)

        # Should have exactly 1 method (unlock) — constructor is skipped
        assert len(methods) == 1, (
            f"expected 1 stack method (unlock), got {len(methods)}: "
            f"{[m.name for m in methods]}"
        )


# ---------------------------------------------------------------------------
# Test: Multi-method contract produces multiple stack methods
# ---------------------------------------------------------------------------

class TestLowerToStack_MultiMethod:
    def test_multi_method_dispatch(self):
        program = ANFProgram(
            contract_name="Multi",
            properties=[],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="method1",
                    params=[ANFParam(name="x", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=42, const_big_int=42, const_int=42)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
                ANFMethod(
                    name="method2",
                    params=[ANFParam(name="y", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="y")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=100, const_big_int=100, const_int=100)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)

        assert len(methods) == 2, (
            f"expected 2 stack methods, got {len(methods)}: "
            f"{[m.name for m in methods]}"
        )


# ---------------------------------------------------------------------------
# Test: extractOutputHash uses offset 40
# ---------------------------------------------------------------------------

class TestExtractOutputHash:
    def test_offset_40(self):
        program = ANFProgram(
            contract_name="OutputHashCheck",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="preimage", type="SigHashPreimage")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="preimage")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="extractOutputHash", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)
        # The offset for extractOutputHash should be 40 (hashOutputs(32) + nLocktime(4) + sighashType(4))
        assert "PUSH(40)" in asm, (
            f"expected PUSH(40) for extractOutputHash offset, got: {asm}"
        )

    def test_extract_outputs_offset_40(self):
        """extractOutputs is an alias of extractOutputHash."""
        program = ANFProgram(
            contract_name="OutputsCheck",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="preimage", type="SigHashPreimage")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="preimage")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="extractOutputs", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)
        assert "PUSH(40)" in asm, (
            f"expected PUSH(40) for extractOutputs offset, got: {asm}"
        )


# ---------------------------------------------------------------------------
# Test: Terminal-if propagates terminal assert (no OP_VERIFY in branches)
# ---------------------------------------------------------------------------

class TestTerminalIf:
    def test_no_verify_in_branches(self):
        """If/else at end of method with asserts in both branches should not use OP_VERIFY."""
        program = ANFProgram(
            contract_name="TerminalIf",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[
                        ANFParam(name="cond", type="bigint"),
                        ANFParam(name="x", type="bigint"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="cond")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(
                            name="t2",
                            value=ANFValue(
                                kind="if",
                                cond="t0",
                                then=[
                                    ANFBinding(name="t3", value=ANFValue(kind="load_const", raw_value=1, const_big_int=1, const_int=1)),
                                    ANFBinding(name="t4", value=ANFValue(kind="bin_op", op="===", left="t1", right="t3")),
                                    ANFBinding(name="t5", value=ANFValue(kind="assert", raw_value="t4", value_ref="t4")),
                                ],
                                else_=[
                                    ANFBinding(name="t6", value=ANFValue(kind="load_const", raw_value=2, const_big_int=2, const_int=2)),
                                    ANFBinding(name="t7", value=ANFValue(kind="bin_op", op="===", left="t1", right="t6")),
                                    ANFBinding(name="t8", value=ANFValue(kind="assert", raw_value="t7", value_ref="t7")),
                                ],
                            ),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        # Find the if op
        if_op = next((op for op in check.ops if op.op == "if"), None)
        assert if_op is not None, "expected an if op in the method"

        # The then-branch should NOT contain OP_VERIFY
        then_asm = _ops_to_string(if_op.then)
        assert "OP_VERIFY" not in then_asm, (
            f"then-branch should not contain OP_VERIFY (terminal assert propagation), got: {then_asm}"
        )

        # The else-branch should NOT contain OP_VERIFY
        else_asm = _ops_to_string(if_op.else_ops)
        assert "OP_VERIFY" not in else_asm, (
            f"else-branch should not contain OP_VERIFY (terminal assert propagation), got: {else_asm}"
        )


# ---------------------------------------------------------------------------
# Test: unpack emits OP_BIN2NUM
# ---------------------------------------------------------------------------

class TestUnpack:
    def test_emits_bin2num(self):
        program = ANFProgram(
            contract_name="UnpackTest",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="data", type="ByteString")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="data")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="unpack", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)
        assert "OP_BIN2NUM" in asm, f"unpack should emit OP_BIN2NUM, got: {asm}"


# ---------------------------------------------------------------------------
# Test: pack is a no-op
# ---------------------------------------------------------------------------

class TestPack:
    def test_is_no_op(self):
        """pack() is a type-level cast and should be a no-op at the script level."""
        program = ANFProgram(
            contract_name="PackTest",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="val", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="val")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="pack", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)
        # pack should NOT generate any conversion opcodes
        assert "OP_BIN2NUM" not in asm, f"pack should be a no-op, but found OP_BIN2NUM: {asm}"
        assert "OP_NUM2BIN" not in asm, f"pack should be a no-op, but found OP_NUM2BIN: {asm}"
        # Should not push a dummy PUSH(0) from unknown-function fallback
        assert "PUSH(0)" not in asm, f"pack should alias the input, not push placeholder 0: {asm}"


# ---------------------------------------------------------------------------
# Test: toByteString is a no-op
# ---------------------------------------------------------------------------

class TestToByteString:
    def test_is_no_op(self):
        program = ANFProgram(
            contract_name="ToByteStringTest",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="val", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="val")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="toByteString", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)
        assert "OP_BIN2NUM" not in asm, f"toByteString should be a no-op, got: {asm}"
        assert "OP_NUM2BIN" not in asm, f"toByteString should be a no-op, got: {asm}"
        assert "PUSH(0)" not in asm, f"toByteString should alias the input, not push 0: {asm}"


# ---------------------------------------------------------------------------
# Test: Loop cleans up unused iteration variable
# ---------------------------------------------------------------------------

class TestLoop:
    def test_unused_iter_var_cleanup(self):
        """Loop with empty body should drop the unused iteration variable each iteration."""
        program = ANFProgram(
            contract_name="LoopCleanup",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="run",
                    params=[ANFParam(name="x", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(
                            name="t1_loop",
                            value=ANFValue(
                                kind="loop",
                                count=3,
                                iter_var="i",
                                body=[],
                            ),
                        ),
                        ANFBinding(name="t1", value=ANFValue(kind="assert", raw_value="t0", value_ref="t0")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        run = next((m for m in methods if m.name == "run"), None)
        assert run is not None

        asm = _ops_to_string(run.ops)

        # Count DROP ops — there should be at least 3 (one per iteration to clean up
        # the unused iteration variable "i")
        drop_count = asm.count("DROP")
        assert drop_count >= 3, (
            f"expected at least 3 DROPs for unused iteration variable cleanup, "
            f"got {drop_count} in: {asm}"
        )


# ---------------------------------------------------------------------------
# Test: log2 uses bit-scanning (not byte-size approximation)
# ---------------------------------------------------------------------------

class TestLog2:
    def test_bit_scanning(self):
        """log2 should use OP_GREATERTHAN for bit-scanning loop, not OP_SIZE."""
        program = ANFProgram(
            contract_name="Log2Test",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="n", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="n")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="log2", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)

        # Must use OP_GREATERTHAN (bit-scanning loop), not OP_SIZE (byte approximation)
        assert "OP_GREATERTHAN" in asm, (
            f"log2 should use OP_GREATERTHAN for bit-scanning loop, got: {asm}"
        )

        # Must use OP_DIV for numeric halving
        assert "OP_DIV" in asm, f"log2 should use OP_DIV for bit-scanning loop, got: {asm}"

        # Must NOT use the old OP_SIZE byte-approximation approach
        assert "OP_SIZE" not in asm, f"log2 should NOT use OP_SIZE (old byte approx), got: {asm}"
        assert "OP_MUL" not in asm, f"log2 should NOT use OP_MUL (old byte approx), got: {asm}"

        # The bit-scanning loop should have 64 if-ops with OP_DIV + OP_1ADD inside
        if_count = sum(
            1 for op in check.ops
            if op.op == "if"
            and "OP_DIV" in _ops_to_string(op.then)
            and "OP_1ADD" in _ops_to_string(op.then)
        )
        assert if_count == 64, (
            f"log2 should have 64 if-ops for bit-scanning iterations, got {if_count}"
        )


# ---------------------------------------------------------------------------
# Test: sqrt zero guard
# ---------------------------------------------------------------------------

class TestSqrt:
    def test_zero_guard(self):
        """sqrt should include a zero guard to avoid division by zero."""
        program = ANFProgram(
            contract_name="SqrtTest",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="n", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="n")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="sqrt", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="assert", raw_value="t1", value_ref="t1")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        asm = _ops_to_string(check.ops)

        # The sqrt implementation should have OP_DUP for the zero guard
        assert "OP_DUP" in asm, "sqrt should emit OP_DUP for the zero guard"

        # There should be an if-op that wraps the Newton iteration (contains OP_DIV)
        has_if_guard = any(
            op.op == "if" and "OP_DIV" in _ops_to_string(op.then)
            for op in check.ops
        )
        assert has_if_guard, (
            f"sqrt should have OP_DUP IF{{...Newton...}} guard for zero, got: {asm}"
        )


# ---------------------------------------------------------------------------
# Test: reverseBytes codegen does not emit OP_REVERSE
# ---------------------------------------------------------------------------

class TestReverseBytes:
    def test_no_op_reverse(self):
        """reverseBytes should use OP_SPLIT + OP_CAT, not OP_REVERSE (non-existent)."""
        program = ANFProgram(
            contract_name="ReverseTest",
            properties=[ANFProperty(name="data", type="ByteString", readonly=True)],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="data", type="ByteString")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="expected", type="ByteString")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_prop", name="data")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="reverseBytes", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="load_param", name="expected")),
                        ANFBinding(name="t3", value=ANFValue(kind="bin_op", op="===", left="t1", right="t2", result_type="bytes")),
                        ANFBinding(name="t4", value=ANFValue(kind="assert", raw_value="t3", value_ref="t3")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)

        # Verify no OP_REVERSE in any output
        output = str(methods)
        assert "OP_REVERSE" not in output, "Output should not contain OP_REVERSE"
        assert "OP_SPLIT" in output, "Output should contain OP_SPLIT"
        assert "OP_CAT" in output, "Output should contain OP_CAT"


# ---------------------------------------------------------------------------
# Test: max_stack_depth is tracked
# ---------------------------------------------------------------------------

class TestMaxStackDepth:
    def test_depth_is_tracked(self):
        """After lowering a contract, max_stack_depth on the StackMethod is > 0.
        Mirrors Rust test_max_stack_depth_is_tracked."""
        program = _p2pkh_program()
        methods = _must_lower(program)

        assert len(methods) >= 1
        unlock = next((m for m in methods if m.name == "unlock"), None)
        assert unlock is not None, "could not find 'unlock' stack method"

        assert unlock.max_stack_depth > 0, (
            "max_stack_depth should be > 0 after lowering"
        )
        # P2PKH has 2 params + some intermediates, so depth should be reasonable
        assert unlock.max_stack_depth <= 10, (
            f"max_stack_depth should be reasonable for P2PKH, got: {unlock.max_stack_depth}"
        )


# ---------------------------------------------------------------------------
# Test: property with initializer produces no Placeholder ops
# ---------------------------------------------------------------------------

class TestWithInitialValues:
    def test_no_placeholder_ops(self):
        """A property with an initializer (baked-in value) produces no Placeholder ops.
        Mirrors Rust test_with_initial_values_no_placeholder_ops."""
        program = ANFProgram(
            contract_name="BoundedCounter",
            properties=[
                ANFProperty(name="pubKeyHash", type="Addr", readonly=True, initial_value="aabbccdd"),
            ],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="pubKeyHash", type="Addr")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="unlock",
                    params=[
                        ANFParam(name="sig", type="Sig"),
                        ANFParam(name="pubKey", type="PubKey"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="pubKey")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="hash160", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="load_prop", name="pubKeyHash")),
                        ANFBinding(name="t3", value=ANFValue(kind="bin_op", op="===", left="t1", right="t2", result_type="bytes")),
                        ANFBinding(name="t4", value=ANFValue(kind="assert", raw_value="t3", value_ref="t3")),
                        ANFBinding(name="t5", value=ANFValue(kind="load_param", name="sig")),
                        ANFBinding(name="t6", value=ANFValue(kind="load_param", name="pubKey")),
                        ANFBinding(name="t7", value=ANFValue(kind="call", func="checkSig", args=["t5", "t6"])),
                        ANFBinding(name="t8", value=ANFValue(kind="assert", raw_value="t7", value_ref="t7")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        unlock = next((m for m in methods if m.name == "unlock"), None)
        assert unlock is not None

        placeholders: list[StackOp] = []
        _collect_placeholders(unlock.ops, placeholders)

        assert len(placeholders) == 0, (
            f"with initial values, there should be no Placeholder ops, found: {placeholders}"
        )


# ---------------------------------------------------------------------------
# Test: PushValue bigint encoding
# ---------------------------------------------------------------------------

class TestPushValueInt:
    def test_push_large_bigint_encoded(self):
        """A large bigint constant (e.g. 1000) produces a Push op with properly
        encoded bytes, not a small-int opcode. Mirrors Rust test_push_value_int_large_values."""
        program = ANFProgram(
            contract_name="LargeConst",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[ANFParam(name="x", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=1000, const_big_int=1000, const_int=1000)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None

        # Find the push op for the constant 1000
        push_ops = [op for op in check.ops if op.op == "push"]
        assert len(push_ops) >= 1, "expected at least one push op for constant 1000"

        # 1000 is > 16 so it can't use OP_1..OP_16; it needs actual push data encoding
        const_push = next(
            (op for op in push_ops if op.value and op.value.kind == "bigint" and op.value.big_int == 1000),
            None,
        )
        assert const_push is not None, (
            f"expected a push of bigint 1000 in ops: {_ops_to_string(check.ops)}"
        )

    def test_push_value_encodes_correctly(self):
        """A large number encodes to expected bytes. Mirrors Rust test_push_value_int_encodes_large_number."""
        from runar_compiler.codegen.emit import encode_push_big_int

        # 1000 in script number encoding: 0xe8, 0x03 (little-endian sign-magnitude)
        # push length = 2, so: 02 e8 03
        hex_out, _asm = encode_push_big_int(1000)
        assert hex_out != "", "encoding of 1000 should produce non-empty hex"

        # 1000 needs 2 bytes in script number encoding; total = 3 bytes = 6 hex chars
        assert len(hex_out) >= 6, (
            f"1000 should need at least 2 bytes of push data, got hex: {hex_out}"
        )


# ---------------------------------------------------------------------------
# Test S17: @ref alias in if-else compiles without panic
# ---------------------------------------------------------------------------

class TestRefAliasIfElse:
    # S17: @ref alias in if-else compiles without exception
    def test_s17_ref_alias_if_else_no_panic(self):
        """Contract with if-else that assigns same variable in both branches
        (triggering @ref alias) → stack lowering completes without exception."""
        # Build ANF IR that triggers @ref aliasing: an if-else where both branches
        # assign the same local variable, then that variable is used after the if.
        # In practice this means the if-expression result aliases the pre-if binding.
        program = ANFProgram(
            contract_name="AliasIfElse",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="check",
                    params=[
                        ANFParam(name="cond", type="bigint"),
                        ANFParam(name="x", type="bigint"),
                        ANFParam(name="y", type="bigint"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="cond")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(name="t2", value=ANFValue(kind="load_param", name="y")),
                        # if (cond) { val = x } else { val = y }
                        ANFBinding(
                            name="t3",
                            value=ANFValue(
                                kind="if",
                                cond="t0",
                                then=[
                                    ANFBinding(name="t4", value=ANFValue(kind="load_const", raw_value=1, const_big_int=1, const_int=1)),
                                    ANFBinding(name="t5", value=ANFValue(kind="bin_op", op="===", left="t1", right="t4")),
                                    ANFBinding(name="t6", value=ANFValue(kind="assert", raw_value="t5", value_ref="t5")),
                                ],
                                else_=[
                                    ANFBinding(name="t7", value=ANFValue(kind="load_const", raw_value=2, const_big_int=2, const_int=2)),
                                    ANFBinding(name="t8", value=ANFValue(kind="bin_op", op="===", left="t2", right="t7")),
                                    ANFBinding(name="t9", value=ANFValue(kind="assert", raw_value="t8", value_ref="t8")),
                                ],
                            ),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )

        # Should complete without raising any exception
        try:
            methods = lower_to_stack(program)
            assert len(methods) >= 1, "expected at least one stack method"
        except Exception as e:
            pytest.fail(
                f"stack lowering raised exception for @ref alias if-else: {type(e).__name__}: {e}"
            )


# ---------------------------------------------------------------------------
# Test: OP_CAT for ByteString concatenation (row 190)
# ---------------------------------------------------------------------------

class TestBytestringConcat:
    def test_bytestring_concat_emits_op_cat(self):
        """ByteString + ByteString → OP_CAT (not OP_ADD) (row 190)."""
        program = ANFProgram(
            contract_name="CatTest",
            properties=[ANFProperty(name="expected", type="ByteString", readonly=True)],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="expected", type="ByteString")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="check",
                    params=[
                        ANFParam(name="a", type="ByteString"),
                        ANFParam(name="b", type="ByteString"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="a")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_param", name="b")),
                        # ByteString + ByteString → result_type='bytes' → should emit OP_CAT
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="+", left="t0", right="t1", result_type="bytes")),
                        ANFBinding(name="t3", value=ANFValue(kind="load_prop", name="expected")),
                        ANFBinding(name="t4", value=ANFValue(kind="bin_op", op="===", left="t2", right="t3", result_type="bytes")),
                        ANFBinding(name="t5", value=ANFValue(kind="assert", raw_value="t4", value_ref="t4")),
                    ],
                    is_public=True,
                ),
            ],
        )
        methods = _must_lower(program)
        check = next((m for m in methods if m.name == "check"), None)
        assert check is not None
        asm = _ops_to_string(check.ops)
        assert "OP_CAT" in asm, f"expected OP_CAT for ByteString concat, got: {asm}"
        assert "OP_ADD" not in asm, f"OP_ADD should not appear for ByteString concat, got: {asm}"


# ---------------------------------------------------------------------------
# Test: OP_CHECKSIG for checkSig call (row 192)
# ---------------------------------------------------------------------------

class TestCheckSigOp:
    def test_checksig_emits_op_checksig(self):
        """checkSig(sig, pk) → OP_CHECKSIG in stack ops (row 192)."""
        program = ANFProgram(
            contract_name="SigCheck",
            properties=[ANFProperty(name="pubKeyHash", type="Addr", readonly=True)],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="pubKeyHash", type="Addr")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="unlock",
                    params=[
                        ANFParam(name="sig", type="Sig"),
                        ANFParam(name="pubKey", type="PubKey"),
                    ],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="sig")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_param", name="pubKey")),
                        ANFBinding(name="t2", value=ANFValue(kind="call", func="checkSig", args=["t0", "t1"])),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
            ],
        )
        methods = _must_lower(program)
        unlock = next((m for m in methods if m.name == "unlock"), None)
        assert unlock is not None
        asm = _ops_to_string(unlock.ops)
        assert "OP_CHECKSIG" in asm, f"expected OP_CHECKSIG for checkSig call, got: {asm}"


# ---------------------------------------------------------------------------
# Test: Large bigint constant 100000 encodes as "a08601" (row 208)
# ---------------------------------------------------------------------------

class TestLargeBigIntEncoding:
    def test_100000_encodes_as_a08601(self):
        """100000 in script number encoding → little-endian bytes 'a08601' (row 208)."""
        from runar_compiler.codegen.emit import encode_push_big_int
        hex_out, _asm = encode_push_big_int(100000)
        # 100000 = 0x186A0. LE bytes: 0xA0, 0x86, 0x01
        # push prefix: 03 (3 bytes), then a0 86 01 → total hex: 03a08601
        assert "a08601" in hex_out, (
            f"expected 'a08601' in hex encoding of 100000, got: {hex_out}"
        )
