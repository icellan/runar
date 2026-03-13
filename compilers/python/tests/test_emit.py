"""Emit pass tests for the Python compiler.

Mirrors compilers/go/codegen/emit_test.go — verifies that the emission pass
converts Stack IR to correct Bitcoin Script hex and tracks constructor slot
byte offsets accurately.
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
from runar_compiler.codegen.emit import emit, emit_method, EmitResult, ConstructorSlot
from runar_compiler.codegen.optimizer import optimize_stack_ops


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _p2pkh_program() -> ANFProgram:
    """Build a standard P2PKH ANF program (same as in test_stack.py)."""
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
# Test: Placeholder produces constructor slot at byte 0
# ---------------------------------------------------------------------------

class TestEmit_Placeholder:
    def test_placeholder_produces_constructor_slot(self):
        method = StackMethod(
            name="unlock",
            ops=[
                StackOp(op="placeholder", param_index=0, param_name="pubKeyHash"),
                StackOp(op="opcode", code="OP_CHECKSIG"),
            ],
        )

        result = emit_method(method)

        assert len(result.constructor_slots) == 1
        slot = result.constructor_slots[0]
        assert slot.param_index == 0
        # The placeholder is the first op, so byte offset should be 0
        assert slot.byte_offset == 0


# ---------------------------------------------------------------------------
# Test: Multiple placeholders have distinct byte offsets
# ---------------------------------------------------------------------------

class TestEmit_MultiplePlaceholders:
    def test_multiple_placeholders_distinct_offsets(self):
        method = StackMethod(
            name="check",
            ops=[
                StackOp(op="placeholder", param_index=0, param_name="x"),
                StackOp(op="placeholder", param_index=1, param_name="y"),
                StackOp(op="opcode", code="OP_ADD"),
            ],
        )

        result = emit_method(method)

        assert len(result.constructor_slots) == 2
        slot0 = result.constructor_slots[0]
        slot1 = result.constructor_slots[1]

        assert slot0.param_index == 0
        assert slot1.param_index == 1

        # Byte offsets must be different
        assert slot0.byte_offset != slot1.byte_offset, (
            f"expected distinct byte offsets, both are {slot0.byte_offset}"
        )

        # Each placeholder emits 1 byte (OP_0 = 0x00)
        assert slot0.byte_offset == 0, f"first slot: expected byteOffset=0, got {slot0.byte_offset}"
        assert slot1.byte_offset == 1, f"second slot: expected byteOffset=1, got {slot1.byte_offset}"


# ---------------------------------------------------------------------------
# Test: Byte offset accounts for preceding opcodes
# ---------------------------------------------------------------------------

class TestEmit_ByteOffsets:
    def test_byte_offset_accounts_for_preceding_opcodes(self):
        method = StackMethod(
            name="check",
            ops=[
                StackOp(op="opcode", code="OP_DUP"),       # 1 byte (0x76)
                StackOp(op="opcode", code="OP_HASH160"),    # 1 byte (0xa9)
                StackOp(op="placeholder", param_index=0, param_name="pubKeyHash"),
                StackOp(op="opcode", code="OP_EQUALVERIFY"),
                StackOp(op="opcode", code="OP_CHECKSIG"),
            ],
        )

        result = emit_method(method)

        assert len(result.constructor_slots) == 1
        slot = result.constructor_slots[0]
        # OP_DUP (1 byte) + OP_HASH160 (1 byte) = 2 bytes before placeholder
        assert slot.byte_offset == 2, (
            f"expected byteOffset=2 (after OP_DUP + OP_HASH160), got {slot.byte_offset}"
        )

    def test_byte_offset_with_push_data(self):
        """Byte offset should account for varying-size push data."""
        method = StackMethod(
            name="check",
            ops=[
                # Push the number 17 — this uses 2 bytes (0x01 length + 0x11 value)
                StackOp(op="push", value=PushValue(kind="bigint", big_int=17)),
                StackOp(op="placeholder", param_index=0, param_name="x"),
                StackOp(op="opcode", code="OP_ADD"),
            ],
        )

        result = emit_method(method)

        assert len(result.constructor_slots) == 1
        slot = result.constructor_slots[0]
        # Push 17 takes 2 bytes (0x01 length prefix + 0x11 value), so placeholder at offset 2
        assert slot.byte_offset == 2, (
            f"expected byteOffset=2 (after push 17), got {slot.byte_offset}"
        )


# ---------------------------------------------------------------------------
# Test: EmitMethod produces correct hex for a simple sequence
# ---------------------------------------------------------------------------

class TestEmit_SimpleSequence:
    def test_simple_sequence_hex(self):
        method = StackMethod(
            name="check",
            ops=[
                StackOp(op="opcode", code="OP_DUP"),
                StackOp(op="opcode", code="OP_HASH160"),
                StackOp(op="opcode", code="OP_SWAP"),
                StackOp(op="opcode", code="OP_EQUALVERIFY"),
                StackOp(op="opcode", code="OP_CHECKSIG"),
            ],
        )

        result = emit_method(method)

        # OP_DUP=76, OP_HASH160=a9, OP_SWAP=7c, OP_EQUALVERIFY=88, OP_CHECKSIG=ac
        expected = "76a97c88ac"
        assert result.script_hex == expected, (
            f"expected hex {expected}, got {result.script_hex}"
        )


# ---------------------------------------------------------------------------
# Test: Peephole optimization before emit
# ---------------------------------------------------------------------------

class TestEmit_PeepholeOptimization:
    def test_checksig_verify_becomes_checksigverify(self):
        """CHECKSIG + VERIFY -> CHECKSIGVERIFY via peephole optimization."""
        methods = [
            StackMethod(
                name="check",
                ops=[
                    StackOp(op="opcode", code="OP_CHECKSIG"),
                    StackOp(op="opcode", code="OP_VERIFY"),
                    StackOp(op="opcode", code="OP_1"),
                ],
            )
        ]

        # Apply peephole optimization (as the compiler pipeline does before emit)
        for m in methods:
            m.ops = optimize_stack_ops(m.ops)

        result = emit(methods)

        # After peephole: CHECKSIG + VERIFY -> CHECKSIGVERIFY (0xad), then OP_1 (0x51)
        expected = "ad51"
        assert result.script_hex == expected, (
            f"expected hex {expected}, got {result.script_hex}"
        )


# ---------------------------------------------------------------------------
# Test: Full P2PKH compilation pipeline
# ---------------------------------------------------------------------------

class TestEmit_FullP2PKH:
    def test_full_p2pkh(self):
        program = _p2pkh_program()
        methods = lower_to_stack(program)
        result = emit(methods)

        assert result.script_hex != "", "expected non-empty script hex for P2PKH"
        assert result.script_asm != "", "expected non-empty script ASM for P2PKH"

    def test_full_p2pkh_asm_contains_expected_opcodes(self):
        program = _p2pkh_program()
        methods = lower_to_stack(program)
        result = emit(methods)

        # P2PKH should contain hash and checksig operations
        assert "OP_HASH160" in result.script_asm, (
            f"expected OP_HASH160 in P2PKH ASM: {result.script_asm}"
        )
        assert "OP_CHECKSIG" in result.script_asm, (
            f"expected OP_CHECKSIG in P2PKH ASM: {result.script_asm}"
        )


# ---------------------------------------------------------------------------
# Test: Multi-method dispatch produces OP_IF/OP_ELSE/OP_ENDIF
# ---------------------------------------------------------------------------

class TestEmit_MultiMethodDispatch:
    def test_multi_method_dispatch(self):
        program = ANFProgram(
            contract_name="Multi",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="m1",
                    params=[ANFParam(name="x", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=1, const_big_int=1, const_int=1)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
                ANFMethod(
                    name="m2",
                    params=[ANFParam(name="y", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="y")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=2, const_big_int=2, const_int=2)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = lower_to_stack(program)
        result = emit(methods)

        assert result.script_asm != "", "expected non-empty ASM"
        assert "OP_IF" in result.script_asm, (
            f"expected OP_IF in multi-method dispatch ASM, got: {result.script_asm}"
        )
        assert "OP_ELSE" in result.script_asm, (
            f"expected OP_ELSE in multi-method dispatch ASM, got: {result.script_asm}"
        )
        assert "OP_ENDIF" in result.script_asm, (
            f"expected OP_ENDIF in multi-method dispatch ASM, got: {result.script_asm}"
        )


# ---------------------------------------------------------------------------
# Test: Push bool ops emit OP_TRUE / OP_FALSE
# ---------------------------------------------------------------------------

class TestEmitPushBool:
    def test_push_bool_true_false(self):
        """A StackMethod with bool Push ops emits OP_TRUE/OP_FALSE (0x51/0x00).
        Mirrors Rust test_emit_push_bool_values."""
        method = StackMethod(
            name="test",
            ops=[
                StackOp(op="push", value=PushValue(kind="bool", bool_val=True)),
                StackOp(op="push", value=PushValue(kind="bool", bool_val=False)),
            ],
        )

        result = emit_method(method)

        # OP_TRUE = 0x51, OP_FALSE = 0x00
        assert result.script_hex.startswith("51"), (
            f"true should emit 0x51 (OP_TRUE), got: {result.script_hex}"
        )
        assert result.script_hex.endswith("00"), (
            f"false should emit 0x00 (OP_FALSE), got: {result.script_hex}"
        )
        assert "OP_TRUE" in result.script_asm, (
            f"expected OP_TRUE in ASM, got: {result.script_asm}"
        )
        assert "OP_FALSE" in result.script_asm, (
            f"expected OP_FALSE in ASM, got: {result.script_asm}"
        )


# ---------------------------------------------------------------------------
# Test: Empty methods produces no output
# ---------------------------------------------------------------------------

class TestEmitEmpty:
    def test_empty_methods_produces_no_output(self):
        """An artifact with no StackMethods produces empty hex.
        Mirrors Rust test_emit_empty_methods_produces_empty_output."""
        result = emit([])

        assert result.script_hex == "", (
            f"empty methods should produce empty hex, got: {result.script_hex}"
        )
        assert len(result.constructor_slots) == 0, (
            f"empty methods should produce no constructor slots, got: {result.constructor_slots}"
        )


# ---------------------------------------------------------------------------
# Test: Small integer opcodes (OP_0 through OP_16)
# ---------------------------------------------------------------------------

class TestEmit_OP0Through16:
    """Verify that small integers 0-16 encode to the correct minimal opcodes."""

    def test_push_0_encodes_to_op0(self):
        """Pushing 0 should encode to OP_0 (hex 00)."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=0))],
        )
        result = emit_method(method)
        assert result.script_hex == "00", (
            f"push 0 should encode to OP_0 (00), got: {result.script_hex}"
        )
        assert "OP_0" in result.script_asm, (
            f"push 0 should produce OP_0 in ASM, got: {result.script_asm}"
        )

    def test_push_1_encodes_to_op1(self):
        """Pushing 1 should encode to OP_1 (hex 51)."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=1))],
        )
        result = emit_method(method)
        assert result.script_hex == "51", (
            f"push 1 should encode to OP_1 (51), got: {result.script_hex}"
        )

    def test_push_16_encodes_to_op16(self):
        """Pushing 16 should encode to OP_16 (hex 60)."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=16))],
        )
        result = emit_method(method)
        assert result.script_hex == "60", (
            f"push 16 should encode to OP_16 (60), got: {result.script_hex}"
        )

    @pytest.mark.parametrize("n,expected_hex,expected_asm", [
        (0,  "00", "OP_0"),
        (1,  "51", "OP_1"),
        (2,  "52", "OP_2"),
        (3,  "53", "OP_3"),
        (8,  "58", "OP_8"),
        (15, "5f", "OP_15"),
        (16, "60", "OP_16"),
    ])
    def test_small_integer_opcodes(self, n, expected_hex, expected_asm):
        """Small integers 0-16 should encode to their minimal opcodes."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=n))],
        )
        result = emit_method(method)
        assert result.script_hex == expected_hex, (
            f"push {n} should encode to {expected_hex}, got: {result.script_hex}"
        )
        assert expected_asm in result.script_asm, (
            f"push {n} should produce {expected_asm} in ASM, got: {result.script_asm}"
        )


# ---------------------------------------------------------------------------
# Test: OP_PUSHDATA1 for data >= 76 bytes
# ---------------------------------------------------------------------------

class TestEmit_PushData1:
    def test_76_byte_data_uses_pushdata1(self):
        """Data of exactly 76 bytes should use OP_PUSHDATA1 (0x4c) prefix."""
        data = bytes(range(76))  # 76 bytes: 0x00..0x4b
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bytes", bytes_val=data))],
        )
        result = emit_method(method)

        # Should start with 4c (OP_PUSHDATA1) followed by 4c (length=76) then 76 bytes
        hex_str = result.script_hex
        assert hex_str.startswith("4c4c"), (
            f"76-byte data should start with 4c4c (OP_PUSHDATA1 + length 76), got: {hex_str[:8]}..."
        )
        # Total bytes: 1 (OP_PUSHDATA1) + 1 (length) + 76 (data) = 78 bytes = 156 hex chars
        assert len(hex_str) == 156, (
            f"expected 156 hex chars (78 bytes) for 76-byte push, got {len(hex_str)}"
        )

    def test_exactly_75_byte_data_no_pushdata1(self):
        """Data of exactly 75 bytes should NOT use OP_PUSHDATA1 — just a direct length prefix."""
        data = bytes(range(75))  # 75 bytes
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bytes", bytes_val=data))],
        )
        result = emit_method(method)

        hex_str = result.script_hex
        # Should start with 4b (75 in hex) — direct length prefix, NOT OP_PUSHDATA1 (0x4c)
        assert hex_str.startswith("4b"), (
            f"75-byte data should start with 4b (direct length), got: {hex_str[:4]}..."
        )
        assert not hex_str.startswith("4c"), (
            f"75-byte data should NOT use OP_PUSHDATA1 (4c), got: {hex_str[:4]}..."
        )
        # Total bytes: 1 (length) + 75 (data) = 76 bytes = 152 hex chars
        assert len(hex_str) == 152, (
            f"expected 152 hex chars (76 bytes) for 75-byte push, got {len(hex_str)}"
        )


# ---------------------------------------------------------------------------
# Gap tests: M10, M20, M21, M22, M24, M25
# ---------------------------------------------------------------------------

class TestEmitGaps:
    # M10: integers 17+ use push prefix (not a special opcode shortcode)
    def test_m10_integer_17_uses_push_prefix(self):
        """Push integer 17 → uses push data prefix byte, not a special opcode shortcode."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=17))],
        )
        result = emit_method(method)
        hex_str = result.script_hex

        # OP_16 = 0x60. 17 should NOT be OP_16 (0x60) nor any OP_1..OP_16.
        # 17 in script number = 0x11, push length = 1, so: 01 11
        assert hex_str != "60", (
            f"push 17 should NOT encode to OP_16 (60), but got: {hex_str}"
        )
        # Should start with 01 (1-byte length prefix) then 11 (= 17 decimal)
        assert hex_str == "0111", (
            f"push 17 should encode to 0111 (len=1, value=0x11), got: {hex_str}"
        )

    # M20: deterministic output
    def test_m20_deterministic_output(self):
        """Compile same ANF IR twice → identical hex output."""
        program = _p2pkh_program()

        methods1 = lower_to_stack(program)
        result1 = emit(methods1)

        methods2 = lower_to_stack(program)
        result2 = emit(methods2)

        assert result1.script_hex == result2.script_hex, (
            f"expected deterministic hex output, got:\n"
            f"  run1: {result1.script_hex[:80]}...\n"
            f"  run2: {result2.script_hex[:80]}..."
        )

    # M21: OP_DUP encodes 0x76
    def test_m21_op_dup_encodes_76(self):
        """Emit Dup op → hex contains 76."""
        method = StackMethod(
            name="test",
            ops=[
                StackOp(op="opcode", code="OP_DUP"),
                StackOp(op="opcode", code="OP_DROP"),
            ],
        )
        result = emit_method(method)
        assert "76" in result.script_hex, (
            f"expected OP_DUP (0x76) in hex output, got: {result.script_hex}"
        )

    # M22: OP_SWAP encodes 0x7c
    def test_m22_op_swap_encodes_7c(self):
        """Emit Swap op → hex contains 7c."""
        method = StackMethod(
            name="test",
            ops=[StackOp(op="opcode", code="OP_SWAP")],
        )
        result = emit_method(method)
        assert "7c" in result.script_hex, (
            f"expected OP_SWAP (0x7c) in hex output, got: {result.script_hex}"
        )

    # M24: if without else → no OP_ELSE in hex
    def test_m24_if_without_else_no_op_else(self):
        """If with empty else → hex does not contain the OP_ELSE byte (63)."""
        method = StackMethod(
            name="test",
            ops=[
                StackOp(
                    op="if",
                    then=[StackOp(op="opcode", code="OP_DROP")],
                    else_ops=[],
                ),
            ],
        )
        result = emit_method(method)
        # OP_ELSE = 0x67. It should NOT appear when else branch is empty.
        assert "67" not in result.script_hex, (
            f"expected no OP_ELSE (67) for if-without-else, got hex: {result.script_hex}"
        )
        # But OP_IF (0x63) and OP_ENDIF (0x68) must still appear
        assert "63" in result.script_hex, (
            f"expected OP_IF (63) in hex, got: {result.script_hex}"
        )
        assert "68" in result.script_hex, (
            f"expected OP_ENDIF (68) in hex, got: {result.script_hex}"
        )

    # M25: single method → no dispatch preamble
    def test_m25_single_method_no_dispatch_preamble(self):
        """1 public method → no OP_IF dispatch."""
        program = ANFProgram(
            contract_name="Single",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                ANFMethod(
                    name="unlock",
                    params=[ANFParam(name="x", type="bigint")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                        ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=1, const_big_int=1, const_int=1)),
                        ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                        ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                    ],
                    is_public=True,
                ),
            ],
        )

        methods = lower_to_stack(program)
        result = emit(methods)

        # A single-method contract does NOT need an OP_IF dispatch selector.
        # The ASM should NOT start with OP_IF (a dispatch selector would be the first thing).
        asm = result.script_asm
        assert not asm.startswith("OP_IF"), (
            f"single-method contract should not start with OP_IF dispatch, got asm: {asm[:80]}"
        )


# ---------------------------------------------------------------------------
# Gap rows 214-216, 220-225, 231, 233, 239
# ---------------------------------------------------------------------------

class TestEmitOpcodeEncodings:
    """Row 220-225: individual opcode hex encodings."""

    def test_m_drop_encodes_75(self):
        """OP_DROP → hex '75' (row 220)."""
        method = StackMethod(name="t", ops=[StackOp(op="drop")])
        result = emit_method(method)
        assert result.script_hex == "75", f"expected 75 for OP_DROP, got {result.script_hex}"

    def test_m_nip_encodes_77(self):
        """OP_NIP → hex '77' (row 221)."""
        method = StackMethod(name="t", ops=[StackOp(op="nip")])
        result = emit_method(method)
        assert result.script_hex == "77", f"expected 77 for OP_NIP, got {result.script_hex}"

    def test_m_over_encodes_78(self):
        """OP_OVER → hex '78' (row 222)."""
        method = StackMethod(name="t", ops=[StackOp(op="over")])
        result = emit_method(method)
        assert result.script_hex == "78", f"expected 78 for OP_OVER, got {result.script_hex}"

    def test_m_pick_encodes_79(self):
        """OP_PICK → hex contains '79' (row 223)."""
        # pick depth:2 → push 2 (0x52) then OP_PICK (0x79)
        method = StackMethod(name="t", ops=[StackOp(op="pick", depth=2)])
        result = emit_method(method)
        assert "79" in result.script_hex, f"expected 79 (OP_PICK) in hex, got {result.script_hex}"

    def test_m_roll_encodes_7a(self):
        """OP_ROLL → hex contains '7a' (row 224)."""
        # roll depth:3 → push 3 (0x53) then OP_ROLL (0x7a)
        method = StackMethod(name="t", ops=[StackOp(op="roll", depth=3)])
        result = emit_method(method)
        assert "7a" in result.script_hex, f"expected 7a (OP_ROLL) in hex, got {result.script_hex}"

    def test_m_rot_encodes_7b(self):
        """OP_ROT → hex '7b' (row 225)."""
        method = StackMethod(name="t", ops=[StackOp(op="rot")])
        result = emit_method(method)
        assert result.script_hex == "7b", f"expected 7b for OP_ROT, got {result.script_hex}"

    def test_m_push_minus_one_encodes_4f(self):
        """Push -1 → OP_1NEGATE ('4f') (row 231)."""
        method = StackMethod(
            name="t",
            ops=[StackOp(op="push", value=PushValue(kind="bigint", big_int=-1))],
        )
        result = emit_method(method)
        assert result.script_hex == "4f", f"expected 4f (OP_1NEGATE) for push(-1), got {result.script_hex}"

    def test_m_256_byte_push_uses_pushdata2(self):
        """256-byte data uses OP_PUSHDATA2 (prefix '4d0001') (row 233)."""
        data = bytes([0xab] * 256)
        method = StackMethod(
            name="t",
            ops=[StackOp(op="push", value=PushValue(kind="bytes", bytes_val=data))],
        )
        result = emit_method(method)
        # OP_PUSHDATA2 = 0x4d, then 2-byte LE length (256 = 0x0001 LE)
        assert result.script_hex.startswith("4d0001"), (
            f"expected 4d0001 prefix for 256-byte OP_PUSHDATA2, got {result.script_hex[:10]}"
        )

    def test_m_if_else_both_branches_emits_if_else_endif(self):
        """If/else with content in both branches → OP_IF OP_ELSE OP_ENDIF all present (row 239)."""
        method = StackMethod(
            name="t",
            ops=[
                StackOp(
                    op="if",
                    then=[StackOp(op="drop")],
                    else_ops=[StackOp(op="drop")],
                ),
            ],
        )
        result = emit_method(method)
        # OP_IF=63, OP_ELSE=67, OP_ENDIF=68
        hex_str = result.script_hex
        assert "63" in hex_str, f"expected OP_IF (63) in {hex_str}"
        assert "67" in hex_str, f"expected OP_ELSE (67) in {hex_str}"
        assert "68" in hex_str, f"expected OP_ENDIF (68) in {hex_str}"


class TestEmitMultiMethodDispatchFull:
    """Row 214: last method uses OP_NUMEQUALVERIFY (fail-closed dispatch)."""

    def test_m_three_method_last_uses_numequalverify(self):
        """3-method contract → last method has OP_NUMEQUALVERIFY (row 214)."""
        def _simple_method(name: str, n: int) -> ANFMethod:
            return ANFMethod(
                name=name,
                params=[ANFParam(name="x", type="bigint")],
                body=[
                    ANFBinding(name="t0", value=ANFValue(kind="load_param", name="x")),
                    ANFBinding(name="t1", value=ANFValue(kind="load_const", raw_value=n, const_big_int=n, const_int=n)),
                    ANFBinding(name="t2", value=ANFValue(kind="bin_op", op="===", left="t0", right="t1")),
                    ANFBinding(name="t3", value=ANFValue(kind="assert", raw_value="t2", value_ref="t2")),
                ],
                is_public=True,
            )

        program = ANFProgram(
            contract_name="Three",
            properties=[],
            methods=[
                ANFMethod(name="constructor", params=[], body=[], is_public=False),
                _simple_method("m1", 1),
                _simple_method("m2", 2),
                _simple_method("m3", 3),
            ],
        )
        methods = lower_to_stack(program)
        result = emit(methods)
        # OP_NUMEQUALVERIFY = 0x9d
        assert "9d" in result.script_hex, (
            f"expected OP_NUMEQUALVERIFY (9d) in 3-method dispatch, got {result.script_hex[:40]}"
        )


class TestEmitSHA256ASM:
    """Row 215: sha256() call emits OP_SHA256 in ASM."""

    def test_m_sha256_call_emits_op_sha256(self):
        """sha256(data) → OP_SHA256 in ASM (row 215)."""
        program = ANFProgram(
            contract_name="HashCheck",
            properties=[ANFProperty(name="digest", type="Sha256", readonly=True)],
            methods=[
                ANFMethod(
                    name="constructor",
                    params=[ANFParam(name="digest", type="Sha256")],
                    body=[],
                    is_public=False,
                ),
                ANFMethod(
                    name="unlock",
                    params=[ANFParam(name="data", type="ByteString")],
                    body=[
                        ANFBinding(name="t0", value=ANFValue(kind="load_param", name="data")),
                        ANFBinding(name="t1", value=ANFValue(kind="call", func="sha256", args=["t0"])),
                        ANFBinding(name="t2", value=ANFValue(kind="load_prop", name="digest")),
                        ANFBinding(name="t3", value=ANFValue(kind="bin_op", op="===", left="t1", right="t2", result_type="bytes")),
                        ANFBinding(name="t4", value=ANFValue(kind="assert", raw_value="t3", value_ref="t3")),
                    ],
                    is_public=True,
                ),
            ],
        )
        methods = lower_to_stack(program)
        result = emit(methods)
        assert "OP_SHA256" in result.script_asm, (
            f"expected OP_SHA256 in ASM, got: {result.script_asm[:100]}"
        )
        # OP_SHA256 = 0xa8
        assert "a8" in result.script_hex, (
            f"expected a8 (OP_SHA256) in hex, got: {result.script_hex[:40]}"
        )


class TestEmitTerminalCheckSig:
    """Row 216: terminal assert leaves checkSig value on stack (no OP_VERIFY)."""

    def test_m_terminal_checksig_no_verify(self):
        """assert(checkSig) → OP_CHECKSIG present, no OP_VERIFY after it (row 216)."""
        program = _p2pkh_program()
        methods = lower_to_stack(program)
        result = emit(methods)

        # OP_CHECKSIG = 0xac, OP_VERIFY = 0x69
        # The last opcode should be OP_CHECKSIG, not OP_CHECKSIGVERIFY (0xad) or OP_VERIFY after it.
        hex_str = result.script_hex
        asm = result.script_asm

        assert "OP_CHECKSIG" in asm, f"expected OP_CHECKSIG in ASM, got: {asm}"
        # OP_CHECKSIGVERIFY = 0xad. The hex should NOT end with "ad" (which would be CHECKSIGVERIFY)
        # The terminal CHECKSIG should be the last opcode.
        assert hex_str.endswith("ac"), (
            f"expected OP_CHECKSIG (ac) as last opcode for terminal assert, got tail: {hex_str[-4:]}"
        )
