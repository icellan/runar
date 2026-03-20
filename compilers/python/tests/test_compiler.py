"""Full compilation pipeline tests for the Python compiler.

Mirrors compilers/go/compiler_test.go — covers IR loading, compilation,
artifact JSON, validation, script number encoding, peephole optimizer,
deterministic output, and conformance golden files.
"""

from __future__ import annotations

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes, artifact_to_json, CompilationError
from runar_compiler.ir.loader import load_ir, validate_ir
from runar_compiler.ir.types import ANFProgram, ANFMethod, ANFParam, ANFBinding, ANFValue, ANFProperty
from runar_compiler.codegen.emit import encode_script_number
from runar_compiler.codegen.optimizer import optimize_stack_ops
from runar_compiler.codegen.stack import StackOp, PushValue

from conftest import load_conformance_ir, load_conformance_script, must_compile_ir


# ---------------------------------------------------------------------------
# IR loading
# ---------------------------------------------------------------------------

class TestLoadIR:
    def test_load_ir_basic_p2pkh(self):
        ir_json = load_conformance_ir("basic-p2pkh")
        program = load_ir(ir_json)

        assert program.contract_name == "P2PKH"
        # constructor + unlock
        assert len(program.methods) == 2
        # unlock method bindings: load_param, call(hash160), load_prop, bin_op, assert, load_param, load_param, call(checkSig), assert
        unlock = [m for m in program.methods if m.name == "unlock"][0]
        assert len(unlock.body) > 0
        assert len(unlock.params) == 2


# ---------------------------------------------------------------------------
# Compilation from IR
# ---------------------------------------------------------------------------

class TestCompileFromIR:
    def test_compile_basic_p2pkh(self):
        ir_json = load_conformance_ir("basic-p2pkh")
        artifact = must_compile_ir(ir_json)

        assert artifact.contract_name == "P2PKH"
        assert len(artifact.script) > 0
        assert len(artifact.asm) > 0

    def test_compile_arithmetic(self):
        ir_json = load_conformance_ir("arithmetic")
        artifact = must_compile_ir(ir_json)

        assert artifact.contract_name == "Arithmetic"
        assert "OP_ADD" in artifact.asm
        assert "OP_SUB" in artifact.asm
        assert "OP_MUL" in artifact.asm
        assert "OP_DIV" in artifact.asm

    def test_compile_if_else(self):
        ir_json = load_conformance_ir("if-else")
        artifact = must_compile_ir(ir_json)

        assert "OP_IF" in artifact.asm
        assert "OP_ELSE" in artifact.asm
        assert "OP_ENDIF" in artifact.asm

    def test_compile_boolean_logic(self):
        ir_json = load_conformance_ir("boolean-logic")
        artifact = must_compile_ir(ir_json)

        assert "OP_BOOLAND" in artifact.asm
        assert "OP_BOOLOR" in artifact.asm
        assert "OP_NOT" in artifact.asm


# ---------------------------------------------------------------------------
# Artifact JSON structure
# ---------------------------------------------------------------------------

class TestArtifactJSON:
    def test_artifact_json(self):
        ir_json = load_conformance_ir("basic-p2pkh")
        artifact = must_compile_ir(ir_json)

        json_str = artifact_to_json(artifact)
        d = json.loads(json_str)

        assert "version" in d
        assert d["version"] == "runar-v0.1.0"
        assert "contractName" in d
        assert d["contractName"] == "P2PKH"
        assert "abi" in d
        assert "script" in d
        assert len(d["script"]) > 0
        assert "asm" in d
        assert len(d["asm"]) > 0
        assert "buildTimestamp" in d


# ---------------------------------------------------------------------------
# IR validation
# ---------------------------------------------------------------------------

class TestIRValidation:
    def test_validation_empty_contract_name(self):
        program = ANFProgram(
            contract_name="",
            properties=[],
            methods=[],
        )
        errors = validate_ir(program)
        assert any("contractName" in e for e in errors)

    def test_validation_unknown_kind(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="test",
                    params=[],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(kind="unknown_kind_xyz"),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert any("unknown kind" in e for e in errors)

    def test_validation_negative_loop_count(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="test",
                    params=[],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(kind="loop", count=-1),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert any("negative loop count" in e for e in errors)

    def test_validation_excessive_loop_count(self):
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[
                ANFMethod(
                    name="test",
                    params=[],
                    body=[
                        ANFBinding(
                            name="t0",
                            value=ANFValue(kind="loop", count=100_000),
                        ),
                    ],
                    is_public=True,
                ),
            ],
        )
        errors = validate_ir(program)
        assert any("exceeding maximum" in e for e in errors)


# ---------------------------------------------------------------------------
# Script number encoding
# ---------------------------------------------------------------------------

class TestEncodeScriptNumber:
    @pytest.mark.parametrize(
        "n, expected",
        [
            (0, b""),
            (1, b"\x01"),
            (16, b"\x10"),
            (-1, b"\x81"),
            (17, b"\x11"),
            (-2, b"\x82"),
            (127, b"\x7f"),
            (128, b"\x80\x00"),
            (-128, b"\x80\x80"),
            (255, b"\xff\x00"),
            (256, b"\x00\x01"),
        ],
    )
    def test_encode_script_number(self, n: int, expected: bytes):
        assert encode_script_number(n) == expected


# ---------------------------------------------------------------------------
# Peephole optimizer
# ---------------------------------------------------------------------------

class TestPeepholeOptimizer:
    def test_optimizer_swap_swap(self):
        ops = [
            StackOp(op="swap"),
            StackOp(op="swap"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_optimizer_checksig_verify(self):
        ops = [
            StackOp(op="opcode", code="OP_CHECKSIG"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "opcode"
        assert result[0].code == "OP_CHECKSIGVERIFY"

    def test_optimizer_numequal_verify(self):
        ops = [
            StackOp(op="opcode", code="OP_NUMEQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_NUMEQUALVERIFY"

    def test_optimizer_push_drop(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=42)),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_optimizer_2drop(self):
        ops = [
            StackOp(op="drop"),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "opcode"
        assert result[0].code == "OP_2DROP"

    def test_optimizer_1add(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_ADD"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_1ADD"

    def test_optimizer_1sub(self):
        ops = [
            StackOp(op="push", value=PushValue(kind="bigint", big_int=1)),
            StackOp(op="opcode", code="OP_SUB"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_1SUB"

    def test_optimizer_equal_verify(self):
        ops = [
            StackOp(op="opcode", code="OP_EQUAL"),
            StackOp(op="opcode", code="OP_VERIFY"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].code == "OP_EQUALVERIFY"

    def test_optimizer_double_not(self):
        ops = [
            StackOp(op="opcode", code="OP_NOT"),
            StackOp(op="opcode", code="OP_NOT"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_optimizer_dup_drop(self):
        ops = [
            StackOp(op="dup"),
            StackOp(op="drop"),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 0

    def test_optimizer_nested_if(self):
        """Optimizer recursively optimizes if-blocks."""
        ops = [
            StackOp(
                op="if",
                then=[
                    StackOp(op="swap"),
                    StackOp(op="swap"),
                ],
                else_ops=[
                    StackOp(op="opcode", code="OP_CHECKSIG"),
                    StackOp(op="opcode", code="OP_VERIFY"),
                ],
            ),
        ]
        result = optimize_stack_ops(ops)
        assert len(result) == 1
        assert result[0].op == "if"
        assert len(result[0].then) == 0
        assert len(result[0].else_ops) == 1
        assert result[0].else_ops[0].code == "OP_CHECKSIGVERIFY"


# ---------------------------------------------------------------------------
# Deterministic output
# ---------------------------------------------------------------------------

class TestDeterministicOutput:
    def test_deterministic_output(self):
        ir_json = load_conformance_ir("arithmetic")
        a1 = must_compile_ir(ir_json)
        a2 = must_compile_ir(ir_json)

        assert a1.script == a2.script
        assert a1.asm == a2.asm


# ---------------------------------------------------------------------------
# Conformance golden files
# ---------------------------------------------------------------------------

BASIC_CONFORMANCE_TESTS = [
    "arithmetic",
    "auction",
    "basic-p2pkh",
    "blake3",
    "boolean-logic",
    "bounded-loop",
    "convergence-proof",
    "covenant-vault",
    "ec-demo",
    "ec-primitives",
    "escrow",
    "function-patterns",
    "if-else",
    "if-without-else",
    "math-demo",
    "multi-method",
    "oracle-price",
    "post-quantum-slhdsa",
    "post-quantum-wallet",
    "post-quantum-wots",
    "property-initializers",
    "schnorr-zkp",
    "sphincs-wallet",
    "stateful",
    "stateful-counter",
    "token-ft",
    "token-nft",
]


class TestConformanceGolden:
    @pytest.mark.parametrize("test_name", BASIC_CONFORMANCE_TESTS)
    def test_conformance_all(self, test_name: str):
        ir_json = load_conformance_ir(test_name)
        expected_hex = load_conformance_script(test_name)

        # Disable constant folding to match golden files
        artifact = must_compile_ir(ir_json, disable_constant_folding=True)
        assert artifact.script == expected_hex, (
            f"Script mismatch for {test_name}:\n"
            f"  expected: {expected_hex}\n"
            f"  got:      {artifact.script}"
        )


# ---------------------------------------------------------------------------
# Stack map exercise
# ---------------------------------------------------------------------------

class TestStackMap:
    def test_stack_map_operations(self):
        """A contract where params and props are interleaved in usage exercises stack manipulation."""
        # Use the arithmetic conformance test which has cross-references between
        # sum, diff, prod, quot variables — ensuring PICK/ROLL/SWAP are needed.
        ir_json = load_conformance_ir("arithmetic")
        artifact = must_compile_ir(ir_json)

        assert len(artifact.script) > 0
        assert "OP_ADD" in artifact.asm
        assert "OP_NUMEQUAL" in artifact.asm

        # Arithmetic test has multiple intermediate values that reference both
        # params and earlier results, requiring stack manipulation
        asm_parts = artifact.asm.split()
        stack_ops = {"OP_PICK", "OP_ROLL", "OP_SWAP", "OP_ROT", "OP_OVER", "OP_DUP"}
        has_stack_ops = any(p in stack_ops for p in asm_parts)
        assert has_stack_ops, f"Expected stack manipulation opcodes in ASM: {artifact.asm}"
