"""F-362: eight bare 2-hex-char opcode substring assertions.

CL-GAP-162 measured that ``assert "XX" in result.script_hex`` false-passes
14%-79% of the time against uniformly random hex of matching length,
because the needle can land inside push-data payload bytes (or straddle two
adjacent bytes) instead of actually being executed as opcode ``XX``.

This file:
  1. unit-tests the shared ``iter_opcodes`` helper (conftest.py) that walks a
     script opcode-by-opcode, skipping push-data payloads;
  2. for three of the eight remediated assertions, constructs a deliberate
     mutation of the REAL compiler output where the real opcode occurrence
     is replaced by an unrelated opcode, and the needle is reintroduced only
     as a push-data payload byte -- proving the old bare substring check
     still (wrongly) "passes" on that mutant, while the opcode-aligned check
     correctly reports the opcode as absent.

What this proves: the opcode-aligned check (now used at test_emit.py:522,534,
627,634,714,754 and test_int2str.py:70,71) rejects a mutation that the old
bare substring check let through.
What this does NOT prove: that the compiler's real codegen is correct for
these opcodes -- that is the job of the (unchanged) assertions in
test_emit.py / test_int2str.py themselves, now strengthened by this helper.
"""

from __future__ import annotations

from conftest import iter_opcodes


# ---------------------------------------------------------------------------
# 1. iter_opcodes correctness
# ---------------------------------------------------------------------------


class TestIterOpcodes:
    def test_single_byte_opcodes(self) -> None:
        # OP_DUP (76), OP_DROP (75) -- no push data at all.
        assert iter_opcodes("7675") == ["76", "75"]

    def test_direct_push_payload_is_skipped(self) -> None:
        # Push 2 bytes (02) whose payload is 0x76 0x76, then OP_DROP (75).
        # The payload bytes must NOT appear as opcodes even though their
        # value equals OP_DUP's byte.
        assert iter_opcodes("027676" + "75") == ["02", "75"]

    def test_pushdata1_payload_is_skipped(self) -> None:
        # OP_PUSHDATA1 (4c) + 1-byte length (03) + 3 payload bytes, then OP_DROP (75).
        assert iter_opcodes("4c03" + "767676" + "75") == ["4c", "75"]

    def test_pushdata2_payload_is_skipped(self) -> None:
        # OP_PUSHDATA2 (4d) + 2-byte LE length (0200 = 2) + 2 payload bytes, then OP_DROP.
        assert iter_opcodes("4d0200" + "7676" + "75") == ["4d", "75"]

    def test_needle_inside_push_payload_is_not_reported_as_opcode(self) -> None:
        # The exact shape of the weak check's blind spot: a one-byte push
        # (01) whose payload is 0x9d does NOT make OP_NUMEQUALVERIFY (9d)
        # present as an executed opcode.
        mutated = "61" + "019d"  # OP_NOP, then push(0x9d)
        assert "9d" in mutated  # bare substring check: false positive
        assert "9d" not in iter_opcodes(mutated)  # aligned check: correct


# ---------------------------------------------------------------------------
# 2. Mutation proof: substring check misses it, aligned check catches it.
# ---------------------------------------------------------------------------


def _mutate_opcode_to_push_payload(script_hex: str, needle: str, replacement: str = "61") -> str:
    """Replace the single real occurrence of opcode byte ``needle`` with
    ``replacement`` (OP_NOP by default), then reintroduce ``needle`` purely
    as a one-byte push payload appended to the script. The needle survives
    textually but is no longer executed as that opcode anywhere.
    """
    byte_pairs = [script_hex[i:i + 2] for i in range(0, len(script_hex), 2)]
    assert byte_pairs.count(needle) == 1, (
        f"test setup error: expected exactly one occurrence of {needle!r} "
        f"in {script_hex!r}, found {byte_pairs.count(needle)}"
    )
    idx = byte_pairs.index(needle)
    byte_pairs[idx] = replacement
    return "".join(byte_pairs) + "01" + needle


class TestMutationRedGreen:
    """Each case below reproduces the real compiler output used by one of
    the remediated assertions, then mutates it so the real opcode is gone
    but the hex substring survives. RED (pre-fix behavior): the bare
    substring check still reports the opcode present. GREEN (post-fix
    behavior): the opcode-aligned check correctly reports it absent.
    """

    def test_op_dup_mutation(self) -> None:
        # Real output of test_emit.py::test_m21_op_dup_encodes_76 (OP_DUP, OP_DROP).
        real_hex = "7675"
        mutated = _mutate_opcode_to_push_payload(real_hex, "76")
        assert mutated == "6175" + "0176"

        # RED: old bare substring check is fooled by the mutation.
        assert "76" in mutated
        # GREEN: opcode-aligned check correctly detects OP_DUP is gone.
        assert "76" not in iter_opcodes(mutated)

    def test_op_numequalverify_mutation(self) -> None:
        # Real output of test_emit.py::test_m_three_method_last_uses_numequalverify
        # (3-method dispatch; OP_NUMEQUALVERIFY = 9d appears exactly once).
        real_hex = "76009c6375517c7c9c6776519c6375527c7c9c67529d537c7c9c6868"
        mutated = _mutate_opcode_to_push_payload(real_hex, "9d")

        # RED: old bare substring check is fooled by the mutation.
        assert "9d" in mutated
        # GREEN: opcode-aligned check correctly detects OP_NUMEQUALVERIFY is gone.
        assert "9d" not in iter_opcodes(mutated)

    def test_op_sha256_mutation(self) -> None:
        # Real output of test_emit.py::test_m_sha256_call_emits_op_sha256 (OP_SHA256 = a8).
        real_hex = "a8007c7c87"
        mutated = _mutate_opcode_to_push_payload(real_hex, "a8")

        # RED: old bare substring check is fooled by the mutation.
        assert "a8" in mutated
        # GREEN: opcode-aligned check correctly detects OP_SHA256 is gone.
        assert "a8" not in iter_opcodes(mutated)
