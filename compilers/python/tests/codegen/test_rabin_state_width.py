"""``RabinSig`` / ``RabinPubKey`` are ``bigint`` ALIASES: a mutable one is
stored in the state section as a bare 8-byte OP_NUM2BIN word, on BOTH sides.

This tier's READER already says so in three places — ``_NUMERIC_STATE_TYPES``
(``codegen/stack.py``), the ``_lower_deserialize_state`` size table (8), and
``_fixed_state_section_length`` (8). Its two state SERIALIZERS did not: they
tested ``prop.type == "bigint"`` literally, so a mutable Rabin field went into
the accumulator in its MINIMAL script-number encoding with no NUM2BIN at all.

Same class of writer/reader split as the ``Sig`` defect next door, and the same
fund loss: for any value whose minimal encoding is not exactly 8 bytes the
continuation this contract builds cannot be re-read by its own script. Deploy
succeeds, the first spend succeeds, and the UTXO it creates is dead.

Cause: ``31276a06`` widened writer AND reader in the TypeScript reference;
``e06f8c2c`` widened only Go's reader, and this tier followed Go.

The lock: a mutable Rabin field must compile BYTE-IDENTICALLY to the same
contract with a ``bigint`` field — the path whose writer and reader are known
to agree. ``ByteString`` / ``Sig`` (framed) and ``PubKey`` (33 raw) stay the
negative controls, so the equality cannot be satisfied by collapsing every
state type onto one shape.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

RABIN_TYPES = ["RabinSig", "RabinPubKey"]


def write_src(prop_type: str) -> str:
    """Mutating method, implicit continuation — the compute-state-bytes writer."""
    return f"""
class RabinStateWrite extends StatefulSmartContract {{
  tag: {prop_type};
  constructor(tag: {prop_type}) {{ super(tag); this.tag = tag; }}
  public update(next: {prop_type}) {{ this.tag = next; }}
}}
"""


def add_output_src(prop_type: str) -> str:
    """Mutating method with an EXPLICIT addOutput — the ``_lower_add_output`` writer."""
    return f"""
class RabinStateAddOutput extends StatefulSmartContract {{
  tag: {prop_type};
  constructor(tag: {prop_type}) {{ super(tag); this.tag = tag; }}
  public update(next: {prop_type}) {{ this.tag = next; this.addOutput(1000n, next); }}
}}
"""


SHAPES = [
    ("implicit continuation", write_src, "RabinStateWrite.runar.ts"),
    ("explicit addOutput", add_output_src, "RabinStateAddOutput.runar.ts"),
]


def _hex(src: str, file_name: str) -> str:
    r = compile_from_source_str_with_result(src, file_name, disable_constant_folding=True)
    assert r.success, [d.message for d in r.diagnostics]
    return r.script_hex


class TestRabinStateWidth:
    @pytest.mark.parametrize("label,build,file_name", SHAPES)
    @pytest.mark.parametrize("prop_type", RABIN_TYPES)
    def test_writes_the_same_fixed_word_as_bigint(self, label, build, file_name, prop_type):
        """The decisive equality: the writer must emit the reader's 8-byte word."""
        control = _hex(build("bigint"), file_name)
        got = _hex(build(prop_type), file_name)
        assert got == control, (
            f"{label}: a mutable {prop_type} field does not serialize like bigint — "
            f"the writer disagrees with its own 8-byte reader "
            f"(got {len(got) // 2} bytes, want {len(control) // 2})"
        )

    @pytest.mark.parametrize("label,build,file_name", SHAPES)
    @pytest.mark.parametrize("prop_type", ["ByteString", "Sig", "PubKey"])
    def test_controls_stay_distinct(self, label, build, file_name, prop_type):
        """The equality must not be reachable by collapsing every type onto one shape."""
        control = _hex(build("bigint"), file_name)
        got = _hex(build(prop_type), file_name)
        assert got != control, (
            f"{label}: a mutable {prop_type} field compiled identically to bigint — "
            "the Rabin equality no longer discriminates"
        )
