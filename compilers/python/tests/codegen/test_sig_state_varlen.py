"""`Sig` / `SigHashPreimage` state fields are push-data-framed variable-length state.

``compilers/python/runar_compiler/codegen/stack.py`` kept three lists of "which
state types carry a push-data length prefix":

* ``is_variable_length_state_type`` + the ``_lower_deserialize_state`` size table
  + the var-length parse loop — all say ``ByteString | Sig | SigHashPreimage``;
* the two state SERIALIZERS (``:2563`` and ``:3110``) — said ``== "ByteString"``;
* the ``var_len_props`` set inside ``_compute_uses_code_part`` (``:5271`` /
  ``:5298``) — same.

Two faces, both fund loss:

* WRITE — a mutating method wrote the continuation state RAW, with no length
  prefix, while the reader in the NEXT spend push-data-decodes it and takes the
  DER ``0x30`` as a length-48 push. Deploy succeeds, the first spend succeeds,
  and the UTXO that spend creates is unspendable.
* READ — for a TERMINAL method reading a mutable ``Sig`` field
  ``uses_code_part`` stayed False, ``_lower_deserialize_state`` took its "no
  ``_codePart``" shortcut and pushed no mutable property at all, so every
  ``load_prop`` fell through to the DEPLOY-TIME constructor placeholder.

The deploy-time writer settles which list is right: every SDK's
``encode_state_value`` enumerates the fixed-size types (PubKey, Addr,
Ripemd160, Sha256, Point, P256Point, P384Point) and push-data-frames the rest.

The lock: a ``Sig`` / ``SigHashPreimage`` field must compile BYTE-IDENTICALLY to
the same contract with a ``ByteString`` field — the path that was already
correct. ``RabinSig`` (a bigint alias, a bare 8-byte NUM2BIN word) and
``PubKey`` (33 raw bytes) are the negative controls and must stay DIFFERENT.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

VAR_LEN_TYPES = ["Sig", "SigHashPreimage"]


def write_src(prop_type: str) -> str:
    """Mutating method — drives the state-continuation WRITE path."""
    return f"""
class VarLenStateWrite extends StatefulSmartContract {{
  tag: {prop_type};
  constructor(tag: {prop_type}) {{ super(tag); this.tag = tag; }}
  public update(next: {prop_type}) {{ this.tag = next; }}
}}
"""


def read_src(prop_type: str) -> str:
    """Terminal method reading the field — drives ``_compute_uses_code_part``."""
    return f"""
class VarLenStateRead extends StatefulSmartContract {{
  tag: {prop_type};
  constructor(tag: {prop_type}) {{ super(tag); this.tag = tag; }}
  public check(expected: bigint) {{ assert(len(this.tag) == expected); }}
}}
"""


def _compile(src: str, file_name: str):
    r = compile_from_source_str_with_result(src, file_name, disable_constant_folding=True)
    assert r.success, [d.message for d in r.diagnostics]
    return r


def _uses_code_part(result, method: str) -> bool:
    for m in result.artifact.abi.methods:
        if m.name == method:
            return bool(m.uses_code_part)
    raise AssertionError(f"method {method!r} not found in the ABI")


class TestVarLenStateWrite:
    @pytest.mark.parametrize("prop_type", VAR_LEN_TYPES)
    def test_continuation_frames_like_bytestring(self, prop_type):
        control = _compile(write_src("ByteString"), "VarLenStateWrite.runar.ts")
        got = _compile(write_src(prop_type), "VarLenStateWrite.runar.ts")
        assert got.script_hex == control.script_hex, (
            f"a mutable {prop_type} field does not push-data-frame its continuation "
            f"state: len(got)={len(got.script_hex)} len(want)={len(control.script_hex)}"
        )


class TestVarLenStateRead:
    @pytest.mark.parametrize("prop_type", VAR_LEN_TYPES)
    def test_terminal_read_matches_bytestring(self, prop_type):
        control = _compile(read_src("ByteString"), "VarLenStateRead.runar.ts")
        got = _compile(read_src(prop_type), "VarLenStateRead.runar.ts")
        assert got.script_hex == control.script_hex, (
            f"a terminal read of a mutable {prop_type} field diverges from the "
            f"ByteString control: len(got)={len(got.script_hex)} "
            f"len(want)={len(control.script_hex)}"
        )

    @pytest.mark.parametrize("prop_type", VAR_LEN_TYPES + ["ByteString"])
    def test_terminal_read_uses_code_part(self, prop_type):
        # The ABI shape, not just the byte count: the SDK reads this flag to
        # decide whether to push _codePart into the unlocking script.
        assert _uses_code_part(_compile(read_src(prop_type), "VarLenStateRead.runar.ts"), "check") is True


class TestNegativeControls:
    """Types this change must NOT move into the variable-length set."""

    @pytest.mark.parametrize("prop_type", ["RabinSig", "RabinPubKey", "PubKey"])
    def test_fixed_width_state_is_not_push_data_framed(self, prop_type):
        control = _compile(write_src("ByteString"), "VarLenStateWrite.runar.ts")
        fixed = _compile(write_src(prop_type), "VarLenStateWrite.runar.ts")
        assert fixed.script_hex != control.script_hex, (
            f"{prop_type} compiled identically to ByteString — it must keep its "
            "fixed-width framing, or the assertions above stop discriminating"
        )
