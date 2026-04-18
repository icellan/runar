"""Tests for StatefulSmartContract output-tracking methods.

Covers add_output (state), add_raw_output (raw), and add_data_output (data).
Each method must record a distinguishable entry in the ``_outputs`` list so
tests can introspect what a contract emitted.
"""

from __future__ import annotations

from runar import StatefulSmartContract


class _Dummy(StatefulSmartContract):
    """Minimal concrete subclass for exercising the output-tracking API."""


def test_add_output_records_state_output():
    c = _Dummy()
    c.add_output(1000, 42, b"\xaa")
    assert len(c._outputs) == 1
    out = c._outputs[0]
    assert out["kind"] == "state"
    assert out["satoshis"] == 1000
    assert out["values"] == [42, b"\xaa"]


def test_add_raw_output_records_raw_output():
    c = _Dummy()
    c.add_raw_output(500, b"\x51")
    assert len(c._outputs) == 1
    out = c._outputs[0]
    assert out["kind"] == "raw"
    assert out["satoshis"] == 500
    assert out["script_bytes"] == b"\x51"


def test_add_data_output_records_data_output():
    """add_data_output should record a 'data'-kind entry distinguishable from
    state and raw outputs."""
    c = _Dummy()
    c.add_data_output(0, b"\x6a\x04test")  # OP_RETURN + 4 bytes "test"
    assert len(c._outputs) == 1
    out = c._outputs[0]
    assert out["kind"] == "data"
    assert out["satoshis"] == 0
    assert out["script_bytes"] == b"\x6a\x04test"


def test_outputs_mixed_order_preserved():
    """When a method emits both state and data outputs, ordering is preserved
    and kinds are distinguishable."""
    c = _Dummy()
    c.add_output(1000, 1)
    c.add_output(1000, 2)
    c.add_data_output(0, b"\xaa")
    c.add_raw_output(42, b"\xbb")

    kinds = [o["kind"] for o in c._outputs]
    assert kinds == ["state", "state", "data", "raw"]


def test_reset_outputs_clears_all_kinds():
    c = _Dummy()
    c.add_output(1000, 1)
    c.add_data_output(0, b"\xaa")
    c.add_raw_output(42, b"\xbb")
    c.reset_outputs()
    assert c._outputs == []
