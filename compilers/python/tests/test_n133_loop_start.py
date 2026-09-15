"""N-133 -- ``loop.start`` on the ``--ir`` trust boundary.

``Loop.start`` is ``integer | string``, and the string arm is the sanctioned
``"<decimal>n"`` form -- the suffix is REQUIRED, which is what Java's loader
implements and what the schema's other two string-carrying integer fields
(``load_const.value``, ``ANFProperty.initialValue``) mean by a string.

Python's ``_anf_value_from_dict`` did two looser things::

    "5"   -> int("5")   = 5      while rust read the same input as 0
    True  -> int(True)  = 1      a boolean silently became a loop start

Both exit 0 and compile a loop the IR does not describe. The second is the
sharper one: ``isinstance(True, int)`` is ``True`` in Python, so a boolean
walks straight through an integer check that looks correct.

The probe is a two-iteration loop summing its iterator, so the start lands in
the emitted bytes and nothing else does.
"""

import pytest

from runar_compiler.compiler import compile_from_ir_bytes


def _ir(start_json: str) -> bytes:
    return (
        """{
      "contractName": "LoopProbe",
      "properties": [{"name": "target", "type": "bigint", "readonly": true}],
      "methods": [
        {"name": "constructor", "params": [], "isPublic": false,
         "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
        {"name": "run", "params": [], "isPublic": true,
         "body": [
           {"name": "acc", "value": {"kind": "load_const", "value": 0}},
           {"name": "t1", "value": {"kind": "loop", "count": 2, "iterVar": "i",
             "start": %s, "step": 1,
             "body": [{"name": "acc", "value": {"kind": "bin_op", "left": "acc", "op": "+", "right": "i"}}]}},
           {"name": "t2", "value": {"kind": "load_prop", "name": "target"}},
           {"name": "t3", "value": {"kind": "bin_op", "left": "acc", "op": "===", "right": "t2"}},
           {"name": "t4", "value": {"kind": "assert", "value": "t3"}}
         ]}
      ]
    }"""
        % start_json
    ).encode()


def _hex(start_json: str) -> str:
    return compile_from_ir_bytes(_ir(start_json)).script


@pytest.mark.parametrize(
    "as_string,as_integer,want",
    [('"5n"', "5", "5b009c"), ('"-3n"', "-3", "0185009c")],
)
def test_decimal_bigint_string_start_means_the_integer(as_string, as_integer, want):
    # Both non-zero: 0 is what every fallback path produces too.
    assert _hex(as_string) == _hex(as_integer) == want


def test_over_int64_start_is_not_truncated():
    # Python ints are arbitrary-precision, so this tier carries the value.
    assert _hex('"999999999999999999999999999999n"') == "0dffffff7fd4dbe98ca039593e19009c"


@pytest.mark.parametrize(
    "bad", ['"5"', '"abc"', '""', '"5nn"', '"n"', '"-n"', '"1.5n"', "true", "null"]
)
def test_unreadable_start_is_refused(bad):
    with pytest.raises(Exception):
        compile_from_ir_bytes(_ir(bad))


def test_zero_start_is_its_own_script():
    # The bytes every fallback-to-zero lands on. If the probe could not tell
    # start 0 from start 5 apart, none of the rows above would mean anything.
    assert _hex("0") == "008b009c"
    assert _hex("0") != _hex("5")
