"""N-132 -- a string ``ANFProperty.initialValue`` on the ``--ir`` trust boundary.

The string arm of ``initialValue`` carries two different things, and the
discriminator is the trailing ``n`` -- exactly as it is for
``load_const.value``::

    "42n"       a decimal bigint -> the number 42
    "deadbeef"  a hex ByteString -> the bytes de ad be ef

Python implemented only the second reading here. ``_decode_const_value``
applies ``_is_decimal_bigint_literal`` to every ``load_const``, but
``_anf_property_from_dict`` passed ``initialValue`` through untouched, so a
``"...n"`` string reached ``_push_property_value``'s hex arm and died::

    stack lowering: non-hexadecimal number found in fromhex() arg at position 2

That is not an edge case. The TypeScript reference compiler emits ``"42n"``
for EVERY bigint property initializer it writes, whatever the magnitude
(measured with ``--emit-ir``), and Rust / Zig / Java emit the same shape once
the value passes int64. Python could not consume any of it.

The probe is a four-byte script -- push the property, OP_EQUALVERIFY against
the parameter -- so each assertion is about the property's bytes and nothing
else.
"""

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes

# secp256k1's group order, minimally encoded as script push data: PUSH33 then
# the 33-byte little-endian sign-magnitude body.
EC_N = (
    "115792089237316195423570985008687907852837564279074904382605163141518161494337"
)
EC_N_PUSH = "21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00"


def _ir(initial_value_json: str) -> bytes:
    """Smallest IR that pushes one property's ``initialValue``.

    ``initial_value_json`` is spliced in as raw JSON text so a test can write a
    string, a number, or a literal of any width without a Python type getting
    an opinion about it first.
    """
    return (
        """{
      "contractName": "InitProbe",
      "properties": [
        {"name": "v", "type": "bigint", "readonly": true, "initialValue": %s}
      ],
      "methods": [
        {"name": "constructor", "params": [], "isPublic": false,
         "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
        {"name": "check", "params": [{"name": "expected", "type": "bigint"}], "isPublic": true,
         "body": [
           {"name": "t0", "value": {"kind": "load_prop", "name": "v"}},
           {"name": "t1", "value": {"kind": "load_param", "name": "expected"}},
           {"name": "t2", "value": {"kind": "bin_op", "left": "t0", "op": "===", "right": "t1"}},
           {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
         ]}
      ]
    }"""
        % initial_value_json
    ).encode()


def _hex(initial_value_json: str) -> str:
    return compile_from_ir_bytes(_ir(initial_value_json)).script


@pytest.mark.parametrize(
    "as_string,as_integer",
    [('"42n"', "42"), ('"-3n"', "-3"), ('"0n"', "0")],
)
def test_decimal_bigint_string_means_the_integer(as_string, as_integer):
    """Not "it loads" -- "it loads AS the number it spells".

    A loader that accepted the string and read it as something else passes any
    does-it-load test and still emits a locking script the IR does not
    describe.
    """
    assert _hex(as_string) == _hex(as_integer)


def test_decimal_bigint_string_exact_bytes():
    # 0 is what every fallback path also produces, so a non-zero case is what
    # makes the equality above mean something. Pin the literal bytes.
    assert _hex('"42n"') == "012a7c9c"


def test_oversize_bigint_string_is_not_truncated():
    # The reason the string form exists (issue #121): a value this wide cannot
    # survive a JSON number in a double-backed reader.
    assert EC_N_PUSH in _hex('"%sn"' % EC_N)


def test_bare_digit_string_is_hex_not_decimal():
    """The control an over-broad fix fails.

    ``"1000"`` is the two bytes 0x10 0x00. One thousand is 0xe8 0x03. A tier
    that reads any all-digit string as decimal passes every other test here.
    """
    as_hex = _hex('"1000"')
    as_decimal = _hex("1000")
    assert as_hex == "0210007c9c"
    assert as_decimal == "02e8037c9c"
    assert as_hex != as_decimal


def test_hex_bytestring_still_decodes():
    assert _hex('"deadbeef"') == "04deadbeef7c9c"
    assert _hex('""') == "007c9c"


@pytest.mark.parametrize("bad", ['"zz"', '"5"', '"5nn"', '"1.5n"', '"n"', '"-n"'])
def test_unreadable_string_is_refused(bad):
    """A string that is neither form is refused, not decoded leniently.

    Python already refused all of these; the rows are here so the new bigint
    arm cannot quietly widen into them.
    """
    with pytest.raises(Exception):
        compile_from_ir_bytes(_ir(bad))


def test_probe_ir_is_well_formed():
    # Vacuity guard: every assertion above rests on this document being the
    # shape it claims, with exactly one property carrying the spliced value.
    doc = json.loads(_ir("42").decode())
    assert [p["name"] for p in doc["properties"]] == ["v"]
    assert doc["properties"][0]["initialValue"] == 42
