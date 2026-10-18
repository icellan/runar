"""N-329: a ByteString-family constructor arg that is not an even-length hex
string must be refused at construction with a typed error, not spliced into
the locking script as raw text (a push header sized for the raw bytes followed
by non-hex characters, with no error).

Proves: ``RunarContract`` raises ``InvalidConstructorArgError`` for raw
(non-hex) Addr text, odd-length hex and a non-hex ``FixedArray<Addr, 2>`` leaf,
with the shared diagnostic; valid hex (either case, empty) and ``bytes`` are
accepted and ``get_locking_script()`` is hex-only.
Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
spendability.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.errors import InvalidConstructorArgError
from runar.sdk.script_utils import is_hex_bytes
from runar.sdk.types import Abi, AbiMethod, AbiParam, ConstructorSlot, RunarArtifact


def _artifact(type_: str, fixed_array: dict | None = None) -> RunarArtifact:
    return RunarArtifact(
        contract_name='N329',
        script='00',
        abi=Abi(
            constructor_params=[AbiParam(name='owner', type=type_, fixed_array=fixed_array)],
            methods=[AbiMethod(name='noop', params=[], is_public=True)],
        ),
        constructor_slots=[ConstructorSlot(param_index=0, byte_offset=0)],
    )


RAW_ADDR = bytes(range(0x80, 0x94)).decode('latin-1')


@pytest.mark.parametrize('type_,arg', [
    ('Addr', RAW_ADDR),
    ('ByteString', 'abc'),
    ('PubKey', 'zz'),
])
def test_non_hex_bytestring_ctor_arg_is_refused(type_, arg):
    with pytest.raises(InvalidConstructorArgError, match=(
        r"constructor arg 'owner' \(.*\) of N329 must be an even-length hex string"
    )):
        RunarContract(_artifact(type_), [arg])


def test_non_hex_fixed_array_leaf_is_refused():
    art = _artifact('FixedArray<Addr, 2>', {'elementType': 'Addr', 'length': 2,
                                            'syntheticNames': ['owner__0', 'owner__1']})
    with pytest.raises(InvalidConstructorArgError):
        RunarContract(art, [['aabb', 'not-hex!']])


@pytest.mark.parametrize('arg', ['9a1c78a5', '9A1C78A5', '', bytes([0x9a, 0x1c])])
def test_hex_bytestring_ctor_arg_is_accepted(arg):
    c = RunarContract(_artifact('ByteString'), [arg])
    assert is_hex_bytes(c.get_locking_script())
