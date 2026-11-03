"""N-330: a non-string ByteString-family constructor arg must be encoded as the
raw bytes it is (``bytes`` / ``bytearray``) or refused with
``InvalidConstructorArgError``. Before, ``_encode_arg``'s fallback did
``str(value)``, so ``None`` became ``"None"`` and a ``bytearray`` became
``"bytearray(b'..')"`` -- spliced into the locking script as text.

Proves: ``bytes`` / ``bytearray`` (scalar and FixedArray leaf) yield the same
locking script as the equivalent hex string; ``None``, ``int``, ``bool``,
``float`` and ``list``-of-int args are refused with the shared diagnostic.
Does NOT prove: width checks, method-call args or on-chain spendability.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.errors import InvalidConstructorArgError
from runar.sdk.types import Abi, AbiMethod, AbiParam, ConstructorSlot, RunarArtifact


def _artifact(type_: str, fixed_array: dict | None = None) -> RunarArtifact:
    return RunarArtifact(
        contract_name='N330',
        script='00',
        abi=Abi(
            constructor_params=[AbiParam(name='owner', type=type_, fixed_array=fixed_array)],
            methods=[AbiMethod(name='noop', params=[], is_public=True)],
        ),
        constructor_slots=[ConstructorSlot(param_index=0, byte_offset=0)],
    )


RAW = bytes([0x9a, 0x1c, 0x78, 0xa5])


@pytest.mark.parametrize('arg', [RAW, bytearray(RAW)], ids=['bytes', 'bytearray'])
def test_raw_bytes_encode_as_those_bytes(arg):
    via_bytes = RunarContract(_artifact('ByteString'), [arg]).get_locking_script()
    via_hex = RunarContract(_artifact('ByteString'), [RAW.hex()]).get_locking_script()
    assert via_bytes == via_hex


def test_raw_bytes_fixed_array_leaf_encodes_as_those_bytes():
    fa = {'elementType': 'Addr', 'length': 2, 'syntheticNames': ['owner__0', 'owner__1']}
    a = _artifact('FixedArray<Addr, 2>', fa)
    # N-073: Addr is fixed-width (20 bytes), so use a full-width value.
    addr = bytes(range(1, 21))
    via_bytes = RunarContract(a, [[bytearray(addr), addr.hex()]]).get_locking_script()
    via_hex = RunarContract(a, [[addr.hex(), addr.hex()]]).get_locking_script()
    assert via_bytes == via_hex


@pytest.mark.parametrize('arg', [None, 5, True, 1.5, [1, 2, 3], {'a': 1}],
                         ids=['None', 'int', 'bool', 'float', 'list', 'dict'])
def test_non_string_bytestring_ctor_arg_is_refused(arg):
    with pytest.raises(InvalidConstructorArgError, match=(
        r"constructor arg 'owner' \(ByteString\) of N330 must be an even-length hex string"
    )):
        RunarContract(_artifact('ByteString'), [arg])


def test_none_fixed_array_leaf_is_refused():
    fa = {'elementType': 'Addr', 'length': 2, 'syntheticNames': ['owner__0', 'owner__1']}
    with pytest.raises(InvalidConstructorArgError):
        RunarContract(_artifact('FixedArray<Addr, 2>', fa), [['aabb', None]])
