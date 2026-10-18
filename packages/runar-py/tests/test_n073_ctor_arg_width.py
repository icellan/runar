"""N-073: a fixed-width ByteString-family constructor arg must have its
declared width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
P384Point 96), with N-045's message. ``from_utxo``'s internal restore path is
unaffected.

Proves: a 33-byte Sha256 and a 19-byte Addr (scalar, bytes, FixedArray leaf)
are refused with ``InvalidConstructorArgError`` carrying the N-045 wording;
correct widths are accepted; ByteString takes any length; ``from_utxo``
restores.
Does NOT prove: method-call or state value widths (N-045), on-chain
spendability, or that the restore bypass is unreachable by user input.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.errors import InvalidConstructorArgError
from runar.sdk.types import Utxo, Abi, AbiMethod, AbiParam, ConstructorSlot, RunarArtifact


def _artifact(type_: str, fixed_array: dict | None = None) -> RunarArtifact:
    return RunarArtifact(
        contract_name='N073',
        script='00',
        abi=Abi(
            constructor_params=[AbiParam(name='owner', type=type_, fixed_array=fixed_array)],
            methods=[AbiMethod(name='noop', params=[], is_public=True)],
        ),
        constructor_slots=[ConstructorSlot(param_index=0, byte_offset=0)],
    )


def _hex(n: int) -> str:
    return 'ab' * n


def test_wrong_width_sha256_is_refused_with_n045_message():
    with pytest.raises(InvalidConstructorArgError, match=(
        r"constructor arg 'owner' \(Sha256\) must be exactly 32 bytes of hex, got 33 bytes"
    )):
        RunarContract(_artifact('Sha256'), [_hex(33)])


@pytest.mark.parametrize('arg', [_hex(19), bytes(19)], ids=['str', 'bytes'])
def test_wrong_width_addr_is_refused(arg):
    with pytest.raises(InvalidConstructorArgError):
        RunarContract(_artifact('Addr'), [arg])


def test_wrong_width_fixed_array_leaf_is_refused():
    fa = {'elementType': 'Addr', 'length': 2, 'syntheticNames': ['owner__0', 'owner__1']}
    with pytest.raises(InvalidConstructorArgError):
        RunarContract(_artifact('FixedArray<Addr, 2>', fa), [[_hex(20), _hex(19)]])


@pytest.mark.parametrize('type_,n', [
    ('Addr', 20), ('Ripemd160', 20), ('Sha256', 32), ('PubKey', 33),
    ('Point', 64), ('P256Point', 64), ('P384Point', 96),
])
def test_correct_width_accepted_and_one_less_refused(type_, n):
    RunarContract(_artifact(type_), [_hex(n)]).get_locking_script()
    with pytest.raises(InvalidConstructorArgError):
        RunarContract(_artifact(type_), [_hex(n - 1)])


def test_bytestring_takes_any_length():
    RunarContract(_artifact('ByteString'), [_hex(3)])


def test_from_utxo_still_restores():
    a = _artifact('Addr')
    script = RunarContract(a, [_hex(20)]).get_locking_script()
    c = RunarContract.from_utxo(a, Utxo(txid='00' * 32, output_index=0, satoshis=1, script=script))
    assert c.get_locking_script() == script
