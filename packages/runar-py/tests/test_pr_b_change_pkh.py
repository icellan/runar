"""#213, SDK side — defence in depth only.

A stateful method's unlocking script pushes the compiler-injected
``_changePKH`` (a Ripemd160, exactly 20 bytes). The consensus defence is the
covenant's entry gate on its width (``OP_SIZE 0x14 OP_NUMEQUALVERIFY``).
``RunarContract`` derives the change PKH as hash160(pubkey), always 20 bytes;
``encode_change_pkh`` is the single encoder every change-PKH push site goes
through, and refuses anything that is not exactly 20 bytes of hex.
``PreparedCall.change_pkh_hex`` is a plain dataclass field a caller can set, so
the refusal is also pinned through ``finalize_call``. Proves nothing on chain.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.state import encode_change_pkh
from runar.sdk.types import (
    Abi, AbiMethod, AbiParam, PreparedCall, RunarArtifact, StateField,
)


@pytest.mark.parametrize('n', [19, 21, 54])
def test_encode_change_pkh_refuses_wrong_width(n):
    with pytest.raises(ValueError, match=r'changePKH \(Ripemd160\) must be exactly 20 bytes'):
        encode_change_pkh('ab' * n)


def test_encode_change_pkh_refuses_non_hex():
    with pytest.raises(ValueError, match=r'changePKH \(Ripemd160\) must be exactly 20 bytes of hex, got a non-hex string'):
        encode_change_pkh('zz' * 20)


def test_encode_change_pkh_accepts_20_bytes():
    assert encode_change_pkh('ab' * 20) == '14' + 'ab' * 20


def _counter_artifact() -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='PrBCounter',
        abi=Abi(
            constructor_params=[AbiParam(name='count', type='bigint')],
            methods=[AbiMethod(name='increment', is_public=True, params=[
                AbiParam(name='_changePKH', type='Ripemd160'),
                AbiParam(name='_changeAmount', type='bigint'),
                AbiParam(name='txPreimage', type='SigHashPreimage'),
            ])],
        ),
        script='51',
        state_fields=[StateField(name='count', type='bigint', index=0)],
        code_separator_index=0,
    )


@pytest.mark.parametrize('n', [19, 21, 54])
def test_finalize_call_refuses_caller_set_change_pkh(n):
    contract = RunarContract(_counter_artifact(), [0])
    prepared = PreparedCall(
        method_name='increment', is_stateful=True, method_needs_change=True,
        change_pkh_hex='ab' * n,
    )
    with pytest.raises(ValueError, match=r'changePKH \(Ripemd160\) must be exactly 20 bytes'):
        contract.finalize_call(prepared, {}, MockProvider('testnet'))
