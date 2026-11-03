"""N-045 (EXT-2 WideHash), SDK side — defence in depth only.

The on-chain state reader slices each fixed-width byte field at its declared
width, so a wrong-width value in a state section shifts every later field. The
consensus defence is the covenant's own ``OP_SIZE <width> OP_NUMEQUALVERIFY``
before each continuation commit (proved under strict Spend in
packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
These tests pin the off-chain refusals: ``serialize_state`` and
``prepare_call`` reject a wrong-width fixed-width value. (Constructor args are
deliberately NOT checked: ``from_utxo`` builds its contract with placeholder
constructor args. A mutable field's deploy-time value still goes through
``serialize_state``.) They prove nothing on chain. Subsumes the writer side of
F-237.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.state import serialize_state
from runar.sdk.types import (
    Abi, AbiMethod, AbiParam, RunarArtifact, StateField, Utxo,
)

TYPES = [
    ('PubKey', 33), ('Sha256', 32), ('Ripemd160', 20), ('Addr', 20),
    ('Point', 64), ('P256Point', 64), ('P384Point', 96),
]


@pytest.mark.parametrize('field_type,width', TYPES)
def test_serialize_state_refuses_wrong_width(field_type, width):
    fields = [StateField(name='k', type=field_type, index=0)]
    for bad in (width - 1, width + 1):
        with pytest.raises(ValueError, match=f'must be exactly {width} bytes'):
            serialize_state(fields, {'k': 'ab' * bad})
    with pytest.raises(ValueError, match='non-hex'):
        serialize_state(fields, {'k': 'zz' * width})
    assert serialize_state(fields, {'k': 'ab' * width}) == 'ab' * width


def _root_artifact() -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='N045Root',
        abi=Abi(
            constructor_params=[AbiParam(name='root', type='Sha256')],
            methods=[AbiMethod(name='updateRoot', is_public=True, params=[
                AbiParam(name='nextRoot', type='Sha256'),
                AbiParam(name='_changePKH', type='Ripemd160'),
                AbiParam(name='_changeAmount', type='bigint'),
                AbiParam(name='txPreimage', type='SigHashPreimage'),
            ])],
        ),
        script='51',
        state_fields=[StateField(name='root', type='Sha256', index=0)],
        code_separator_index=0,
    )


@pytest.mark.parametrize('bad', [31, 33, 66])
def test_prepare_call_refuses_wrong_width_sha256_arg(bad):
    contract = RunarContract(_root_artifact(), ['11' * 32])
    signer = MockSigner(address='00' * 20)
    provider = MockProvider('testnet')
    # Pretend deployed: the refusal must fire before any UTXO is touched.
    contract._current_utxo = Utxo(
        txid='bb' * 32, output_index=0, satoshis=10_000,
        script=contract.get_locking_script(),
    )
    with pytest.raises(ValueError, match=r"arg 'nextRoot' \(index 0\).*must be exactly 32 bytes"):
        contract.prepare_call('updateRoot', ['22' * bad], provider, signer)
