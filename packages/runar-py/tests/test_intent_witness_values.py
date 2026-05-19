"""R-6 — SDK consumer support for intent-intrinsic auto-injected witness params.

Covers ``_prevOutScript_<i>`` and ``_serialisedOutputs``:

  - filter: auto-injected witness params are NOT part of the user arg count
  - setters: set_prev_out_script / set_serialised_outputs store witness bytes
  - errors: missing witness raises a typed WitnessValueMissingError
  - wiring: witness bytes are appended to the primary unlocking script in
    ABI order (`_prevOutScript_*` first, then `_serialisedOutputs`)
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.errors import WitnessValueMissingError
from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.types import (
    Abi, AbiMethod, AbiParam, CallOptions, DeployOptions, RunarArtifact, StateField, Utxo,
)


def _make_intent_artifact(prev_out_inputs: list[int], serialised: bool) -> RunarArtifact:
    params: list[AbiParam] = [
        AbiParam(name='amount', type='bigint'),
        AbiParam(name='_changePKH', type='Ripemd160'),
        AbiParam(name='_changeAmount', type='bigint'),
        AbiParam(name='_newAmount', type='bigint'),
        AbiParam(name='txPreimage', type='SigHashPreimage'),
    ]
    for i in prev_out_inputs:
        params.append(AbiParam(name=f'_prevOutScript_{i}', type='ByteString'))
    if serialised:
        params.append(AbiParam(name='_serialisedOutputs', type='ByteString'))

    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='IntentWitnessTest',
        abi=Abi(
            constructor_params=[AbiParam(name='count', type='bigint')],
            methods=[AbiMethod(name='move', params=params, is_public=True)],
        ),
        script='51',
        state_fields=[StateField(name='count', type='bigint', index=0)],
        # Stateful with codeSeparatorIndex=0 keeps the stateful branch active.
        code_separator_index=0,
    )


def _funded_provider(address: str, satoshis: int = 100_000) -> MockProvider:
    provider = MockProvider('testnet')
    provider.add_utxo(address, Utxo(
        txid='aa' * 32,
        output_index=0,
        satoshis=satoshis,
        script='76a914' + '00' * 20 + '88ac',
    ))
    return provider


def _deploy(artifact: RunarArtifact):
    contract = RunarContract(artifact, [0])
    signer = MockSigner(address='00' * 20)
    provider = _funded_provider(signer.get_address())
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    # Funding UTXO for the call
    provider.add_utxo(signer.get_address(), Utxo(
        txid='bb' * 32,
        output_index=1,
        satoshis=100_000,
        script='76a914' + '00' * 20 + '88ac',
    ))
    return contract, provider, signer


# ---------------------------------------------------------------------------
# Filter: arg-count check excludes _prevOutScript_* / _serialisedOutputs
# ---------------------------------------------------------------------------

def test_filter_excludes_auto_injected_witness_params():
    artifact = _make_intent_artifact([0, 1], serialised=True)
    contract, provider, signer = _deploy(artifact)

    contract.set_prev_out_script(0, 'aa')
    contract.set_prev_out_script(1, 'bb')
    contract.set_serialised_outputs('cc')

    contract.call('move', [123], provider, signer, CallOptions(new_state={'count': 1}))
    assert contract._state['count'] == 1


def test_filter_still_rejects_real_arg_count_mismatch():
    artifact = _make_intent_artifact([0], serialised=True)
    contract, provider, signer = _deploy(artifact)

    with pytest.raises(ValueError) as exc_info:
        contract.call('move', [1, 2], provider, signer)
    assert 'expects 1 args, got 2' in str(exc_info.value)


# ---------------------------------------------------------------------------
# Missing witness ⇒ typed WitnessValueMissingError
# ---------------------------------------------------------------------------

def test_missing_prev_out_script_raises_typed_error():
    artifact = _make_intent_artifact([0], serialised=False)
    contract, provider, signer = _deploy(artifact)

    with pytest.raises(WitnessValueMissingError) as exc_info:
        contract.call('move', [1], provider, signer)
    err = exc_info.value
    assert err.param_name == '_prevOutScript_0'
    assert err.method_name == 'move'
    assert err.contract_name == 'IntentWitnessTest'


def test_missing_serialised_outputs_raises_typed_error():
    artifact = _make_intent_artifact([], serialised=True)
    contract, provider, signer = _deploy(artifact)

    with pytest.raises(WitnessValueMissingError) as exc_info:
        contract.call('move', [1], provider, signer)
    assert exc_info.value.param_name == '_serialisedOutputs'


# ---------------------------------------------------------------------------
# Wiring: witness bytes appear in the broadcast unlocking script
# ---------------------------------------------------------------------------

def test_appends_multiple_prev_out_scripts_in_abi_order():
    artifact = _make_intent_artifact([0, 1], serialised=False)
    contract, provider, signer = _deploy(artifact)

    contract.set_prev_out_script(0, 'deadbeef')
    contract.set_prev_out_script(1, 'cafebabe')

    contract.call('move', [1], provider, signer, CallOptions(new_state={'count': 1}))

    txs = provider.get_broadcasted_txs()
    assert len(txs) == 2  # deploy + call
    call_tx_hex = txs[1]
    push0 = '04' + 'deadbeef'
    push1 = '04' + 'cafebabe'
    idx0 = call_tx_hex.find(push0)
    idx1 = call_tx_hex.find(push1)
    assert idx0 >= 0, 'witness 0 push not found'
    assert idx1 > idx0, f'witness 1 must follow witness 0 (idx0={idx0}, idx1={idx1})'


def test_appends_prev_out_then_serialised_in_abi_order():
    artifact = _make_intent_artifact([0], serialised=True)
    contract, provider, signer = _deploy(artifact)

    contract.set_prev_out_script(0, '11223344')
    contract.set_serialised_outputs('55667788')

    contract.call('move', [1], provider, signer, CallOptions(new_state={'count': 1}))

    call_tx_hex = provider.get_broadcasted_txs()[1]
    push_prev = '04' + '11223344'
    push_serial = '04' + '55667788'
    idx_prev = call_tx_hex.find(push_prev)
    idx_serial = call_tx_hex.find(push_serial)
    assert idx_prev >= 0
    assert idx_serial > idx_prev


def test_accepts_witness_values_as_bytes():
    artifact = _make_intent_artifact([0], serialised=False)
    contract, provider, signer = _deploy(artifact)

    contract.set_prev_out_script(0, bytes.fromhex('abcd'))
    contract.call('move', [1], provider, signer, CallOptions(new_state={'count': 1}))
    call_tx_hex = provider.get_broadcasted_txs()[1]
    # 2-byte push = "02abcd"
    assert '02abcd' in call_tx_hex


def test_rejects_invalid_hex():
    artifact = _make_intent_artifact([0], serialised=False)
    contract = RunarContract(artifact, [0])
    with pytest.raises(ValueError):
        contract.set_prev_out_script(0, 'not-hex!')
    with pytest.raises(ValueError):
        contract.set_serialised_outputs('abc')
