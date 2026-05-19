"""Item 8 — ScriptSizeExceededError at SDK entry points (Python).

Verifies that deploy/call/provider entry points reject scripts that exceed
MAX_SCRIPT_BYTES with a typed ScriptSizeExceededError BEFORE any signing /
broadcast work happens.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.errors import ScriptSizeExceededError
from runar.sdk.input_limits import MAX_SCRIPT_BYTES
from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.types import (
    Abi, AbiMethod, DeployOptions, RunarArtifact, Utxo,
)


def _oversized_script_hex() -> str:
    return '51' * (MAX_SCRIPT_BYTES + 1)


def _at_limit_script_hex() -> str:
    return '51' * MAX_SCRIPT_BYTES


def _make_artifact(script: str, contract_name: str = 'OversizedContract',
                   methods: list[AbiMethod] | None = None) -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name=contract_name,
        abi=Abi(constructor_params=[], methods=methods or []),
        script=script,
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


# ---------------------------------------------------------------------------
# deploy()
# ---------------------------------------------------------------------------

def test_deploy_rejects_oversized_script():
    contract = RunarContract(_make_artifact(_oversized_script_hex()), [])
    signer = MockSigner(address='00' * 20)
    provider = _funded_provider(signer.get_address())

    with pytest.raises(ScriptSizeExceededError) as exc_info:
        contract.deploy(provider, signer, DeployOptions(satoshis=1_000))

    err = exc_info.value
    assert err.limit == MAX_SCRIPT_BYTES
    assert err.actual == MAX_SCRIPT_BYTES + 1
    assert 'OversizedContract.deploy' in err.context
    assert f'limit={MAX_SCRIPT_BYTES}' in str(err)
    assert f'actual={MAX_SCRIPT_BYTES + 1}' in str(err)

    # No broadcast should have happened — guard fires BEFORE signing/broadcast.
    assert len(provider.get_broadcasted_txs()) == 0


# ---------------------------------------------------------------------------
# call()
# ---------------------------------------------------------------------------

def test_call_rejects_oversized_current_utxo_script():
    # Use from_utxo() to simulate a reconnect with a poisoned (oversized)
    # locking script. Avoids needing to deploy first.
    artifact = _make_artifact(
        '51',
        methods=[AbiMethod(name='spend', params=[], is_public=True)],
    )
    poisoned_utxo = Utxo(
        txid='aa' * 32,
        output_index=0,
        satoshis=50_000,
        script=_oversized_script_hex(),
    )
    contract = RunarContract.from_utxo(artifact, poisoned_utxo)
    signer = MockSigner(address='00' * 20)
    provider = _funded_provider(signer.get_address())

    with pytest.raises(ScriptSizeExceededError) as exc_info:
        contract.call('spend', [], provider, signer)

    err = exc_info.value
    assert err.limit == MAX_SCRIPT_BYTES
    assert err.actual == MAX_SCRIPT_BYTES + 1
    assert 'OversizedContract.call(spend)' in err.context

    # No broadcast should have happened.
    assert len(provider.get_broadcasted_txs()) == 0


# ---------------------------------------------------------------------------
# Provider.get_utxos / get_contract_utxo
# ---------------------------------------------------------------------------

def test_mock_provider_get_utxos_rejects_oversized_script():
    provider = MockProvider('testnet')
    provider.add_utxo('addr', Utxo(
        txid='bb' * 32,
        output_index=0,
        satoshis=1_000,
        script=_oversized_script_hex(),
    ))

    with pytest.raises(ScriptSizeExceededError) as exc_info:
        provider.get_utxos('addr')

    err = exc_info.value
    assert err.limit == MAX_SCRIPT_BYTES
    assert err.actual == MAX_SCRIPT_BYTES + 1
    assert 'MockProvider.get_utxos' in err.context


def test_mock_provider_get_contract_utxo_rejects_oversized_script():
    provider = MockProvider('testnet')
    provider.add_contract_utxo('script-hash', Utxo(
        txid='cc' * 32,
        output_index=0,
        satoshis=1_000,
        script=_oversized_script_hex(),
    ))

    with pytest.raises(ScriptSizeExceededError) as exc_info:
        provider.get_contract_utxo('script-hash')

    assert 'MockProvider.get_contract_utxo' in exc_info.value.context


def test_at_limit_script_passes_provider_guard():
    provider = MockProvider('testnet')
    provider.add_utxo('addr', Utxo(
        txid='dd' * 32,
        output_index=0,
        satoshis=1_000,
        script=_at_limit_script_hex(),
    ))
    utxos = provider.get_utxos('addr')
    assert len(utxos) == 1
    assert len(utxos[0].script) == MAX_SCRIPT_BYTES * 2
