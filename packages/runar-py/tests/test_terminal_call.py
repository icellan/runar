"""Tests for terminal method calls in RunarContract."""

import pytest
from runar.sdk.types import (
    RunarArtifact, Abi, AbiParam, AbiMethod, Utxo, DeployOptions,
    CallOptions, TerminalOutput,
)
from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner


def make_artifact(script: str, methods: list[AbiMethod]) -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='Test',
        abi=Abi(constructor_params=[], methods=methods),
        script=script,
    )


def setup_funded_contract(satoshis: int = 50_000):
    """Deploy a simple OP_TRUE contract and return (contract, provider, signer)."""
    artifact = make_artifact('51', [
        AbiMethod(name='cancel', params=[], is_public=True),
    ])
    contract = RunarContract(artifact, [])
    provider = MockProvider(network='testnet')
    signer = MockSigner()
    address = signer.get_address()

    provider.add_utxo(address, Utxo(
        txid='aa' * 32,
        output_index=0,
        satoshis=100_000,
        script='76a914' + '00' * 20 + '88ac',
    ))

    contract.deploy(provider, signer, DeployOptions(satoshis=satoshis))
    return contract, provider, signer


def test_terminal_call_sets_utxo_to_none():
    contract, provider, signer = setup_funded_contract()

    payout_script = '76a914' + 'bb' * 20 + '88ac'
    txid, _tx = contract.call('cancel', [], provider, signer, CallOptions(
        terminal_outputs=[TerminalOutput(script_hex=payout_script, satoshis=49_000)],
    ))

    assert len(txid) == 64
    assert contract.get_utxo() is None


def test_terminal_call_subsequent_call_fails():
    contract, provider, signer = setup_funded_contract(satoshis=10_000)

    contract.call('cancel', [], provider, signer, CallOptions(
        terminal_outputs=[TerminalOutput(
            script_hex='76a914' + 'cc' * 20 + '88ac',
            satoshis=9_000,
        )],
    ))

    # Subsequent call should fail with "not deployed"
    with pytest.raises(RuntimeError, match='not deployed'):
        contract.call('cancel', [], provider, signer)


def test_terminal_call_multiple_outputs():
    contract, provider, signer = setup_funded_contract(satoshis=20_000)

    txid, _ = contract.call('cancel', [], provider, signer, CallOptions(
        terminal_outputs=[
            TerminalOutput(script_hex='76a914' + 'aa' * 20 + '88ac', satoshis=10_000),
            TerminalOutput(script_hex='76a914' + 'bb' * 20 + '88ac', satoshis=9_000),
        ],
    ))

    assert len(txid) == 64
    assert contract.get_utxo() is None


def test_terminal_call_tx_structure():
    contract, provider, signer = setup_funded_contract()

    payout_script = '76a914' + 'dd' * 20 + '88ac'
    contract.call('cancel', [], provider, signer, CallOptions(
        terminal_outputs=[TerminalOutput(script_hex=payout_script, satoshis=49_000)],
    ))

    broadcasted = provider.get_broadcasted_txs()
    # Deploy + terminal = 2 broadcasts
    assert len(broadcasted) == 2

    term_tx_hex = broadcasted[1]
    # Version should be 01000000
    assert term_tx_hex[:8] == '01000000'
    # Input count should be 1 (no funding inputs)
    assert term_tx_hex[8:10] == '01'


def test_terminal_call_dict_format():
    """Terminal outputs can also be passed as dicts."""
    contract, provider, signer = setup_funded_contract()

    payout_script = '76a914' + 'ee' * 20 + '88ac'
    txid, _ = contract.call('cancel', [], provider, signer, CallOptions(
        terminal_outputs=[{'script_hex': payout_script, 'satoshis': 49_000}],
    ))

    assert len(txid) == 64
    assert contract.get_utxo() is None
