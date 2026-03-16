"""Tests for RunarContract.from_txid.

Mirrors TestFromTxId_* tests from packages/runar-go/sdk_test.go.
"""

import pytest
from runar.sdk.contract import RunarContract
from runar.sdk.types import (
    RunarArtifact, Abi, AbiParam, AbiMethod, StateField,
    TransactionData, TxOutput, TxInput,
)
from runar.sdk.provider import MockProvider
from runar.sdk.state import serialize_state


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_artifact(script: str, ctor_params=None, methods=None, state_fields=None) -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='Test',
        abi=Abi(
            constructor_params=ctor_params or [],
            methods=methods or [],
        ),
        script=script,
        state_fields=state_fields or [],
    )


def _make_tx(txid: str, outputs: list[TxOutput]) -> TransactionData:
    return TransactionData(
        txid=txid,
        version=1,
        inputs=[TxInput(txid='00' * 32, output_index=0, script='', sequence=0xFFFFFFFF)],
        outputs=outputs,
        locktime=0,
    )


FAKE_TXID = 'aa' * 32


# ---------------------------------------------------------------------------
# TestFromTxId
# ---------------------------------------------------------------------------

class TestFromTxId:
    def test_stateful_extracts_state(self):
        """from_txid on a stateful contract correctly extracts state fields."""
        state_fields = [
            StateField(name='count', type='bigint', index=0),
            StateField(name='active', type='bool', index=1),
        ]
        code_hex = '76a988ac'
        state_values = {'count': 42, 'active': True}
        state_hex = serialize_state(state_fields, state_values)
        full_script = code_hex + '6a' + state_hex

        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=10_000, script=full_script),
        ]))

        artifact = _make_artifact(
            code_hex,
            ctor_params=[
                AbiParam(name='count', type='bigint'),
                AbiParam(name='active', type='bool'),
            ],
            state_fields=state_fields,
        )

        contract = RunarContract.from_txid(artifact, FAKE_TXID, 0, provider)

        state = contract.get_state()
        assert state['count'] == 42
        assert state['active'] is True

    def test_stateless(self):
        """from_txid on a stateless contract works without state extraction."""
        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=5_000, script='51'),
        ]))

        artifact = _make_artifact(
            '51',
            methods=[AbiMethod(name='spend', params=[], is_public=True)],
        )

        contract = RunarContract.from_txid(artifact, FAKE_TXID, 0, provider)

        state = contract.get_state()
        assert len(state) == 0

    def test_out_of_range_output_index_raises(self):
        """from_txid with output_index >= number of outputs raises an error."""
        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=5_000, script='51'),
        ]))

        artifact = _make_artifact('51')

        with pytest.raises((ValueError, RuntimeError)):
            RunarContract.from_txid(artifact, FAKE_TXID, 5, provider)

    def test_unknown_txid_raises(self):
        """from_txid with a txid not in the provider raises an error."""
        provider = MockProvider('testnet')  # empty, no transactions

        artifact = _make_artifact('51')

        unknown_txid = 'ff' * 32
        with pytest.raises((RuntimeError, ValueError)):
            RunarContract.from_txid(artifact, unknown_txid, 0, provider)

    def test_reconnects_contract(self):
        """After from_txid, the contract has the UTXO set so it can be called."""
        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=10_000, script='51'),
        ]))

        artifact = _make_artifact(
            '51',
            methods=[AbiMethod(name='spend', params=[], is_public=True)],
        )

        contract = RunarContract.from_txid(artifact, FAKE_TXID, 0, provider)

        utxo = contract.get_utxo()
        assert utxo is not None
        assert utxo.txid == FAKE_TXID
        assert utxo.output_index == 0
        assert utxo.satoshis == 10_000

    def test_preserves_code_script_for_state_update(self):
        """After from_txid, updating state uses the code portion from the on-chain script."""
        state_fields = [StateField(name='count', type='bigint', index=0)]
        code_hex = '76a988ac'
        state_hex = serialize_state(state_fields, {'count': 10})
        full_script = code_hex + '6a' + state_hex

        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=10_000, script=full_script),
        ]))

        artifact = _make_artifact(
            code_hex,
            ctor_params=[AbiParam(name='count', type='bigint')],
            state_fields=state_fields,
        )

        contract = RunarContract.from_txid(artifact, FAKE_TXID, 0, provider)
        contract.set_state({'count': 99})

        new_script = contract.get_locking_script()
        new_state_hex = serialize_state(state_fields, {'count': 99})
        expected = code_hex + '6a' + new_state_hex
        assert new_script == expected

    def test_out_of_range_error_message(self):
        """out-of-range output index error mentions 'out of range' or similar."""
        provider = MockProvider('testnet')
        provider.add_transaction(_make_tx(FAKE_TXID, [
            TxOutput(satoshis=5_000, script='51'),
        ]))

        artifact = _make_artifact('51')

        with pytest.raises((ValueError, RuntimeError)) as exc_info:
            RunarContract.from_txid(artifact, FAKE_TXID, 5, provider)

        msg = str(exc_info.value).lower()
        assert 'out of range' in msg or 'index' in msg

    def test_unknown_txid_error_message(self):
        """Unknown txid error mentions 'not found' or similar."""
        provider = MockProvider('testnet')

        artifact = _make_artifact('51')

        with pytest.raises((RuntimeError, ValueError)) as exc_info:
            RunarContract.from_txid(artifact, 'ff' * 32, 0, provider)

        msg = str(exc_info.value).lower()
        assert 'not found' in msg or 'ff' * 32 in msg
