"""R-062 — the unsound-primitive deploy gate must cover the WALLET funding path.

``deploy`` refuses to fund an artifact the compiler marked unsound unless the
caller names every listed primitive. ``deploy_with_wallet`` is a SECOND funding
path — a BRC-100 wallet creates and funds the transaction via ``create_action``
— and it ran the DoS script-size bound but never the unsound gate.

Three cases, because over-rejection here breaks every legitimate wallet deploy:
the refusal, an ordinary artifact, and an acknowledged unsound one.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.types import Abi, RunarArtifact
from runar.sdk.wallet import WalletClient, WalletProvider, WalletSigner


class RecordingWallet(WalletClient):
    """Records every create_action reached — proof the gate ran before it."""

    def __init__(self):
        self.actions: list[tuple] = []

    def get_public_key(self, protocol_id: tuple, key_id: str) -> str:
        return '02' + '11' * 32

    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes:
        return b'\x30\x06\x02\x01\x01\x02\x01\x01'

    def create_action(self, description: str, outputs: list[dict]) -> dict:
        self.actions.append((description, outputs))
        return {'txid': 'ab' * 32}

    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]:
        return []


def _artifact(*primitives: str) -> RunarArtifact:
    return RunarArtifact(
        version='runar-v1.0.0-rc.1',
        contract_name='Sp1Rollup',
        abi=Abi(constructor_params=[], methods=[]),
        script='51',
        unsound_primitives=list(primitives),
    )


def _connected(*primitives: str) -> tuple[RunarContract, RecordingWallet]:
    wallet = RecordingWallet()
    signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
    provider = WalletProvider(wallet, signer, basket='test-basket')
    contract = RunarContract(_artifact(*primitives), [])
    contract.connect(provider, signer)
    return contract, wallet


def test_refuses_unacknowledged_unsound_artifact():
    contract, wallet = _connected('verifySP1FRI')
    with pytest.raises(RuntimeError, match='verifySP1FRI'):
        contract.deploy_with_wallet(satoshis=1)
    with pytest.raises(RuntimeError, match=r'Sp1Rollup\.deploy_with_wallet'):
        contract.deploy_with_wallet(satoshis=1)
    with pytest.raises(RuntimeError, match='acknowledge_unsound'):
        contract.deploy_with_wallet(satoshis=1)
    assert wallet.actions == []


def test_control_ordinary_artifact_still_funds():
    contract, wallet = _connected()
    txid, output_index = contract.deploy_with_wallet(satoshis=1)
    assert txid == 'ab' * 32
    assert output_index == 0
    assert len(wallet.actions) == 1


def test_control_acknowledged_unsound_artifact_still_funds():
    contract, wallet = _connected('verifySP1FRI')
    txid, _ = contract.deploy_with_wallet(satoshis=1, acknowledge_unsound=['verifySP1FRI'])
    assert txid == 'ab' * 32
    assert len(wallet.actions) == 1


def test_partial_acknowledgement_is_still_a_refusal():
    contract, wallet = _connected('verifySP1FRI', 'someFutureStub')
    with pytest.raises(RuntimeError, match='someFutureStub'):
        contract.deploy_with_wallet(satoshis=1, acknowledge_unsound=['verifySP1FRI'])
    assert wallet.actions == []
