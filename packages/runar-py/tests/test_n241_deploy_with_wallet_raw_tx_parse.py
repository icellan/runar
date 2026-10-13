"""N-241: ``RunarContract.deploy_with_wallet`` swallowed a raw_tx parse failure:

    if raw_tx:
        try:
            ...
            tx_data = _parse_raw_tx_to_data(txid, raw_tx)
            ...
        except Exception:
            pass

Mirrors N-168 (TS): ``deployWithWallet``'s whole job is to hand the caller
back a real ``(txid, output_index)`` for a contract UTXO that exists on
chain. Swallowing a parse failure meant the call still returned normally —
with ``output_index`` defaulted to 0 and ``actual_satoshis`` defaulted to the
requested amount — when the wallet handed back a ``raw_tx`` that could not be
parsed at all, so the caller could end up tracking the wrong vout, or one
that doesn't exist, with no indication anything went wrong.

``deploy_with_wallet`` must now raise, naming itself, when a non-empty
``raw_tx`` fails to parse. A wallet that returns ONLY a txid (no ``raw_tx``
at all) must keep working exactly as before — that path never reaches the
parser.

Scope: this test covers `RunarContract.deploy_with_wallet` only.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.types import Abi, RunarArtifact
from runar.sdk.wallet import WalletClient, WalletProvider, WalletSigner

_STUB_PUBKEY = '02' + '11' * 32
_STUB_SIG = b'\x30\x06\x02\x01\x01\x02\x01\x01'

# A locking script with no constructor slots / state fields, so
# get_locking_script() returns this verbatim.
_SCRIPT = '51'

_ARTIFACT = RunarArtifact(
    version='runar-v1.0.0-rc.1',
    contract_name='Counter',
    abi=Abi(constructor_params=[], methods=[]),
    script=_SCRIPT,
)


class _StubWallet(WalletClient):
    """A wallet whose create_action returns a caller-supplied result."""

    def __init__(self, result: dict):
        self._result = result

    def get_public_key(self, protocol_id: tuple, key_id: str) -> str:
        return _STUB_PUBKEY

    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes:
        return _STUB_SIG

    def create_action(self, description: str, outputs: list[dict]) -> dict:
        return self._result

    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]:
        return []


def _connected(wallet: WalletClient) -> RunarContract:
    signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
    provider = WalletProvider(wallet, signer, basket='test-basket')
    contract = RunarContract(_ARTIFACT, [])
    contract.connect(provider, signer)
    return contract


def _valid_raw_tx(txid: str) -> str:
    """A minimal, well-formed raw tx: no inputs, two outputs. The contract's
    locking script ('51') sits at vout 1, behind an unrelated dummy output at
    vout 0 -- so a correct-vout assertion actually proves the output scan
    found the right one rather than defaulting to 0."""
    version = '01000000'
    input_count = '00'
    output_count = '02'
    # vout 0: 999 sats, dummy script '00'
    out0 = (999).to_bytes(8, 'little').hex() + '01' + '00'
    # vout 1: 5000 sats, our locking script '51'
    out1 = (5000).to_bytes(8, 'little').hex() + '01' + _SCRIPT
    locktime = '00000000'
    return version + input_count + output_count + out0 + out1 + locktime


def test_raises_when_raw_tx_does_not_parse():
    txid = 'aa' * 32
    # Not valid hex -- bytes.fromhex must raise on this.
    wallet = _StubWallet({'txid': txid, 'raw_tx': 'not-hex-zz'})
    contract = _connected(wallet)

    with pytest.raises(RuntimeError, match='deploy_with_wallet'):
        contract.deploy_with_wallet(satoshis=1)


def test_control_wallet_returning_only_txid_still_works():
    """A wallet that returns ONLY a txid (no raw_tx key at all) must keep
    working -- this path never calls the parser."""
    txid = 'bb' * 32
    wallet = _StubWallet({'txid': txid})
    contract = _connected(wallet)

    returned_txid, output_index = contract.deploy_with_wallet(satoshis=1)
    assert returned_txid == txid
    assert output_index == 0


def test_control_valid_raw_tx_finds_correct_vout():
    txid = 'cc' * 32
    wallet = _StubWallet({'txid': txid, 'raw_tx': _valid_raw_tx(txid)})
    contract = _connected(wallet)

    returned_txid, output_index = contract.deploy_with_wallet(satoshis=1)
    assert returned_txid == txid
    assert output_index == 1
