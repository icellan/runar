"""Tests for BRC-100 wallet integration — WalletClient, WalletSigner, WalletProvider.

Uses a mock WalletClient to test WalletSigner and WalletProvider without
any real wallet or network access.
"""

import hashlib
import pytest

from runar.sdk.wallet import WalletClient, WalletProvider, WalletSigner
from runar.sdk.types import Utxo, RunarArtifact, Abi, AbiParam, AbiMethod, DeployOptions
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.contract import RunarContract


# ---------------------------------------------------------------------------
# Mock WalletClient
# ---------------------------------------------------------------------------

MOCK_PUB_KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

# A valid minimal DER-encoded ECDSA signature (r=0xab*32, s=0xcd*32)
MOCK_DER_SIG = (
    bytes([0x30, 0x44])
    + bytes([0x02, 0x20]) + bytes([0xab] * 32)
    + bytes([0x02, 0x20]) + bytes([0xcd] * 32)
)


class MockWalletClient(WalletClient):
    """In-memory mock wallet for testing."""

    def __init__(self):
        self.get_public_key_calls: list[tuple] = []
        self.create_signature_calls: list[tuple] = []
        self.create_action_calls: list[tuple] = []
        self.list_outputs_calls: list[tuple] = []
        self._outputs: list[dict] = []
        self._action_result: dict = {'txid': 'aa' * 32}

    def set_outputs(self, outputs: list[dict]) -> None:
        self._outputs = outputs

    def set_action_result(self, result: dict) -> None:
        self._action_result = result

    def get_public_key(self, protocol_id: tuple, key_id: str) -> str:
        self.get_public_key_calls.append((protocol_id, key_id))
        return MOCK_PUB_KEY

    def create_signature(self, hash_to_sign: bytes, protocol_id: tuple, key_id: str) -> bytes:
        self.create_signature_calls.append((hash_to_sign, protocol_id, key_id))
        return MOCK_DER_SIG

    def create_action(self, description: str, outputs: list[dict]) -> dict:
        self.create_action_calls.append((description, outputs))
        return dict(self._action_result)

    def list_outputs(self, basket: str, tags: list[str], limit: int = 100) -> list[dict]:
        self.list_outputs_calls.append((basket, tags, limit))
        return list(self._outputs)


def _mock_pub_key_hash() -> str:
    """Compute hash160 of MOCK_PUB_KEY."""
    pub_bytes = bytes.fromhex(MOCK_PUB_KEY)
    sha = hashlib.sha256(pub_bytes).digest()
    return hashlib.new('ripemd160', sha).digest().hex()


# A minimal valid transaction hex with 1 input and 1 output.
MINIMAL_TX_HEX = (
    '01000000'           # version 1
    + '01'               # 1 input
    + '00' * 32          # prevTxid (32 zero bytes)
    + '00000000'         # prevIndex 0
    + '00'               # empty scriptSig
    + 'ffffffff'         # sequence
    + '01'               # 1 output
    + '5000000000000000' # 80 satoshis (LE)
    + '01'               # script length 1
    + '51'               # OP_1
    + '00000000'         # locktime 0
)


# ---------------------------------------------------------------------------
# WalletClient ABC
# ---------------------------------------------------------------------------

class TestWalletClientABC:
    def test_cannot_instantiate_abc(self):
        """WalletClient cannot be instantiated directly."""
        with pytest.raises(TypeError):
            WalletClient()  # type: ignore[abstract]

    def test_mock_implements_all_methods(self):
        """MockWalletClient implements all abstract methods."""
        client = MockWalletClient()
        assert hasattr(client, 'get_public_key')
        assert hasattr(client, 'create_signature')
        assert hasattr(client, 'create_action')
        assert hasattr(client, 'list_outputs')


# ---------------------------------------------------------------------------
# WalletSigner — constructor
# ---------------------------------------------------------------------------

class TestWalletSignerConstructor:
    def test_accepts_mock_wallet(self):
        """WalletSigner can be constructed with a mock wallet."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        assert signer is not None


# ---------------------------------------------------------------------------
# WalletSigner.get_public_key
# ---------------------------------------------------------------------------

class TestWalletSignerGetPublicKey:
    def test_delegates_to_wallet(self):
        """get_public_key calls wallet.get_public_key with correct args."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'myapp'), key_id='42')

        pk = signer.get_public_key()

        assert pk == MOCK_PUB_KEY
        assert len(wallet.get_public_key_calls) == 1
        assert wallet.get_public_key_calls[0] == ((2, 'myapp'), '42')

    def test_caches_after_first_call(self):
        """Public key is cached after the first call."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        signer.get_public_key()
        signer.get_public_key()
        signer.get_public_key()

        assert len(wallet.get_public_key_calls) == 1

    def test_returns_66_hex_chars(self):
        """Public key is 33 bytes = 66 hex chars."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        pk = signer.get_public_key()
        assert len(pk) == 66


# ---------------------------------------------------------------------------
# WalletSigner.get_address
# ---------------------------------------------------------------------------

class TestWalletSignerGetAddress:
    def test_returns_hash160_of_pubkey(self):
        """get_address returns hash160 of the public key as 40-char hex."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        address = signer.get_address()

        expected = _mock_pub_key_hash()
        assert address == expected
        assert len(address) == 40
        assert all(c in '0123456789abcdef' for c in address)


# ---------------------------------------------------------------------------
# WalletSigner.sign
# ---------------------------------------------------------------------------

class TestWalletSignerSign:
    def test_calls_create_signature(self):
        """sign() calls wallet.create_signature with a 32-byte hash."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        signer.sign(MINIMAL_TX_HEX, 0, '51', 100)

        assert len(wallet.create_signature_calls) == 1
        hash_to_sign, proto, kid = wallet.create_signature_calls[0]
        assert len(hash_to_sign) == 32
        assert proto == (2, 'test')
        assert kid == '1'

    def test_returns_der_plus_sighash(self):
        """sign() returns DER hex ending with sighash flag byte."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        sig = signer.sign(MINIMAL_TX_HEX, 0, '51', 100)

        # Ends with 0x41 (SIGHASH_ALL | FORKID)
        assert sig[-2:] == '41'
        # Starts with DER prefix 0x30
        assert sig[:2] == '30'
        # All hex
        assert all(c in '0123456789abcdef' for c in sig)

    def test_default_sighash_all_forkid(self):
        """Default sighash type is 0x41."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        sig = signer.sign(MINIMAL_TX_HEX, 0, '51', 100)
        assert sig[-2:] == '41'

    def test_custom_sighash_type(self):
        """Respects custom sighash type."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        sig = signer.sign(MINIMAL_TX_HEX, 0, '51', 100, sighash_type=0xc1)
        assert sig[-2:] == 'c1'

    def test_deterministic_sighash(self):
        """Same inputs produce the same sighash."""
        w1 = MockWalletClient()
        w2 = MockWalletClient()
        s1 = WalletSigner(w1, protocol_id=(2, 'test'), key_id='1')
        s2 = WalletSigner(w2, protocol_id=(2, 'test'), key_id='1')

        s1.sign(MINIMAL_TX_HEX, 0, '51', 100)
        s2.sign(MINIMAL_TX_HEX, 0, '51', 100)

        hash1 = w1.create_signature_calls[0][0]
        hash2 = w2.create_signature_calls[0][0]
        assert hash1 == hash2


# ---------------------------------------------------------------------------
# WalletSigner.sign_hash
# ---------------------------------------------------------------------------

class TestWalletSignerSignHash:
    def test_signs_precomputed_hash(self):
        """sign_hash delegates to wallet.create_signature."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        sighash_hex = 'ab' * 32
        result = signer.sign_hash(sighash_hex)

        assert len(wallet.create_signature_calls) == 1
        assert wallet.create_signature_calls[0][0] == bytes.fromhex(sighash_hex)
        # Result is DER hex without sighash flag
        assert result == MOCK_DER_SIG.hex()


# ---------------------------------------------------------------------------
# WalletProvider — constructor
# ---------------------------------------------------------------------------

class TestWalletProviderConstructor:
    def test_defaults(self):
        """WalletProvider stores constructor args with defaults."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='mybasket')

        assert provider.basket == 'mybasket'
        assert provider.funding_tag == 'funding'
        assert provider.arc_url == 'https://arc.gorillapool.io'
        assert provider.overlay_url is None
        assert provider.get_network() == 'mainnet'
        assert provider.get_fee_rate() == 100

    def test_custom_options(self):
        """WalletProvider accepts custom options."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(
            wallet, signer,
            basket='app',
            funding_tag='fund',
            arc_url='https://my-arc.example.com',
            overlay_url='https://overlay.example.com',
            network='testnet',
            fee_rate=50,
        )

        assert provider.funding_tag == 'fund'
        assert provider.arc_url == 'https://my-arc.example.com'
        assert provider.overlay_url == 'https://overlay.example.com'
        assert provider.get_network() == 'testnet'
        assert provider.get_fee_rate() == 50

    def test_r179_testnet_without_arc_url_is_refused(self):
        """R-179: arc_url and network were defaulted independently, so a
        testnet provider reported get_network() == 'testnet' and broadcast to
        the MAINNET ARC. There is no canonical testnet ARC endpoint to default
        to, so a non-mainnet provider must name its own."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')

        with pytest.raises(ValueError) as excinfo:
            WalletProvider(wallet, signer, basket='app', network='testnet')
        assert 'testnet' in str(excinfo.value)
        assert 'arc.gorillapool.io' in str(excinfo.value)

    def test_r179_testnet_with_an_explicit_arc_url_is_accepted(self):
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(
            wallet, signer, basket='app',
            network='testnet', arc_url='https://arc.testnet.example',
        )
        assert provider.get_network() == 'testnet'
        assert provider.arc_url == 'https://arc.testnet.example'

    def test_r179_mainnet_default_is_unchanged(self):
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        for kwargs in ({}, {'network': 'mainnet'}):
            provider = WalletProvider(wallet, signer, basket='app', **kwargs)
            assert provider.get_network() == 'mainnet'
            assert provider.arc_url == 'https://arc.gorillapool.io'


# ---------------------------------------------------------------------------
# WalletProvider.get_utxos
# ---------------------------------------------------------------------------

class TestWalletProviderGetUtxos:
    def test_filters_spendable_p2pkh(self):
        """get_utxos returns only spendable P2PKH UTXOs matching the signer."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        expected_script = build_p2pkh_script(MOCK_PUB_KEY)
        wallet.set_outputs([
            {
                'outpoint': 'aa' * 32 + '.0',
                'satoshis': 50_000,
                'locking_script': expected_script,
                'spendable': True,
            },
            {
                'outpoint': 'bb' * 32 + '.1',
                'satoshis': 30_000,
                'locking_script': expected_script,
                'spendable': False,  # not spendable
            },
            {
                'outpoint': 'cc' * 32 + '.2',
                'satoshis': 20_000,
                'locking_script': '5151',  # wrong script
                'spendable': True,
            },
        ])

        utxos = provider.get_utxos('ignored_address')

        assert len(utxos) == 1
        assert utxos[0].txid == 'aa' * 32
        assert utxos[0].output_index == 0
        assert utxos[0].satoshis == 50_000
        assert utxos[0].script == expected_script

    def test_calls_wallet_list_outputs(self):
        """get_utxos calls wallet.list_outputs with correct basket and tags."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='mybasket', funding_tag='myfund')

        provider.get_utxos('addr')

        assert len(wallet.list_outputs_calls) == 1
        basket, tags, limit = wallet.list_outputs_calls[0]
        assert basket == 'mybasket'
        assert tags == ['myfund']
        assert limit == 100

    def test_empty_outputs(self):
        """get_utxos returns empty list when wallet has no outputs."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        utxos = provider.get_utxos('addr')
        assert utxos == []


# ---------------------------------------------------------------------------
# WalletProvider.get_transaction
# ---------------------------------------------------------------------------

class TestWalletProviderGetTransaction:
    def test_returns_from_cache(self):
        """get_transaction returns data from the tx cache."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        provider.cache_tx('aabb', MINIMAL_TX_HEX)
        tx = provider.get_transaction('aabb')

        assert tx.txid == 'aabb'
        assert tx.version == 1
        assert len(tx.outputs) == 1

    def test_fallback_for_unknown_txid(self):
        """get_transaction returns minimal fallback for unknown txid."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        tx = provider.get_transaction('unknown')
        assert tx.txid == 'unknown'
        assert tx.version == 1


# ---------------------------------------------------------------------------
# WalletProvider.get_contract_utxo
# ---------------------------------------------------------------------------

class TestWalletProviderGetContractUtxo:
    def test_returns_none(self):
        """get_contract_utxo always returns None (managed by overlay)."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        assert provider.get_contract_utxo('hash') is None


# ---------------------------------------------------------------------------
# WalletProvider.ensure_funding
# ---------------------------------------------------------------------------

class TestWalletProviderEnsureFunding:
    def test_no_action_when_funded(self):
        """ensure_funding does nothing when balance is sufficient."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        expected_script = build_p2pkh_script(MOCK_PUB_KEY)
        wallet.set_outputs([{
            'outpoint': 'aa' * 32 + '.0',
            'satoshis': 100_000,
            'locking_script': expected_script,
            'spendable': True,
        }])

        provider.ensure_funding(50_000)

        assert len(wallet.create_action_calls) == 0

    def test_creates_action_when_underfunded(self):
        """ensure_funding calls create_action when balance is insufficient."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        # No existing UTXOs
        wallet.set_outputs([])
        wallet.set_action_result({'txid': 'ff' * 32, 'raw_tx': MINIMAL_TX_HEX})

        provider.ensure_funding(10_000)

        assert len(wallet.create_action_calls) == 1
        desc, outputs = wallet.create_action_calls[0]
        assert desc == 'Runar contract funding'
        assert len(outputs) == 1
        assert outputs[0]['satoshis'] == 10_000


# ---------------------------------------------------------------------------
# WalletProvider.cache_tx / get_raw_transaction
# ---------------------------------------------------------------------------

class TestWalletProviderTxCache:
    def test_cache_and_retrieve(self):
        """Cached transactions can be retrieved via get_raw_transaction."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        provider.cache_tx('txid123', 'deadbeef')
        assert provider.get_raw_transaction('txid123') == 'deadbeef'

    def test_raises_for_uncached_without_overlay(self):
        """get_raw_transaction raises when tx is not cached and no overlay."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        with pytest.raises(RuntimeError, match='could not fetch'):
            provider.get_raw_transaction('unknown')


# ---------------------------------------------------------------------------
# deploy_with_wallet on RunarContract
# ---------------------------------------------------------------------------

def _simple_artifact() -> RunarArtifact:
    """Minimal stateless contract with a single 'spend' method."""
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='TestContract',
        abi=Abi(
            constructor_params=[],
            methods=[AbiMethod(name='spend', params=[], is_public=True)],
        ),
        script='51',
    )


class TestDeployWithWallet:
    def test_requires_wallet_provider(self):
        """deploy_with_wallet raises when not connected to a WalletProvider."""
        contract = RunarContract(_simple_artifact(), [])

        with pytest.raises(RuntimeError, match='WalletProvider'):
            contract.deploy_with_wallet()

    def test_deploy_calls_create_action(self):
        """deploy_with_wallet delegates to wallet.create_action."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='mybasket')

        wallet.set_action_result({'txid': 'dd' * 32})

        contract = RunarContract(_simple_artifact(), [])
        contract.connect(provider, signer)

        txid, output_index = contract.deploy_with_wallet(satoshis=500)

        assert txid == 'dd' * 32
        assert output_index == 0

        # Verify create_action was called
        assert len(wallet.create_action_calls) == 1
        desc, outputs = wallet.create_action_calls[0]
        assert 'deployment' in desc.lower()
        assert len(outputs) == 1
        assert outputs[0]['satoshis'] == 500
        assert outputs[0]['basket'] == 'mybasket'

    def test_deploy_tracks_utxo(self):
        """After deploy_with_wallet, the contract tracks the current UTXO."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        wallet.set_action_result({'txid': 'ee' * 32})

        contract = RunarContract(_simple_artifact(), [])
        contract.connect(provider, signer)

        contract.deploy_with_wallet(satoshis=1000)

        utxo = contract.get_utxo()
        assert utxo is not None
        assert utxo.txid == 'ee' * 32
        assert utxo.output_index == 0
        assert utxo.satoshis == 1000

    def test_deploy_custom_description(self):
        """deploy_with_wallet passes custom description."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        wallet.set_action_result({'txid': 'ff' * 32})

        contract = RunarContract(_simple_artifact(), [])
        contract.connect(provider, signer)

        contract.deploy_with_wallet(description='My custom deploy')

        desc, _ = wallet.create_action_calls[0]
        assert desc == 'My custom deploy'

    def test_deploy_default_satoshis(self):
        """deploy_with_wallet defaults to 1 satoshi."""
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')

        wallet.set_action_result({'txid': '11' * 32})

        contract = RunarContract(_simple_artifact(), [])
        contract.connect(provider, signer)

        contract.deploy_with_wallet()

        _, outputs = wallet.create_action_calls[0]
        assert outputs[0]['satoshis'] == 1


# ---------------------------------------------------------------------------
# Integration: WalletSigner implements Signer ABC
# ---------------------------------------------------------------------------

class TestWalletSignerIsSigner:
    def test_isinstance_signer(self):
        """WalletSigner is a valid Signer instance."""
        from runar.sdk.signer import Signer
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        assert isinstance(signer, Signer)


# ---------------------------------------------------------------------------
# Integration: WalletProvider implements Provider ABC
# ---------------------------------------------------------------------------

class TestWalletProviderIsProvider:
    def test_isinstance_provider(self):
        """WalletProvider is a valid Provider instance."""
        from runar.sdk.provider import Provider
        wallet = MockWalletClient()
        signer = WalletSigner(wallet, protocol_id=(2, 'test'), key_id='1')
        provider = WalletProvider(wallet, signer, basket='test')
        assert isinstance(provider, Provider)
