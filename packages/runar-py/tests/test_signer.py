"""Tests for runar.sdk.signer — MockSigner, ExternalSigner, and LocalSigner."""

import sys
import types
import pytest
from unittest.mock import MagicMock, patch
from runar.sdk.signer import MockSigner, ExternalSigner


# ---------------------------------------------------------------------------
# MockSigner
# ---------------------------------------------------------------------------

class TestMockSigner:
    def test_default_public_key_length(self):
        """Default MockSigner public key is a 33-byte compressed key (66 hex chars)."""
        s = MockSigner()
        pk = s.get_public_key()
        assert len(pk) == 66  # 33 bytes × 2 hex chars

    def test_default_public_key_prefix(self):
        """Default MockSigner public key starts with 02 (compressed even-y)."""
        s = MockSigner()
        assert s.get_public_key()[:2] == '02'

    def test_custom_public_key(self):
        """Constructor accepts a custom public key hex string."""
        custom_pk = '03' + 'ab' * 32
        s = MockSigner(pub_key_hex=custom_pk)
        assert s.get_public_key() == custom_pk

    def test_default_address(self):
        """Default address is 40 hex chars (20 bytes)."""
        s = MockSigner()
        assert len(s.get_address()) == 40

    def test_custom_address(self):
        """Constructor accepts a custom address."""
        addr = 'de' * 20
        s = MockSigner(address=addr)
        assert s.get_address() == addr

    def test_sign_returns_hex_string(self):
        """sign() returns a non-empty hex string."""
        s = MockSigner()
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert all(c in '0123456789abcdef' for c in sig)

    def test_sign_deterministic(self):
        """MockSigner always returns the same mock signature regardless of inputs."""
        s = MockSigner()
        sig1 = s.sign('aabbccdd', 0, '51', 50_000)
        sig2 = s.sign('11223344', 1, '5151', 1_000)
        assert sig1 == sig2

    def test_sign_ends_with_sighash_byte(self):
        """Mock DER signature ends with sighash byte 0x41 (SIGHASH_ALL | SIGHASH_FORKID)."""
        s = MockSigner()
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert sig.endswith('41')

    def test_sign_starts_with_der_prefix(self):
        """Mock signature starts with DER compound tag 0x30."""
        s = MockSigner()
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert sig[:2] == '30'

    def test_sign_with_explicit_sighash_type(self):
        """sign() with explicit sighash_type still returns a valid hex string."""
        s = MockSigner()
        sig = s.sign('deadbeef', 0, '51', 10_000, sighash_type=0x01)
        assert isinstance(sig, str)
        assert len(sig) > 0


# ---------------------------------------------------------------------------
# ExternalSigner
# ---------------------------------------------------------------------------

class TestExternalSigner:
    def test_get_public_key(self):
        """ExternalSigner returns the public key passed at construction."""
        pk = '02' + 'cc' * 32
        s = ExternalSigner(pub_key_hex=pk, address='00' * 20, sign_fn=lambda *_: '3000' + '41')
        assert s.get_public_key() == pk

    def test_get_address(self):
        """ExternalSigner returns the address passed at construction."""
        addr = 'ef' * 20
        s = ExternalSigner(pub_key_hex='02' + '00' * 32, address=addr, sign_fn=lambda *_: '3000' + '41')
        assert s.get_address() == addr

    def test_sign_delegates_to_fn(self):
        """sign() calls the provided sign_fn with the correct arguments."""
        calls = []

        def sign_fn(tx_hex, input_index, subscript, satoshis, sighash_type):
            calls.append((tx_hex, input_index, subscript, satoshis, sighash_type))
            return 'aabbcc41'

        s = ExternalSigner(pub_key_hex='02' + '00' * 32, address='00' * 20, sign_fn=sign_fn)
        result = s.sign('deadbeef', 2, '5151', 99_000, sighash_type=0x41)

        assert result == 'aabbcc41'
        assert len(calls) == 1
        assert calls[0] == ('deadbeef', 2, '5151', 99_000, 0x41)

    def test_sign_passes_none_sighash_when_not_given(self):
        """sign() without sighash_type passes None to the sign_fn."""
        received = {}

        def sign_fn(tx_hex, input_index, subscript, satoshis, sighash_type):
            received['sighash_type'] = sighash_type
            return '3041'

        s = ExternalSigner(pub_key_hex='02' + '00' * 32, address='00' * 20, sign_fn=sign_fn)
        s.sign('ff', 0, '51', 1_000)
        assert received['sighash_type'] is None


# ---------------------------------------------------------------------------
# LocalSigner (bsv-sdk mocked)
# ---------------------------------------------------------------------------

def _make_bsv_mock():
    """Build a minimal mock of the bsv-sdk module hierarchy used by LocalSigner."""
    bsv_mod = types.ModuleType('bsv')
    bsv_constants = types.ModuleType('bsv.constants')

    # Mock PublicKey: hex() returns a 33-byte compressed key, address() returns P2PKH addr
    mock_pub = MagicMock()
    mock_pub.hex.return_value = '02' + 'ab' * 32
    mock_pub.address.return_value = '1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf'

    # Mock PrivateKey: constructed from bytes, exposes public_key()
    mock_priv_cls = MagicMock()
    mock_priv_instance = MagicMock()
    mock_priv_instance.public_key.return_value = mock_pub
    mock_priv_cls.return_value = mock_priv_instance

    # A valid P2PKH-style unlocking script: <47-byte sig> <33-byte pubkey>
    # Sig: opcode 0x47 (71 bytes), then DER sig ending in 0x41
    sig_bytes = bytes([0x30]) + bytes(69) + bytes([0x41])  # 71 bytes, DER prefix, ends 0x41
    pub_bytes = bytes.fromhex('02' + 'ab' * 32)  # 33 bytes
    script_data = bytes([len(sig_bytes)]) + sig_bytes + bytes([len(pub_bytes)]) + pub_bytes
    mock_script = MagicMock()
    mock_script.hex.return_value = script_data.hex()

    mock_input = MagicMock()
    mock_input.source_output_index = 0
    mock_input.unlocking_script = mock_script

    mock_tx = MagicMock()
    mock_tx.inputs = [mock_input]

    # When tx.sign() is called, restore unlocking_script to the mock script.
    # LocalSigner sets unlocking_script = None before calling tx.sign(); sign() is
    # supposed to fill it back in with the real signature.
    def _fill_unlocking_script():
        mock_input.unlocking_script = mock_script
    mock_tx.sign.side_effect = _fill_unlocking_script

    mock_tx_cls = MagicMock()
    mock_tx_cls.from_hex.return_value = mock_tx
    mock_tx_cls.return_value = MagicMock()  # new BsvTransaction()

    bsv_mod.PrivateKey = mock_priv_cls
    bsv_mod.PublicKey = MagicMock()
    bsv_mod.Transaction = mock_tx_cls
    bsv_mod.P2PKH = MagicMock()
    bsv_mod.Script = MagicMock()
    bsv_mod.TransactionInput = MagicMock()
    bsv_mod.TransactionOutput = MagicMock()
    bsv_constants.SIGHASH = MagicMock()

    return bsv_mod, bsv_constants


@pytest.fixture()
def bsv_mocked():
    """Inject a mock bsv module into sys.modules and reload LocalSigner."""
    bsv_mod, bsv_constants = _make_bsv_mock()

    # Patch sys.modules before importing so local_signer's try-import succeeds
    with patch.dict(sys.modules, {'bsv': bsv_mod, 'bsv.constants': bsv_constants}):
        # Force re-evaluation of _BSV_SDK_AVAILABLE in a fresh import
        import importlib
        import runar.sdk.local_signer as ls_module
        original_available = ls_module._BSV_SDK_AVAILABLE
        ls_module._BSV_SDK_AVAILABLE = True
        # Patch the module-level names that were captured at import time
        ls_module.PrivateKey = bsv_mod.PrivateKey
        ls_module.BsvTransaction = bsv_mod.Transaction
        ls_module.P2PKH = bsv_mod.P2PKH
        ls_module.Script = bsv_mod.Script
        ls_module.TransactionOutput = bsv_mod.TransactionOutput
        yield ls_module, bsv_mod
        # Restore
        ls_module._BSV_SDK_AVAILABLE = original_available


class TestLocalSigner:
    def test_raises_without_bsv_sdk(self):
        """LocalSigner raises RuntimeError when bsv-sdk is not installed."""
        import runar.sdk.local_signer as ls_module
        original = ls_module._BSV_SDK_AVAILABLE
        ls_module._BSV_SDK_AVAILABLE = False
        try:
            with pytest.raises(RuntimeError, match='bsv-sdk'):
                from runar.sdk.local_signer import LocalSigner
                LocalSigner('aa' * 32)
        finally:
            ls_module._BSV_SDK_AVAILABLE = original

    def test_get_public_key(self, bsv_mocked):
        """get_public_key() returns the hex from PrivateKey.public_key().hex()."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('aa' * 32)
        pk = s.get_public_key()
        assert pk == '02' + 'ab' * 32

    def test_get_public_key_is_33_bytes(self, bsv_mocked):
        """get_public_key() returns 66 hex chars (33-byte compressed key)."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('bb' * 32)
        assert len(s.get_public_key()) == 66

    def test_get_address(self, bsv_mocked):
        """get_address() returns the address from the public key."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('cc' * 32)
        addr = s.get_address()
        assert isinstance(addr, str)
        assert len(addr) > 0

    def test_sign_returns_hex_string(self, bsv_mocked):
        """sign() returns a non-empty hex string."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('dd' * 32)
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert all(c in '0123456789abcdef' for c in sig)

    def test_sign_ends_with_sighash_byte(self, bsv_mocked):
        """sign() extracts the first push data element (the DER sig) ending in 0x41."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('ee' * 32)
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert sig.endswith('41')

    def test_sign_starts_with_der_prefix(self, bsv_mocked):
        """sign() result starts with DER compound tag 0x30."""
        ls_module, bsv_mod = bsv_mocked
        from runar.sdk.local_signer import LocalSigner
        s = LocalSigner('ff' * 32)
        sig = s.sign('deadbeef', 0, '51', 10_000)
        assert sig[:2] == '30'


# ---------------------------------------------------------------------------
# _extract_first_push helper (unit tests, no bsv-sdk needed)
# ---------------------------------------------------------------------------

class TestExtractFirstPush:
    def _f(self, hex_str: str) -> str:
        from runar.sdk.local_signer import _extract_first_push
        return _extract_first_push(hex_str)

    def test_direct_push_1_byte(self):
        """opcode 0x01 pushes the following 1 byte."""
        assert self._f('01ab') == 'ab'

    def test_direct_push_n_bytes(self):
        """opcode 0x47 pushes the following 71 bytes."""
        payload = 'cd' * 71
        assert self._f('47' + payload) == payload

    def test_pushdata1(self):
        """0x4c NN <data> — OP_PUSHDATA1."""
        payload = 'ef' * 10
        assert self._f('4c0a' + payload) == payload

    def test_pushdata2(self):
        """0x4d NN NN <data> — OP_PUSHDATA2 little-endian length."""
        payload = 'ab' * 300
        length_le = (300).to_bytes(2, 'little').hex()
        assert self._f('4d' + length_le + payload) == payload

    def test_empty_raises(self):
        """empty script raises ValueError."""
        from runar.sdk.local_signer import _extract_first_push
        with pytest.raises(ValueError, match='empty'):
            _extract_first_push('')

    def test_unknown_opcode_raises(self):
        """OP_0 (0x00) at start raises ValueError."""
        from runar.sdk.local_signer import _extract_first_push
        with pytest.raises(ValueError, match='unexpected opcode'):
            _extract_first_push('00' + 'aa' * 4)
