"""Tests for the pure-Python ECDSA fallback path in LocalSigner.

Verifies that LocalSigner works correctly when ``bsv-sdk`` is not
installed and the bundled ``runar.ecdsa`` implementation is used instead.
"""

from __future__ import annotations

import hashlib
import importlib
import sys

import pytest

from runar.ecdsa import _decompress_pubkey, ecdsa_verify, ecdsa_sign


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reload_with_bsv_unavailable():
    """Reload ``runar.sdk.local_signer`` after hiding ``bsv`` from sys.modules.

    Returns the freshly-imported ``LocalSigner`` class and the reloaded module.
    """
    saved_bsv = {k: v for k, v in sys.modules.items() if k == 'bsv' or k.startswith('bsv.')}
    for k in list(saved_bsv):
        del sys.modules[k]
    # Poison sys.modules['bsv'] so `import bsv` raises ImportError inside the
    # module under test.
    sys.modules['bsv'] = None  # type: ignore[assignment]
    try:
        import runar.sdk.local_signer as ls_module
        ls_module = importlib.reload(ls_module)
        return ls_module.LocalSigner, ls_module
    finally:
        # Restore
        if 'bsv' in sys.modules:
            del sys.modules['bsv']
        for k, v in saved_bsv.items():
            sys.modules[k] = v


# ---------------------------------------------------------------------------
# Pubkey derivation matches known secp256k1 fixture
# ---------------------------------------------------------------------------


class TestFallbackPubKey:
    def test_imports_without_bsv(self):
        """LocalSigner class imports cleanly with bsv-sdk hidden."""
        LocalSigner, mod = _reload_with_bsv_unavailable()
        assert mod._BSV_SDK_AVAILABLE is False
        assert mod._FALLBACK_AVAILABLE is True
        # Constructing must not raise
        s = LocalSigner('01' + '00' * 31)
        assert s is not None

    def test_known_pubkey_for_priv_key_1(self):
        """Private key = 1 → well-known secp256k1 generator public key."""
        LocalSigner, _ = _reload_with_bsv_unavailable()
        # priv = 1 maps to the secp256k1 generator point G (compressed, even y)
        s = LocalSigner('0' * 63 + '1')
        expected = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        assert s.get_public_key() == expected

    def test_pubkey_matches_test_fixture(self):
        """Fallback pubkey matches the precomputed test_keys.ALICE fixture."""
        LocalSigner, _ = _reload_with_bsv_unavailable()
        from runar.test_keys import ALICE
        s = LocalSigner(ALICE.priv_key)
        assert s.get_public_key() == ALICE.pub_key.hex()

    def test_address_is_mainnet_p2pkh(self):
        """Fallback produces a mainnet P2PKH address starting with '1'."""
        LocalSigner, _ = _reload_with_bsv_unavailable()
        s = LocalSigner('0' * 63 + '1')
        addr = s.get_address()
        assert addr.startswith('1'), f'expected mainnet address, got {addr}'
        assert len(addr) >= 26


# ---------------------------------------------------------------------------
# Signature round-trip: sign a tx, verify DER sig via internal ecdsa_verify
# ---------------------------------------------------------------------------


def _minimal_tx_hex() -> str:
    """A minimal single-input single-output tx for sighash testing.

    Matches the minimal fixture in packages/runar-rs/src/sdk/signer.rs.
    """
    return (
        '01000000'              # version
        '01'                    # 1 input
        + '00' * 32             # prev txid
        + '00000000'            # prev vout
        + '00'                  # empty scriptSig
        + 'ffffffff'            # sequence
        + '01'                  # 1 output
        + '5000000000000000'    # 80 satoshis LE
        + '01'                  # script len
        + '51'                  # OP_1
        + '00000000'            # locktime
    )


class TestFallbackSign:
    def test_sign_returns_hex_der_with_sighash_byte(self):
        LocalSigner, _ = _reload_with_bsv_unavailable()
        s = LocalSigner('0' * 63 + '1')
        sig_hex = s.sign(_minimal_tx_hex(), 0, '51', 100)
        assert all(c in '0123456789abcdef' for c in sig_hex)
        assert sig_hex[:2] == '30', f'missing DER prefix: {sig_hex[:4]}'
        assert sig_hex.endswith('41'), f'missing sighash byte: {sig_hex[-2:]}'

    def test_sign_is_deterministic(self):
        """RFC 6979 k → identical signatures for identical inputs."""
        LocalSigner, _ = _reload_with_bsv_unavailable()
        s = LocalSigner('aa' * 32)
        tx = _minimal_tx_hex()
        sig1 = s.sign(tx, 0, '51', 100)
        sig2 = s.sign(tx, 0, '51', 100)
        assert sig1 == sig2

    def test_sign_different_keys_different_sigs(self):
        LocalSigner, _ = _reload_with_bsv_unavailable()
        s1 = LocalSigner('11' * 32)
        s2 = LocalSigner('22' * 32)
        tx = _minimal_tx_hex()
        assert s1.sign(tx, 0, '51', 100) != s2.sign(tx, 0, '51', 100)

    def test_signature_verifies_via_internal_ecdsa_verify(self):
        """Round-trip: sign then verify the DER sig against the public key."""
        LocalSigner, ls_module = _reload_with_bsv_unavailable()
        priv_hex = 'cc' * 32
        s = LocalSigner(priv_hex)
        tx_hex = _minimal_tx_hex()
        subscript = '51'
        satoshis = 100

        # Extract the sighash the signer produced
        parsed = ls_module._parse_raw_tx(bytes.fromhex(tx_hex))
        sighash = ls_module._bip143_sighash(
            parsed, 0, bytes.fromhex(subscript), satoshis, 0x41
        )

        sig_hex = s.sign(tx_hex, 0, subscript, satoshis)
        # Strip sighash byte for verification
        assert sig_hex.endswith('41')
        der_bytes = bytes.fromhex(sig_hex[:-2])
        pub_bytes = bytes.fromhex(s.get_public_key())

        assert ecdsa_verify(der_bytes, pub_bytes, sighash) is True

    def test_sign_raw_message_verifies(self):
        """Sanity: sign a non-tx message hash directly and verify round-trip."""
        from runar.ecdsa import pub_key_from_priv_key
        priv_hex = 'de' * 32
        msg_hash = hashlib.sha256(b'hello runar').digest()
        der = ecdsa_sign(int(priv_hex, 16), msg_hash)
        pub = pub_key_from_priv_key(priv_hex)
        assert ecdsa_verify(der, pub, msg_hash) is True

    def test_rejects_non_hex_key(self):
        LocalSigner, _ = _reload_with_bsv_unavailable()
        with pytest.raises(ValueError):
            LocalSigner('not-a-hex-key')  # wrong length

    def test_rejects_wrong_length_key(self):
        LocalSigner, _ = _reload_with_bsv_unavailable()
        with pytest.raises(ValueError):
            LocalSigner('ab' * 16)  # 32 hex chars instead of 64
