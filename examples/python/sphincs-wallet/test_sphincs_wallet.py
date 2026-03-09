from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract
from runar import hash160, mock_sig, mock_pub_key

import pytest

contract_mod = load_contract(str(Path(__file__).parent / "SPHINCSWallet.runar.py"))
SPHINCSWallet = contract_mod.SPHINCSWallet

# Import real SLH-DSA crypto. Skip signature tests if not installed.
from runar import slh_keygen
from runar.slhdsa_impl import _HAS_SLHDSA

# Module-level shared SLH-DSA keypair (keygen is slow, ~2-3s).
_slh_kp = None


def get_slh_kp():
    """Lazily generate and cache an SLH-DSA keypair."""
    global _slh_kp
    if _slh_kp is None:
        _slh_kp = slh_keygen('sha2_128s')
    return _slh_kp


@pytest.mark.skipif(not _HAS_SLHDSA, reason="slh-dsa package not installed")
def test_spend():
    """Valid spend with real SLH-DSA keygen and signature."""
    ecdsa_pub_key = mock_pub_key()
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)

    kp = get_slh_kp()
    slhdsa_pub_key_hash = hash160(kp.pk)
    ecdsa_sig = mock_sig()
    slhdsa_sig = kp.sign(ecdsa_sig)

    c = SPHINCSWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        slhdsa_pub_key_hash=slhdsa_pub_key_hash,
    )
    c.spend(
        slhdsa_sig=slhdsa_sig,
        slhdsa_pub_key=kp.pk,
        sig=ecdsa_sig,
        pub_key=ecdsa_pub_key,
    )


def test_wrong_ecdsa_pub_key_hash():
    """Spend with wrong ECDSA public key should fail the hash160 check."""
    ecdsa_pub_key_hash = hash160(mock_pub_key())
    slhdsa_pub_key = b'\x00' * 32
    slhdsa_pub_key_hash = hash160(slhdsa_pub_key)

    c = SPHINCSWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        slhdsa_pub_key_hash=slhdsa_pub_key_hash,
    )

    wrong_ecdsa_pub_key = b'\x03' + b'\xff' * 32

    with pytest.raises(AssertionError):
        c.spend(
            slhdsa_sig=b'\x00' * 7856,
            slhdsa_pub_key=slhdsa_pub_key,
            sig=mock_sig(),
            pub_key=wrong_ecdsa_pub_key,
        )


def test_wrong_slhdsa_pub_key_hash():
    """Spend with wrong SLH-DSA public key should fail the hash160 check."""
    ecdsa_pub_key = mock_pub_key()
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)
    slhdsa_pub_key_hash = hash160(b'\x00' * 32)

    c = SPHINCSWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        slhdsa_pub_key_hash=slhdsa_pub_key_hash,
    )

    wrong_slhdsa_pub_key = b'\xff' * 32

    with pytest.raises(AssertionError):
        c.spend(
            slhdsa_sig=b'\x00' * 7856,
            slhdsa_pub_key=wrong_slhdsa_pub_key,
            sig=mock_sig(),
            pub_key=ecdsa_pub_key,
        )


@pytest.mark.skipif(not _HAS_SLHDSA, reason="slh-dsa package not installed")
def test_tampered_slhdsa_sig():
    """Tampered SLH-DSA signature should fail verification."""
    ecdsa_pub_key = mock_pub_key()
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)

    kp = get_slh_kp()
    slhdsa_pub_key_hash = hash160(kp.pk)
    ecdsa_sig = mock_sig()
    slhdsa_sig = bytearray(kp.sign(ecdsa_sig))
    slhdsa_sig[0] ^= 0xFF  # Corrupt first byte
    slhdsa_sig = bytes(slhdsa_sig)

    c = SPHINCSWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        slhdsa_pub_key_hash=slhdsa_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            slhdsa_sig=slhdsa_sig,
            slhdsa_pub_key=kp.pk,
            sig=ecdsa_sig,
            pub_key=ecdsa_pub_key,
        )


@pytest.mark.skipif(not _HAS_SLHDSA, reason="slh-dsa package not installed")
def test_slhdsa_signed_wrong_message():
    """SLH-DSA signed different ECDSA sig bytes -- should fail verification."""
    ecdsa_pub_key = mock_pub_key()
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)

    kp = get_slh_kp()
    slhdsa_pub_key_hash = hash160(kp.pk)

    ecdsa_sig_a = b'\x30\x01' + b'\x00' * 70
    ecdsa_sig_b = b'\x30\x02' + b'\x00' * 70
    slhdsa_sig = kp.sign(ecdsa_sig_a)

    c = SPHINCSWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        slhdsa_pub_key_hash=slhdsa_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            slhdsa_sig=slhdsa_sig,
            slhdsa_pub_key=kp.pk,
            sig=ecdsa_sig_b,  # Different from what SLH-DSA signed
            pub_key=ecdsa_pub_key,
        )
