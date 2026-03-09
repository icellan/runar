from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract
from runar import hash160, mock_sig, mock_pub_key, wots_keygen, wots_sign

import pytest

contract_mod = load_contract(str(Path(__file__).parent / "PostQuantumWallet.runar.py"))
PostQuantumWallet = contract_mod.PostQuantumWallet


def setup_keys():
    ecdsa_pub_key = mock_pub_key()
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)
    # Real WOTS+ keypair
    seed = b'\x42' + b'\x00' * 31
    pub_seed = b'\x01' + b'\x00' * 31
    kp = wots_keygen(seed, pub_seed)
    wots_pub_key_hash = hash160(kp.pk)
    return ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash


def test_spend():
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash = setup_keys()
    ecdsa_sig = mock_sig()

    # Real WOTS+ signature over the ECDSA sig bytes
    wots_sig = wots_sign(ecdsa_sig, kp.sk, kp.pub_seed)

    c = PostQuantumWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        wots_pub_key_hash=wots_pub_key_hash,
    )
    c.spend(
        wots_sig=wots_sig,
        wots_pub_key=kp.pk,
        sig=ecdsa_sig,
        pub_key=ecdsa_pub_key,
    )


def test_wrong_ecdsa_pub_key_hash():
    """Spend with wrong ECDSA public key should fail the hash160 check."""
    _, ecdsa_pub_key_hash, kp, wots_pub_key_hash = setup_keys()

    c = PostQuantumWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        wots_pub_key_hash=wots_pub_key_hash,
    )

    wrong_ecdsa_pub_key = b'\x03' + b'\xff' * 32
    ecdsa_sig = mock_sig()
    wots_sig = wots_sign(ecdsa_sig, kp.sk, kp.pub_seed)

    with pytest.raises(AssertionError):
        c.spend(
            wots_sig=wots_sig,
            wots_pub_key=kp.pk,
            sig=ecdsa_sig,
            pub_key=wrong_ecdsa_pub_key,
        )


def test_wrong_wots_pub_key_hash():
    """Spend with wrong WOTS+ public key should fail the hash160 check."""
    ecdsa_pub_key, ecdsa_pub_key_hash, _, wots_pub_key_hash = setup_keys()

    c = PostQuantumWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        wots_pub_key_hash=wots_pub_key_hash,
    )

    # Different WOTS keypair whose hash160 won't match
    wrong_kp = wots_keygen(b'\x99' + b'\x00' * 31, b'\x02' + b'\x00' * 31)

    ecdsa_sig = mock_sig()
    wots_sig = wots_sign(ecdsa_sig, wrong_kp.sk, wrong_kp.pub_seed)

    with pytest.raises(AssertionError):
        c.spend(
            wots_sig=wots_sig,
            wots_pub_key=wrong_kp.pk,
            sig=ecdsa_sig,
            pub_key=ecdsa_pub_key,
        )


def test_tampered_wots_sig():
    """Tampered WOTS+ signature should fail verification."""
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash = setup_keys()
    ecdsa_sig = mock_sig()

    wots_sig = bytearray(wots_sign(ecdsa_sig, kp.sk, kp.pub_seed))
    wots_sig[0] ^= 0xFF  # Corrupt first byte
    wots_sig = bytes(wots_sig)

    c = PostQuantumWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        wots_pub_key_hash=wots_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            wots_sig=wots_sig,
            wots_pub_key=kp.pk,
            sig=ecdsa_sig,
            pub_key=ecdsa_pub_key,
        )


def test_wots_signed_wrong_message():
    """WOTS+ signed different ECDSA sig bytes -- should fail verification."""
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, wots_pub_key_hash = setup_keys()

    # WOTS signs one ECDSA sig, but spend provides a different one
    ecdsa_sig_a = b'\x30\x01' + b'\x00' * 70
    ecdsa_sig_b = b'\x30\x02' + b'\x00' * 70
    wots_sig = wots_sign(ecdsa_sig_a, kp.sk, kp.pub_seed)

    c = PostQuantumWallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        wots_pub_key_hash=wots_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            wots_sig=wots_sig,
            wots_pub_key=kp.pk,
            sig=ecdsa_sig_b,  # Different from what WOTS signed
            pub_key=ecdsa_pub_key,
        )
