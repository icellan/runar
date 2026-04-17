from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract
from runar import hash160, ALICE, BOB, p384_keygen, p384_sign

import pytest

contract_mod = load_contract(str(Path(__file__).parent / "P384Wallet.runar.py"))
P384Wallet = contract_mod.P384Wallet


def setup_keys():
    ecdsa_pub_key = ALICE.pub_key
    ecdsa_pub_key_hash = hash160(ecdsa_pub_key)
    kp = p384_keygen()
    p384_pub_key_hash = hash160(kp.pk_compressed)
    return ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash


def test_spend():
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash = setup_keys()
    ecdsa_sig = ALICE.test_sig

    # P-384-sign the secp256k1 signature bytes
    p384_sig = p384_sign(ecdsa_sig, kp.sk)

    c = P384Wallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        p384_pub_key_hash=p384_pub_key_hash,
    )
    c.spend(
        p384_sig=p384_sig,
        p384_pub_key=kp.pk_compressed,
        sig=ecdsa_sig,
        pub_key=ecdsa_pub_key,
    )


def test_wrong_ecdsa_pub_key_hash():
    """Spend with wrong secp256k1 public key should fail the hash160 check."""
    _, ecdsa_pub_key_hash, kp, p384_pub_key_hash = setup_keys()

    c = P384Wallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        p384_pub_key_hash=p384_pub_key_hash,
    )

    wrong_ecdsa_pub_key = BOB.pub_key
    ecdsa_sig = BOB.test_sig
    p384_sig = p384_sign(ecdsa_sig, kp.sk)

    with pytest.raises(AssertionError):
        c.spend(
            p384_sig=p384_sig,
            p384_pub_key=kp.pk_compressed,
            sig=ecdsa_sig,
            pub_key=wrong_ecdsa_pub_key,
        )


def test_wrong_p384_pub_key_hash():
    """Spend with wrong P-384 public key should fail the hash160 check."""
    ecdsa_pub_key, ecdsa_pub_key_hash, _, p384_pub_key_hash = setup_keys()

    c = P384Wallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        p384_pub_key_hash=p384_pub_key_hash,
    )

    # Different P-384 keypair whose hash160 won't match
    wrong_kp = p384_keygen()

    ecdsa_sig = ALICE.test_sig
    p384_sig = p384_sign(ecdsa_sig, wrong_kp.sk)

    with pytest.raises(AssertionError):
        c.spend(
            p384_sig=p384_sig,
            p384_pub_key=wrong_kp.pk_compressed,
            sig=ecdsa_sig,
            pub_key=ecdsa_pub_key,
        )


def test_tampered_p384_sig():
    """Tampered P-384 signature should fail verification."""
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash = setup_keys()
    ecdsa_sig = ALICE.test_sig

    p384_sig = bytearray(p384_sign(ecdsa_sig, kp.sk))
    p384_sig[0] ^= 0xFF  # Corrupt first byte
    p384_sig = bytes(p384_sig)

    c = P384Wallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        p384_pub_key_hash=p384_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            p384_sig=p384_sig,
            p384_pub_key=kp.pk_compressed,
            sig=ecdsa_sig,
            pub_key=ecdsa_pub_key,
        )


def test_p384_signed_wrong_message():
    """P-384 signed different bytes than the secp256k1 sig -- should fail P-384 verification."""
    ecdsa_pub_key, ecdsa_pub_key_hash, kp, p384_pub_key_hash = setup_keys()

    # P-384 signs arbitrary bytes (not the real secp256k1 sig)
    fake_ecdsa_sig = b'\x30\x01' + b'\x00' * 69
    p384_sig = p384_sign(fake_ecdsa_sig, kp.sk)

    c = P384Wallet(
        ecdsa_pub_key_hash=ecdsa_pub_key_hash,
        p384_pub_key_hash=p384_pub_key_hash,
    )

    with pytest.raises(AssertionError):
        c.spend(
            p384_sig=p384_sig,
            p384_pub_key=kp.pk_compressed,
            sig=ALICE.test_sig,  # Real secp256k1 sig, but P-384 signed something else
            pub_key=ecdsa_pub_key,
        )


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "P384Wallet.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "P384Wallet.runar.py")
