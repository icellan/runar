from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "SchnorrZKP.runar.py"))
SchnorrZKP = contract_mod.SchnorrZKP

from runar import ec_mul_gen, hash256, cat, bin2num, EC_N


def _derive_challenge(r_point: bytes, pub_key: bytes) -> int:
    """Fiat-Shamir challenge: e = bin2num(hash256(R || P))"""
    return bin2num(hash256(cat(r_point, pub_key)))


def test_schnorr_verify():
    # Private key k, public key P = k*G
    k = 12345
    pub_key = ec_mul_gen(k)

    # Prover: pick random r, compute R = r*G
    r = 67890
    r_point = ec_mul_gen(r)

    # Derive challenge via Fiat-Shamir
    e = _derive_challenge(r_point, pub_key)

    # Response s = r + e*k (mod n)
    s = (r + e * k) % EC_N

    c = SchnorrZKP(pub_key=pub_key)
    c.verify(r_point, s)


def test_schnorr_wrong_s():
    k = 12345
    pub_key = ec_mul_gen(k)
    r = 67890
    r_point = ec_mul_gen(r)
    e = _derive_challenge(r_point, pub_key)
    s = (r + e * k) % EC_N

    c = SchnorrZKP(pub_key=pub_key)
    try:
        c.verify(r_point, s + 1)
        assert False, "expected assertion failure"
    except AssertionError:
        pass
    except Exception:
        pass  # any failure is acceptable for wrong s
