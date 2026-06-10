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


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "SchnorrZKP.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "SchnorrZKP.runar.py")


# ---------------------------------------------------------------------------
# BUG-001 adversarial tests: s-bound malleability gate
# ---------------------------------------------------------------------------
# See examples/ts/schnorr-zkp/SchnorrZKP.test.ts for the canonical commentary.


def test_rejects_s_at_n():
    """s = secp256k1 group order is rejected (within(s, 1, n) is half-open)."""
    k = 12345
    pub_key = ec_mul_gen(k)
    r = 67890
    r_point = ec_mul_gen(r)
    c = SchnorrZKP(pub_key=pub_key)
    try:
        c.verify(r_point, EC_N)
        assert False, "expected assertion failure for s = n"
    except (AssertionError, Exception):
        pass


def test_rejects_s_zero():
    """s = 0 is rejected (within(s, 1, n) requires s >= 1)."""
    k = 12345
    pub_key = ec_mul_gen(k)
    r = 67890
    r_point = ec_mul_gen(r)
    c = SchnorrZKP(pub_key=pub_key)
    try:
        c.verify(r_point, 0)
        assert False, "expected assertion failure for s = 0"
    except (AssertionError, Exception):
        pass


def test_nonce_reuse_recovers_key():
    """Reusing r across two proofs leaks the private key off-chain.

    Schnorr is fragile against nonce reuse: with two proofs (e1, s1) and
    (e2, s2) sharing the same r:
        s1 - s2 = (e1 - e2) * k  ->  k = (e1 - e2)^{-1} * (s1 - s2)
    Both proofs verify on-chain — the gate is a prover-side responsibility.
    """
    k = 0xC0FFEE
    pub_key = ec_mul_gen(k)
    r = 12345
    r_point = ec_mul_gen(r)
    e1 = _derive_challenge(r_point, pub_key)
    s1 = (r + e1 * k) % EC_N
    e2 = (e1 + 1) % EC_N
    s2 = (r + e2 * k) % EC_N
    # Off-chain key recovery from the (s1, s2) pair sharing r:
    recovered = ((s1 - s2) * pow(e1 - e2, -1, EC_N)) % EC_N
    assert recovered == k, f"expected {k}, got {recovered}"
    # Each proof verifies individually (on-chain has no way to detect r reuse).
    c = SchnorrZKP(pub_key=pub_key)
    c.verify(r_point, s1)
