"""SLH-DSA keygen/sign wrapper (slhdsa package) and verify (repo variant).

Signatures are the repo's SHA-256-only SLH-DSA variant, the one the compiled
on-chain verifier and the other six SDKs implement (F-133). For the 192/256
sets that is NOT real FIPS 205 (which uses SHA-512 there), so keygen/sign
instantiate the upstream package's SHA-256-only `Sha2_1Parameter` at the
FIPS 205 Table 2 dimensions instead of its FIPS `sha2_192*` / `sha2_256*`.

`slh_verify` is pure stdlib (runar/slh_dsa.py) and needs no optional package.
`slh_keygen` fails closed when the optional `slh-dsa` PyPI package is not
installed: it raises `RuntimeError` instead of returning a mock key. The
SPHINCSWallet / post-quantum-slhdsa-naive integration tests gate themselves on
`_HAS_SLHDSA` and skip explicitly.

Install: pip install slh-dsa
"""

from runar.slh_dsa import slh_verify as _slh_verify_repo

try:
    from slhdsa import KeyPair as _KeyPair
    from slhdsa.lowlevel.parameters import Sha2_1Parameter as _Sha2_1Parameter
    import slhdsa as _slhdsa
    _HAS_SLHDSA = True
except ImportError:
    _HAS_SLHDSA = False


# -- Parameter set mapping ---------------------------------------------------

def _sha256_only(p):
    """The upstream FIPS parameter set's dimensions, SHA-256-only hashing."""
    return _Sha2_1Parameter(p.oid_no, p.n, p.h, p.d, p.h_m, p.a, p.k, p.lgw, p.m)


_PARAM_SETS = {}
if _HAS_SLHDSA:
    _PARAM_SETS = {
        'sha2_128s': _slhdsa.sha2_128s,
        'sha2_128f': _slhdsa.sha2_128f,
        'sha2_192s': _sha256_only(_slhdsa.sha2_192s),
        'sha2_192f': _sha256_only(_slhdsa.sha2_192f),
        'sha2_256s': _sha256_only(_slhdsa.sha2_256s),
        'sha2_256f': _sha256_only(_slhdsa.sha2_256f),
    }


class SLHKeyPair:
    """SLH-DSA keypair wrapper."""

    def __init__(self, pk: bytes, _inner=None):
        self.pk = pk        # Raw public key bytes
        self._inner = _inner  # Internal slhdsa KeyPair for signing

    def sign(self, msg: bytes) -> bytes:
        """Sign a message. Returns the signature bytes."""
        if self._inner is None:
            raise RuntimeError("Cannot sign: no secret key (public-key-only keypair)")
        return self._inner.sign(msg)


def slh_keygen(param_set: str = 'sha2_128s') -> SLHKeyPair:
    """Generate an SLH-DSA keypair.

    Args:
        param_set: One of 'sha2_128s', 'sha2_128f', 'sha2_192s',
                   'sha2_192f', 'sha2_256s', 'sha2_256f'.

    Returns:
        SLHKeyPair with pk (public key bytes) and sign() method.
    """
    if not _HAS_SLHDSA:
        raise RuntimeError("slh-dsa package not installed. Install with: pip install slh-dsa")

    ps = _PARAM_SETS.get(param_set)
    if ps is None:
        raise ValueError(f"Unknown parameter set: {param_set}")

    kp = _KeyPair.gen(ps)
    pk_bytes = kp.pub.digest()
    return SLHKeyPair(pk=pk_bytes, _inner=kp)


def slh_verify(msg: bytes, sig: bytes, pk: bytes, param_set: str = 'sha2_128s') -> bool:
    """Verify an SLH-DSA signature (repo SHA-256-only variant).

    Args:
        msg: Original message bytes.
        sig: Signature bytes.
        pk: Public key bytes.
        param_set: Parameter set name.

    Returns:
        True if valid, False otherwise.
    """
    return _slh_verify_repo(param_set, msg, sig, pk)
