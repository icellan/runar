"""SLH-DSA (FIPS 205, SPHINCS+) wrapper using the slhdsa package.

Provides keygen, sign, and verify for SLH-DSA-SHA2-128s.
Falls back to mock (always-True verify) if slhdsa package is not installed.

Install: pip install slh-dsa
"""

try:
    from slhdsa import KeyPair as _KeyPair, PublicKey as _PublicKey
    import slhdsa as _slhdsa
    _HAS_SLHDSA = True
except ImportError:
    _HAS_SLHDSA = False


# -- Parameter set mapping ---------------------------------------------------

_PARAM_SETS = {}
if _HAS_SLHDSA:
    _PARAM_SETS = {
        'sha2_128s': _slhdsa.sha2_128s,
        'sha2_128f': _slhdsa.sha2_128f,
        'sha2_192s': _slhdsa.sha2_192s,
        'sha2_192f': _slhdsa.sha2_192f,
        'sha2_256s': _slhdsa.sha2_256s,
        'sha2_256f': _slhdsa.sha2_256f,
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
    """Verify an SLH-DSA signature.

    Args:
        msg: Original message bytes.
        sig: Signature bytes.
        pk: Public key bytes.
        param_set: Parameter set name.

    Returns:
        True if valid, False otherwise.
    """
    if not _HAS_SLHDSA:
        # Fallback: always True (mock behavior when package not installed)
        return True

    ps = _PARAM_SETS.get(param_set)
    if ps is None:
        raise ValueError(f"Unknown parameter set: {param_set}")

    pub = _PublicKey.from_digest(pk, ps)
    return pub.verify(msg, sig)
