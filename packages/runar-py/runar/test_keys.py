"""Pre-generated deterministic test keys for use across all Python test suites.

These keys match the TypeScript test-keys.ts exactly. All derived values
(public key, pubkey hash, test signature) are deterministic and reproducible.
"""

import hashlib

from runar.ecdsa import sign_test_message, pub_key_from_priv_key


class TestKeyPair:
    """A pre-generated test keypair with all derived values."""

    __slots__ = ('name', 'priv_key', 'pub_key', 'pub_key_hash', 'test_sig')

    def __init__(self, name: str, priv_key: str, pub_key: bytes,
                 pub_key_hash: bytes, test_sig: bytes):
        self.name = name
        self.priv_key = priv_key      # hex string (64 chars)
        self.pub_key = pub_key        # 33 bytes (compressed)
        self.pub_key_hash = pub_key_hash  # 20 bytes (HASH160)
        self.test_sig = test_sig      # DER-encoded ECDSA signature bytes


def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def _make_key(name: str, priv_key_hex: str) -> TestKeyPair:
    """Build a TestKeyPair from a private key hex string."""
    pub_key = pub_key_from_priv_key(priv_key_hex)
    pub_key_hash = _hash160(pub_key)
    test_sig = sign_test_message(priv_key_hex)
    return TestKeyPair(
        name=name,
        priv_key=priv_key_hex,
        pub_key=pub_key,
        pub_key_hash=pub_key_hash,
        test_sig=test_sig,
    )


# Named test keys -- matching TypeScript test-keys.ts
ALICE = _make_key('alice', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
BOB = _make_key('bob', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2')
CHARLIE = _make_key('charlie', 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')
DAVE = _make_key('dave', 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe')
EVE = _make_key('eve', 'abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01')
FRANK = _make_key('frank', '1111111111111111111111111111111111111111111111111111111111111111')
GRACE = _make_key('grace', '2222222222222222222222222222222222222222222222222222222222222222')
HEIDI = _make_key('heidi', '3333333333333333333333333333333333333333333333333333333333333333')
IVAN = _make_key('ivan', '4444444444444444444444444444444444444444444444444444444444444444')
JUDY = _make_key('judy', '5555555555555555555555555555555555555555555555555555555555555555')

TEST_KEYS = [ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE, HEIDI, IVAN, JUDY]
