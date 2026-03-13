"""Tests for runar.wots — WOTS+ one-time signature scheme."""

import pytest
from runar.wots import (
    wots_keygen, wots_sign, wots_verify,
    _extract_digits, _checksum_digits, _all_digits,
    WOTS_W, WOTS_N, WOTS_LEN, WOTS_LEN1, WOTS_LEN2,
)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestWotsKeygen:
    def test_keygen_sizes(self):
        """Public key is 64 bytes (pubSeed || pkRoot); SK has 67 elements of 32 bytes each."""
        kp = wots_keygen()
        assert len(kp.pk) == 2 * WOTS_N          # 64 bytes
        assert len(kp.pub_seed) == WOTS_N         # 32 bytes
        assert len(kp.sk) == WOTS_LEN             # 67 elements
        for i, sk_elem in enumerate(kp.sk):
            assert len(sk_elem) == WOTS_N, f"SK element {i}: expected {WOTS_N} bytes, got {len(sk_elem)}"

    def test_keygen_pub_seed_in_pk(self):
        """First 32 bytes of public key must equal pubSeed."""
        seed = bytes(range(32))
        pub_seed = bytes(i * 2 % 256 for i in range(32))
        kp = wots_keygen(seed=seed, pub_seed=pub_seed)
        assert kp.pk[:WOTS_N] == pub_seed

    def test_keygen_deterministic(self):
        """Same seed + pub_seed produce identical keypairs."""
        seed = b'deterministic-seed-for-wots-test!'
        pub_seed = bytes(32)
        kp1 = wots_keygen(seed=seed, pub_seed=pub_seed)
        kp2 = wots_keygen(seed=seed, pub_seed=pub_seed)
        assert kp1.pk == kp2.pk
        for i in range(WOTS_LEN):
            assert kp1.sk[i] == kp2.sk[i], f"SK element {i} differs"

    def test_keygen_random_when_no_seed(self):
        """With no seed, two keygens should (almost certainly) produce different keys."""
        kp1 = wots_keygen()
        kp2 = wots_keygen()
        # Probability of collision is negligible for random 64-byte values
        assert kp1.pk != kp2.pk


# ---------------------------------------------------------------------------
# Sign + verify round-trip
# ---------------------------------------------------------------------------

class TestWotsSignVerify:
    def test_sign_produces_correct_length(self):
        """Signature must be LEN*N = 67*32 = 2144 bytes."""
        kp = wots_keygen(seed=b'test-seed-for-wots-sign-verify!!', pub_seed=bytes(32))
        sig = wots_sign(b'hello, WOTS+ verification test!', kp.sk, kp.pub_seed)
        assert len(sig) == WOTS_LEN * WOTS_N

    def test_sign_verify_roundtrip(self):
        """Valid signature verifies correctly."""
        seed = b'test-seed-for-wots-sign-verify!!'
        kp = wots_keygen(seed=seed, pub_seed=bytes(32))
        msg = b'hello, WOTS+ verification test!'
        sig = wots_sign(msg, kp.sk, kp.pub_seed)
        assert wots_verify(msg, sig, kp.pk) is True

    def test_verify_wrong_message_fails(self):
        """Verifying a valid signature against a different message must fail."""
        kp = wots_keygen(seed=b'test-seed-for-wrong-message-chk!', pub_seed=bytes(32))
        msg = b'original message for signing test'
        sig = wots_sign(msg, kp.sk, kp.pub_seed)
        wrong_msg = b'different message than was signed'
        assert wots_verify(wrong_msg, sig, kp.pk) is False

    def test_verify_tampered_sig_fails(self):
        """Flipping a byte in the signature must cause verification to fail."""
        kp = wots_keygen(seed=b'test-seed-for-tampered-sig-test!', pub_seed=bytes(32))
        msg = b'message for tampered sig testing'
        sig = wots_sign(msg, kp.sk, kp.pub_seed)
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        assert wots_verify(msg, bytes(tampered), kp.pk) is False

    def test_verify_wrong_pk_fails(self):
        """Signature verified with a different public key must fail."""
        kp1 = wots_keygen(seed=b'keypair-one-for-wrong-pk-test!!a', pub_seed=bytes(32))
        kp2 = wots_keygen(seed=b'keypair-two-for-wrong-pk-test!!b', pub_seed=bytes(32))
        msg = b'test message'
        sig = wots_sign(msg, kp1.sk, kp1.pub_seed)
        assert wots_verify(msg, sig, kp2.pk) is False


# ---------------------------------------------------------------------------
# Bad-input length checks
# ---------------------------------------------------------------------------

class TestWotsVerifyBadLengths:
    def test_verify_bad_sig_length(self):
        """Short signature (not LEN*N bytes) returns False immediately."""
        pk = bytes(2 * WOTS_N)
        assert wots_verify(b'msg', b'short', pk) is False

    def test_verify_bad_pk_length(self):
        """Public key shorter than 64 bytes returns False immediately."""
        sig = bytes(WOTS_LEN * WOTS_N)
        assert wots_verify(b'msg', sig, b'short-pk') is False

    def test_verify_empty_sig(self):
        """Empty signature returns False."""
        pk = bytes(2 * WOTS_N)
        assert wots_verify(b'msg', b'', pk) is False


# ---------------------------------------------------------------------------
# Internal digit helpers
# ---------------------------------------------------------------------------

class TestExtractDigits:
    def test_length_is_len1(self):
        """_extract_digits on 32 bytes yields exactly LEN1=64 digits."""
        digits = _extract_digits(bytes(32))
        assert len(digits) == WOTS_LEN1

    def test_digits_in_range(self):
        """Every digit must be in [0, W) = [0, 16)."""
        digits = _extract_digits(bytes(b'\xff' * 32))
        for i, d in enumerate(digits):
            assert 0 <= d < WOTS_W, f"digit {i} out of range: {d}"

    def test_zero_hash_gives_zero_digits(self):
        """All-zero hash → all zero digits."""
        digits = _extract_digits(bytes(32))
        assert all(d == 0 for d in digits)

    def test_max_byte_gives_max_digits(self):
        """0xFF byte splits into two nibbles of 15."""
        digits = _extract_digits(b'\xff')
        assert digits == [15, 15]


class TestChecksumDigits:
    def test_length_is_len2(self):
        """_checksum_digits yields exactly LEN2=3 digits."""
        msg_digits = [0] * WOTS_LEN1
        csum = _checksum_digits(msg_digits)
        assert len(csum) == WOTS_LEN2

    def test_zero_msg_digits_gives_max_checksum(self):
        """All-zero message digits → maximum checksum value."""
        msg_digits = [0] * WOTS_LEN1
        csum = _checksum_digits(msg_digits)
        max_csum = WOTS_LEN1 * (WOTS_W - 1)
        assert sum(d * (WOTS_W ** (WOTS_LEN2 - 1 - i)) for i, d in enumerate(csum)) == max_csum

    def test_max_msg_digits_gives_zero_checksum(self):
        """All-max (W-1) message digits → checksum of zero."""
        msg_digits = [WOTS_W - 1] * WOTS_LEN1
        csum = _checksum_digits(msg_digits)
        assert all(d == 0 for d in csum)

    def test_digits_in_range(self):
        """All checksum digits must be in [0, W)."""
        for val in [0, 5, 10, WOTS_W - 1]:
            msg_digits = [val] * WOTS_LEN1
            csum = _checksum_digits(msg_digits)
            for d in csum:
                assert 0 <= d < WOTS_W


class TestAllDigits:
    def test_total_length_is_len(self):
        """_all_digits yields exactly LEN=67 digits (64 msg + 3 checksum)."""
        digits = _all_digits(bytes(32))
        assert len(digits) == WOTS_LEN

    def test_first_len1_digits_match_extract(self):
        """The first LEN1 digits of _all_digits match _extract_digits output."""
        import hashlib
        msg_hash = hashlib.sha256(b'test').digest()
        msg_digits = _extract_digits(msg_hash)
        # _all_digits takes the pre-computed SHA-256 hash, not the raw message
        all_d = _all_digits(msg_hash)
        assert all_d[:WOTS_LEN1] == msg_digits

    def test_last_len2_digits_match_checksum(self):
        """The last LEN2 digits of _all_digits match _checksum_digits output."""
        import hashlib
        msg = b'checksum test'
        msg_hash = hashlib.sha256(msg).digest()
        msg_digits = _extract_digits(msg_hash)
        expected_csum = _checksum_digits(msg_digits)
        # _all_digits takes the pre-computed SHA-256 hash
        all_d = _all_digits(msg_hash)
        assert all_d[WOTS_LEN1:] == expected_csum
