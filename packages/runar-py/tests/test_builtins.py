"""Tests for runar.builtins — hash functions, mock crypto, math utilities, binary ops."""

import pytest
from runar.builtins import (
    hash160, hash256, sha256, ripemd160,
    check_sig, check_multi_sig, check_preimage,
    num2bin, bin2num, cat, substr, reverse_bytes, len_,
    safediv, safemod, clamp, sign, pow_, mul_div, percent_of, sqrt, gcd, divmod_, log2,
    mock_sig, mock_pub_key, mock_preimage,
    assert_,
)


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

class TestHashFunctions:
    def test_hash160_empty(self):
        """hash160(b'') produces 20 bytes."""
        result = hash160(b'')
        assert len(result) == 20
        assert isinstance(result, bytes)

    def test_sha256_empty(self):
        """sha256(b'') matches the well-known SHA-256 of empty string."""
        result = sha256(b'')
        assert result.hex() == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    def test_hash256_is_double_sha256(self):
        """hash256(data) == sha256(sha256(data))."""
        data = b'hello'
        expected = sha256(sha256(data))
        assert hash256(data) == expected

    def test_hash256_empty(self):
        """hash256(b'') == sha256(sha256(b''))."""
        assert hash256(b'') == sha256(sha256(b''))

    def test_ripemd160_length(self):
        """ripemd160 always produces 20 bytes."""
        result = ripemd160(b'test')
        assert len(result) == 20


# ---------------------------------------------------------------------------
# Mock crypto
# ---------------------------------------------------------------------------

class TestRealCrypto:
    def test_check_sig_valid(self):
        """Real ECDSA: mock_sig() + mock_pub_key() should verify."""
        assert check_sig(mock_sig(), mock_pub_key()) is True

    def test_check_sig_invalid(self):
        """Real ECDSA: random bytes should not verify."""
        assert check_sig(b'\x00' * 72, b'\x02' + b'\x00' * 32) is False

    def test_check_multi_sig_empty(self):
        assert check_multi_sig([], []) is True

    def test_check_preimage_always_true(self):
        assert check_preimage(b'\x00' * 181) is True


# ---------------------------------------------------------------------------
# num2bin / bin2num
# ---------------------------------------------------------------------------

class TestNum2BinBin2Num:
    def test_zero(self):
        assert num2bin(0, 1) == b'\x00'

    def test_one(self):
        assert num2bin(1, 1) == b'\x01'

    def test_negative_one(self):
        result = num2bin(-1, 2)
        assert result == b'\x01\x80'

    def test_bin2num_one(self):
        assert bin2num(b'\x01') == 1

    def test_bin2num_negative_one(self):
        assert bin2num(b'\x01\x80') == -1

    def test_bin2num_empty(self):
        assert bin2num(b'') == 0

    def test_round_trip_positive(self):
        for n in [0, 1, 127, 128, 255, 256, 10000]:
            assert bin2num(num2bin(n, 8)) == n

    def test_round_trip_negative(self):
        for n in [-1, -127, -128, -255, -10000]:
            assert bin2num(num2bin(n, 8)) == n


# ---------------------------------------------------------------------------
# Binary utilities
# ---------------------------------------------------------------------------

class TestBinaryUtils:
    def test_cat(self):
        assert cat(b'ab', b'cd') == b'abcd'

    def test_cat_empty(self):
        assert cat(b'', b'hello') == b'hello'

    def test_substr(self):
        data = b'abcdef'
        assert substr(data, 2, 3) == b'cde'

    def test_substr_from_start(self):
        assert substr(b'hello', 0, 2) == b'he'

    def test_reverse_bytes(self):
        assert reverse_bytes(b'\x01\x02\x03') == b'\x03\x02\x01'

    def test_reverse_bytes_single(self):
        assert reverse_bytes(b'\xff') == b'\xff'

    def test_len(self):
        assert len_(b'abc') == 3
        assert len_(b'') == 0


# ---------------------------------------------------------------------------
# Math utilities
# ---------------------------------------------------------------------------

class TestMathUtils:
    def test_safediv_positive(self):
        assert safediv(7, 2) == 3

    def test_safediv_negative_truncates_toward_zero(self):
        assert safediv(-7, 2) == -3

    def test_safediv_by_zero(self):
        assert safediv(10, 0) == 0

    def test_safemod(self):
        assert safemod(7, 2) == 1

    def test_safemod_negative(self):
        # Bitcoin Script: sign matches dividend
        assert safemod(-7, 2) == -1

    def test_clamp_within_range(self):
        assert clamp(5, 0, 10) == 5

    def test_clamp_below(self):
        assert clamp(-1, 0, 10) == 0

    def test_clamp_above(self):
        assert clamp(15, 0, 10) == 10

    def test_sign_positive(self):
        assert sign(42) == 1

    def test_sign_negative(self):
        assert sign(-3) == -1

    def test_sign_zero(self):
        assert sign(0) == 0

    def test_pow(self):
        assert pow_(2, 10) == 1024

    def test_mul_div(self):
        assert mul_div(10, 20, 5) == 40

    def test_percent_of(self):
        assert percent_of(10000, 500) == 500  # 5%

    def test_sqrt_perfect_square(self):
        assert sqrt(16) == 4

    def test_sqrt_non_perfect(self):
        assert sqrt(15) == 3

    def test_sqrt_zero(self):
        assert sqrt(0) == 0

    def test_sqrt_one(self):
        assert sqrt(1) == 1

    def test_gcd(self):
        assert gcd(12, 8) == 4

    def test_gcd_coprime(self):
        assert gcd(7, 13) == 1

    def test_log2_power_of_two(self):
        assert log2(8) == 3

    def test_log2_one(self):
        assert log2(1) == 0

    def test_log2_non_power(self):
        assert log2(10) == 3  # floor(log2(10))

    def test_log2_zero(self):
        assert log2(0) == 0


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class TestMockHelpers:
    def test_mock_sig_is_valid_der(self):
        """mock_sig() returns a real DER-encoded ECDSA signature."""
        sig = mock_sig()
        assert sig[0] == 0x30  # DER SEQUENCE tag
        # DER length: sig[1] + 2 == total length
        assert sig[1] + 2 == len(sig)

    def test_mock_pub_key_length(self):
        assert len(mock_pub_key()) == 33

    def test_mock_pub_key_prefix(self):
        """Compressed public key should start with 0x02 or 0x03."""
        assert mock_pub_key()[0] in (0x02, 0x03)

    def test_mock_sig_verifies_with_mock_pub_key(self):
        """mock_sig() should verify against mock_pub_key()."""
        assert check_sig(mock_sig(), mock_pub_key()) is True

    def test_mock_preimage_length(self):
        assert len(mock_preimage()) == 181


# ---------------------------------------------------------------------------
# assert_
# ---------------------------------------------------------------------------

class TestAssert:
    def test_passes_on_true(self):
        assert_(True)  # Should not raise

    def test_raises_on_false(self):
        with pytest.raises(AssertionError, match='assertion failed'):
            assert_(False)
