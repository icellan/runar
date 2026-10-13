"""Tests for runar.builtins — hash functions, mock crypto, math utilities, binary ops."""

import pytest
from runar.builtins import (
    hash160, hash256, sha256, ripemd160,
    check_sig, check_multi_sig, check_preimage,
    num2bin, bin2num, int_to_str, cat, substr, reverse_bytes, len_,
    safediv, safemod, clamp, sign, pow_, mul_div, percent_of, sqrt, gcd, divmod_, log2,
    mock_sig, mock_pub_key, mock_preimage,
    extract_output_hash,
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
# int_to_str (alias for num2bin)
# ---------------------------------------------------------------------------

class TestIntToStr:
    def test_int_to_str_matches_num2bin(self):
        """int_to_str is an alias for num2bin with identical output."""
        for n in [0, 1, 42, 127, 128, 255, 256, -1, -127, -10000]:
            for width in [1, 4, 8]:
                if abs(n) < (1 << (8 * width - 1)):
                    assert int_to_str(n, width) == num2bin(n, width)

    def test_int_to_str_round_trip(self):
        for n in [0, 1, 127, 256, -1, -10000]:
            assert bin2num(int_to_str(n, 8)) == n


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
        # The script aborts on a zero divisor (OP_0NOTEQUAL OP_VERIFY), so the
        # mock refuses instead of returning a value (F-134).
        with pytest.raises(ZeroDivisionError):
            safediv(10, 0)

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
# extract_output_hash (N-246)
# ---------------------------------------------------------------------------

def _build_preimage_n246(hash_prevouts_byte: bytes, hash_outputs_byte: bytes) -> bytes:
    """Lays out a syntactically valid BIP-143 preimage with a zero-length
    scriptCode, so every field lands at its fixed offset:
      version(4) hashPrevouts(32) hashSequence(32) outpoint(36)
      scriptCodeLen(1=0x00) amount(8) sequence(4) hashOutputs(32)
      locktime(4) sighashType(4)
    """
    version = bytes.fromhex('01000000')
    hash_prevouts = hash_prevouts_byte * 32
    hash_sequence = b'\x00' * 32
    outpoint = b'\x00' * 36
    script_code_len = b'\x00'
    amount = bytes.fromhex('1027000000000000')  # 10000 satoshis, LE int64
    sequence = bytes.fromhex('feffffff')
    hash_outputs = hash_outputs_byte * 32
    locktime = b'\x00' * 4
    sighash_type = bytes.fromhex('41000000')
    return (version + hash_prevouts + hash_sequence + outpoint + script_code_len +
            amount + sequence + hash_outputs + locktime + sighash_type)


class TestExtractOutputHash:
    def test_returns_hash_outputs_not_leading_bytes(self):
        """N-246: extract_output_hash must return the preimage's actual
        hashOutputs field, not the leading 32 bytes (which cover nVersion +
        most of hashPrevouts in a real BIP-143 preimage). Mirrors the
        landed TS fix (N-245, packages/runar-lang/src/runtime/preimage.ts)
        and the Java fix (N-188, Preimage.extractOutputHash).

        Proves: the correct end-relative hashOutputs window is read.
        Does not prove: anything about on-chain behaviour, which this mock
        never touches.
        """
        preimage = _build_preimage_n246(b'\xaa', b'\xbb')
        result = extract_output_hash(preimage)
        assert result == b'\xbb' * 32
        assert result != b'\xaa' * 32

    def test_falls_back_to_zero_when_too_short(self):
        assert extract_output_hash(b'') == b'\x00' * 32
        assert extract_output_hash(b'\xaa' * 32) == b'\x00' * 32  # 32 bytes = too short


# ---------------------------------------------------------------------------
# assert_
# ---------------------------------------------------------------------------

class TestAssert:
    def test_passes_on_true(self):
        assert_(True)  # Should not raise

    def test_raises_on_false(self):
        with pytest.raises(AssertionError, match='assertion failed'):
            assert_(False)
