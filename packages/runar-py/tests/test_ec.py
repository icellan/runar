"""Tests for runar.ec — pure Python secp256k1 elliptic curve operations."""

import pytest
from runar.ec import (
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_on_curve,
    ec_point_x, ec_point_y, ec_make_point, ec_encode_compressed,
    ec_mod_reduce, EC_P, EC_N, EC_G,
    EC_G_X, EC_G_Y,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_ec_g_is_64_bytes(self):
        assert len(EC_G) == 64

    def test_ec_g_on_curve(self):
        assert ec_on_curve(EC_G) is True

    def test_ec_g_coordinates(self):
        """EC_G encodes the well-known secp256k1 generator Gx, Gy."""
        assert ec_point_x(EC_G) == EC_G_X
        assert ec_point_y(EC_G) == EC_G_Y

    def test_ec_p_is_prime(self):
        """EC_P is the known secp256k1 field prime."""
        assert EC_P == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def test_ec_n_is_group_order(self):
        assert EC_N == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------
# Point operations
# ---------------------------------------------------------------------------

class TestPointOps:
    def test_ec_add_g_plus_g_equals_mul_2(self):
        """G + G should equal 2 * G."""
        sum_gg = ec_add(EC_G, EC_G)
        double_g = ec_mul(EC_G, 2)
        assert sum_gg == double_g

    def test_ec_mul_gen_2_equals_add_g_g(self):
        """ec_mul_gen(2) should equal ec_add(G, G)."""
        gen2 = ec_mul_gen(2)
        sum_gg = ec_add(EC_G, EC_G)
        assert gen2 == sum_gg

    def test_ec_mul_gen_1_equals_g(self):
        """ec_mul_gen(1) is the generator point itself."""
        assert ec_mul_gen(1) == EC_G

    def test_ec_mul_gen_result_on_curve(self):
        """Any scalar multiple of G should be on the curve."""
        for k in [1, 2, 3, 7, 42, 999]:
            p = ec_mul_gen(k)
            assert ec_on_curve(p), f"ec_mul_gen({k}) not on curve"

    def test_ec_add_associativity(self):
        """(G + 2G) + 3G == G + (2G + 3G)."""
        g2 = ec_mul_gen(2)
        g3 = ec_mul_gen(3)
        lhs = ec_add(ec_add(EC_G, g2), g3)
        rhs = ec_add(EC_G, ec_add(g2, g3))
        assert lhs == rhs


# ---------------------------------------------------------------------------
# Negation
# ---------------------------------------------------------------------------

class TestNegate:
    def test_negate_flips_y(self):
        """ec_negate(G) produces a point with y = P - Gy."""
        neg = ec_negate(EC_G)
        neg_y = ec_point_y(neg)
        expected_y = (EC_P - EC_G_Y) % EC_P
        assert neg_y == expected_y

    def test_negate_preserves_x(self):
        neg = ec_negate(EC_G)
        assert ec_point_x(neg) == EC_G_X

    def test_negated_point_on_curve(self):
        neg = ec_negate(EC_G)
        assert ec_on_curve(neg) is True

    def test_double_negate_is_identity(self):
        assert ec_negate(ec_negate(EC_G)) == EC_G


# ---------------------------------------------------------------------------
# make_point / encode_compressed
# ---------------------------------------------------------------------------

class TestEncoding:
    def test_make_point_recreates_g(self):
        p = ec_make_point(EC_G_X, EC_G_Y)
        assert p == EC_G

    def test_encode_compressed_length(self):
        compressed = ec_encode_compressed(EC_G)
        assert len(compressed) == 33

    def test_encode_compressed_prefix(self):
        """Compressed encoding starts with 0x02 (even y) or 0x03 (odd y)."""
        compressed = ec_encode_compressed(EC_G)
        assert compressed[0] in (0x02, 0x03)

    def test_encode_compressed_x_matches(self):
        """The 32 bytes after the prefix should be the x-coordinate."""
        compressed = ec_encode_compressed(EC_G)
        x_bytes = compressed[1:]
        assert int.from_bytes(x_bytes, 'big') == EC_G_X


# ---------------------------------------------------------------------------
# ec_mod_reduce
# ---------------------------------------------------------------------------

class TestModReduce:
    def test_reduce_p_plus_1(self):
        assert ec_mod_reduce(EC_P + 1, EC_P) == 1

    def test_reduce_zero(self):
        assert ec_mod_reduce(0, EC_P) == 0

    def test_reduce_already_in_range(self):
        assert ec_mod_reduce(42, EC_P) == 42

    def test_reduce_exact_multiple(self):
        assert ec_mod_reduce(EC_P * 3, EC_P) == 0


# ---------------------------------------------------------------------------
# ec_on_curve
# ---------------------------------------------------------------------------

class TestOnCurve:
    def test_random_bytes_not_on_curve(self):
        """Arbitrary 64 bytes are extremely unlikely to be on the curve."""
        fake_point = b'\x01' * 64
        # This might or might not be on curve, but let's test with known off-curve
        off_curve = ec_make_point(1, 1)
        # (1, 1): 1^2 mod p = 1, (1^3 + 7) mod p = 8 => not on curve
        assert ec_on_curve(off_curve) is False

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match='64 bytes'):
            ec_on_curve(b'\x00' * 32)

    def test_rejects_noncanonical_x(self):
        """CL-BUG-161 / F-243: coordinate canonicity.

        x0 = 1 is a genuine secp256k1 curve point (y0 below). _decode_point
        parses each half as an unsigned big-endian int with no range check,
        so a coordinate written as x0 + EC_P (still exactly 32 bytes) reaches
        the field arithmetic below, which reduces it mod EC_P and accepts it
        as if it were x0. The compiled script range-checks x < p AND y < p
        BEFORE the curve-equation check (GAP-301), so this mock must reject
        what the script rejects. Verified against the real compiled script
        via @bsv/sdk's Spend in
        packages/runar-testing/src/__tests__/r117-coordinate-canonicity.test.ts
        ("the predicate stays TOTAL: onCurve(alias) is false").
        """
        y0 = 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee
        noncanonical_x = EC_P + 1
        alias_point = ec_make_point(noncanonical_x, y0)
        assert ec_on_curve(alias_point) is False
