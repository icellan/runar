import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ECDemo.runar.py"))
ECDemo = contract_mod.ECDemo

from runar import (
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_on_curve,
    ec_mod_reduce, ec_encode_compressed, ec_make_point,
    ec_point_x, ec_point_y, EC_N, EC_P,
)


# --- Helper: a real curve point to use throughout tests ---
# Use k=7 so the point is a known, small-scalar multiple of G.
K = 7
PT = ec_mul_gen(K)
PT_X = ec_point_x(PT)
PT_Y = ec_point_y(PT)

# A second point for addition tests (k=13)
K2 = 13
PT2 = ec_mul_gen(K2)
PT2_X = ec_point_x(PT2)
PT2_Y = ec_point_y(PT2)


# -------------------------------------------------------------------
# Coordinate extraction and construction
# -------------------------------------------------------------------

def test_check_x():
    c = ECDemo(pt=PT)
    c.check_x(PT_X)


def test_check_y():
    c = ECDemo(pt=PT)
    c.check_y(PT_Y)


def test_check_make_point():
    c = ECDemo(pt=PT)
    c.check_make_point(PT_X, PT_Y, PT_X, PT_Y)


def test_check_make_point_different_coords():
    c = ECDemo(pt=PT)
    c.check_make_point(PT2_X, PT2_Y, PT2_X, PT2_Y)


# -------------------------------------------------------------------
# Curve membership
# -------------------------------------------------------------------

def test_check_on_curve():
    c = ECDemo(pt=PT)
    c.check_on_curve()


def test_check_on_curve_generator():
    """Generator point G itself is on the curve."""
    g = ec_mul_gen(1)
    c = ECDemo(pt=g)
    c.check_on_curve()


# -------------------------------------------------------------------
# Point arithmetic
# -------------------------------------------------------------------

def test_check_add():
    expected = ec_add(PT, PT2)
    ex = ec_point_x(expected)
    ey = ec_point_y(expected)
    c = ECDemo(pt=PT)
    c.check_add(PT2, ex, ey)


def test_check_add_commutativity():
    """ec_add(A, B) == ec_add(B, A)."""
    sum_ab = ec_add(PT, PT2)
    sum_ba = ec_add(PT2, PT)
    assert sum_ab == sum_ba


def test_check_mul():
    scalar = 42
    expected = ec_mul(PT, scalar)
    ex = ec_point_x(expected)
    ey = ec_point_y(expected)
    c = ECDemo(pt=PT)
    c.check_mul(scalar, ex, ey)


def test_check_mul_gen():
    scalar = 99
    expected = ec_mul_gen(scalar)
    ex = ec_point_x(expected)
    ey = ec_point_y(expected)
    c = ECDemo(pt=PT)
    c.check_mul_gen(scalar, ex, ey)


def test_check_mul_gen_matches_ec_mul():
    """ec_mul_gen(k) should equal ec_mul(G, k)."""
    scalar = 55
    from_gen = ec_mul_gen(scalar)
    g = ec_mul_gen(1)
    from_mul = ec_mul(g, scalar)
    assert from_gen == from_mul


# -------------------------------------------------------------------
# Point negation
# -------------------------------------------------------------------

def test_check_negate():
    neg = ec_negate(PT)
    neg_y = ec_point_y(neg)
    c = ECDemo(pt=PT)
    c.check_negate(neg_y)


def test_check_negate_y_relationship():
    """Negated y should be EC_P - original y."""
    neg = ec_negate(PT)
    neg_y = ec_point_y(neg)
    assert neg_y == (EC_P - PT_Y) % EC_P


def test_check_negate_roundtrip():
    c = ECDemo(pt=PT)
    c.check_negate_roundtrip()


# -------------------------------------------------------------------
# Modular arithmetic
# -------------------------------------------------------------------

def test_check_mod_reduce_positive():
    c = ECDemo(pt=PT)
    c.check_mod_reduce(17, 5, 2)


def test_check_mod_reduce_negative():
    c = ECDemo(pt=PT)
    # Python % always returns non-negative for positive modulus
    c.check_mod_reduce(-3, 5, 2)


def test_check_mod_reduce_with_ec_n():
    """Reduce a large value mod the curve order."""
    large = EC_N + 42
    c = ECDemo(pt=PT)
    c.check_mod_reduce(large, EC_N, 42)


# -------------------------------------------------------------------
# Compressed encoding
# -------------------------------------------------------------------

def test_check_encode_compressed():
    expected = ec_encode_compressed(PT)
    c = ECDemo(pt=PT)
    c.check_encode_compressed(expected)


def test_compressed_prefix():
    """Compressed encoding starts with 0x02 (even y) or 0x03 (odd y)."""
    compressed = ec_encode_compressed(PT)
    assert compressed[0] in (0x02, 0x03)
    assert len(compressed) == 33


# -------------------------------------------------------------------
# Algebraic properties
# -------------------------------------------------------------------

def test_check_mul_identity():
    c = ECDemo(pt=PT)
    c.check_mul_identity()


def test_check_add_on_curve():
    c = ECDemo(pt=PT)
    c.check_add_on_curve(PT2)


def test_check_mul_gen_on_curve():
    c = ECDemo(pt=PT)
    c.check_mul_gen_on_curve(12345)


def test_check_mul_gen_on_curve_large_scalar():
    """Even very large scalars produce valid curve points."""
    c = ECDemo(pt=PT)
    c.check_mul_gen_on_curve(EC_N - 1)


def test_check_x_wrong():
    """Wrong x-coordinate value fails."""
    c = ECDemo(pt=PT)
    with pytest.raises(AssertionError):
        c.check_x(PT_X + 1)


def test_check_y_wrong():
    """Wrong y-coordinate value fails."""
    c = ECDemo(pt=PT)
    with pytest.raises(AssertionError):
        c.check_y(PT_Y + 1)


def test_check_make_point_wrong():
    """Wrong expected coordinates fail."""
    c = ECDemo(pt=PT)
    with pytest.raises(AssertionError):
        c.check_make_point(PT_X, PT_Y, PT_X + 1, PT_Y)


def test_check_add_wrong():
    """Wrong result coordinates for ec_add fail."""
    c = ECDemo(pt=PT)
    with pytest.raises(AssertionError):
        c.check_add(PT2, PT_X, PT_Y)  # PT_X/PT_Y is not the sum


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ECDemo.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ECDemo.runar.py")
