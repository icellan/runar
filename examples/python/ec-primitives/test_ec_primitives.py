import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ECPrimitives.runar.py"))
ECPrimitives = contract_mod.ECPrimitives

from runar import (
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_encode_compressed,
    ec_point_x, ec_point_y, EC_P,
)


# Deterministic small-scalar test points.
PT = ec_mul_gen(7)
PT2 = ec_mul_gen(13)
PT_X = ec_point_x(PT)
PT_Y = ec_point_y(PT)


def test_check_x():
    c = ECPrimitives(pt=PT)
    c.check_x(PT_X)


def test_check_y():
    c = ECPrimitives(pt=PT)
    c.check_y(PT_Y)


def test_check_on_curve():
    c = ECPrimitives(pt=PT)
    c.check_on_curve()


def test_check_negate_y():
    expected_neg_y = (EC_P - PT_Y) % EC_P
    c = ECPrimitives(pt=PT)
    c.check_negate_y(expected_neg_y)


def test_check_mod_reduce_basic():
    c = ECPrimitives(pt=PT)
    c.check_mod_reduce(17, 5, 2)


def test_check_add():
    s = ec_add(PT, PT2)
    c = ECPrimitives(pt=PT)
    c.check_add(PT2, ec_point_x(s), ec_point_y(s))


def test_check_mul():
    scalar = 11
    r = ec_mul(PT, scalar)
    c = ECPrimitives(pt=PT)
    c.check_mul(scalar, ec_point_x(r), ec_point_y(r))


def test_check_mul_gen():
    scalar = 99
    r = ec_mul_gen(scalar)
    c = ECPrimitives(pt=PT)
    c.check_mul_gen(scalar, ec_point_x(r), ec_point_y(r))


def test_check_make_point():
    c = ECPrimitives(pt=PT)
    c.check_make_point(PT_X, PT_Y, PT_X, PT_Y)


def test_check_encode_compressed():
    expected = ec_encode_compressed(PT)
    c = ECPrimitives(pt=PT)
    c.check_encode_compressed(expected)


def test_check_mul_identity():
    c = ECPrimitives(pt=PT)
    c.check_mul_identity()


def test_check_negate_roundtrip():
    c = ECPrimitives(pt=PT)
    c.check_negate_roundtrip()


def test_check_add_on_curve():
    c = ECPrimitives(pt=PT)
    c.check_add_on_curve(PT2)


def test_check_mul_gen_on_curve():
    c = ECPrimitives(pt=PT)
    c.check_mul_gen_on_curve(12345)


def test_check_x_wrong():
    c = ECPrimitives(pt=PT)
    with pytest.raises(AssertionError):
        c.check_x(PT_X + 1)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ECPrimitives.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ECPrimitives.runar.py")
