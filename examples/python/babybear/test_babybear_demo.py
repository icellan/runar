import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BabyBearDemo.runar.py"))
BabyBearDemo = contract_mod.BabyBearDemo

from runar import bb_field_add, bb_field_sub, bb_field_mul, bb_field_inv

# Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
BB_P = 2013265921


# ---------------------------------------------------------------------------
# check_add (bb_field_add)
# ---------------------------------------------------------------------------

def test_check_add_small():
    c = BabyBearDemo()
    c.check_add(5, 7, 12)


def test_check_add_wrap():
    c = BabyBearDemo()
    # (p-1) + 1 wraps to 0
    c.check_add(BB_P - 1, 1, 0)


def test_check_add_zero():
    c = BabyBearDemo()
    c.check_add(42, 0, 42)


def test_check_add_wrong():
    c = BabyBearDemo()
    with pytest.raises(AssertionError):
        c.check_add(5, 7, 13)


# ---------------------------------------------------------------------------
# check_sub (bb_field_sub)
# ---------------------------------------------------------------------------

def test_check_sub():
    c = BabyBearDemo()
    c.check_sub(10, 3, 7)


def test_check_sub_wrap():
    c = BabyBearDemo()
    # 0 - 1 = p - 1
    c.check_sub(0, 1, BB_P - 1)


def test_check_sub_wrong():
    c = BabyBearDemo()
    with pytest.raises(AssertionError):
        c.check_sub(10, 3, 8)


# ---------------------------------------------------------------------------
# check_mul (bb_field_mul)
# ---------------------------------------------------------------------------

def test_check_mul():
    c = BabyBearDemo()
    c.check_mul(6, 7, 42)


def test_check_mul_large_wrap():
    c = BabyBearDemo()
    # (p-1) * 2 mod p = p - 2
    c.check_mul(BB_P - 1, 2, BB_P - 2)


def test_check_mul_zero():
    c = BabyBearDemo()
    c.check_mul(12345, 0, 0)


def test_check_mul_wrong():
    c = BabyBearDemo()
    with pytest.raises(AssertionError):
        c.check_mul(6, 7, 43)


# ---------------------------------------------------------------------------
# check_inv (bb_field_inv)
# ---------------------------------------------------------------------------

def test_check_inv_one():
    c = BabyBearDemo()
    c.check_inv(1)


def test_check_inv_two():
    c = BabyBearDemo()
    c.check_inv(2)


def test_check_inv_large():
    c = BabyBearDemo()
    c.check_inv(1000000007)


# ---------------------------------------------------------------------------
# check_add_sub_roundtrip
# ---------------------------------------------------------------------------

def test_check_add_sub_roundtrip():
    c = BabyBearDemo()
    c.check_add_sub_roundtrip(42, 99)


# ---------------------------------------------------------------------------
# check_distributive
# ---------------------------------------------------------------------------

def test_check_distributive():
    c = BabyBearDemo()
    c.check_distributive(5, 7, 11)


# ---------------------------------------------------------------------------
# Compile check
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BabyBearDemo.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BabyBearDemo.runar.py")
