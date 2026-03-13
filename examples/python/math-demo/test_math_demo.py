import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "MathDemo.runar.py"))
MathDemo = contract_mod.MathDemo


def test_divide_by():
    c = MathDemo(value=100)
    c.divide_by(4)
    assert c.value == 25


def test_clamp_value():
    c = MathDemo(value=150)
    c.clamp_value(0, 100)
    assert c.value == 100


def test_normalize():
    c = MathDemo(value=-42)
    c.normalize()
    assert c.value == -1


def test_exponentiate():
    c = MathDemo(value=3)
    c.exponentiate(4)
    assert c.value == 81


def test_square_root():
    c = MathDemo(value=144)
    c.square_root()
    assert c.value == 12


def test_reduce_gcd():
    c = MathDemo(value=48)
    c.reduce_gcd(18)
    assert c.value == 6


def test_scale_by_ratio():
    c = MathDemo(value=100)
    c.scale_by_ratio(3, 4)
    assert c.value == 75


def test_compute_log2():
    c = MathDemo(value=256)
    c.compute_log2()
    assert c.value == 8


def test_safediv_truncates():
    c = MathDemo(value=7)
    c.divide_by(2)
    assert c.value == 3


def test_safediv_rejects_zero():
    # Python mock safediv returns 0 for division by zero (mirrors Bitcoin Script
    # semantics where the transaction fails on-chain). The mock doesn't raise.
    c = MathDemo(value=10)
    c.divide_by(0)
    assert c.value == 0


def test_percent_of():
    c = MathDemo(value=10000)
    c.withdraw_with_fee(1000, 500)  # 5% fee = 50, total = 1050
    assert c.value == 8950


def test_clamp_below():
    c = MathDemo(value=3)
    c.clamp_value(10, 100)
    assert c.value == 10


def test_clamp_above():
    c = MathDemo(value=200)
    c.clamp_value(10, 100)
    assert c.value == 100


def test_clamp_in_range():
    c = MathDemo(value=50)
    c.clamp_value(10, 100)
    assert c.value == 50


def test_sign_positive():
    c = MathDemo(value=42)
    c.normalize()
    assert c.value == 1


def test_sign_negative():
    c = MathDemo(value=-7)
    c.normalize()
    assert c.value == -1


def test_sign_zero():
    c = MathDemo(value=0)
    c.normalize()
    assert c.value == 0


def test_pow_zero():
    c = MathDemo(value=99)
    c.exponentiate(0)
    assert c.value == 1


def test_sqrt_non_perfect():
    c = MathDemo(value=10)
    c.square_root()
    assert c.value == 3


def test_gcd_coprime():
    c = MathDemo(value=7)
    c.reduce_gcd(13)
    assert c.value == 1


def test_mul_div():
    c = MathDemo(value=1000)
    c.scale_by_ratio(3, 4)
    assert c.value == 750


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "MathDemo.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "MathDemo.runar.py")
