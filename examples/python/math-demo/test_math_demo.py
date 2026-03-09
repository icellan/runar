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
