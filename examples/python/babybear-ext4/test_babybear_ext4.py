"""Runtime tests for BabyBearExt4Demo.

Verifies the business-logic assertions hold against known ext4 test vectors.
Also acts as an import-regression test: if `bb_ext4_*` helpers are ever
dropped from `runar/__init__.py`, `load_contract` will fail at import time.
"""

from pathlib import Path

from conftest import load_contract
from runar import (
    bb_ext4_mul0, bb_ext4_mul1, bb_ext4_mul2, bb_ext4_mul3,
    bb_ext4_inv0, bb_ext4_inv1, bb_ext4_inv2, bb_ext4_inv3,
)


contract_mod = load_contract(str(Path(__file__).parent / "BabyBearExt4Demo.runar.py"))
BabyBearExt4Demo = contract_mod.BabyBearExt4Demo


def test_check_mul_with_known_vectors():
    a = (7, 11, 13, 17)
    b = (1, 0, 0, 0)  # identity
    e = (
        bb_ext4_mul0(*a, *b),
        bb_ext4_mul1(*a, *b),
        bb_ext4_mul2(*a, *b),
        bb_ext4_mul3(*a, *b),
    )
    assert e == a, e
    c = BabyBearExt4Demo()
    c.check_mul(*a, *b, *e)


def test_check_inv_roundtrip():
    a = (100, 200, 300, 400)
    inv = (
        bb_ext4_inv0(*a),
        bb_ext4_inv1(*a),
        bb_ext4_inv2(*a),
        bb_ext4_inv3(*a),
    )
    prod = (
        bb_ext4_mul0(*a, *inv),
        bb_ext4_mul1(*a, *inv),
        bb_ext4_mul2(*a, *inv),
        bb_ext4_mul3(*a, *inv),
    )
    assert prod == (1, 0, 0, 0), prod
    c = BabyBearExt4Demo()
    c.check_inv(*a, *inv)


def test_check_mul_nontrivial():
    a = (2, 3, 5, 7)
    b = (11, 13, 17, 19)
    e = (
        bb_ext4_mul0(*a, *b),
        bb_ext4_mul1(*a, *b),
        bb_ext4_mul2(*a, *b),
        bb_ext4_mul3(*a, *b),
    )
    c = BabyBearExt4Demo()
    c.check_mul(*a, *b, *e)
