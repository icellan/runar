import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ConvergenceProof.runar.py"))
ConvergenceProof = contract_mod.ConvergenceProof

from runar import ec_mul_gen, ec_add, EC_N


def test_prove_convergence():
    # R_A = (T + o_A) * G, R_B = (T + o_B) * G
    # delta_o = o_A - o_B
    t = 42
    o_a = 100
    o_b = 60
    delta_o = o_a - o_b  # 40

    r_a = ec_mul_gen(t + o_a)
    r_b = ec_mul_gen(t + o_b)

    c = ConvergenceProof(r_a=r_a, r_b=r_b)
    c.prove_convergence(delta_o)


def test_wrong_delta():
    token = 42
    o_a = 100
    o_b = 37

    r_a = ec_mul_gen(token + o_a)
    r_b = ec_mul_gen(token + o_b)
    wrong_delta = o_a - o_b + 1

    c = ConvergenceProof(r_a=r_a, r_b=r_b)
    with pytest.raises(AssertionError):
        c.prove_convergence(wrong_delta)


def test_different_tokens():
    """Tokens that are actually different (different T values) should fail."""
    token_a = 42
    token_b = 99
    o_a = 100
    o_b = 37

    r_a = ec_mul_gen(token_a + o_a)
    r_b = ec_mul_gen(token_b + o_b)
    delta_o = o_a - o_b  # correct offsets, but different underlying tokens

    c = ConvergenceProof(r_a=r_a, r_b=r_b)
    with pytest.raises(AssertionError):
        c.prove_convergence(delta_o)


def test_larger_scalars():
    """Proof works with large scalar values."""
    token = 1234567890
    o_a = 987654321
    o_b = 111111111

    r_a = ec_mul_gen(token + o_a)
    r_b = ec_mul_gen(token + o_b)
    delta_o = o_a - o_b

    c = ConvergenceProof(r_a=r_a, r_b=r_b)
    c.prove_convergence(delta_o)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ConvergenceProof.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ConvergenceProof.runar.py")
