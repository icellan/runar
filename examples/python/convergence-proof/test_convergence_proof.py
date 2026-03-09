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
