from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "ECUnit.runar.py"))
ECUnit = contract_mod.ECUnit

from runar import ALICE


def test_test_ops_runs():
    c = ECUnit(pub_key=ALICE.pub_key)
    c.test_ops()


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "ECUnit.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "ECUnit.runar.py")
