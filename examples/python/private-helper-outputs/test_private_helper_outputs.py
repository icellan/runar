from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "PrivateHelperOutputs.runar.py"))
PrivateHelperOutputs = contract_mod.PrivateHelperOutputs


def test_commit_runs():
    c = PrivateHelperOutputs(counter=5)
    c.commit()
    assert c.counter == 6


def test_log_runs():
    c = PrivateHelperOutputs(counter=0)
    c.log(b"hello")
    assert c.counter == 0


def test_partition_runs():
    c = PrivateHelperOutputs(counter=100)
    c.partition(30, 70)
    assert c.counter == 100


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "PrivateHelperOutputs.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "PrivateHelperOutputs.runar.py")
