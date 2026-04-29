from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "DataOutputTest.runar.py"))
DataOutputTest = contract_mod.DataOutputTest


def test_publish_runs():
    c = DataOutputTest(count=0)
    c.publish(b"hello world")
    assert c.count == 1


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "DataOutputTest.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "DataOutputTest.runar.py")
