from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "RawOutputTest.runar.py"))
RawOutputTest = contract_mod.RawOutputTest


def test_send_to_script_runs():
    c = RawOutputTest(count=0)
    c.send_to_script(b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac")
    assert c.count == 1


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "RawOutputTest.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "RawOutputTest.runar.py")
