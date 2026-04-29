import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Stateful.runar.py"))
Stateful = contract_mod.Stateful


def test_increment_within_bounds():
    c = Stateful(count=0, max_count=10)
    c.increment(3)
    assert c.count == 3
    c.increment(7)
    assert c.count == 10


def test_increment_above_max_fails():
    c = Stateful(count=0, max_count=10)
    with pytest.raises(AssertionError):
        c.increment(11)


def test_reset_clears_count():
    c = Stateful(count=5, max_count=10)
    c.reset()
    assert c.count == 0


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Stateful.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Stateful.runar.py")
