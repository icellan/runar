import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Counter.runar.py"))
Counter = contract_mod.Counter


def test_increment():
    c = Counter(count=0)
    c.increment()
    assert c.count == 1


def test_increment_multiple():
    c = Counter(count=0)
    c.increment()
    c.increment()
    c.increment()
    assert c.count == 3


def test_decrement():
    c = Counter(count=5)
    c.decrement()
    assert c.count == 4


def test_decrement_at_zero_fails():
    c = Counter(count=0)
    with pytest.raises(AssertionError):
        c.decrement()


def test_increment_then_decrement():
    c = Counter(count=0)
    c.increment()
    c.increment()
    c.increment()
    c.decrement()
    assert c.count == 2


def test_compile():
    import os
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Counter.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Counter.runar.py")
