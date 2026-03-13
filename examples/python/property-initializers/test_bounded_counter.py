import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "BoundedCounter.runar.py"))
BoundedCounter = contract_mod.BoundedCounter


def test_default_initializers():
    # Only max_count is required — count and active use property initializers
    c = BoundedCounter(max_count=10)
    # count defaults to 0
    assert c.count == 0
    # active defaults to True — verified by increment succeeding (it asserts active)
    c.increment(1)
    assert c.count == 1


def test_increment():
    c = BoundedCounter(max_count=10)
    c.increment(3)
    assert c.count == 3


def test_rejects_increment_beyond_max():
    c = BoundedCounter(max_count=5)
    with pytest.raises(AssertionError):
        c.increment(6)


def test_reset():
    c = BoundedCounter(max_count=10)
    c.increment(7)
    assert c.count == 7
    c.reset()
    assert c.count == 0


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "BoundedCounter.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "BoundedCounter.runar.py")
