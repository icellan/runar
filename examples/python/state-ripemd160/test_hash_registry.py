import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "HashRegistry.runar.py"))
HashRegistry = contract_mod.HashRegistry


INITIAL = bytes.fromhex("01020304050607080910111213141516171819ff")
NEXT = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4")


def test_update_overwrites_hash():
    c = HashRegistry(current_hash=INITIAL)
    c.update(NEXT)
    assert c.current_hash == NEXT


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "HashRegistry.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "HashRegistry.runar.py")
