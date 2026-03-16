import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "P2PKH.runar.py"))
P2PKH = contract_mod.P2PKH

from runar import hash160, ALICE, BOB


def test_unlock():
    c = P2PKH(pub_key_hash=hash160(ALICE.pub_key))
    c.unlock(ALICE.test_sig, ALICE.pub_key)


def test_unlock_wrong_key():
    c = P2PKH(pub_key_hash=hash160(ALICE.pub_key))
    with pytest.raises(AssertionError):
        c.unlock(BOB.test_sig, BOB.pub_key)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "P2PKH.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "P2PKH.runar.py")
