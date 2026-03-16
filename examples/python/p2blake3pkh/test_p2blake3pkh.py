import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "P2Blake3PKH.runar.py"))
P2Blake3PKH = contract_mod.P2Blake3PKH

from runar import blake3_hash, ALICE


def test_unlock():
    pk = ALICE.pub_key
    c = P2Blake3PKH(pub_key_hash=blake3_hash(pk))
    c.unlock(ALICE.test_sig, pk)


def test_unlock_wrong_hash():
    pk = ALICE.pub_key
    # blake3_hash is mocked (always returns 32 zero bytes), so use a non-matching hash
    wrong_hash = b'\xff' * 32
    c = P2Blake3PKH(pub_key_hash=wrong_hash)
    with pytest.raises(AssertionError):
        c.unlock(ALICE.test_sig, pk)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "P2Blake3PKH.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "P2Blake3PKH.runar.py")
