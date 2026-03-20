from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract
from runar import sha256_finalize

contract_mod = load_contract(str(Path(__file__).parent / "Sha256FinalizeTest.runar.py"))
Sha256FinalizeTest = contract_mod.Sha256FinalizeTest

SHA256_IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")


def test_verify():
    expected = sha256_finalize(SHA256_IV, b"abc", 24)
    c = Sha256FinalizeTest(expected=expected)
    c.verify(SHA256_IV, b"abc", 24)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Sha256FinalizeTest.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Sha256FinalizeTest.runar.py")
