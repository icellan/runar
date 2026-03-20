from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract
from runar import sha256_compress

contract_mod = load_contract(str(Path(__file__).parent / "Sha256CompressTest.runar.py"))
Sha256CompressTest = contract_mod.Sha256CompressTest

SHA256_IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
ABC_BLOCK = bytes.fromhex(
    "6162638000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000018"
)


def test_verify():
    expected = sha256_compress(SHA256_IV, ABC_BLOCK)
    c = Sha256CompressTest(expected=expected)
    c.verify(SHA256_IV, ABC_BLOCK)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Sha256CompressTest.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Sha256CompressTest.runar.py")
