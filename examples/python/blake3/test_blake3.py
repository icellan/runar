from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Blake3Test.runar.py"))
Blake3Test = contract_mod.Blake3Test


def test_verify_compress():
    # Mock blake3_compress returns 32 zero bytes, so set expected to match.
    c = Blake3Test(expected=b'\x00' * 32)
    c.verify_compress(b'\x00' * 32, b'\x00' * 64)


def test_verify_hash():
    # Mock blake3_hash returns 32 zero bytes, so set expected to match.
    c = Blake3Test(expected=b'\x00' * 32)
    c.verify_hash(b'\x00' * 32)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Blake3Test.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Blake3Test.runar.py")
