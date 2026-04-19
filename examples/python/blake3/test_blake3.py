from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Blake3Test.runar.py"))
Blake3Test = contract_mod.Blake3Test


def test_verify_compress():
    from runar import blake3_compress
    cv = b'\x00' * 32
    block = b'\x00' * 64
    c = Blake3Test(expected=blake3_compress(cv, block))
    c.verify_compress(cv, block)


def test_verify_hash():
    from runar import blake3_hash
    message = b'\x00' * 32
    c = Blake3Test(expected=blake3_hash(message))
    c.verify_hash(message)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Blake3Test.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Blake3Test.runar.py")
