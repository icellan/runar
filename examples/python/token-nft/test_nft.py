from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "NFTExample.runar.py"))
SimpleNFT = contract_mod.SimpleNFT

from runar import ALICE, BOB, CHARLIE


def test_transfer():
    c = SimpleNFT(owner=ALICE.pub_key, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c.transfer(ALICE.test_sig, BOB.pub_key, 546)
    assert len(c._outputs) == 1


def test_burn():
    c = SimpleNFT(owner=ALICE.pub_key, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c.burn(ALICE.test_sig)
    assert len(c._outputs) == 0


def test_transfer_chain():
    """Transfer succeeds for different recipients; each creates one output."""
    # First transfer: ALICE -> BOB
    c = SimpleNFT(owner=ALICE.pub_key, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c.transfer(ALICE.test_sig, BOB.pub_key, 546)
    assert len(c._outputs) == 1
    assert c._outputs[0]['values'][0] == BOB.pub_key
    # Second transfer: BOB -> CHARLIE
    c2 = SimpleNFT(owner=BOB.pub_key, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c2.transfer(BOB.test_sig, CHARLIE.pub_key, 546)
    assert len(c2._outputs) == 1
    assert c2._outputs[0]['values'][0] == CHARLIE.pub_key


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "NFTExample.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "NFTExample.runar.py")
