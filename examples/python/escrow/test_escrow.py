from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Escrow.runar.py"))
Escrow = contract_mod.Escrow

from runar import ALICE, BOB, CHARLIE


def test_release():
    c = Escrow(buyer=ALICE.pub_key, seller=BOB.pub_key, arbiter=CHARLIE.pub_key)
    c.release(BOB.test_sig, CHARLIE.test_sig)


def test_refund():
    c = Escrow(buyer=ALICE.pub_key, seller=BOB.pub_key, arbiter=CHARLIE.pub_key)
    c.refund(ALICE.test_sig, CHARLIE.test_sig)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Escrow.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Escrow.runar.py")
