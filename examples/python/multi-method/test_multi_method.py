import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "MultiMethod.runar.py"))
MultiMethod = contract_mod.MultiMethod

from runar import ALICE, BOB


def test_spend_with_owner_succeeds_when_threshold_is_met():
    c = MultiMethod(owner=ALICE.pub_key, backup=BOB.pub_key)
    # amount * 2 + 1 must be > 10 → amount >= 5.
    c.spend_with_owner(ALICE.test_sig, 6)


def test_spend_with_owner_below_threshold_fails():
    c = MultiMethod(owner=ALICE.pub_key, backup=BOB.pub_key)
    with pytest.raises(AssertionError):
        c.spend_with_owner(ALICE.test_sig, 1)


def test_spend_with_backup_succeeds():
    c = MultiMethod(owner=ALICE.pub_key, backup=BOB.pub_key)
    c.spend_with_backup(BOB.test_sig)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "MultiMethod.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "MultiMethod.runar.py")
