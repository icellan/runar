import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Directives.runar.py"))
Directives = contract_mod.Directives

from runar import hash160, ALICE, BOB


def _make():
    return Directives(pub_key_hash=hash160(ALICE.pub_key), deploy_tag=b"\x01\x02")


def test_spend_all():
    _make().spend_all(ALICE.test_sig, ALICE.pub_key)


def test_spend_single():
    # @public(sighash=...) leaves the method an ordinary callable natively.
    _make().spend_single(ALICE.test_sig, ALICE.pub_key)


def test_spend_all_wrong_key():
    with pytest.raises(AssertionError):
        _make().spend_all(BOB.test_sig, BOB.pub_key)


def test_spend_single_wrong_key():
    with pytest.raises(AssertionError):
        _make().spend_single(BOB.test_sig, BOB.pub_key)


def test_deploy_tag_is_kept_on_the_instance():
    assert _make().deploy_tag == b"\x01\x02"


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "Directives.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "Directives.runar.py")
