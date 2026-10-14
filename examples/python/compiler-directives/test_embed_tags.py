import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "EmbedTags.runar.py"))
EmbedTags = contract_mod.EmbedTags

from runar import hash160, ALICE, BOB


def _make():
    return EmbedTags(pub_key_hash=hash160(ALICE.pub_key))


def test_tags_default():
    assert _make().tags == [7, 9, 11]


def test_unlock_at_threshold():
    _make().unlock(ALICE.test_sig, ALICE.pub_key, 9)


def test_unlock_below_threshold():
    with pytest.raises(AssertionError):
        _make().unlock(ALICE.test_sig, ALICE.pub_key, 8)


def test_unlock_wrong_key():
    with pytest.raises(AssertionError):
        _make().unlock(BOB.test_sig, BOB.pub_key, 9)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "EmbedTags.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "EmbedTags.runar.py")
