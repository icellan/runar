import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "MessageBoard.runar.py"))
MessageBoard = contract_mod.MessageBoard

from runar import ALICE, BOB


def test_post():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    b.post(b"hello")
    assert b.message == b"hello"


def test_post_multiple():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    b.post(b"first")
    b.post(b"second")
    assert b.message == b"second"


def test_burn():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    b.burn(ALICE.test_sig)


def test_burn_wrong_key_fails():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    with pytest.raises(AssertionError):
        b.burn(BOB.test_sig)


def test_owner_unchanged_after_post():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    original_owner = b.owner
    b.post(b"test")
    assert b.owner == original_owner


def test_empty_initial_message():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    assert b.message == b""


def test_post_to_empty():
    b = MessageBoard(message=b"", owner=ALICE.pub_key)
    b.post(b"48656c6c6f")
    assert b.message == b"48656c6c6f"


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "MessageBoard.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "MessageBoard.runar.py")
