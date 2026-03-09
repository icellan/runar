import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "P2PKH.runar.py"))
P2PKH = contract_mod.P2PKH

from runar import hash160, mock_sig, mock_pub_key


def test_unlock():
    pk = mock_pub_key()
    c = P2PKH(pub_key_hash=hash160(pk))
    c.unlock(mock_sig(), pk)


def test_unlock_wrong_key():
    pk = mock_pub_key()
    wrong_pk = b'\x03' + b'\x00' * 32
    c = P2PKH(pub_key_hash=hash160(pk))
    with pytest.raises(AssertionError):
        c.unlock(mock_sig(), wrong_pk)
