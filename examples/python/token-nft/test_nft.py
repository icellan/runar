from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "NFTExample.runar.py"))
SimpleNFT = contract_mod.SimpleNFT

from runar import mock_sig, mock_pub_key


def test_transfer():
    c = SimpleNFT(owner=mock_pub_key(), token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    new_owner = b'\x03' + b'\x01' * 32
    c.transfer(mock_sig(), new_owner, 546)
    assert len(c._outputs) == 1


def test_burn():
    c = SimpleNFT(owner=mock_pub_key(), token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c.burn(mock_sig())
    assert len(c._outputs) == 0
