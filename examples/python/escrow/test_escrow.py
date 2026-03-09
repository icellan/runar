from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Escrow.runar.py"))
Escrow = contract_mod.Escrow

from runar import mock_sig, mock_pub_key


def test_release():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.release(mock_sig(), mock_sig())


def test_refund():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.refund(mock_sig(), mock_sig())
