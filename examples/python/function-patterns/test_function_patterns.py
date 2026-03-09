import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "FunctionPatterns.runar.py"))
FunctionPatterns = contract_mod.FunctionPatterns

from runar import mock_sig, mock_pub_key


def test_deposit():
    c = FunctionPatterns(owner=mock_pub_key(), balance=1000)
    c.deposit(mock_sig(), 500)
    assert c.balance == 1500


def test_withdraw():
    c = FunctionPatterns(owner=mock_pub_key(), balance=10000)
    # 100 bps = 1% fee on 1000 = 10
    c.withdraw(mock_sig(), 1000, 100)
    assert c.balance == 8990


def test_scale():
    c = FunctionPatterns(owner=mock_pub_key(), balance=100)
    c.scale(mock_sig(), 3, 2)
    assert c.balance == 150


def test_normalize():
    c = FunctionPatterns(owner=mock_pub_key(), balance=157)
    c.normalize(mock_sig(), 0, 200, 10)
    assert c.balance == 150
