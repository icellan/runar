import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "OraclePriceFeed.runar.py"))
OraclePriceFeed = contract_mod.OraclePriceFeed

from runar import mock_sig, mock_pub_key


def test_settle():
    c = OraclePriceFeed(
        oracle_pub_key=b'\x00' * 64,
        receiver=mock_pub_key(),
    )
    c.settle(60000, b'\x00' * 64, b'\x00' * 32, mock_sig())


def test_settle_price_too_low_fails():
    c = OraclePriceFeed(
        oracle_pub_key=b'\x00' * 64,
        receiver=mock_pub_key(),
    )
    with pytest.raises(AssertionError):
        c.settle(50000, b'\x00' * 64, b'\x00' * 32, mock_sig())


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "OraclePriceFeed.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "OraclePriceFeed.runar.py")
