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
