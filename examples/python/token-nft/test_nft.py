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


def test_transfer_chain():
    """Transfer succeeds for different recipients; each creates one output."""
    owner1 = mock_pub_key()
    owner2 = b'\x03' + b'\x01' * 32
    owner3 = b'\x03' + b'\x02' * 32
    # First transfer: creates output for owner2
    c = SimpleNFT(owner=owner1, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c.transfer(mock_sig(), owner2, 546)
    assert len(c._outputs) == 1
    assert c._outputs[0]['values'][0] == owner2
    # Second transfer from new owner: creates output for owner3
    c2 = SimpleNFT(owner=owner2, token_id=b'\x01' * 16, metadata=b'\x02' * 32)
    c2.transfer(mock_sig(), owner3, 546)
    assert len(c2._outputs) == 1
    assert c2._outputs[0]['values'][0] == owner3


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "NFTExample.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "NFTExample.runar.py")
