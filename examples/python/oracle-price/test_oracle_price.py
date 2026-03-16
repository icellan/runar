import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "OraclePriceFeed.runar.py"))
OraclePriceFeed = contract_mod.OraclePriceFeed

from runar import ALICE

# Rabin test keypair (same primes as TypeScript rabin.ts)
# p = 1361129467683753853853498429727072846227 (130-bit, 3 mod 4)
# q = 1361129467683753853853498429727082846007 (130-bit, 3 mod 4)
# n = p * q
_RABIN_N_BYTES = bytes.fromhex('950b36f00000000000000000000000002863620200000000000000000000000010')

# Pre-computed Rabin signature for price=60000 (num2bin(60000,8) = 60ea000000000000)
# Equation: (sig^2 + padding) mod n == SHA256(msg) mod n
_RABIN_SIG_60000 = bytes.fromhex('35f75f63384cae3c1f874e64d0d4692ea1cb595df52fe14930745c43e16f6eb001')
_RABIN_PAD_60000 = bytes.fromhex('040000000000000000000000000000000000000000000000000000000000000000')


def test_settle():
    c = OraclePriceFeed(
        oracle_pub_key=_RABIN_N_BYTES,
        receiver=ALICE.pub_key,
    )
    c.settle(60000, _RABIN_SIG_60000, _RABIN_PAD_60000, ALICE.test_sig)


def test_settle_price_too_low_fails():
    c = OraclePriceFeed(
        oracle_pub_key=_RABIN_N_BYTES,
        receiver=ALICE.pub_key,
    )
    with pytest.raises(AssertionError):
        # Even with valid Rabin sig for 60000, the price arg 50000 fails the threshold
        c.settle(50000, _RABIN_SIG_60000, _RABIN_PAD_60000, ALICE.test_sig)


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "OraclePriceFeed.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "OraclePriceFeed.runar.py")
