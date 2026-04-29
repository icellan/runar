# PEDAGOGY: intentionally broken pattern — "anyone can spend" once a single
# (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by the
# spender and is not bound to the spending transaction. See the source file
# header for a full explanation. The hybrid pattern lives in
# examples/python/sphincs-wallet/.
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(
    str(Path(__file__).parent / "PostQuantumSLHDSANaiveInsecure.runar.py")
)
PostQuantumSLHDSANaiveInsecure = contract_mod.PostQuantumSLHDSANaiveInsecure

from runar import slh_keygen
from runar.slhdsa_impl import _HAS_SLHDSA

_requires_slhdsa = pytest.mark.skipif(
    not _HAS_SLHDSA, reason="slh-dsa package not installed (pip install slh-dsa)"
)
_slow = pytest.mark.slow

_kp = None


def get_kp():
    global _kp
    if _kp is None:
        _kp = slh_keygen("sha2_128s")
    return _kp


@_slow
@_requires_slhdsa
def test_arbitrary_message_passes_anyone_can_spend():
    """Demonstrate the flaw: any (msg, sig) pair under the contract's pubkey
    satisfies the spend, with no transaction binding. Whoever holds the
    SLH-DSA key can sign anything — and the contract has no view of the
    transaction, so signatures are not bound to the spend."""
    kp = get_kp()
    c = PostQuantumSLHDSANaiveInsecure(pubkey=kp.pk)

    arbitrary_msg = b"\xde\xad\xbe\xef" + b"\x00" * 60
    sig = kp.sign(arbitrary_msg)

    # Contract accepts it — that's the bug.
    c.spend(arbitrary_msg, sig)


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "PostQuantumSLHDSANaiveInsecure.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "PostQuantumSLHDSANaiveInsecure.runar.py")
