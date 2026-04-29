# PEDAGOGY: intentionally broken pattern — "anyone can spend" once a single
# (msg, sig) pair under `pubkey` is observed, because `msg` is supplied by the
# spender and is not bound to the spending transaction. See the source file
# header for a full explanation. The hybrid pattern lives in
# examples/python/post-quantum-wallet/.
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(
    str(Path(__file__).parent / "PostQuantumWOTSNaiveInsecure.runar.py")
)
PostQuantumWOTSNaiveInsecure = contract_mod.PostQuantumWOTSNaiveInsecure

from runar import wots_keygen, wots_sign


def setup_contract():
    seed = b"\x42" + b"\x00" * 31
    pub_seed = b"\x01" + b"\x00" * 31
    kp = wots_keygen(seed, pub_seed)
    c = PostQuantumWOTSNaiveInsecure(pubkey=kp.pk)
    return c, kp


def test_arbitrary_message_passes_anyone_can_spend():
    """Demonstrate the flaw: any (msg, sig) pair under the contract's pubkey
    satisfies the spend, with no transaction binding. The 'message' is
    chosen by the spender — i.e. anyone holding (or able to construct) a
    valid signature can spend, regardless of the transaction context."""
    c, kp = setup_contract()

    # Attacker picks an arbitrary message and signs it themselves with the
    # legitimate WOTS+ secret key. In a real attack scenario the attacker
    # would observe a single broadcast spend and replay (msg, sig) — here
    # we simulate that by generating a fresh (msg, sig) under the same key.
    arbitrary_msg = b"\xde\xad\xbe\xef" + b"\x00" * 28
    sig = wots_sign(arbitrary_msg, kp.sk, kp.pub_seed)

    # The contract accepts it — that's the bug.
    c.spend(arbitrary_msg, sig)

    # And a totally different message the attacker chose also works, as long
    # as they can produce a signature for it — which they can, with the key.
    other_msg = b"\xff" * 32
    other_sig = wots_sign(other_msg, kp.sk, kp.pub_seed)
    c.spend(other_msg, other_sig)


def test_invalid_signature_rejected():
    """Sanity check: garbage signature still fails the verifier."""
    c, kp = setup_contract()
    with pytest.raises(AssertionError):
        c.spend(b"\x00" * 32, b"\x00" * len(wots_sign(b"\x00" * 32, kp.sk, kp.pub_seed)))


def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "PostQuantumWOTSNaiveInsecure.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "PostQuantumWOTSNaiveInsecure.runar.py")
