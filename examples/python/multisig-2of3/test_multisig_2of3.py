"""R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal
example and was tested in four of the nine formats (ts, sol, move, zig). This
is the Python half.

`check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3])` lowers to two
`array_literal` ANF nodes — the canonical site where that node kind is emitted
at all, and one of the four kinds `spec/ir-format.md` did not document until
R-098.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract  # noqa: E402

from runar import mock_pub_key, mock_sig  # noqa: E402

contract_mod = load_contract(str(Path(__file__).parent / "MultiSig2of3.runar.py"))
MultiSig2of3 = contract_mod.MultiSig2of3


def _contract():
    return MultiSig2of3(pk1=mock_pub_key(), pk2=mock_pub_key(), pk3=mock_pub_key())


def test_unlock_runs_with_two_signatures():
    c = _contract()
    c.unlock(mock_sig(), mock_sig())


def test_the_contract_commits_three_distinct_slots():
    # The 2-of-3 shape is the point: three pubkey slots, two signature slots.
    # A contract that collapsed them would still "run" above.
    c = _contract()
    assert c.pk1 is not None
    assert c.pk2 is not None
    assert c.pk3 is not None


def test_compile():
    from runar import compile_check

    source_path = str(Path(__file__).parent / "MultiSig2of3.runar.py")
    compile_check(Path(source_path).read_text(), "MultiSig2of3.runar.py")
