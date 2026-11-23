"""reverse_bytes 520-byte bound.

Since D12 BM-F3 every compiler's reverseBytes ends in OP_0 OP_EQUALVERIFY, so
the script ABORTS on an input longer than 520 bytes. The native builtin must
refuse the same input rather than reverse it in full.
"""

import pytest

from runar.builtins import reverse_bytes


@pytest.mark.parametrize('n', [0, 1, 520])
def test_reverses_up_to_520(n):
    src = bytes(i % 256 for i in range(n))
    assert reverse_bytes(src) == src[::-1]


def test_refuses_521():
    with pytest.raises(ValueError, match='520'):
        reverse_bytes(bytes(521))
