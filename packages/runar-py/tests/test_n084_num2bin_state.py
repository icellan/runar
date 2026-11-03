"""N-084: the num2bin state encode path fails closed.

``_encode_state_value`` wrote ``None`` as 0 and ``int()``-coerced floats
(1.5 -> 1) and bools (True -> 1) for int / bigint / RabinSig / RabinPubKey
state fields, so a value that is not an integer was committed on chain as a
number the caller never supplied.

Proves: ``serialize_state`` raises ``ValueError`` naming the field and type for
None, bool, float, bytes, '', a hex string and a non-decimal string in each of
the four num2bin types, and valid integers / decimal integer strings keep
their exact bytes. Does not prove anything on chain, nor the other six SDKs.
"""

import pytest

from runar.sdk.state import serialize_state
from runar.sdk.types import StateField

TYPES = ['int', 'bigint', 'RabinSig', 'RabinPubKey']


@pytest.mark.parametrize('field_type', TYPES)
@pytest.mark.parametrize('bad', [None, True, 1.5, 2.0, b'\x01\x02', '', 'deadbeef', '0x10', 'abc', [1]],
                         ids=repr)
def test_refuses_non_integer(field_type, bad):
    fields = [StateField(name='k', type=field_type, index=0)]
    with pytest.raises(ValueError, match=rf"state field 'k' \({field_type}\) must be an integer"):
        serialize_state(fields, {'k': bad})


@pytest.mark.parametrize('field_type', TYPES)
def test_valid_integers_unchanged(field_type):
    fields = [StateField(name='k', type=field_type, index=0)]
    for v, want in [(0, '0000000000000000'), (5, '0500000000000000'),
                    (-5, '0500000000000080'), ('5', '0500000000000000'),
                    ('5n', '0500000000000000'), ('-5n', '0500000000000080')]:
        assert serialize_state(fields, {'k': v}) == want
