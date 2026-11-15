"""GK-BUG-010: a boolean state field accepts only a real bool.

``_encode_state_value`` wrote ``'01' if value else '00'``, so 1, 'false' and
'00' encoded by Python truthiness, while each peer tier had its own coercion
rule: one non-boolean input gave different on-chain bytes per tier. Every
tier now refuses a non-boolean, as the num2bin arm (N-084) refuses a
non-integer.

Proves: ``serialize_state`` raises ``ValueError`` naming the field and type for
0, 1, 1.0, 'true', 'false', '', '01' and None in both spellings of the type,
and True / False keep 01 / 00. Does not prove anything on chain, nor the other
six SDKs.
"""

import pytest

from runar.sdk.state import serialize_state
from runar.sdk.types import StateField

TYPES = ['bool', 'boolean']


@pytest.mark.parametrize('field_type', TYPES)
@pytest.mark.parametrize('bad', [0, 1, 1.0, 'true', 'false', '', '01', None, b'\x01'], ids=repr)
def test_refuses_non_bool(field_type, bad):
    fields = [StateField(name='flag', type=field_type, index=0)]
    with pytest.raises(ValueError, match=rf"state field 'flag' \({field_type}\) must be a boolean"):
        serialize_state(fields, {'flag': bad})


@pytest.mark.parametrize('field_type', TYPES)
def test_true_false_unchanged(field_type):
    fields = [StateField(name='flag', type=field_type, index=0)]
    assert serialize_state(fields, {'flag': True}) == '01'
    assert serialize_state(fields, {'flag': False}) == '00'
