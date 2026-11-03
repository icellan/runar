"""F-035: RabinPubKey / RabinSig state fields are a bare 8-byte OP_NUM2BIN word,
exactly like bigint.

Both are bigint aliases and every compiler writes and reads them that way in
the state section (the compiler is canonical, user decision D2). The SDK width
table omitted both, so they fell to the push-data branch, where an int is not a
str and became '' -- OP_0, the value silently lost.

RABIN_STATE_GOLDEN is hand-derived and byte-identical across all seven SDKs
(the same three values are the `state-rabin` sdk-output fixture):

    RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
    RabinSig    -1000000007        -> 07ca9a3b00000080
    bigint      3                  -> 0300000000000000

Proves: the Python codec writes and reads that layout. Does not prove the
script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).
"""

import pytest

from runar.sdk.state import serialize_state, deserialize_state
from runar.sdk.types import StateField

RABIN_STATE_GOLDEN = 'efcdab9078563412' + '07ca9a3b00000080' + '0300000000000000'

FIELDS = [
    StateField(name='oracleKey', type='RabinPubKey', index=0),
    StateField(name='lastSig', type='RabinSig', index=1),
    StateField(name='count', type='bigint', index=2),
]

VALUES = {'oracleKey': 0x1234567890ABCDEF, 'lastSig': -1000000007, 'count': 3}


class TestRabinStateWidth:
    def test_serialize_as_num2bin8(self):
        assert serialize_state(FIELDS, VALUES) == RABIN_STATE_GOLDEN

    def test_deserialize(self):
        assert deserialize_state(FIELDS, RABIN_STATE_GOLDEN) == VALUES

    def test_out_of_range_refused(self):
        with pytest.raises(ValueError, match='does not fit'):
            serialize_state([StateField(name='k', type='RabinPubKey', index=0)], {'k': 1 << 63})
