"""P256Point (64) and P384Point (96) are FIXED-WIDTH RAW state fields.

All seven compilers emit them as fixed raw slices in the state tail, and
runar-lang's cast constructors hard-assert exactly those widths. The seven SDKs
used to omit both from their width tables, so they fell through to the push-data
default and deployed a state section 1 byte (0x40 direct push) or 2 bytes
(OP_PUSHDATA1 0x60) longer than the script's own on-chain reader expects. The
deploy succeeded and the FIRST spend failed with "OP_NUMEQUALVERIFY requires the
top stack item to be truthy" — funds locked.

CROSS_SDK_GOLDEN is byte-identical across all seven SDKs; every tier carries the
same literal and the same field list.
"""

from runar.sdk.state import serialize_state, deserialize_state
from runar.sdk.types import StateField

FIELDS = [
    StateField(name='n', type='bigint', index=0),
    StateField(name='flag', type='bool', index=1),
    StateField(name='pk', type='PubKey', index=2),
    StateField(name='h', type='Sha256', index=3),
    StateField(name='ad', type='Addr', index=4),
    StateField(name='pt', type='Point', index=5),
    StateField(name='p256', type='P256Point', index=6),
    StateField(name='p384', type='P384Point', index=7),
    StateField(name='sig', type='Sig', index=8),
    StateField(name='rab', type='RabinSig', index=9),
    StateField(name='bs', type='ByteString', index=10),
]

VALUES = {
    'n': 1,
    'flag': True,
    'pk': '02' + 'aa' * 32,
    'h': 'bb' * 32,
    'ad': 'cc' * 20,
    'pt': 'dd' * 64,
    'p256': '11' * 64,
    'p384': '22' * 96,
    'sig': '3044' + 'ee' * 66,
    'rab': 'ff' * 8,
    'bs': '0011',
}

# The one wire record every tier must reproduce byte for byte.
CROSS_SDK_GOLDEN = (
    '0100000000000000'      # bigint 1, NUM2BIN 8
    '01'                    # bool true
    + '02' + 'aa' * 32      # PubKey    33 raw
    + 'bb' * 32             # Sha256    32 raw
    + 'cc' * 20             # Addr      20 raw
    + 'dd' * 64             # Point     64 raw
    + '11' * 64             # P256Point 64 raw   <- was framed "40" + 64
    + '22' * 96             # P384Point 96 raw   <- was framed "4c60" + 96
    + '44' + '3044' + 'ee' * 66   # Sig        framed <len><data>
    + '08' + 'ff' * 8             # RabinSig   framed <len><data>
    + '02' + '0011'               # ByteString framed <len><data>
)


class TestCurvePointStateWidth:
    def test_cross_sdk_golden_serialize(self):
        assert len(CROSS_SDK_GOLDEN) // 2 == 399
        assert serialize_state(FIELDS, VALUES) == CROSS_SDK_GOLDEN

    def test_cross_sdk_golden_deserialize(self):
        back = deserialize_state(FIELDS, CROSS_SDK_GOLDEN)
        assert back['n'] == 1
        assert back['flag'] is True
        for k in ('pk', 'h', 'ad', 'pt', 'p256', 'p384', 'sig', 'rab', 'bs'):
            assert back[k] == VALUES[k], k

    def test_lone_curve_point_round_trip(self):
        for field_type, size, fill in (('P256Point', 64, '11'), ('P384Point', 96, '22')):
            fields = [StateField(name='v', type=field_type, index=0)]
            v = fill * size
            hex_str = serialize_state(fields, {'v': v})
            assert hex_str == v, field_type
            assert len(hex_str) // 2 == size, field_type
            assert deserialize_state(fields, hex_str)['v'] == v, field_type

    def test_controls_unchanged(self):
        for field_type, size in (('Point', 64), ('PubKey', 33), ('Sha256', 32)):
            v = 'ab' * size
            got = serialize_state([StateField(name='v', type=field_type, index=0)], {'v': v})
            assert got == v, field_type
        for field_type in ('ByteString', 'Sig', 'RabinSig'):
            v = 'ab' * 64
            got = serialize_state([StateField(name='v', type=field_type, index=0)], {'v': v})
            assert got == '40' + v, field_type
