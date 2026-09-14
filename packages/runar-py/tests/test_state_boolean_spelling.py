"""A mutable `boolean` state field is ONE raw byte — 01 or 00.

The compiler spells the type `boolean`. `bool` appears nowhere in any of the
seven frontends, so an artifact's stateFields never carries it; the SDKs that
matched on 'bool' alone were matching a spelling no compiler emits, and every
real boolean field fell through to their push-data default:

    typescript  01           correct
    ruby        01           correct
    go          02 74727565  push-framed ASCII "true" — 3 bytes too long
    java        02 74727565  same
    python      00           right width, ALWAYS false
    zig         00           same
    rust        panic        as_bytes() on a Bool variant

All five are fund-affecting. Go and Java deploy a state tail longer than the one
the script's own reader rebuilds, so hash256(outputs) can never match and the
first spend is impossible. Python and Zig deploy a well-formed tail that says
false whatever the caller passed, so the first call that sets the flag builds a
continuation the covenant rejects. Rust fails closed.

BOOLEAN_SPELLING_GOLDEN is byte-identical across all seven SDKs; every tier
carries the same literal and the same field list. The trailing bigint is
load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a
length error that a lone boolean field would hide.
"""

from runar.sdk.state import serialize_state, deserialize_state
from runar.sdk.types import StateField

FIELDS = [
    StateField(name='count', type='bigint', index=0),
    # The canonical spelling — the only one any compiler emits.
    StateField(name='flag', type='boolean', index=1),
    # The alias. Several tiers accepted only this one; it must keep working.
    StateField(name='alias', type='bool', index=2),
    StateField(name='tail', type='bigint', index=3),
]

# The one wire record every tier must reproduce byte for byte.
BOOLEAN_SPELLING_GOLDEN = (
    '0700000000000000'   # bigint 7, NUM2BIN 8
    '01'                 # boolean true  — 1 raw byte
    '00'                 # bool    false — 1 raw byte
    '0100000000000000'   # bigint 1, NUM2BIN 8
)

FLIPPED_GOLDEN = '0700000000000000' + '00' + '01' + '0100000000000000'


class TestBooleanSpelling:
    def test_cross_sdk_golden_serialize(self):
        assert len(BOOLEAN_SPELLING_GOLDEN) // 2 == 18
        got = serialize_state(
            FIELDS, {'count': 7, 'flag': True, 'alias': False, 'tail': 1}
        )
        assert got == BOOLEAN_SPELLING_GOLDEN

    def test_opposite_polarity(self):
        got = serialize_state(
            FIELDS, {'count': 7, 'flag': False, 'alias': True, 'tail': 1}
        )
        assert got == FLIPPED_GOLDEN

    def test_cross_sdk_golden_deserialize(self):
        back = deserialize_state(FIELDS, BOOLEAN_SPELLING_GOLDEN)
        assert back['count'] == 7
        assert back['flag'] is True
        assert back['alias'] is False
        assert back['tail'] == 1

    def test_flipped_deserialize(self):
        back = deserialize_state(FIELDS, FLIPPED_GOLDEN)
        assert back['flag'] is False
        assert back['alias'] is True

    def test_lone_boolean_field_is_one_byte(self):
        fields = [StateField(name='v', type='boolean', index=0)]
        for value, want in ((True, '01'), (False, '00')):
            assert serialize_state(fields, {'v': value}) == want
            assert deserialize_state(fields, want)['v'] is value
