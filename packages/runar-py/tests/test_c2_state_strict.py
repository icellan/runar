"""C2 — ``deserialize_state`` failed OPEN.

The state blob is read back out of a deployed locking script's OP_RETURN tail
(``RunarContract.from_utxo`` -> ``extract_state_from_script`` ->
``deserialize_state``). That script is something any third party can
construct, so the blob is untrusted input — and the caller then builds and
SIGNS a continuation output committing to whatever state came back.

Every arm of the Python decoder returned a DEFAULT on a short blob and
advanced the nominal width anyway, desynchronising every later field, and
``deserialize_state`` had no trailing-byte check at all. Measured before the
fix, ``python3`` exit 0::

    2a00000000000000                  a,b bigint    -> {'a': 42, 'b': 0}
    2a.. + 01.. + deadbeef            a,b bigint    -> {'a': 42, 'b': 1}
    4b aaaaaa                         m ByteString  -> {'m': 'aaaaaa'}
    aa x10                            k PubKey      -> {'k': ''}
    55                                m ByteString  -> {'m': ''}

The semantics here are TypeScript's (C28, ``packages/runar-sdk/src/state.ts``,
test ``c28-state-strict.test.ts``): refuse rather than default, and refuse
trailing bytes. All seven SDKs read the SAME wire format, so the triggering
conditions must be identical even though each tier raises its own error type.
"""

import pytest

from runar.sdk.state import (
    deserialize_state,
    extract_state_from_script,
    serialize_state,
)
from runar.sdk.types import RunarArtifact, StateField


def F(name: str, type_: str, index: int) -> StateField:
    return StateField(name=name, type=type_, index=index)


TWO_INTS = [F('a', 'bigint', 0), F('b', 'bigint', 1)]
BYTESTR = [F('blob', 'ByteString', 0)]
PUBKEY = [F('k', 'PubKey', 0)]

# Every fixed-width type and its declared width in bytes.
FIXED_WIDTHS = [
    ('boolean', 1), ('bool', 1), ('bigint', 8), ('int', 8),
    ('PubKey', 33), ('Addr', 20), ('Ripemd160', 20), ('Sha256', 32),
    ('Point', 64), ('P256Point', 64), ('P384Point', 96),
]


# ---------------------------------------------------------------------------
# The five hostile blobs from the finding, verbatim.
# ---------------------------------------------------------------------------

class TestHostileBlobs:
    def test_truncated_trailing_bigint(self):
        with pytest.raises(ValueError, match='(?i)truncat'):
            deserialize_state(TWO_INTS, '2a00000000000000')

    def test_trailing_bytes(self):
        with pytest.raises(ValueError, match='(?i)trailing'):
            deserialize_state(TWO_INTS, '2a000000000000000100000000000000deadbeef')

    def test_push_payload_runs_past_the_end(self):
        with pytest.raises(ValueError, match='(?i)truncat'):
            deserialize_state(BYTESTR, '4baaaaaa')

    def test_short_pubkey(self):
        with pytest.raises(ValueError, match='(?i)truncat'):
            deserialize_state(PUBKEY, 'aa' * 10)

    def test_non_push_opcode(self):
        with pytest.raises(ValueError, match='is not a push opcode'):
            deserialize_state(BYTESTR, '55')


# ---------------------------------------------------------------------------
# Truncation, exhaustively
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('type_,width', FIXED_WIDTHS)
def test_every_fixed_width_arm_refuses_a_short_blob(type_, width):
    with pytest.raises(ValueError):
        deserialize_state([F('v', type_, 0)], 'aa' * (width - 1))


@pytest.mark.parametrize('blob', [
    '4c',            # OP_PUSHDATA1, no length byte
    '4c05aabb',      # OP_PUSHDATA1 declares 5 bytes, 2 supplied
    '4d',            # OP_PUSHDATA2, no length bytes
    '4d00',          # half a length
    '4d0500aabb',    # declares 5, 2 supplied
    '4e',            # OP_PUSHDATA4, no length bytes
    '4e05000000',    # declares 5, none supplied
    '05aabb',        # direct push declares 5, 2 supplied
])
def test_push_framing_is_bounds_checked(blob):
    with pytest.raises(ValueError):
        deserialize_state(BYTESTR, blob)


def test_missing_push_opcode_byte_entirely():
    fields = [F('n', 'bigint', 0), F('blob', 'ByteString', 1)]
    full = serialize_state(fields, {'n': 1, 'blob': 'aa'})
    with pytest.raises(ValueError, match='(?i)truncat'):
        deserialize_state(fields, full[:16])


def test_truncated_fixed_array_element():
    fields = [StateField(
        name='board', type='FixedArray<bigint, 3>', index=0,
        fixed_array={'syntheticNames': ['board__0', 'board__1', 'board__2'],
                     'elementType': 'bigint', 'length': 3},
    )]
    full = serialize_state(fields, {'board': [1, 2, 3]})
    assert len(full) == 48
    with pytest.raises(ValueError):
        deserialize_state(fields, full[:40])


def test_odd_length_blob():
    with pytest.raises(ValueError):
        deserialize_state([F('count', 'bigint', 0)], '00112233445566778')


# ---------------------------------------------------------------------------
# Overlong tails
# ---------------------------------------------------------------------------

def test_one_unexpected_trailing_byte():
    full = serialize_state([F('a', 'bigint', 0)], {'a': 42})
    with pytest.raises(ValueError, match='(?i)trailing'):
        deserialize_state([F('a', 'bigint', 0)], full + 'ff')


def test_trailing_byte_after_a_variable_length_field():
    full = serialize_state(BYTESTR, {'blob': 'aabbcc'})
    with pytest.raises(ValueError, match='(?i)trailing'):
        deserialize_state(BYTESTR, full + '00')


def test_a_whole_extra_field():
    full = serialize_state(TWO_INTS, {'a': 1, 'b': 2})
    with pytest.raises(ValueError, match='(?i)trailing'):
        deserialize_state([F('a', 'bigint', 0)], full)


def test_extract_state_from_script_surfaces_a_corrupted_continuation():
    fields = [F('count', 'bigint', 0)]
    artifact = RunarArtifact(state_fields=fields)
    state_hex = serialize_state(fields, {'count': 5})
    with pytest.raises(ValueError, match='(?i)trailing'):
        extract_state_from_script(artifact, '51' + '6a' + state_hex + 'ff')


# ---------------------------------------------------------------------------
# CONTROLS — a guard that rejects legitimate state is just as broken.
# ---------------------------------------------------------------------------

class TestControls:
    def test_mixed_type_record_round_trips_exactly(self):
        fields = [
            F('count', 'bigint', 0),
            F('active', 'boolean', 1),
            F('owner', 'PubKey', 2),
            F('blob', 'ByteString', 3),
        ]
        values = {'count': -9, 'active': True, 'owner': 'cd' * 33, 'blob': 'deadbeef'}
        assert deserialize_state(fields, serialize_state(fields, values)) == values

    def test_one_byte_bytestring_in_the_op_n_value_range(self):
        hex_ = serialize_state(BYTESTR, {'blob': '05'})
        # <len><data>, the compiler's on-chain state codec — NOT the
        # MINIMALDATA opcode form ('55'), which the contract cannot read.
        assert hex_ == '0105'
        assert deserialize_state(BYTESTR, hex_) == {'blob': '05'}

    def test_empty_bytestring(self):
        hex_ = serialize_state(BYTESTR, {'blob': ''})
        assert deserialize_state(BYTESTR, hex_) == {'blob': ''}

    def test_empty_field_list_and_empty_blob(self):
        assert deserialize_state([], '') == {}

    def test_maximal_direct_push(self):
        payload = 'ab' * 75
        assert deserialize_state(BYTESTR, serialize_state(BYTESTR, {'blob': payload})) == {'blob': payload}

    def test_pushdata1_framed_payload(self):
        payload = 'ab' * 76
        hex_ = serialize_state(BYTESTR, {'blob': payload})
        assert hex_.startswith('4c4c')
        assert deserialize_state(BYTESTR, hex_) == {'blob': payload}

    @pytest.mark.parametrize('type_,width', [
        ('PubKey', 33), ('Addr', 20), ('Ripemd160', 20), ('Sha256', 32),
        ('Point', 64), ('P256Point', 64), ('P384Point', 96),
    ])
    def test_every_fixed_width_type_at_its_exact_width(self, type_, width):
        payload = '7e' * width
        assert deserialize_state([F('v', type_, 0)], payload) == {'v': payload}

    def test_fixed_array_round_trips(self):
        fields = [StateField(
            name='board', type='FixedArray<bigint, 3>', index=0,
            fixed_array={'syntheticNames': ['board__0', 'board__1', 'board__2'],
                         'elementType': 'bigint', 'length': 3},
        )]
        assert deserialize_state(fields, serialize_state(fields, {'board': [1, 2, 3]})) == {'board': [1, 2, 3]}

    def test_a_legitimate_continuation_still_restores(self):
        fields = [F('count', 'bigint', 0)]
        artifact = RunarArtifact(state_fields=fields)
        state_hex = serialize_state(fields, {'count': 5})
        assert extract_state_from_script(artifact, '51' + '6a' + state_hex) == {'count': 5}


# ---------------------------------------------------------------------------
# Null value for a raw fixed-width field — the four-way byte divergence.
#
# Python wrote '' (zero bytes for a field the artifact declares N bytes wide),
# Go '<nil>', Java 'null', TS 'undefined'. None is valid hex; all four deploy a
# corrupt state section, just differently. Refusing is the only answer that is
# the same everywhere.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('type_', [
    'PubKey', 'Addr', 'Ripemd160', 'Sha256', 'Point', 'P256Point', 'P384Point',
])
def test_serializing_a_missing_raw_fixed_width_value_is_refused(type_):
    with pytest.raises(ValueError, match='(?i)no value'):
        serialize_state([F('v', type_, 0)], {})
