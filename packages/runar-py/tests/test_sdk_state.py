"""Tests for runar.sdk.state — state serialization and deserialization."""

import pytest
from runar.sdk.state import (
    serialize_state, deserialize_state, extract_state_from_script,
    find_last_op_return, encode_push_data, decode_push_data,
    _encode_state_value,
)
from runar.sdk.types import StateField, RunarArtifact, Abi, AbiMethod


def _make_artifact(state_fields: list[StateField], script: str = '51') -> RunarArtifact:
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='Test',
        abi=Abi(constructor_params=[], methods=[]),
        script=script,
        state_fields=state_fields,
    )


# ---------------------------------------------------------------------------
# serialize_state / deserialize_state round-trip
# ---------------------------------------------------------------------------

class TestStateRoundTrip:
    def test_bigint_round_trip(self):
        """Serializing and deserializing a bigint value produces the same integer."""
        fields = [StateField(name='count', type='bigint', index=0)]
        values = {'count': 42}
        hex_out = serialize_state(fields, values)
        result = deserialize_state(fields, hex_out)
        assert result['count'] == 42

    def test_bigint_zero_round_trip(self):
        fields = [StateField(name='val', type='bigint', index=0)]
        hex_out = serialize_state(fields, {'val': 0})
        result = deserialize_state(fields, hex_out)
        assert result['val'] == 0

    def test_bigint_negative_round_trip(self):
        fields = [StateField(name='val', type='bigint', index=0)]
        hex_out = serialize_state(fields, {'val': -999})
        result = deserialize_state(fields, hex_out)
        assert result['val'] == -999

    def test_bool_true_round_trip(self):
        fields = [StateField(name='flag', type='bool', index=0)]
        hex_out = serialize_state(fields, {'flag': True})
        result = deserialize_state(fields, hex_out)
        assert result['flag'] is True

    def test_bool_false_round_trip(self):
        fields = [StateField(name='flag', type='bool', index=0)]
        hex_out = serialize_state(fields, {'flag': False})
        result = deserialize_state(fields, hex_out)
        assert result['flag'] is False

    def test_pubkey_round_trip(self):
        """PubKey (33 bytes) round-trips as raw hex without push-data prefix."""
        fields = [StateField(name='pk', type='PubKey', index=0)]
        pubkey_hex = '02' + 'ab' * 32  # 33 bytes
        hex_out = serialize_state(fields, {'pk': pubkey_hex})
        result = deserialize_state(fields, hex_out)
        assert result['pk'] == pubkey_hex

    def test_multiple_fields_ordered_by_index(self):
        """Fields are serialized in index order regardless of dict insertion order."""
        fields = [
            StateField(name='b', type='bigint', index=1),
            StateField(name='a', type='bigint', index=0),
        ]
        values = {'a': 10, 'b': 20}
        hex_out = serialize_state(fields, values)
        result = deserialize_state(fields, hex_out)
        assert result['a'] == 10
        assert result['b'] == 20

    def test_large_bigint_round_trip(self):
        """A very large bigint (> 32-bit range) serializes and deserializes correctly."""
        fields = [StateField(name='count', type='bigint', index=0)]
        hex_out = serialize_state(fields, {'count': 999999999999})
        result = deserialize_state(fields, hex_out)
        assert result['count'] == 999999999999

    def test_bigint_and_bool_together(self):
        """A state with one bigint and one bool field both round-trip correctly."""
        fields = [
            StateField(name='count', type='bigint', index=0),
            StateField(name='active', type='bool', index=1),
        ]
        values = {'count': 100, 'active': True}
        hex_out = serialize_state(fields, values)
        result = deserialize_state(fields, hex_out)
        assert result['count'] == 100
        assert result['active'] is True

    @pytest.mark.parametrize('value', [0, 1, -1, 127, 128, 255, 256, -128, -256, 1000])
    def test_various_bigints_round_trip(self, value):
        """Multiple bigint values all serialize and deserialize correctly."""
        fields = [StateField(name='v', type='bigint', index=0)]
        hex_out = serialize_state(fields, {'v': value})
        result = deserialize_state(fields, hex_out)
        assert result['v'] == value, f"failed for value {value}"


# ---------------------------------------------------------------------------
# find_last_op_return
# ---------------------------------------------------------------------------

class TestFindLastOpReturn:
    def test_finds_op_return_in_script(self):
        """OP_RETURN (0x6a) at a real opcode boundary is found."""
        # OP_TRUE (0x51) + OP_RETURN (0x6a) + some data
        script = '51' + '6a' + 'deadbeef'
        pos = find_last_op_return(script)
        assert pos == 2  # hex-char offset

    def test_returns_negative_one_when_absent(self):
        """No OP_RETURN in the script returns -1."""
        script = '5151'  # OP_TRUE OP_TRUE
        pos = find_last_op_return(script)
        assert pos == -1

    def test_skips_0x6a_inside_push_data(self):
        """0x6a embedded inside a push data segment should not be mistaken for OP_RETURN."""
        # Push 2 bytes: 0x02 0x6a 0x6a (the pushed data contains 0x6a)
        # Then OP_TRUE
        script = '026a6a' + '51'
        pos = find_last_op_return(script)
        # The 0x6a bytes are inside push data, so no real OP_RETURN
        assert pos == -1


# ---------------------------------------------------------------------------
# extract_state_from_script
# ---------------------------------------------------------------------------

class TestExtractStateFromScript:
    def test_extracts_state_after_op_return(self):
        """State is everything after the last OP_RETURN."""
        fields = [StateField(name='count', type='bigint', index=0)]
        artifact = _make_artifact(fields)

        # Build a script: OP_TRUE + OP_RETURN + serialized state
        state_hex = serialize_state(fields, {'count': 7})
        full_script = '51' + '6a' + state_hex

        result = extract_state_from_script(artifact, full_script)
        assert result is not None
        assert result['count'] == 7

    def test_returns_none_without_state_fields(self):
        artifact = _make_artifact([])
        result = extract_state_from_script(artifact, '516adeadbeef')
        assert result is None

    def test_returns_none_without_op_return(self):
        fields = [StateField(name='count', type='bigint', index=0)]
        artifact = _make_artifact(fields)
        result = extract_state_from_script(artifact, '5151')
        assert result is None


# ---------------------------------------------------------------------------
# encode_push_data / decode_push_data round-trip
# ---------------------------------------------------------------------------

class TestPushDataRoundTrip:
    def test_small_data(self):
        """Data <= 75 bytes uses direct length prefix."""
        data_hex = 'aabbccdd'  # 4 bytes
        encoded = encode_push_data(data_hex)
        decoded, consumed = decode_push_data(encoded, 0)
        assert decoded == data_hex
        assert consumed == len(encoded)

    def test_single_byte(self):
        data_hex = 'ff'
        encoded = encode_push_data(data_hex)
        decoded, _ = decode_push_data(encoded, 0)
        assert decoded == data_hex

    def test_76_bytes_uses_op_pushdata1(self):
        """Data of 76 bytes triggers OP_PUSHDATA1 (0x4c) prefix."""
        data_hex = 'ab' * 76
        encoded = encode_push_data(data_hex)
        # Should start with 0x4c (OP_PUSHDATA1) then length byte
        assert encoded[:2] == '4c'
        decoded, consumed = decode_push_data(encoded, 0)
        assert decoded == data_hex
        assert consumed == len(encoded)

    def test_empty_data(self):
        data_hex = ''
        encoded = encode_push_data(data_hex)
        decoded, consumed = decode_push_data(encoded, 0)
        assert decoded == data_hex


# ---------------------------------------------------------------------------
# MINIMALDATA-correct single-byte push encoding (SCRIPT_VERIFY_MINIMALDATA)
# — for EXECUTED pushes only, i.e. `encode_push_data`, which builds unlocking
# scripts and splices constructor args.
#
# A 1-byte payload in {0x01..0x10, 0x81} must use the minimal opcode
# (OP_1..OP_16 / OP_1NEGATE), not a direct push "01 NN". Byte-identical
# with the other six SDKs.
#
# The STATE serializer is the opposite — see TestStatePushFraming below. The
# state section is raw data after OP_RETURN, never executed, and framed
# <len><data> to match the compiler's on-chain state codec.
#
# 0x00 is deliberately EXCLUDED from that set (C9 / S1): OP_0 pushes the EMPTY
# byte array, not a 1-byte 0x00, so the minimal encoding of a 1-byte 0x00
# payload is the direct push "01 00" — exactly what the compiler's
# `encodePushBytesHex` (packages/runar-compiler/src/passes/push-encoding.ts)
# emits. The SDK previously special-cased 0x00 -> OP_0, which is not the
# inverse of any decoder (a real OP_0 decodes to the empty string, not "00")
# and diverges from the compiler's own byte-for-byte encoding.
# ---------------------------------------------------------------------------

class TestPushDataMinimalData:
    def test_single_zero_byte_is_direct_push_not_op_0(self):
        # NOT '00' (OP_0) — OP_0 pushes [], not [0x00].
        assert encode_push_data('00') == '0100'

    def test_op_1negate(self):
        assert encode_push_data('81') == '4f'

    def test_op_5(self):
        assert encode_push_data('05') == '55'

    def test_op_1_through_16(self):
        for n in range(1, 17):
            assert encode_push_data(f'{n:02x}') == f'{0x50 + n:02x}'

    def test_single_byte_outside_range_still_direct_push(self):
        for b in (0x11, 0x4f, 0x50, 0x60, 0x80, 0x82, 0xff):
            assert encode_push_data(f'{b:02x}') == f'01{b:02x}'

    def test_two_byte_payload_still_direct_push(self):
        assert encode_push_data('0011') == '020011'


# ---------------------------------------------------------------------------
# The state section is framed <len><data>, never MINIMALDATA.
#
# It is raw data after OP_RETURN in the locking script: never executed, never
# MINIMALDATA-checked, and read back by the compiler's on-chain state codec
# (emitPushDataEncode in 05-stack-lower.ts), which understands only
# <len><data>.
#
# #110 applied the MINIMALDATA short-circuit to the state serializer in all
# seven SDKs and none of the seven compilers. A 1-byte 0x05 state field then
# serialised off-chain as "55" while the script rebuilt it as "0105", so the
# continuation hash never matched (unspendable), and a contract DEPLOYED with
# such a value could not be spent at all (the on-chain reader takes 0x55 as a
# length-85 push).
# ---------------------------------------------------------------------------

class TestStatePushFraming:
    fields = [StateField(name='b', type='ByteString', index=0)]

    def _encode(self, payload: str) -> str:
        return serialize_state(self.fields, {'b': payload})

    def test_op_n_range_stays_a_direct_push(self):
        for n in range(1, 17):
            assert self._encode(f'{n:02x}') == f'01{n:02x}'

    def test_0x81_is_not_op_1negate(self):
        assert self._encode('81') == '0181'

    def test_single_zero_byte_is_a_direct_push(self):
        assert self._encode('00') == '0100'

    def test_empty_is_a_zero_length_push(self):
        assert self._encode('') == '00'

    def test_values_outside_the_op_n_range_are_unchanged(self):
        assert self._encode('11') == '0111'
        assert self._encode('0011') == '020011'

    def test_round_trips_for_every_single_byte_value(self):
        for b in range(0x100):
            payload = f'{b:02x}'
            assert deserialize_state(self.fields, self._encode(payload)) == {'b': payload}


# ---------------------------------------------------------------------------
# extract_state_from_script — end-to-end tests
# ---------------------------------------------------------------------------

class TestExtractStateEndToEnd:
    def test_extract_state_finds_last_op_return(self):
        """When a script has a 0x6a inside a push data segment followed by a real OP_RETURN,
        extract_state_from_script reads state from after the real (last) OP_RETURN."""
        fields = [StateField(name='count', type='bigint', index=0)]
        artifact = _make_artifact(fields)

        state_hex = serialize_state(fields, {'count': 42})
        # '016a' = PUSH 1 byte (0x6a) — the 0x6a here is push data, not OP_RETURN
        # '93'   = OP_ADD (filler opcode)
        # '6a'   = real OP_RETURN
        # state_hex = serialized state after the real OP_RETURN
        full_script = '016a' + '93' + '6a' + state_hex

        result = extract_state_from_script(artifact, full_script)
        assert result is not None
        assert result['count'] == 42

    def test_roundtrip_via_extract_state(self):
        """Full end-to-end: serialize state → embed in locking script → extract → verify."""
        fields = [
            StateField(name='count', type='bigint', index=0),
            StateField(name='owner', type='PubKey', index=1),
            StateField(name='active', type='bool', index=2),
        ]
        pubkey_hex = 'ab' * 33  # 33-byte PubKey
        values = {'count': 7, 'owner': pubkey_hex, 'active': True}

        state_hex = serialize_state(fields, values)
        # Build a locking script: OP_TRUE + OP_RETURN + state bytes
        full_script = '51' + '6a' + state_hex

        artifact = _make_artifact(fields, script='51')
        result = extract_state_from_script(artifact, full_script)

        assert result is not None
        assert result['count'] == 7
        assert result['owner'] == pubkey_hex
        assert result['active'] is True


# ---------------------------------------------------------------------------
# encode_state_value — row 370-372, 374
# ---------------------------------------------------------------------------

class TestEncodeStateValue:
    def test_bool_true_encodes_as_01(self):
        """bool true → raw byte '01' (row 370)."""
        result = _encode_state_value(True, 'bool')
        assert result == '01'

    def test_bool_false_encodes_as_00(self):
        """bool false → raw byte '00' (row 371)."""
        result = _encode_state_value(False, 'bool')
        assert result == '00'

    def test_bool_true_via_serialize(self):
        """bool true encodes to '01' when accessed via serialize_state (row 372)."""
        fields = [StateField(name='flag', type='bool', index=0)]
        hex_out = serialize_state(fields, {'flag': True})
        # State hex should start with '01' for true
        assert hex_out == '01'

    def test_bool_false_via_serialize(self):
        """bool false encodes to '00' when accessed via serialize_state."""
        fields = [StateField(name='flag', type='bool', index=0)]
        hex_out = serialize_state(fields, {'flag': False})
        assert hex_out == '00'

    def test_pubkey_encodes_as_raw_hex(self):
        """PubKey encodes as raw hex without any push-data prefix (row 374)."""
        pubkey_hex = '02' + 'ab' * 32  # 33 bytes
        result = _encode_state_value(pubkey_hex, 'PubKey')
        # Should be the raw hex, no push prefix
        assert result == pubkey_hex
        assert len(result) == 66  # 33 bytes * 2 hex chars

    def test_bigint_zero_encodes_to_8_zero_bytes(self):
        """bigint 0 → 8 zero bytes LE (row 369)."""
        result = _encode_state_value(0, 'bigint')
        assert result == '0000000000000000'


# ---------------------------------------------------------------------------
# FixedArray state serialization
# ---------------------------------------------------------------------------

class TestFixedArrayState:
    def test_flat_fixed_array_roundtrip(self):
        """A flat FixedArray state field round-trips as a Python list."""
        fields = [
            StateField(
                name='board',
                type='FixedArray<bigint, 3>',
                index=0,
                fixed_array={
                    'elementType': 'bigint',
                    'length': 3,
                    'syntheticNames': ['board__0', 'board__1', 'board__2'],
                },
            )
        ]
        hex_out = serialize_state(fields, {'board': [1, 2, 3]})
        # Should equal the concatenation of three 8-byte bigints
        assert hex_out == (
            _encode_state_value(1, 'bigint')
            + _encode_state_value(2, 'bigint')
            + _encode_state_value(3, 'bigint')
        )
        result = deserialize_state(fields, hex_out)
        assert result == {'board': [1, 2, 3]}

    def test_flat_fixed_array_scalar_override(self):
        """Underlying scalar names take precedence over the grouped list."""
        fields = [
            StateField(
                name='board',
                type='FixedArray<bigint, 3>',
                index=0,
                fixed_array={
                    'elementType': 'bigint',
                    'length': 3,
                    'syntheticNames': ['board__0', 'board__1', 'board__2'],
                },
            )
        ]
        hex_out = serialize_state(
            fields, {'board': [10, 20, 30], 'board__1': 99}
        )
        expected = (
            _encode_state_value(10, 'bigint')
            + _encode_state_value(99, 'bigint')
            + _encode_state_value(30, 'bigint')
        )
        assert hex_out == expected

    def test_nested_fixed_array_roundtrip(self):
        """A 2D FixedArray state field round-trips as a nested list."""
        fields = [
            StateField(
                name='grid',
                type='FixedArray<FixedArray<bigint, 2>, 2>',
                index=0,
                fixed_array={
                    'elementType': 'FixedArray<bigint, 2>',
                    'length': 2,
                    'syntheticNames': [
                        'grid__0__0', 'grid__0__1',
                        'grid__1__0', 'grid__1__1',
                    ],
                },
            )
        ]
        hex_out = serialize_state(fields, {'grid': [[1, 2], [3, 4]]})
        result = deserialize_state(fields, hex_out)
        assert result == {'grid': [[1, 2], [3, 4]]}

    def test_nested_fixed_array_flat_underlying(self):
        """Nested FixedArray can also be written via flat underlying names."""
        fields = [
            StateField(
                name='grid',
                type='FixedArray<FixedArray<bigint, 2>, 2>',
                index=0,
                fixed_array={
                    'elementType': 'FixedArray<bigint, 2>',
                    'length': 2,
                    'syntheticNames': [
                        'grid__0__0', 'grid__0__1',
                        'grid__1__0', 'grid__1__1',
                    ],
                },
            )
        ]
        hex_out = serialize_state(
            fields,
            {
                'grid__0__0': 5, 'grid__0__1': 6,
                'grid__1__0': 7, 'grid__1__1': 8,
            },
        )
        result = deserialize_state(fields, hex_out)
        assert result == {'grid': [[5, 6], [7, 8]]}


# N-044: the compiler's on-chain state reader and writer frame a ByteString
# with an UNSIGNED length (<len> below 76, 4c <len8>, 4d <len16 LE>,
# 4e <len32 LE>), and the covenant only accepts a continuation whose state
# bytes equal the SDK's. Hand-written expected headers at every boundary where
# a signed reading of the length used to differ (0x80, 0x81.., 0x8000, 0xffff)
# and where PUSHDATA4 starts. The on-chain side is run against the same frames
# by packages/runar-testing/src/__tests__/n044-state-length-sign-spend.
@pytest.mark.parametrize('n,header', [
    (75, '4b'), (76, '4c4c'), (127, '4c7f'), (128, '4c80'), (129, '4c81'),
    (255, '4cff'), (256, '4d0001'), (32767, '4dff7f'), (32768, '4d0080'),
    (65535, '4dffff'), (65536, '4e00000100'),
])
def test_bytestring_pushdata_length_boundaries_match_on_chain_frame(n, header):
    fields = [StateField(name='b', type='ByteString', index=0)]
    payload = 'ab' * n
    encoded = serialize_state(fields, {'b': payload})
    assert encoded == header + payload
    assert deserialize_state(fields, encoded) == {'b': payload}
