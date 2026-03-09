"""Tests for BigInt values from JSON artifacts without a custom reviver.

The compiler serializes BigInt values as strings with "n" suffix (e.g. "0n",
"1000n") using a custom JSON replacer.  When artifacts are loaded via standard
JSON parsing, these remain as plain strings.  Python's int("0n") raises
ValueError, so the SDK must strip the suffix before converting.
"""

import pytest
from runar.sdk.types import (
    RunarArtifact, Abi, AbiParam, AbiMethod, StateField,
)
from runar.sdk.contract import RunarContract
from runar.sdk.state import serialize_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stateful_artifact(
    state_fields: list[StateField],
    ctor_params: list[AbiParam] | None = None,
) -> RunarArtifact:
    """Build a minimal stateful artifact for testing."""
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='Test',
        abi=Abi(
            constructor_params=ctor_params or [],
            methods=[AbiMethod(name='increment', params=[], is_public=True)],
        ),
        script='51',  # OP_TRUE
        state_fields=state_fields,
    )


# ---------------------------------------------------------------------------
# Constructor state initialization from initialValue
# ---------------------------------------------------------------------------

class TestConstructorRevivesBigIntStrings:
    def test_revives_zero_n(self):
        """Constructor correctly revives "0n" initial_value from JSON."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='count', type='bigint', index=0, initial_value='0n')],
        )
        contract = RunarContract(artifact, [])
        assert contract.get_state()['count'] == 0

    def test_revives_1000n(self):
        """Constructor correctly revives "1000n" initial_value from JSON."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='amount', type='bigint', index=0, initial_value='1000n')],
        )
        contract = RunarContract(artifact, [])
        assert contract.get_state()['amount'] == 1000

    def test_revives_negative_n(self):
        """Constructor correctly revives "-42n" initial_value from JSON."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='offset', type='bigint', index=0, initial_value='-42n')],
        )
        contract = RunarContract(artifact, [])
        assert contract.get_state()['offset'] == -42

    def test_revives_int_type(self):
        """Constructor revives "5n" for type 'int' as well."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='val', type='int', index=0, initial_value='5n')],
        )
        contract = RunarContract(artifact, [])
        assert contract.get_state()['val'] == 5

    def test_plain_int_initial_value_passthrough(self):
        """Constructor handles a plain int initial_value (already correct type)."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='count', type='bigint', index=0, initial_value=42)],
        )
        contract = RunarContract(artifact, [])
        assert contract.get_state()['count'] == 42

    def test_no_initial_value_uses_constructor_arg(self):
        """Without initial_value, state comes from constructor args."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='count', type='bigint', index=0)],
            ctor_params=[AbiParam(name='count', type='bigint')],
        )
        contract = RunarContract(artifact, [99])
        assert contract.get_state()['count'] == 99


# ---------------------------------------------------------------------------
# State serialization defensive handling
# ---------------------------------------------------------------------------

class TestSerializeStateBigIntStrings:
    def test_serialize_zero_n(self):
        """serialize_state handles "0n" string values defensively."""
        fields = [StateField(name='count', type='bigint', index=0)]
        hex_out = serialize_state(fields, {'count': '0n'})
        assert hex_out == '0000000000000000'

    def test_serialize_1000n(self):
        """serialize_state handles "1000n" string values defensively."""
        fields = [StateField(name='count', type='bigint', index=0)]
        hex_from_str = serialize_state(fields, {'count': '1000n'})
        hex_from_int = serialize_state(fields, {'count': 1000})
        assert hex_from_str == hex_from_int

    def test_serialize_negative_n(self):
        """serialize_state handles "-42n" string values defensively."""
        fields = [StateField(name='val', type='bigint', index=0)]
        hex_from_str = serialize_state(fields, {'val': '-42n'})
        hex_from_int = serialize_state(fields, {'val': -42})
        assert hex_from_str == hex_from_int

    def test_serialize_int_type(self):
        """serialize_state handles "7n" for type 'int'."""
        fields = [StateField(name='val', type='int', index=0)]
        hex_from_str = serialize_state(fields, {'val': '7n'})
        hex_from_int = serialize_state(fields, {'val': 7})
        assert hex_from_str == hex_from_int


# ---------------------------------------------------------------------------
# End-to-end: get_locking_script with "0n" initial values
# ---------------------------------------------------------------------------

class TestEndToEndLockingScript:
    def test_get_locking_script_with_zero_n_initial_value(self):
        """get_locking_script works with "0n" initial_values from JSON."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='count', type='bigint', index=0, initial_value='0n')],
        )
        contract = RunarContract(artifact, [])
        script = contract.get_locking_script()
        # Should be valid hex, no crash
        assert all(c in '0123456789abcdef' for c in script)
        # Should contain OP_RETURN separator
        assert '6a' in script

    def test_get_locking_script_with_1000n_initial_value(self):
        """get_locking_script works with "1000n" initial_values from JSON."""
        artifact = _make_stateful_artifact(
            state_fields=[StateField(name='amount', type='bigint', index=0, initial_value='1000n')],
        )
        contract = RunarContract(artifact, [])
        script = contract.get_locking_script()
        assert all(c in '0123456789abcdef' for c in script)
        assert '6a' in script


# ---------------------------------------------------------------------------
# from_dict round-trip
# ---------------------------------------------------------------------------

class TestFromDictInitialValue:
    def test_from_dict_parses_initial_value(self):
        """RunarArtifact.from_dict correctly reads initialValue from JSON."""
        raw = {
            'version': 'runar-v0.1.0',
            'contractName': 'Counter',
            'abi': {'constructor': {'params': []}, 'methods': []},
            'script': '51',
            'stateFields': [
                {'name': 'count', 'type': 'bigint', 'index': 0, 'initialValue': '0n'},
            ],
        }
        artifact = RunarArtifact.from_dict(raw)
        assert artifact.state_fields[0].initial_value == '0n'

        # And using it in a contract should work
        contract = RunarContract(artifact, [])
        assert contract.get_state()['count'] == 0

    def test_from_dict_missing_initial_value(self):
        """RunarArtifact.from_dict sets initial_value to None when absent."""
        raw = {
            'version': 'runar-v0.1.0',
            'contractName': 'Counter',
            'abi': {'constructor': {'params': [{'name': 'count', 'type': 'bigint'}]}, 'methods': []},
            'script': '51',
            'stateFields': [
                {'name': 'count', 'type': 'bigint', 'index': 0},
            ],
        }
        artifact = RunarArtifact.from_dict(raw)
        assert artifact.state_fields[0].initial_value is None
