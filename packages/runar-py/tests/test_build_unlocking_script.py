"""Tests for RunarContract.build_unlocking_script — method selector and argument encoding.

Mirrors TestBuildUnlockingScript_* tests from packages/runar-go/sdk_test.go.
"""

import pytest
from runar.sdk.contract import RunarContract
from runar.sdk.types import RunarArtifact, Abi, AbiParam, AbiMethod


def _make_artifact(script: str, methods: list[AbiMethod], ctor_params: list[AbiParam] | None = None) -> RunarArtifact:
    """Helper: build a minimal RunarArtifact with the given ABI."""
    return RunarArtifact(
        version='runar-v0.1.0',
        contract_name='TestContract',
        abi=Abi(
            constructor_params=ctor_params or [],
            methods=methods,
        ),
        script=script,
    )


def _make_contract(script: str, methods: list[AbiMethod], ctor_args: list | None = None) -> RunarContract:
    artifact = _make_artifact(script, methods)
    return RunarContract(artifact, ctor_args or [])


# ---------------------------------------------------------------------------
# Method selector encoding
# ---------------------------------------------------------------------------

class TestBuildUnlockingScriptSelector:
    def test_no_selector_single_method(self):
        """Single public method → no selector prefix appended."""
        contract = _make_contract('51', [
            AbiMethod(name='unlock', params=[AbiParam(name='sig', type='Sig')], is_public=True),
        ])
        sig_hex = '00' * 72
        script = contract.build_unlocking_script('unlock', [sig_hex])
        # Expected: just the pushed sig (72 bytes = 0x48 length prefix + 72 bytes data)
        expected = '48' + sig_hex
        assert script == expected

    def test_selector_index_0(self):
        """First of two public methods → selector 0x00 appended after args."""
        contract = _make_contract('51', [
            AbiMethod(name='release', params=[], is_public=True),
            AbiMethod(name='refund', params=[], is_public=True),
        ])
        script = contract.build_unlocking_script('release', [])
        assert script == '00'

    def test_selector_index_1(self):
        """Second of two public methods → selector 0x51 (OP_1) appended after args."""
        contract = _make_contract('51', [
            AbiMethod(name='release', params=[], is_public=True),
            AbiMethod(name='refund', params=[], is_public=True),
        ])
        script = contract.build_unlocking_script('refund', [])
        assert script == '51'

    def test_skips_private_methods_for_selector(self):
        """Private methods are excluded from the public index count."""
        contract = _make_contract('51', [
            AbiMethod(name='release', params=[], is_public=True),
            AbiMethod(name='_helper', params=[], is_public=False),
            AbiMethod(name='refund', params=[], is_public=True),
        ])
        # 'refund' is public index 1 (private _helper doesn't count)
        script = contract.build_unlocking_script('refund', [])
        assert script == '51'  # OP_1

    def test_three_public_methods_selector_indices(self):
        """Three public methods → selectors 0x00, 0x51 (OP_1), 0x52 (OP_2)."""
        contract = _make_contract('51', [
            AbiMethod(name='a', params=[], is_public=True),
            AbiMethod(name='b', params=[], is_public=True),
            AbiMethod(name='c', params=[], is_public=True),
        ])
        assert contract.build_unlocking_script('a', []) == '00'
        assert contract.build_unlocking_script('b', []) == '51'
        assert contract.build_unlocking_script('c', []) == '52'


# ---------------------------------------------------------------------------
# Argument encoding
# ---------------------------------------------------------------------------

class TestBuildUnlockingScriptArgs:
    def test_bigint_zero(self):
        """bigint 0 encodes as OP_0 = 0x00."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='n', type='bigint')], is_public=True),
        ])
        script = contract.build_unlocking_script('check', [0])
        assert script == '00'

    def test_bigint_small_numbers_op_codes(self):
        """Integers 1–16 encode as OP_1–OP_16 (0x51–0x60)."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='n', type='bigint')], is_public=True),
        ])
        assert contract.build_unlocking_script('check', [1]) == '51'
        assert contract.build_unlocking_script('check', [2]) == '52'
        assert contract.build_unlocking_script('check', [15]) == '5f'
        assert contract.build_unlocking_script('check', [16]) == '60'

    def test_bigint_large(self):
        """1000 encodes as 02e803 (length prefix + little-endian bytes)."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='n', type='bigint')], is_public=True),
        ])
        script = contract.build_unlocking_script('check', [1000])
        assert script == '02e803'

    def test_bigint_negative_one(self):
        """-1 encodes as OP_1NEGATE = 0x4f."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='n', type='bigint')], is_public=True),
        ])
        script = contract.build_unlocking_script('check', [-1])
        assert script == '4f'

    def test_bigint_negative(self):
        """-42 (0x2a, negative → 0x2a | 0x80 = 0xaa) encodes as 01aa."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='n', type='bigint')], is_public=True),
        ])
        script = contract.build_unlocking_script('check', [-42])
        assert script == '01aa'

    def test_hex_string_arg(self):
        """A 20-byte hex string gets a 0x14 length prefix."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='addr', type='Addr')], is_public=True),
        ])
        addr = 'ab' * 20  # 20 bytes
        script = contract.build_unlocking_script('check', [addr])
        assert script == '14' + addr

    def test_bool_true(self):
        """bool True encodes as OP_1 = 0x51."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='flag', type='bool')], is_public=True),
        ])
        assert contract.build_unlocking_script('check', [True]) == '51'

    def test_bool_false(self):
        """bool False encodes as OP_0 = 0x00."""
        contract = _make_contract('51', [
            AbiMethod(name='check', params=[AbiParam(name='flag', type='bool')], is_public=True),
        ])
        assert contract.build_unlocking_script('check', [False]) == '00'

    def test_args_with_selector(self):
        """Args are encoded before the selector when multiple public methods exist."""
        contract = _make_contract('51', [
            AbiMethod(name='release', params=[AbiParam(name='sig', type='Sig')], is_public=True),
            AbiMethod(name='refund', params=[AbiParam(name='sig', type='Sig')], is_public=True),
        ])
        sig_hex = 'ff' * 72
        script = contract.build_unlocking_script('release', [sig_hex])
        # Args come first, selector last; release is index 0 → OP_0 = '00'
        expected_arg = '48' + sig_hex
        expected = expected_arg + '00'
        assert script == expected
