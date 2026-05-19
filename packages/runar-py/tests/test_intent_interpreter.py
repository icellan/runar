"""Intent-intrinsics ANF interpreter coverage (Python peer of
``packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts``).

The four shipping intent-covenant intrinsics
(``extractPrevOutputScript``, ``requireOutputP2PKH``,
``currentBlockHeight``, plus ``len``-branching on a read-only intrinsic
value) desugar at ANF-lowering time to existing primitives
(``load_param``, ``hash256``, ``substr``, ``cat``, ``num2bin``,
``extractLocktime``, ``extractOutputHash``, ``bin_op``, ``assert``).

These tests prove the Python ANF interpreter accepts and correctly
executes the four shipping fixtures end-to-end under realistic SIGHASH
mocks, with witness bytes routed in through the new
:meth:`IntentInterpreter.set_prev_out_script` /
:meth:`IntentInterpreter.set_serialised_outputs` channel.

Per-fixture coverage (10 tests total, 1-for-1 with the TS reference):

* intent-prev-output-script:    1 success + 2 failure (wrong hash, empty witness)
* intent-output-p2pkh:          1 success + 2 failure (wrong PKH bytes, wrong hashOutputs)
* intent-current-block-height:  1 success + 1 failure (locktime > deadline)
* branched-readonly-len:        1 then-branch + 1 else-branch (no failure path:
                                both arms succeed; affine-checker smoke test)

Note on error matchers: the Python ANF interpreter raises
:class:`AssertionFailureError` with the generic
``assert failed in <method>: binding '<tNN>' evaluated to false`` shape
(strict-mode parity with the Go / Rust / Zig / Java SDKs), so failure
cases match against that envelope rather than the TS-specific
``extractPrevOutputScript: hash256 mismatch`` strings. Missing-witness
cases use :class:`WitnessBytesMissingError`, whose message string carries
the missing param name so the test can pin the cause.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from runar.sdk.anf_interpreter import (
    IntentInterpreter,
    WitnessBytesMissingError,
)
from runar_compiler.compiler import compile_source_to_ir, _serialize_anf_program


# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path('/Users/siggioskarsson/gitcheckout/runar-review-remediation')
EX = REPO_ROOT / 'examples' / 'ts'


def _compile_anf(rel_path: str) -> dict:
    """Compile a TS source path to an ANF dict via the Python compiler.

    Mirrors ``TestContract.fromSource(...)`` in the TS reference. The
    constant-folding pass is left ON (the compiler's default) so the
    interpreter sees the same shape the SDK consumes in production.
    """
    src_path = EX / rel_path
    program = compile_source_to_ir(str(src_path), disable_constant_folding=False)
    return _serialize_anf_program(program)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _p2pkh_output(amount: int, pkh: bytes) -> bytes:
    """Build a canonical 34-byte P2PKH output:
    8-byte LE amount || 0x19 0x76 0xa9 0x14 || 20-byte pkh || 0x88 0xac.
    """
    assert len(pkh) == 20, 'pkh must be 20 bytes'
    out = bytearray(34)
    a = amount
    for i in range(8):
        out[i] = a & 0xff
        a >>= 8
    out[8:12] = bytes([0x19, 0x76, 0xa9, 0x14])
    out[12:32] = pkh
    out[32:34] = bytes([0x88, 0xac])
    return bytes(out)


# ---------------------------------------------------------------------------
# intent-prev-output-script (3 tests)
# ---------------------------------------------------------------------------

class TestIntentPrevOutputScript:
    """``extractPrevOutputScript(0, expectedHash)`` desugars to a
    ``hash256(_prevOutScript_0) === expectedHash`` strict assert and
    returns the witness ref. Three coverage points: matching witness,
    mismatching witness, and missing witness."""

    PREV_OUT_SCRIPT = bytes.fromhex(
        '76a91400112233445566778899aabbccddeeff0011223388ac'
    )
    EXPECTED_HASH = _hash256(PREV_OUT_SCRIPT)

    @classmethod
    def _make(cls) -> IntentInterpreter:
        anf = _compile_anf('intent-prev-output-script/IntentPrevOutputScript.runar.ts')
        return IntentInterpreter(
            anf,
            initial_state={'expectedHash': cls.EXPECTED_HASH.hex(), 'count': 0},
            constructor_args=[cls.EXPECTED_HASH.hex(), 0],
        )

    def test_success_matching_witness_increments_count(self):
        c = self._make()
        c.set_prev_out_script(0, self.PREV_OUT_SCRIPT)

        r = c.call('bind')

        assert r.success is True, r.error
        assert r.error is None
        # count is mutable; assignment in the method must have taken effect.
        assert c.state['count'] == 1

    def test_failure_witness_mismatches_expected_hash(self):
        c = self._make()
        # Different bytes => different hash256.
        c.set_prev_out_script(0, bytes.fromhex('deadbeef'))

        r = c.call('bind')

        assert r.success is False
        assert r.error is not None
        # Strict-mode shape: the desugared `===` evaluates falsy and the
        # following assert raises AssertionFailureError with the binding
        # name carrying the failed ANF binding.
        assert 'assert failed in bind' in r.error
        # State unchanged on failure.
        assert c.state['count'] == 0

    def test_failure_no_witness_supplied_raises_explicit_error(self):
        c = self._make()
        # Intentionally omit set_prev_out_script. The interpreter must
        # raise the typed witness-missing error rather than silently
        # passing or producing a hash256 of None.

        r = c.call('bind')

        assert r.success is False
        assert r.error is not None
        assert '_prevOutScript_0' in r.error
        assert 'witness' in r.error
        assert c.state['count'] == 0


# ---------------------------------------------------------------------------
# intent-output-p2pkh (3 tests)
# ---------------------------------------------------------------------------

class TestIntentOutputP2PKH:
    """``requireOutputP2PKH(0, bondPKH, bondAmount)`` desugars to two
    strict asserts: (a) hash256 of the serialised-outputs witness equals
    extractOutputHash(preimage), and (b) the 34-byte slice at offset 0
    equals the canonical P2PKH output bytes. Three coverage points:
    everything matches, P2PKH bytes mismatch, hashOutputs mismatch."""

    BOND_PKH = bytes.fromhex('00112233445566778899aabbccddeeff00112233')
    BOND_AMOUNT = 5000

    @classmethod
    def _make(cls) -> IntentInterpreter:
        anf = _compile_anf('intent-output-p2pkh/IntentOutputP2PKH.runar.ts')
        return IntentInterpreter(
            anf,
            initial_state={
                'bondPKH': cls.BOND_PKH.hex(),
                'bondAmount': cls.BOND_AMOUNT,
                'count': 0,
            },
            constructor_args=[cls.BOND_PKH.hex(), cls.BOND_AMOUNT, 0],
        )

    def test_success_serialised_p2pkh_matches_expected(self):
        serialised = _p2pkh_output(self.BOND_AMOUNT, self.BOND_PKH)
        output_hash = _hash256(serialised)

        c = self._make()
        c.set_serialised_outputs(serialised)
        c.set_mock_preimage_bytes({'outputHash': output_hash})

        r = c.call('payBond')

        assert r.success is True, r.error
        assert r.error is None
        assert c.state['count'] == 1

    def test_failure_wrong_pubkey_hash_in_serialised_outputs(self):
        # Wrong PKH inside the serialised set. hashOutputs must still
        # match the witness so the outer hash assertion passes -- it's
        # the per-output substring comparison we want to trip.
        wrong_pkh = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffff')
        wrong_serialised = _p2pkh_output(self.BOND_AMOUNT, wrong_pkh)
        wrong_output_hash = _hash256(wrong_serialised)

        c = self._make()
        c.set_serialised_outputs(wrong_serialised)
        c.set_mock_preimage_bytes({'outputHash': wrong_output_hash})

        r = c.call('payBond')

        assert r.success is False
        assert r.error is not None
        assert 'assert failed in payBond' in r.error
        assert c.state['count'] == 0

    def test_failure_hashoutputs_preimage_mismatch(self):
        serialised = _p2pkh_output(self.BOND_AMOUNT, self.BOND_PKH)

        c = self._make()
        c.set_serialised_outputs(serialised)
        # Wrong outputHash on the preimage -- desugar's first assert fails.
        c.set_mock_preimage_bytes({'outputHash': bytes(32)})

        r = c.call('payBond')

        assert r.success is False
        assert r.error is not None
        assert 'assert failed in payBond' in r.error
        assert c.state['count'] == 0


# ---------------------------------------------------------------------------
# intent-current-block-height (2 tests)
# ---------------------------------------------------------------------------

class TestIntentCurrentBlockHeight:
    """``currentBlockHeight()`` is pure source sugar for
    ``extractLocktime(this.txPreimage)``. The desugared form pulls the
    mock locktime out of the intent context and the user assert
    enforces it against the contract's deadline property."""

    def test_success_locktime_within_deadline(self):
        anf = _compile_anf(
            'intent-current-block-height/IntentCurrentBlockHeight.runar.ts'
        )
        c = IntentInterpreter(
            anf,
            initial_state={'deadline': 1_000_000, 'count': 0},
            constructor_args=[1_000_000, 0],
        )
        c.set_mock_preimage({'locktime': 500_000})

        r = c.call('spend')

        assert r.success is True, r.error
        assert r.error is None
        assert c.state['count'] == 1

    def test_failure_locktime_exceeds_deadline(self):
        anf = _compile_anf(
            'intent-current-block-height/IntentCurrentBlockHeight.runar.ts'
        )
        c = IntentInterpreter(
            anf,
            initial_state={'deadline': 100, 'count': 0},
            constructor_args=[100, 0],
        )
        c.set_mock_preimage({'locktime': 999_999})

        r = c.call('spend')

        assert r.success is False
        assert r.error is not None
        assert 'assert failed in spend' in r.error
        assert c.state['count'] == 0


# ---------------------------------------------------------------------------
# branched-readonly-len (2 tests; no failure path -- both arms succeed)
# ---------------------------------------------------------------------------

class TestBranchedReadonlyLen:
    """``len(scratch)``-driven if/else with state mutation on both arms.

    The hand-off concern is the section-3 affine checker: branching on a
    ``bigint``-returning intrinsic with state mutations on both arms must
    pass. Both arms succeed end-to-end through the interpreter, with
    the trailing ``addOutput`` recorded on ``r.outputs``."""

    @classmethod
    def _anf(cls) -> dict:
        return _compile_anf('branched-readonly-len/BranchedReadonlyLen.runar.ts')

    def test_then_branch_when_scratch_nonempty(self):
        c = IntentInterpreter(
            self._anf(),
            initial_state={'count': 10, 'tag': '00'},
            constructor_args=[10, '00'],
        )

        r = c.call('spend', {'scratch': 'aabbcc'})

        assert r.success is True, r.error
        assert r.error is None
        assert c.state['count'] == 11
        # tag := scratch (the source uses `this.tag = scratch`).
        assert c.state['tag'] == 'aabbcc'
        # Single addOutput emitted with satoshis 1000.
        assert len(r.outputs) == 1
        assert r.outputs[0]['satoshis'] == 1000

    def test_else_branch_when_scratch_empty(self):
        c = IntentInterpreter(
            self._anf(),
            initial_state={'count': 10, 'tag': 'aa'},
            constructor_args=[10, 'aa'],
        )

        r = c.call('spend', {'scratch': ''})

        assert r.success is True, r.error
        assert r.error is None
        assert c.state['count'] == 9
        # tag := '3030' (compile-time ByteString literal in the source).
        assert c.state['tag'] == '3030'
        assert len(r.outputs) == 1
