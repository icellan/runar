"""Testing-gap remediation Phase A5 (Python tier).

``MockProvider.broadcast`` is fail-CLOSED by default, in TWO layers:

1. **Structural / non-vacuity / value conservation — stdlib only, always on.**
   The payload must parse as a Bitcoin transaction, at least one spent outpoint
   must be known to the provider, and (when every input is known) the outputs
   must not exceed the inputs.
2. **Script execution** — every known input replayed through the upstream
   ``bsv-sdk`` ``Spend`` interpreter with full transaction context.

Two deliberate departures from the TypeScript reference
(``packages/runar-sdk/src/providers/mock.ts``):

1. **No vacuous pass.** TS accepts a transaction none of whose inputs it knows
   — it validates NOTHING and returns valid. Here that is an error.
2. **The optional dependency is handled explicitly, never silently.** Layer 2
   needs ``bsv-sdk``, which ``runar`` does not require at runtime. When it is
   absent the provider records ``script_vm_available: False`` in
   ``last_validation_report`` (so a skipped script check can never be mistaken
   for a passing one), layer 1 still runs, and **in CI (``$CI`` set) the
   provider raises ``BroadcastValidationUnavailable``** — CI must never lose
   the script layer. CI already installs it for this package
   (``.github/workflows/ci.yml``: ``pip install pytest slh-dsa bsv-sdk``), and
   ``pyproject.toml``'s ``dev`` extra now declares it.

   Consequence to state plainly: **outside CI, Python fund-path script
   validation is conditional on an optional dependency.** Layer 1 is
   unconditional; layer 2 is not.
"""

import pytest

from runar.sdk.errors import BroadcastRejected
from runar.sdk.provider import MockProvider, _bsv_sdk_available
from runar.sdk.types import Utxo

# The structural / non-vacuity / value-conservation layer is stdlib-only and
# ALWAYS runs — those tests are unconditional below. Only the SCRIPT-EXECUTION
# layer needs the optional bsv-sdk dependency.
#
# In CI its absence is a hard error (the provider raises
# BroadcastValidationUnavailable when $CI is set), because CI must never lose
# the script layer silently. Locally the script-layer tests skip with a loud
# reason and the report records `script_vm_available: False`, so the
# degradation is visible rather than reported as validated. This matches the
# precedent the ScriptVM tests already set (tests/test_script_vm.py).
BSV_SDK = _bsv_sdk_available()
needs_script_vm = pytest.mark.skipif(
    not BSV_SDK,
    reason=(
        "bsv-sdk not installed: MockProvider's SCRIPT-EXECUTION layer cannot run. "
        "Install with `pip install bsv-sdk` (or `pip install 'runar[dev]'`). "
        "The structural / non-vacuity / value-conservation layer is still "
        "exercised by the unmarked tests in this module, and CI fails hard "
        "rather than skipping."
    ),
)

ANYONE_CAN_SPEND = '51'  # OP_TRUE


def _varint(n: int) -> str:
    if n < 0xFD:
        return f'{n:02x}'
    if n <= 0xFFFF:
        return 'fd' + n.to_bytes(2, 'little').hex()
    if n <= 0xFFFF_FFFF:
        return 'fe' + n.to_bytes(4, 'little').hex()
    return 'ff' + n.to_bytes(8, 'little').hex()


def build_tx(prev_txid: str, outputs, script_sig_hex: str = '') -> str:
    """Serialize a one-input transaction spending ``prev_txid:0``."""
    tx = '01000000'
    tx += '01'
    tx += bytes.fromhex(prev_txid)[::-1].hex()
    tx += '00000000'
    tx += _varint(len(script_sig_hex) // 2) + script_sig_hex
    tx += 'ffffffff'
    tx += _varint(len(outputs))
    for sats, script_hex in outputs:
        tx += int(sats).to_bytes(8, 'little').hex()
        tx += _varint(len(script_hex) // 2) + script_hex
    tx += '00000000'
    return tx


def seed(provider: MockProvider, txid: str, satoshis: int, script: str = ANYONE_CAN_SPEND):
    provider.add_utxo('addr', Utxo(txid=txid, output_index=0, satoshis=satoshis, script=script))


# --- rejection --------------------------------------------------------------

@needs_script_vm
def test_broadcast_rejects_script_invalid_spend():
    p = MockProvider()
    # "00" is OP_0: leaves a falsey top of stack, so the spend must fail.
    seed(p, 'aa' * 32, 10_000, '00')
    with pytest.raises(BroadcastRejected) as exc:
        p.broadcast(build_tx('aa' * 32, [(1_000, ANYONE_CAN_SPEND)]))
    assert 'input 0' in str(exc.value)


def test_broadcast_rejects_underfunded_tx():
    p = MockProvider()
    seed(p, 'bb' * 32, 1_000)
    with pytest.raises(BroadcastRejected, match='underfunded'):
        p.broadcast(build_tx('bb' * 32, [(5_000, ANYONE_CAN_SPEND)]))


def test_broadcast_rejects_vacuous_validation():
    """A gate that validates nothing is worse than no gate.

    This is the TS reference's fail-open hole, deliberately closed here.
    """
    p = MockProvider()
    with pytest.raises(BroadcastRejected, match='NOTHING was checked'):
        p.broadcast(build_tx('cc' * 32, [(1_000, ANYONE_CAN_SPEND)]))


def test_broadcast_rejects_unparseable_payload():
    p = MockProvider()
    with pytest.raises(BroadcastRejected, match='not a parseable Bitcoin transaction'):
        p.broadcast('rawhexdata')


# --- acceptance -------------------------------------------------------------

def test_broadcast_accepts_valid_spend_and_reports_non_vacuity():
    p = MockProvider()
    seed(p, 'dd' * 32, 10_000)
    txid = p.broadcast(build_tx('dd' * 32, [(9_000, ANYONE_CAN_SPEND)]))

    assert len(txid) == 64
    report = p.last_validation_report
    # Layer 1 always runs, with or without bsv-sdk.
    assert report['unknown'] == 0
    assert report['total'] == 1
    assert report['value_conserved'] is True
    assert report['script_vm_available'] is BSV_SDK
    # Layer 2 only when the interpreter is installed — and its absence is
    # REPORTED, never dressed up as a pass.
    assert report['validated'] == (1 if BSV_SDK else 0)
    assert report['unvalidatable'] == 0


def test_broadcast_chains_its_own_outputs():
    p = MockProvider()
    seed(p, 'ee' * 32, 10_000)
    first = p.broadcast(build_tx('ee' * 32, [(9_000, ANYONE_CAN_SPEND)]))
    second = p.broadcast(build_tx(first, [(8_000, ANYONE_CAN_SPEND)]))
    assert len(second) == 64
    assert p.last_validation_report['unknown'] == 0


COUNTER_SRC = '''from runar import StatefulSmartContract, Bigint, public


class Counter(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def inc(self):
        self.count = self.count + 1
'''


@needs_script_vm
def test_broadcast_accepts_real_deploy_and_call():
    """The fund path itself, on a real compiled contract with a real signer."""
    import json  # noqa: PLC0415

    compiler = pytest.importorskip('runar_compiler.compiler')
    from runar.sdk.contract import RunarContract  # noqa: PLC0415
    from runar.sdk.deployment import build_p2pkh_script  # noqa: PLC0415
    from runar.sdk.local_signer import LocalSigner  # noqa: PLC0415
    from runar.sdk.types import DeployOptions, RunarArtifact  # noqa: PLC0415

    result = compiler.compile_from_source_str_with_result(COUNTER_SRC, 'Counter.runar.py')
    errs = [d.message for d in result.diagnostics if d.severity == 'error']
    assert result.artifact is not None, errs
    artifact = RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))

    signer = LocalSigner('00' * 31 + '03')
    p = MockProvider()
    # A REAL P2PKH funding script for this signer. A bogus one
    # ("76a914" + "00"*20 + "88ac") is not spendable by ANY key — the deploy
    # input it produced would be rejected by a node, which the pre-Phase-A5
    # always-ack MockProvider hid.
    p.add_utxo(signer.get_address(), Utxo(
        txid='cc' * 32, output_index=0, satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))

    contract = RunarContract(artifact, [5])
    contract.deploy(p, signer, DeployOptions(satoshis=1_000))
    assert p.last_validated_input_count >= 1, p.last_validation_report

    contract.call('inc', [], p, signer)
    assert len(p.get_broadcasted_txs()) == 2
    # The call's FUNDING input really executed — the gate is not vacuous.
    assert p.last_validated_input_count >= 1, p.last_validation_report

    # PIN on the tier's one carve-out. The call's contract input is a Rúnar
    # OP_PUSH_TX covenant, which bsv-sdk sighashes over a mis-encoded
    # scriptCode (its from_chunks drops the OP_RETURN before the state; see the
    # R2-GAP008 pins in test_gk_gap_008_covenant_carveout.py). It is
    # recorded as UNVALIDATABLE, never as validated. If this assertion ever
    # fails because the count dropped to 0, bsv-sdk was fixed:
    # delete the _COVENANT_PUSHTX_MARKER carve-out in provider.py and validate
    # covenant inputs for real.
    assert p.last_validation_report['unvalidatable'] == 1, (
        'the Rúnar covenant input is now validatable by bsv-sdk — remove the '
        '_COVENANT_PUSHTX_MARKER carve-out in runar/sdk/provider.py'
    )


# --- the governed opt-out ----------------------------------------------------

def test_always_ack_provider_skips_validation():
    p = MockProvider.always_ack()
    assert len(p.broadcast('rawhexdata')) == 64


def test_disable_and_re_enable_broadcast_validation():
    p = MockProvider()
    with pytest.raises(BroadcastRejected):
        p.broadcast('rawhexdata')
    p.disable_broadcast_validation()
    assert len(p.broadcast('rawhexdata')) == 64
    p.enable_broadcast_validation(True)
    with pytest.raises(BroadcastRejected):
        p.broadcast('rawhexdata')
