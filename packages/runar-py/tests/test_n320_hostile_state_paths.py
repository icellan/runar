"""N-320: the state-reading paths must refuse a hostile script with a typed
error, never raise an untyped exception, hang or fabricate state.

Replays ``conformance/sdk-matches-artifact/hostile-state.json`` — the N-317
hostile scripts of ``hostile.json`` with expected outcomes for
``extract_state_from_script``, ``from_utxo`` and ``from_txid`` (replayed by
all 7 SDKs) — plus ``find_last_op_return`` called directly, which raised
``ValueError`` from ``int(.., 16)`` on a non-hex script.

Proves: for each of the 30 scripts, ``extract_state_from_script`` on the
stateful artifact returns exactly the expected state / ``None`` /
``MalformedScriptError``, and ``from_utxo`` and ``from_txid`` either reconnect
or raise ``MalformedScriptError`` (a ``ValueError`` or any other exception
fails it) — an odd-length, non-hex or non-ASCII script is refused before any
reader runs, and a stateful artifact over a script with no state section is
refused (C10, as in TS) instead of carrying constructor-initial state;
``find_last_op_return`` returns an offset or raises ``MalformedScriptError``;
the replay stays inside a process-CPU budget (``ITIMER_PROF``).
Does NOT prove: on-chain spendability of a reconnected contract; artifact
shapes beyond the fixture's two; the ``ValueError`` ``deserialize_state``
raises on a hex-valid truncated or overlong state section (no case reaches
it).
"""

import json
import pathlib
import signal

from runar.sdk.contract import RunarContract
from runar.sdk.errors import MalformedScriptError
from runar.sdk.provider import MockProvider
from runar.sdk.state import extract_state_from_script, find_last_op_return
from runar.sdk.types import RunarArtifact, TransactionData, TxOutput, Utxo

_DIR = pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-matches-artifact"
FIXTURE = json.loads((_DIR / "hostile.json").read_text(encoding="utf-8"))
STATE_FIXTURE = json.loads((_DIR / "hostile-state.json").read_text(encoding="utf-8"))

CPU_BUDGET_SECS = 20


class _OverBudget(BaseException):
    """BaseException so no ``except Exception`` under test can swallow it."""


def _script(c):
    return c["prefix"] + c.get("repeat", "") * c.get("count", 0) + c.get("suffix", "")


def _outcome(run):
    try:
        return run()
    except MalformedScriptError:
        return "malformed"
    except Exception as e:  # noqa: BLE001 - any other exception is the defect
        return f"error:{type(e).__name__}: {e}"


def _replay():
    artifacts = {k: RunarArtifact.from_dict(v) for k, v in FIXTURE["artifacts"].items()}
    cases = FIXTURE["cases"]
    want = STATE_FIXTURE["cases"]
    assert cases and len(cases) == len(want)
    provider = MockProvider()
    diffs = []
    for i, (c, w) in enumerate(zip(cases, want)):
        assert c["name"] == w["name"]
        script = _script(c)
        txid = f"{i:02x}" * 32
        provider.add_transaction(TransactionData(
            txid=txid, outputs=[TxOutput(satoshis=1000, script=script)]))

        def extract():
            s = extract_state_from_script(artifacts["stateful"], script)
            return None if s is None else {k: str(v) for k, v in s.items()}

        got = _outcome(extract)
        if got != w["state"]:
            diffs.append(f"extract_state_from_script {c['name']}: want {w['state']}, got {got}")

        artifact = artifacts[c["artifact"]]

        def from_utxo():
            RunarContract.from_utxo(artifact, Utxo(
                txid=txid, output_index=0, satoshis=1000, script=script))
            return "ok"

        def from_txid():
            RunarContract.from_txid(artifact, txid, 0, provider)
            return "ok"

        for what, run in (("from_utxo", from_utxo), ("from_txid", from_txid)):
            got = _outcome(run)
            if got != w["fromUtxo"]:
                diffs.append(f"{what} {c['name']}: want {w['fromUtxo']}, got {got}")

        got = _outcome(lambda: find_last_op_return(script))
        if not (isinstance(got, int) or got == "malformed"):
            diffs.append(f"find_last_op_return {c['name']}: {got}")
    return diffs


def test_hostile_scripts_on_the_state_reading_paths():
    def over_budget(signum, frame):
        raise _OverBudget(f"replay exceeded {CPU_BUDGET_SECS} s of CPU")

    previous = signal.signal(signal.SIGPROF, over_budget)
    signal.setitimer(signal.ITIMER_PROF, CPU_BUDGET_SECS)
    try:
        diffs = _replay()
    finally:
        signal.setitimer(signal.ITIMER_PROF, 0)
        signal.signal(signal.SIGPROF, previous)
    assert not diffs, "\n".join(diffs)
