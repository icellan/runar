"""N-317: one hostile UTXO script must not take ``TokenWallet.get_utxos`` down,
and ``matches_artifact`` must agree with the TS SDK on every malformed shape.

Replays the shared cross-tier vector
``conformance/sdk-matches-artifact/hostile.json`` (also replayed by the TS, Go,
Rust, Zig, Ruby and Java SDKs): odd-length and non-hex scripts, truncated
OP_PUSHDATA1/2/4, OP_PUSHDATA4 lengths with the high bit set, a push running
past the slot, empty and short scripts and ~1 MiB scripts, beside SDK-built
genuine instances.

Proves: ``matches_artifact`` gives exactly the fixture's outcome per vector
(True / False / ``MalformedScriptError``; a ``ValueError`` or any other
exception fails it); ``get_utxos`` keeps exactly the genuine instances for a
stateful and a stateless artifact and never raises; the replay stays inside a
process-CPU budget (``ITIMER_PROF`` interrupts it at the budget, so a hang
fails instead of running forever).
Does NOT prove: on-chain spendability of the kept UTXOs, artifact shapes
beyond the fixture's two, or anything about a forged codeSepIndex element
(N-318).
"""

import json
import pathlib
import signal

from runar.sdk.errors import MalformedScriptError
from runar.sdk.provider import MockProvider
from runar.sdk.script_utils import matches_artifact
from runar.sdk.signer import MockSigner
from runar.sdk.token_wallet import TokenWallet
from runar.sdk.types import RunarArtifact, Utxo

FIXTURE = json.loads(
    (pathlib.Path(__file__).resolve().parents[3]
     / "conformance" / "sdk-matches-artifact" / "hostile.json").read_text(encoding="utf-8")
)

# Measured: well under a second of CPU after the fix.
CPU_BUDGET_SECS = 20


class _OverBudget(BaseException):
    """BaseException so no ``except Exception`` under test can swallow it."""


def _script(c):
    return c["prefix"] + c.get("repeat", "") * c.get("count", 0) + c.get("suffix", "")


def _replay():
    artifacts = {k: RunarArtifact.from_dict(v) for k, v in FIXTURE["artifacts"].items()}
    cases = FIXTURE["cases"]
    diffs = []
    for c in cases:
        try:
            got = "match" if matches_artifact(artifacts[c["artifact"]], _script(c)) else "no_match"
        except MalformedScriptError:
            got = "malformed"
        except Exception as e:  # noqa: BLE001 - any other exception is the defect
            got = f"error:{type(e).__name__}: {e}"
        if got != c["matches"]:
            diffs.append(f"{c['name']}: want {c['matches']}, got {got}")
    for name, artifact in artifacts.items():
        provider = MockProvider()
        signer = MockSigner()
        addr = signer.get_address()
        want = []
        for i, c in enumerate(cases):
            if c["artifact"] != name or c["wallet"] is None:
                continue
            txid = f"{i:02x}" * 32
            provider.add_utxo(addr, Utxo(txid=txid, output_index=0, satoshis=1000, script=_script(c)))
            if c["wallet"]:
                want.append(txid)
        try:
            kept = [u.txid for u in TokenWallet(artifact, provider, signer).get_utxos()]
        except Exception as e:  # noqa: BLE001
            diffs.append(f"get_utxos ({name}) raised {type(e).__name__}: {e}")
            continue
        if kept != want:
            diffs.append(f"get_utxos ({name}): want {want}, got {kept}")
    return diffs


def test_hostile_utxo_scripts_are_rejected_without_aborting_the_listing():
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
