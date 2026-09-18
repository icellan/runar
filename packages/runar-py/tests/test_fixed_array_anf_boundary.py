"""FixedArray state across the ANF-interpreter boundary (call path) -- Python SDK.

Pass ``03b-expand-fixed-arrays`` runs BEFORE ANF lowering, so the ANF program has
no property called ``table`` at all -- it has ``table__0``..``table__3``, and every
``load_prop`` / ``update_prop`` in the method body names one of those. The SDK's
user-facing ``_state``, by contrast, is keyed by the GROUPED name. Both directions
of that boundary have to be bridged (``_flatten_fixed_array_state`` /
``_regroup_fixed_array_state``) or the continuation output commits a state the
method did not compute.

The sharp probe is the RECONNECT path: ``from_utxo`` sets ``_state`` to exactly
what ``extract_state_from_script`` decodes, which for a FixedArray field is the
grouped entry and nothing else -- no synthetic leaves to mask an unbridged inbound
boundary. Because ``self.table[i] += 1`` at a runtime index lowers to a per-leaf
select, an absent property makes the interpreter fall back to each leaf's ANF
``initialValue`` and rewrite ALL FOUR leaves from it, so the continuation commits
the deploy-time array and the covenant's hashOutputs binding rejects the spend.

Fixture: ``examples/*/fixed-array-write/ArrayWrite.runar.*`` --
``table: FixedArray<bigint, 4> = [0,0,0,0]``, ``bump(i)`` doing
``self.table[i] += 1``. Checked in at ``tests/testdata/arraywrite-artifact.json``,
compiled with ``--ir`` so the artifact carries the ANF the call path needs.

Every test runs on the DEFAULT validating MockProvider with a real LocalSigner, so
each broadcast goes through the fail-closed gate and each call spends the
continuation the previous call built. The Python tier's script layer records a
Rúnar covenant input as UNVALIDATABLE (a pre-existing runar-py <-> bsv-sdk
OP_PUSH_TX incompatibility, pinned by ``test_mock_broadcast_validation.py``), so the
load-bearing assertion here is the continuation BYTES: the 32-byte state section
the next spend is bound to.
"""

from __future__ import annotations

import json
from pathlib import Path

from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import DeployOptions, RunarArtifact, Utxo

DEPLOYER_KEY = "00" * 31 + "07"

_ARTIFACT_PATH = Path(__file__).resolve().parent / "testdata" / "arraywrite-artifact.json"


def _artifact() -> RunarArtifact:
    artifact = RunarArtifact.from_dict(json.loads(_ARTIFACT_PATH.read_text()))
    # Without ANF the call path never reaches the interpreter and this whole
    # module would be vacuous.
    assert artifact.anf is not None, "ArrayWrite artifact carries no ANF"
    return artifact


def _le_hex(*vals: int) -> str:
    """Little-endian 8-byte words, one per leaf -- the contract's state bytes."""
    return "".join(v.to_bytes(8, "little", signed=True).hex() for v in vals)


def _state_tail_hex(script_hex: str) -> str:
    """The 32-byte state section after the final OP_RETURN of a locking script."""
    nibbles = 4 * 8 * 2
    assert len(script_hex) > nibbles + 2, "locking script too short to carry a state section"
    sep = script_hex[-nibbles - 2:-nibbles]
    assert sep == "6a", f"expected OP_RETURN (6a) before the state section, found {sep!r}"
    return script_hex[-nibbles:]


def _grouped_table(state: dict) -> list[int]:
    raw = state.get("table")
    assert isinstance(raw, (list, tuple)), f"state has no grouped `table` array: {raw!r}"
    out = []
    for v in raw:
        if isinstance(v, str):
            # A grouped entry still holding the artifact's `initialValue` is the
            # compiler's `"0n"` literal form.
            v = int(v.rstrip("n"))
        out.append(int(v))
    return out


def _deploy_array_write():
    provider = MockProvider("testnet")
    signer = LocalSigner(DEPLOYER_KEY)
    provider.add_utxo(signer.get_address(), Utxo(
        txid="aa" * 32,
        output_index=0,
        satoshis=1_000_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    contract = RunarContract(_artifact(), [])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    return contract, provider, signer


def test_outbound_continuation_and_grouped_entry_carry_the_computed_state():
    """The post-call state the interpreter computed under the SYNTHETIC leaf names
    has to reach BOTH the continuation output's state section and the grouped
    user-facing `table` entry."""
    contract, provider, signer = _deploy_array_write()

    assert _state_tail_hex(contract.get_utxo().script) == _le_hex(0, 0, 0, 0)

    contract.call("bump", [0], provider, signer)

    assert _state_tail_hex(contract.get_utxo().script) == _le_hex(1, 0, 0, 0)
    assert _grouped_table(contract.get_state()) == [1, 0, 0, 0]


def test_inbound_repeated_bumps_of_one_slot_accumulate():
    """The interpreter must see the CURRENT value of each leaf; otherwise every
    bump computes from the property's initialValue and sticks at 1."""
    contract, provider, signer = _deploy_array_write()

    for n in range(1, 4):
        contract.call("bump", [0], provider, signer)
        assert _state_tail_hex(contract.get_utxo().script) == _le_hex(n, 0, 0, 0)
        assert _grouped_table(contract.get_state()) == [n, 0, 0, 0]


def test_inbound_reconnected_contract_commits_the_restored_state():
    """The fund-path probe: a contract reconnected with from_utxo carries the
    grouped entry ONLY. Without the inbound bridge the interpreter falls back to
    each leaf's ANF initialValue, and because the runtime-index write lowers to a
    per-leaf select it rewrites ALL FOUR leaves -- the continuation commits the
    deploy-time array and the covenant rejects the spend."""
    contract, provider, signer = _deploy_array_write()

    # Real on-chain history: table -> [0,2,0,0].
    contract.call("bump", [1], provider, signer)
    contract.call("bump", [1], provider, signer)
    on_chain = contract.get_utxo()
    assert _state_tail_hex(on_chain.script) == _le_hex(0, 2, 0, 0)

    # A fresh process that only ever sees the deployed script.
    restored = RunarContract.from_utxo(_artifact(), Utxo(
        txid=on_chain.txid,
        output_index=on_chain.output_index,
        satoshis=on_chain.satoshis,
        script=on_chain.script,
    ))
    assert "table__1" not in restored.get_state(), (
        "from_utxo leaked a synthetic leaf; this test no longer probes the "
        "grouped-only restore path"
    )
    assert _grouped_table(restored.get_state()) == [0, 2, 0, 0]

    restored.call("bump", [1], provider, signer)

    assert _state_tail_hex(restored.get_utxo().script) == _le_hex(0, 3, 0, 0)
    assert _grouped_table(restored.get_state()) == [0, 3, 0, 0]
