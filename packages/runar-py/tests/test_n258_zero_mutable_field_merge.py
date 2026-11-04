"""N-258 (user decision R99): a zero-mutable-field StatefulSmartContract
call that also spends additional_contract_inputs builds a REAL per-input
unlock for every extra contract input (its own OP_PUSH_TX preimage over its
own outpoint / scriptCode / amount, and its own Sig signed at its own input
index over the post-OP_CODESEPARATOR subscript), instead of refusing (N-227)
or shipping the sizing placeholder. Fee/change are re-derived from the real
unlocks.

The scenario is the cross-tier N-258 vector: same contract, key, outpoints and
amounts as packages/runar-sdk/src/__tests__/n258-zero-mutable-field-merge.test.ts,
whose tx @bsv/sdk Spend accepts on every input.

Proves: the Python SDK's merge tx is accepted by MockProvider's default
broadcast validation, which runs the upstream bsv-sdk Spend interpreter on
every known input (all three are known), and is byte-identical to the
TS-produced vector.

Does NOT prove: merges on a zero-mutable-field contract with more than one
public method (the stateless branch derives OP_PUSH_TX from the primary's
code-separator index), allPrevouts auto-resolution on this branch, or the
terminal-outputs path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

KEY = "0000000000000000000000000000000000000000000000000000000000000003"
SRC_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples" / "ts" / "all-readonly-cleanstack" / "AllReadonlyCleanstack.runar.ts"
)

N258_MERGE_TX_HEX = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde502483045022100ade686ada1bdadb2468b07f0699412c9d7016ca589633ac0730ea806c47437db022073f4f2a4e1bc2def562624d3ac86e4233410ca8aa84e102615ea3176fd84bb85414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde5024830450221009a9a66120d3a5e7f7d936b6b3c5a50116922b0eb6ae6255cc2c4280bab7b2f8b02200cb7382c58409af60b09bde18c241316f68dd95f2d1326109142f7794953704a414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000069463043021f10b0ce2db56a17ad04c53de15da45671cd370f10aef72f52f1b07d41c9c4c102206ccf57f5b8e81448179f0882f269ffca5baddf87066c7c2cbf48fa4a6c0b7e7c412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01d0b40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(
        SRC_PATH.read_text(), "AllReadonlyCleanstack.runar.ts",
    )
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def test_zero_mutable_field_merge_is_spend_valid_and_matches_vector():
    art = _artifact()
    assert art.parent_class == "StatefulSmartContract"
    assert not art.state_fields

    signer = LocalSigner(KEY)
    address = signer.get_address()
    pub_key = signer.get_public_key()
    locking_hex = RunarContract(art, [pub_key]).get_locking_script()

    primary = Utxo(txid="aa" * 32, output_index=0, satoshis=5_000, script=locking_hex)
    extra = Utxo(txid="cc" * 32, output_index=1, satoshis=7_000, script=locking_hex)

    provider = MockProvider("testnet")  # broadcast validation default-on
    provider.add_utxo(address, Utxo(
        txid="bb" * 32, output_index=0, satoshis=100_000, script=build_p2pkh_script(pub_key),
    ))
    provider.add_contract_utxo(locking_hex, primary)
    provider.add_contract_utxo(locking_hex + ":extra", extra)

    contract = RunarContract.from_utxo(art, primary)
    contract.call(
        "claim", [None, None], provider, signer,
        CallOptions(additional_contract_inputs=[extra]),
    )

    report = provider.last_validation_report
    assert report["script_vm_available"] is True, "bsv-sdk Spend did not run"
    assert provider.last_validated_input_count == 3
    assert provider.get_broadcasted_txs()[-1] == N258_MERGE_TX_HEX
