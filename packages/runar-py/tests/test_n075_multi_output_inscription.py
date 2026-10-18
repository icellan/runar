"""N-075 — the multi-output continuation path keeps the 1sat inscription envelope.

``call(..., CallOptions(outputs=[...]))`` built each output from the bare code
script and dropped the inscription envelope, while the single-output path
(``get_locking_script``) kept it. The covenant's ``_codePart`` includes the
envelope, so the multi-output spend's hashOutputs check could never match.

Proves: with an inscription attached, every output of a multi-output call is
byte-identical to the single-output locking script for the same state.

Does NOT prove: that a full spend validates under a script interpreter (the
test inspects the outputs the SDK commits to), nor the same fix in other SDKs.
"""

from __future__ import annotations

from runar.sdk.contract import RunarContract
from runar.sdk.ordinals import Inscription
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.types import CallOptions, DeployOptions, OutputSpec, RunarArtifact, Utxo

ARTIFACT_DICT = {
    'version': 'runar-v0.1.0',
    'compilerVersion': '0.1.0',
    'contractName': 'Counter',
    'abi': {
        'constructor': {'params': [{'name': 'count', 'type': 'bigint'}]},
        'methods': [{'name': 'increment', 'params': [], 'isPublic': True}],
    },
    'script': 'aabbcc',
    'asm': '',
    'stateFields': [{'name': 'count', 'type': 'bigint', 'index': 0}],
    'constructorSlots': [],
    'codeSeparatorIndex': 0,
}


def _artifact() -> RunarArtifact:
    return RunarArtifact.from_dict(ARTIFACT_DICT)


def test_multi_output_scripts_equal_single_output_locking_script():
    art = _artifact()
    # Default (validating) MockProvider: the deploy broadcast is checked, so the
    # funding UTXO must be a REAL P2PKH the signer can spend.
    signer = LocalSigner("00" * 31 + "05")
    provider = MockProvider('testnet')
    provider.add_utxo(signer.get_address(), Utxo(
        txid="11" * 32, output_index=0, satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    ins = Inscription(content_type='text/plain', data='68656c6c6f')
    contract = RunarContract(art, [0]).with_inscription(ins)
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))

    prepared = contract.prepare_call(
        'increment', [], provider, signer,
        CallOptions(outputs=[OutputSpec(satoshis=2000, state={'count': 7}),
                             OutputSpec(satoshis=2000, state={'count': 9})]),
    )
    assert len(prepared.contract_outputs) == 2
    for out, count in zip(prepared.contract_outputs, (7, 9)):
        expected = RunarContract(art, [count]).with_inscription(ins).get_locking_script()
        assert out['script'] == expected
