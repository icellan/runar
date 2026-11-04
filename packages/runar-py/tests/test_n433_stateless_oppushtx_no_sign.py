"""N-433: the stateless / zero-mutable-field prepare_call branch and the
stateless terminal branch computed a k=1 OP_PUSH_TX ECDSA signature through
``compute_op_push_tx`` and never put it in any output (``_build_stateful_prefix``
discards its argument; the only reader of the value was a
``final_op_push_tx_sig`` truthiness flag that is true exactly when
``needs_op_push_tx`` is). They now use ``compute_op_push_tx_preimage`` (N-253).

Proves: on each stateless path (zero-mutable merge with an extra contract
input, single-input call, terminal call) zero OP_PUSH_TX signs happen, counted
by wrapping ``_ecdsa_sign_k1``, and the broadcast bytes equal the pinned
pre-change cross-tier vectors (N-258 merge, N-270 methodB, terminal vector
captured at base).
Does NOT prove anything on-chain beyond MockProvider's Spend validation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.sdk import oppushtx
from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.types import CallOptions, RunarArtifact, TerminalOutput, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

KEY = "0000000000000000000000000000000000000000000000000000000000000003"
SRC_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples" / "ts" / "all-readonly-cleanstack" / "AllReadonlyCleanstack.runar.ts"
)

TWO_METHOD_SRC = """import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
class TwoMethodReadonly extends StatefulSmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
  public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
}
"""

N258_MERGE_TX_HEX = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde502483045022100ade686ada1bdadb2468b07f0699412c9d7016ca589633ac0730ea806c47437db022073f4f2a4e1bc2def562624d3ac86e4233410ca8aa84e102615ea3176fd84bb85414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde5024830450221009a9a66120d3a5e7f7d936b6b3c5a50116922b0eb6ae6255cc2c4280bab7b2f8b02200cb7382c58409af60b09bde18c241316f68dd95f2d1326109142f7794953704a414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000069463043021f10b0ce2db56a17ad04c53de15da45671cd370f10aef72f52f1b07d41c9c4c102206ccf57f5b8e81448179f0882f269ffca5baddf87066c7c2cbf48fa4a6c0b7e7c412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01d0b40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"
N270_METHOD_B_TX_HEX = "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc202473044022025bdb788c88800da0e122ee07bd7e7cf108c4c6d53ebf09ed2ed7f37e4ab1ec3022012880daf6cb232de74f645e6c69e69b74e7096257735aea1ff394d87d6309fcf414d760201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"
N433_TERMINAL_TX_HEX = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc302483045022100923a5fee18fb37ef44a838f67ddf578473ec3ac72becc46c99e78caa1a11423f022038c8f6f613e9b1b6c61a200f443ee6987755170a43ff9c2056e0dccc8ca84953414d7602010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000"


@pytest.fixture
def k1_sign_count(monkeypatch):
    calls = {"n": 0}
    orig = oppushtx._ecdsa_sign_k1

    def counting(msg_hash):
        calls["n"] += 1
        return orig(msg_hash)

    monkeypatch.setattr(oppushtx, "_ecdsa_sign_k1", counting)
    return calls


def _artifact(src: str, name: str) -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(src, name)
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _setup(art):
    signer = LocalSigner(KEY)
    address = signer.get_address()
    pub_key = signer.get_public_key()
    locking_hex = RunarContract(art, [pub_key]).get_locking_script()
    primary = Utxo(txid="aa" * 32, output_index=0, satoshis=5_000, script=locking_hex)
    provider = MockProvider("testnet")
    provider.add_utxo(address, Utxo(
        txid="bb" * 32, output_index=0, satoshis=100_000, script=build_p2pkh_script(pub_key),
    ))
    provider.add_contract_utxo(locking_hex, primary)
    return signer, pub_key, primary, provider, locking_hex


def test_n433_zero_mutable_merge_computes_no_op_push_tx_signature(k1_sign_count):
    art = _artifact(SRC_PATH.read_text(), "AllReadonlyCleanstack.runar.ts")
    signer, _pk, primary, provider, locking_hex = _setup(art)
    extra = Utxo(txid="cc" * 32, output_index=1, satoshis=7_000, script=locking_hex)
    provider.add_contract_utxo(locking_hex + ":extra", extra)
    RunarContract.from_utxo(art, primary).call(
        "claim", [None, None], provider, signer,
        CallOptions(additional_contract_inputs=[extra]),
    )
    assert k1_sign_count["n"] == 0, f"merge computed {k1_sign_count['n']} OP_PUSH_TX signature(s)"
    assert provider.get_broadcasted_txs()[-1] == N258_MERGE_TX_HEX


def test_n433_stateless_single_input_computes_no_op_push_tx_signature(k1_sign_count):
    art = _artifact(TWO_METHOD_SRC, "TwoMethodReadonly.runar.ts")
    signer, _pk, primary, provider, _l = _setup(art)
    RunarContract.from_utxo(art, primary).call("methodB", [None, None], provider, signer)
    assert k1_sign_count["n"] == 0, f"call computed {k1_sign_count['n']} OP_PUSH_TX signature(s)"
    assert provider.get_broadcasted_txs()[-1] == N270_METHOD_B_TX_HEX


def test_n433_stateless_terminal_computes_no_op_push_tx_signature(k1_sign_count):
    art = _artifact(TWO_METHOD_SRC, "TwoMethodReadonly.runar.ts")
    signer, pub_key, primary, provider, _l = _setup(art)
    RunarContract.from_utxo(art, primary).call(
        "methodB", [None, None], provider, signer,
        CallOptions(terminal_outputs=[TerminalOutput(script_hex=build_p2pkh_script(pub_key), satoshis=4_000)]),
    )
    assert k1_sign_count["n"] == 0, f"terminal computed {k1_sign_count['n']} OP_PUSH_TX signature(s)"
    assert provider.get_broadcasted_txs()[-1] == N433_TERMINAL_TX_HEX
