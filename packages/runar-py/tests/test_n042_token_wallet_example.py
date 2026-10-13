"""N-042: ``TokenWallet`` must drive a SHIPPED example contract, not only the
fixture inlined in the F-045 test. This compiles
``examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts`` with the
Python compiler and runs ``transfer`` / ``merge`` against it.

Oracle: the F-045 one, reused. bsv-sdk's ``Spend`` cannot replay a Rúnar
OP_PUSH_TX covenant in this tier, so MockProvider's default broadcast
validation records the token inputs as unvalidatable (it still executes the
P2PKH funding input and checks value conservation). Each token-input
signature must therefore have been computed over a tx whose BIP-143 fields
equal the broadcast tx's. Script execution of this same example is proven by
the TS and Go N-042 tests.

Proves: the shipped example compiles in the Python tier; transfer and merge
sign the tx they broadcast; merge spends both token outpoints once into a
continuation holding the summed supply.
Does NOT prove: script execution in this tier, node acceptance, or that the
example is a sound token (its header documents the ABI's limits).
"""

from __future__ import annotations

import json
from pathlib import Path

import runar_compiler.compiler as compiler
from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.oppushtx import _parse_raw_tx
from runar.sdk.types import RunarArtifact, Utxo
from test_f045_token_wallet import OTHER_KEY, _assert_token_sigs_cover, _outpoints, _setup

EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples" / "ts" / "token-wallet-naive-INSECURE" / "WalletToken.runar.ts"
)


def _artifact() -> RunarArtifact:
    src = EXAMPLE.read_text()
    result = compiler.compile_from_source_str_with_result(src, "WalletToken.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def test_transfer_drives_the_shipped_example():
    art = _artifact()
    provider, wallet, tokens, signer = _setup(art, [100])
    assert wallet.get_balance() == 100
    wallet.transfer(LocalSigner(OTHER_KEY).get_address(), 100)
    broadcast = provider.get_broadcasted_txs()[-1]
    assert _outpoints(broadcast)[0] == f"{tokens[0].txid}:0"
    _assert_token_sigs_cover(signer, tokens, broadcast)


def test_merge_drives_the_shipped_example():
    art = _artifact()
    provider, wallet, tokens, signer = _setup(art, [100, 250])
    wallet.merge()
    broadcast = provider.get_broadcasted_txs()[-1]
    spent = _outpoints(broadcast)
    for u in tokens:
        assert spent.count(f"{u.txid}:0") == 1, spent
    _assert_token_sigs_cover(signer, tokens, broadcast)
    out0 = _parse_raw_tx(bytes.fromhex(broadcast))["outputs"][0]
    merged = RunarContract.from_utxo(art, Utxo(txid="00" * 32, output_index=0, satoshis=out0["satoshis"], script=out0["script"].hex()))
    assert merged.get_state()["supply"] == 350
