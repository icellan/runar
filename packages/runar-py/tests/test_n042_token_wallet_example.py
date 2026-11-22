"""N-042: ``TokenWallet`` must drive a SHIPPED example contract, not only the
fixture inlined in the F-045 test. This compiles
``examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts`` with the
Python compiler and runs ``transfer`` / ``merge`` against it.

Oracle: the F-045 one, reused. Each token-input signature must have been
computed over a tx whose BIP-143 fields equal the broadcast tx's. MockProvider's
default broadcast validation runs every known input through bsv-sdk's
``Spend`` (covenant inputs too, since bsv-sdk 2.5.0 fixed py-sdk#247), but this
test asserts nothing about which inputs it executed. Script execution of this
same example is proven by the TS and Go N-042 tests.

Proves: the shipped example compiles in the Python tier; transfer signs the
tx it broadcasts; merge (mutate-only, so SIGHASH_SINGLE under D25) is refused
before anything is broadcast.
Does NOT prove: script execution in this tier, node acceptance, or that the
example is a sound token (its header documents the ABI's limits).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import runar_compiler.compiler as compiler
from runar.sdk.local_signer import LocalSigner
from runar.sdk.types import RunarArtifact
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


# D25: WalletToken's continuation method (merge) is mutate-only, so it commits
# under SIGHASH_SINGLE, one output per input; a two-input merge into one
# continuation is the twin-input shape SINGLE closes, refused up front.
def test_merge_is_refused_before_broadcast():
    art = _artifact()
    provider, wallet, tokens, signer = _setup(art, [100, 250])
    assert wallet.get_balance() == 350
    before = len(provider.get_broadcasted_txs())
    with pytest.raises(ValueError, match="additionalContractInputs cannot be spent into one continuation by a SIGHASH_SINGLE method"):
        wallet.merge()
    assert len(provider.get_broadcasted_txs()) == before
