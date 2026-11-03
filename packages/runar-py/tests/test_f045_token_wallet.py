"""F-045: ``TokenWallet.transfer`` / ``.merge`` must sign the transaction that
is actually broadcast, and ``merge`` must spend BOTH token UTXOs.

Pre-fix, ``merge`` passed only the first token UTXO to ``call`` (the second was
read for its supply and left unspent), and ``transfer`` built and discarded a
preliminary tx and passed the Base58 recipient address verbatim as the 20-byte
``Addr`` argument.

Oracle: bsv-sdk's ``Spend`` cannot replay a Rúnar OP_PUSH_TX covenant in this
tier (see ``test_g1_raw_outputs_spend.py``), so the stateful token inputs are
not script-executed here. Instead every signature the wallet's signer made for
a TOKEN input must have been computed over a tx whose BIP-143-relevant fields
(version, every outpoint + sequence, every output, locktime) equal the
broadcast tx's; BIP-143 reads nothing else except the subscript and amount,
taken from the spent UTXO. The on-chain verdict for the same flow is proven by
the TS/Go F-045 tests.

Proves: each token-input signature covers the broadcast tx; merge spends both
token outpoints exactly once into one continuation holding the summed supply.
Does NOT prove: script execution in this tier, node acceptance, or token
semantics beyond this fixture (its transfer does not reassign the holder).
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.oppushtx import _parse_raw_tx
from runar.sdk.provider import MockProvider
from runar.sdk.token_wallet import TokenWallet
from runar.sdk.types import RunarArtifact, TransactionData, TxOutput, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

HOLDER_KEY = "00" * 31 + "45"
OTHER_KEY = "00" * 31 + "47"

SRC = """
import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';

class WalletToken extends StatefulSmartContract {
  supply: bigint;
  holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  public transfer(sig: Sig, to: Addr) {
    assert(checkSig(sig, this.holder));
    assert(len(to) === 20n);
  }

  public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    assert(otherHolder === this.holder);
    assert(otherSupply >= 0n);
    this.supply = this.supply + otherSupply;
  }
}
"""


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "WalletToken.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


class _Recording(LocalSigner):
    """LocalSigner that records every (tx_hex, input_index) it signs."""

    def __init__(self, key: str):
        super().__init__(key)
        self.log: list[tuple[str, int]] = []

    def sign(self, tx_hex, input_index, subscript, satoshis, sighash_type=None):
        self.log.append((tx_hex, input_index))
        return super().sign(tx_hex, input_index, subscript, satoshis, sighash_type)


def _sighash_view(tx_hex: str):
    """The tx fields BIP-143 reads (unlocking scripts excluded)."""
    t = _parse_raw_tx(bytes.fromhex(tx_hex))
    return (
        t["version"],
        [(i["prev_txid_bytes"], i["prev_output_index"], i["sequence"]) for i in t["inputs"]],
        [(o["satoshis"], o["script"]) for o in t["outputs"]],
        t["locktime"],
    )


def _outpoints(tx_hex: str) -> list[str]:
    t = _parse_raw_tx(bytes.fromhex(tx_hex))
    return [f"{i['prev_txid_bytes'][::-1].hex()}:{i['prev_output_index']}" for i in t["inputs"]]


def _setup(art, supplies, token_sats=5_000, funding_sats=200_000):
    signer = _Recording(HOLDER_KEY)
    addr = signer.get_address()
    pub = signer.get_public_key()
    provider = MockProvider("testnet")
    tokens = []
    for i, s in enumerate(supplies):
        lock = RunarContract(art, [s, pub]).get_locking_script()
        txid = f"{i + 1:02x}" * 32
        provider.add_transaction(TransactionData(txid=txid, outputs=[TxOutput(satoshis=token_sats, script=lock)]))
        u = Utxo(txid=txid, output_index=0, satoshis=token_sats, script=lock)
        provider.add_utxo(addr, u)
        tokens.append(u)
    provider.add_utxo(addr, Utxo(txid="fe" * 32, output_index=0, satoshis=funding_sats, script=build_p2pkh_script(addr)))
    return provider, TokenWallet(art, provider, signer), tokens, signer


def _assert_token_sigs_cover(signer, tokens, broadcast):
    want = _sighash_view(broadcast)
    spent = _outpoints(broadcast)
    idxs = [spent.index(f"{u.txid}:0") for u in tokens if f"{u.txid}:0" in spent]
    assert idxs, f"no token input in the broadcast tx: {spent}"
    for idx in idxs:
        # The LAST signature for this input is the one embedded.
        signed = [tx for tx, i in signer.log if i == idx]
        assert signed, f"signer never signed token input {idx}"
        assert _sighash_view(signed[-1]) == want, f"token input {idx} was signed over a different tx"


@pytest.mark.parametrize("recipient_kind", ["hash160", "base58"])
def test_transfer_signs_the_broadcast_tx(recipient_kind):
    art = _artifact()
    provider, wallet, tokens, signer = _setup(art, [100])
    other_addr = LocalSigner(OTHER_KEY).get_address()
    # An Addr is a hash160; the Base58 address is the documented form.
    recipient = build_p2pkh_script(other_addr)[6:46] if recipient_kind == "hash160" else other_addr
    wallet.transfer(recipient, 100)
    broadcast = provider.get_broadcasted_txs()[-1]
    assert _outpoints(broadcast)[0] == f"{tokens[0].txid}:0"
    _assert_token_sigs_cover(signer, tokens, broadcast)


@pytest.mark.parametrize("token_sats,funding_sats", [(5_000, 200_000), (300_000, 50_000)])
def test_merge_spends_both_token_utxos(token_sats, funding_sats):
    # Second case: token UTXOs larger than the funding coin -- funding
    # selection must not also pick the second token UTXO as a P2PKH input.
    art = _artifact()
    provider, wallet, tokens, signer = _setup(art, [100, 250], token_sats, funding_sats)
    wallet.merge()
    broadcast = provider.get_broadcasted_txs()[-1]
    spent = _outpoints(broadcast)
    for u in tokens:
        assert spent.count(f"{u.txid}:0") == 1, spent
    assert len(set(spent)) == len(spent), spent
    _assert_token_sigs_cover(signer, tokens, broadcast)
    out0 = _parse_raw_tx(bytes.fromhex(broadcast))["outputs"][0]
    merged = RunarContract.from_utxo(art, Utxo(txid="00" * 32, output_index=0, satoshis=out0["satoshis"], script=out0["script"].hex()))
    assert merged.get_state()["supply"] == 350
