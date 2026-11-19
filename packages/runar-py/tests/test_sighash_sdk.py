"""Issue #123 — SDK-side per-method @sighash threading (preimage + signature).

Verifies the Python SDK builds the BIP-143 preimage under the method's declared
sighash mode (from ABI ``sigHashType``): the appended sighash flag byte matches,
and the zeroed BIP-143 digest fields match the mode. Parity target: the preimage
sighash byte equals the TS reference (0x43 for SINGLE|FORKID, 0xC1 for
ALL|ANYONECANPAY|FORKID (0xC3 under D25 for a mutate-only contract), 0x41 for the default / no directive).
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.oppushtx import compute_op_push_tx, _bip143_preimage, _parse_raw_tx, _ZERO32
from runar.sdk.types import RunarArtifact, DeployOptions
from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.contract import RunarContract

compiler = pytest.importorskip("runar_compiler.compiler")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _artifact(src: str, file_name: str) -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(src, file_name)
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    d = json.loads(compiler.artifact_to_json(result.artifact))
    return RunarArtifact.from_dict(d)


def _funded_provider(address: str, satoshis: int = 500_000) -> MockProvider:
    from runar.sdk.types import Utxo
    provider = MockProvider.always_ack('testnet')
    provider.add_utxo(address, Utxo(
        txid="00" * 32, output_index=0, satoshis=satoshis,
        script="76a914" + "00" * 20 + "88ac",
    ))
    return provider


def _sighash_byte_of(preimage_hex: str) -> int:
    """Last 4 preimage bytes = sighashType (LE uint32); the flag is the first."""
    return bytes.fromhex(preimage_hex)[-4]


# ---------------------------------------------------------------------------
# ABI plumbing
# ---------------------------------------------------------------------------

class TestAbiSigHashType:
    def test_parsed_from_json(self):
        art = _artifact(
            """
class Pay extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public settle(): void { this.addOutput(1000n, this.n); }
}""",
            "Pay.runar.ts",
        )
        settle = next(m for m in art.abi.methods if m.name == "settle")
        assert settle.sig_hash_type == 0x43

    def test_default_omitted(self):
        # D25: the addOutput sibling keeps the contract on ALL (a contract
        # whose continuation methods are all mutate-only defaults to SINGLE).
        art = _artifact(
            """
class Counter extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.n = this.n + 1n; }
  public put(): void { this.addOutput(1n, this.n); }
}""",
            "Counter.runar.ts",
        )
        bump = next(m for m in art.abi.methods if m.name == "bump")
        assert bump.sig_hash_type is None


# ---------------------------------------------------------------------------
# compute_op_push_tx: appended sighash byte + BIP-143 zeroing
# ---------------------------------------------------------------------------

class TestComputeOpPushTx:
    # A minimal 1-in / 2-out raw tx.
    RAW_TX = (
        "01000000"                                          # version
        "01"                                                # 1 input
        + "11" * 32 + "00000000"                            # outpoint
        + "00"                                              # empty scriptSig
        + "ffffffff"                                        # sequence
        + "02"                                              # 2 outputs
        + "e803000000000000" + "01" + "51"                  # out0: 1000 sat, script 0x51
        + "d007000000000000" + "01" + "52"                  # out1: 2000 sat, script 0x52
        + "00000000"                                        # locktime
    )
    SUBSCRIPT = "76a914" + "00" * 20 + "88ac"

    def _preimage_for(self, sig_hash_type: int) -> bytes:
        _sig, pre = compute_op_push_tx(
            self.RAW_TX, 0, self.SUBSCRIPT, 1000, -1, sig_hash_type
        )
        return bytes.fromhex(pre)

    def test_appended_byte_default(self):
        sig, _pre = compute_op_push_tx(self.RAW_TX, 0, self.SUBSCRIPT, 1000)
        assert sig.endswith("41")

    def test_appended_byte_single(self):
        sig, pre = compute_op_push_tx(self.RAW_TX, 0, self.SUBSCRIPT, 1000, -1, 0x43)
        assert sig.endswith("43")
        assert _sighash_byte_of(pre) == 0x43

    def test_appended_byte_anyonecanpay(self):
        sig, pre = compute_op_push_tx(self.RAW_TX, 0, self.SUBSCRIPT, 1000, -1, 0xC1)
        assert sig.endswith("c1")
        assert _sighash_byte_of(pre) == 0xC1

    def test_anyonecanpay_zeroes_hashprevouts_and_sequence(self):
        pre = self._preimage_for(0xC1)
        # preimage layout: version(4) hashPrevouts(32) hashSequence(32) ...
        assert pre[4:36] == _ZERO32          # hashPrevouts zeroed
        assert pre[36:68] == _ZERO32         # hashSequence zeroed (ACP)

    def test_none_zeroes_hashoutputs(self):
        pre = self._preimage_for(0x42)  # NONE|FORKID
        # hashOutputs is 32 bytes ending 8 bytes before the tail (outputs(32)
        # locktime(4) sighash(4)).
        hash_outputs = pre[-40:-8]
        assert hash_outputs == _ZERO32
        # hashSequence zeroed under NONE too.
        assert pre[36:68] == _ZERO32

    def test_single_hashes_same_index_output_only(self):
        # SINGLE (input 0) commits hash256(output[0]) only — not the whole set.
        from runar.sdk.oppushtx import _sha256d, _encode_varint
        import struct
        pre = self._preimage_for(0x43)
        hash_outputs = pre[-40:-8]
        tx = _parse_raw_tx(bytes.fromhex(self.RAW_TX))
        out0 = tx["outputs"][0]
        expected = _sha256d(
            struct.pack("<Q", out0["satoshis"]) + _encode_varint(len(out0["script"])) + out0["script"]
        )
        assert hash_outputs == expected
        # And NOT the digest of all outputs.
        all_outs = b""
        for o in tx["outputs"]:
            all_outs += struct.pack("<Q", o["satoshis"]) + _encode_varint(len(o["script"])) + o["script"]
        assert hash_outputs != _sha256d(all_outs)

    def test_all_default_unchanged(self):
        # The default 0x41 preimage is byte-identical whether or not the flag is
        # passed explicitly (regression guard for existing behaviour).
        a = self._preimage_for(0x41)
        _sig, b_hex = compute_op_push_tx(self.RAW_TX, 0, self.SUBSCRIPT, 1000)
        assert a == bytes.fromhex(b_hex)


# ---------------------------------------------------------------------------
# End-to-end: deploy + prepare_call threads the ABI sighash mode
# ---------------------------------------------------------------------------

class TestEndToEndSighashByte:
    def _deploy_and_prepare(self, art: RunarArtifact, ctor_args, method, call_args):
        signer = MockSigner()
        provider = _funded_provider(signer.get_address())
        contract = RunarContract(art, ctor_args)
        contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
        prepared = contract.prepare_call(method, call_args, provider, signer)
        return prepared

    def test_default_preimage_byte_is_0x41(self):
        # D25: the addOutput sibling keeps the contract on ALL (see above).
        art = _artifact(
            """
class Counter extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.n = this.n + 1n; }
  public put(): void { this.addOutput(1n, this.n); }
}""",
            "Counter.runar.ts",
        )
        prepared = self._deploy_and_prepare(art, [0], "bump", [])
        assert prepared.preimage
        assert _sighash_byte_of(prepared.preimage) == 0x41

    def test_anyonecanpay_preimage_byte_is_0xC3(self):
        # D25: in a contract whose continuation methods are all mutate-only
        # the ALL base becomes SINGLE (ALL|ACP|FORKID -> SINGLE|ACP|FORKID =
        # 0xC3), so the pledge commits only its own same-index continuation.
        art = _artifact(
            """
class Fund extends StatefulSmartContract {
  raised: bigint;
  constructor(raised: bigint) { super(raised); this.raised = raised; }
  /** @sighash ALL|ANYONECANPAY|FORKID */
  public pledge(amount: bigint): void { this.raised = this.raised + amount; }
}""",
            "Fund.runar.ts",
        )
        assert next(m for m in art.abi.methods if m.name == "pledge").sig_hash_type == 0xC3
        prepared = self._deploy_and_prepare(art, [0], "pledge", [7])
        assert prepared.preimage
        assert _sighash_byte_of(prepared.preimage) == 0xC3

    def test_single_addoutput_preimage_byte_is_0x43(self):
        art = _artifact(
            """
class Pay extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  /** @sighash SINGLE|FORKID */
  public settle(): void { this.addOutput(1000n, this.n); }
}""",
            "Pay.runar.ts",
        )
        prepared = self._deploy_and_prepare(art, [0], "settle", [])
        assert prepared.preimage
        assert _sighash_byte_of(prepared.preimage) == 0x43
