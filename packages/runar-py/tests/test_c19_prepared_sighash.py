"""Deep-review finding C19 (P1) -- ``PreparedCall.sighash`` must be the true
BIP-143 digest ``hash256(preimage)`` = ``sha256(sha256(preimage))``, NOT the
intermediate ``sha256(preimage)``.

``PreparedCall.sighash`` is handed to an EXTERNAL signer -- a BRC-100-style
``WalletSigner.sign_hash(digest)`` wallet or a hardware device -- that
ECDSA-signs those 32 bytes DIRECTLY, with no further hashing (see
``runar/sdk/wallet.py`` ``WalletSigner.sign_hash``). Storing the single-hashed
value makes such a wallet sign the wrong message and the node's real
``OP_CHECKSIG`` rejects the spend.

The default ``call()`` path hides the bug: it never reads
``PreparedCall.sighash``. It re-derives the digest inside ``LocalSigner.sign``
(``_bip143_sighash`` -> ``_sha256d`` -> ``ecdsa_sign``), which is correct by
construction. Only the documented multi-signer ``prepare_call()`` /
``finalize_call()`` path is affected.

Ported from the TS reference fix in ``packages/runar-sdk/src/contract.ts``
(``computeBip143Sighash``).

Verification strategy
---------------------
The Python tier's ``ScriptVM`` needs the optional ``bsv-sdk`` dependency, so a
full interpreter replay is not always available. This test instead performs the
cryptographic check ``OP_CHECKSIG`` itself performs: the signature an external
``sign_hash`` wallet produces over ``prepared.sighash`` MUST verify, under the
owner's public key, against ``hash256(preimage)``. Pre-fix the wallet signs
``sha256(preimage)`` and that verification fails.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from runar.ecdsa import ecdsa_sign, ecdsa_verify
from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.types import DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

SIGNER_KEY = "00" * 31 + "03"
FUNDER_KEY = "00" * 31 + "04"

# A stateful contract whose public method takes an external `Sig` -- the
# multi-signer / hardware-wallet shape prepare_call() exists to serve.
SRC = '''from runar import StatefulSmartContract, Bigint, PubKey, Sig, Readonly, public, assert_, check_sig


class SigCounter(StatefulSmartContract):
    count: Bigint
    owner: Readonly[PubKey]

    def __init__(self, count: Bigint, owner: PubKey):
        super().__init__(count, owner)
        self.count = count
        self.owner = owner

    @public
    def inc(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
        self.count = self.count + 1
'''


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "SigCounter.runar.py")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _funded_signer(provider: MockProvider, key_hex: str, satoshis: int) -> LocalSigner:
    signer = LocalSigner(key_hex)
    # A REAL P2PKH script for this signer. The old fixture
    # ("76a914" + "00"*20 + "88ac") is not spendable by ANY key, so the funding
    # input it produced would be rejected by a node — visible only once
    # MockProvider stopped always-acking (testing-gap remediation Phase A5).
    provider.add_utxo(signer.get_address(), Utxo(
        txid=key_hex[:64],
        output_index=0,
        satoshis=satoshis,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    return signer


def _deploy():
    """Deploy SigCounter (count = 5, owner = the signer's pubkey)."""
    artifact = _artifact()
    provider = MockProvider("testnet")
    signer = _funded_signer(provider, SIGNER_KEY, 500_000)
    _funded_signer(provider, FUNDER_KEY, 500_000)

    contract = RunarContract(artifact, [5, signer.get_public_key()])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    return contract, provider, signer


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def test_prepared_call_sighash_is_bip143_hash256():
    """PreparedCall.sighash must be hash256(preimage), never sha256(preimage)."""
    contract, provider, signer = _deploy()

    prepared = contract.prepare_call("inc", [None], provider, signer)
    assert prepared.preimage, "a stateful call must carry a BIP-143 preimage"

    preimage = bytes.fromhex(prepared.preimage)
    want = _sha256d(preimage).hex()
    wrong_single = hashlib.sha256(preimage).hexdigest()

    assert prepared.sighash != wrong_single, (
        "PreparedCall.sighash is sha256(preimage) -- an external sign_hash() wallet "
        f"would ECDSA-sign the WRONG digest (want hash256 = {want})"
    )
    assert prepared.sighash == want, "PreparedCall.sighash must be hash256(preimage)"


def test_external_sign_hash_wallet_signature_verifies_on_chain_digest():
    """End-to-end multi-signer proof.

    An external ``sign_hash`` wallet ECDSA-signs ``prepared.sighash`` DIRECTLY
    (no extra hashing), ``finalize_call`` assembles the transaction, and the
    resulting signature must verify against the digest the on-chain
    ``OP_CHECKSIG`` validates -- ``hash256(preimage)``.
    """
    contract, provider, signer = _deploy()

    prepared = contract.prepare_call("inc", [None], provider, signer)
    assert len(prepared.sig_indices) == 1, (
        f"expected exactly one external Sig slot, got {prepared.sig_indices}"
    )

    # --- the external wallet: sign_hash(digest) -> DER sig, NO extra hashing ---
    digest = bytes.fromhex(prepared.sighash)
    assert len(digest) == 32, (
        f"prepared.sighash must be a 32-byte digest, got {len(digest)} bytes"
    )
    der = ecdsa_sign(int(SIGNER_KEY, 16), digest)
    sig_hex = der.hex() + "41"  # ALL | FORKID
    # --- end external wallet ---

    # What OP_CHECKSIG actually verifies against on-chain.
    on_chain_digest = _sha256d(bytes.fromhex(prepared.preimage))
    pub_key = bytes.fromhex(signer.get_public_key())
    assert ecdsa_verify(der, pub_key, on_chain_digest), (
        "the external wallet's signature over PreparedCall.sighash does NOT verify "
        "against the on-chain BIP-143 digest hash256(preimage) -- OP_CHECKSIG would "
        "reject this spend"
    )

    contract.finalize_call(prepared, {prepared.sig_indices[0]: sig_hex}, provider)

    txs = provider.get_broadcasted_txs()
    assert len(txs) == 2, f"expected deploy + call broadcasts, got {len(txs)}"
    assert sig_hex in txs[1], (
        "the externally-produced signature must appear in the broadcast transaction"
    )


def test_default_call_path_still_works():
    """Guards the trace risk: nothing internal consumes PreparedCall.sighash, so
    the default call() path must keep working end-to-end after the C19 change."""
    contract, provider, signer = _deploy()

    contract.call("inc", [None], provider, signer)

    assert int(contract._state["count"]) == 6, "count should have incremented to 6"
    assert len(provider.get_broadcasted_txs()) == 2, "expected deploy + call broadcasts"


def test_script_code_intent_is_bytes_varint_plus_body(monkeypatch):
    """N-171-FU regression (sibling of N-171/R67): ``RunarContract.prepare_call``'s
    stateful-continuation path builds
    ``intent.mock_preimage_bytes['scriptCode']`` as
    ``_encode_varint(len(body) // 2) + bytes.fromhex(body)``.
    ``_encode_varint`` (``runar/sdk/deployment.py``) returns a HEX STRING, not
    bytes, so ``str + bytes`` raised
    ``TypeError: can only concatenate str (not "bytes") to str`` on every
    stateful call -- this is what previously made
    ``test_prepared_call_sighash_is_bip143_hash256`` and its siblings in this
    file fail (wrapped in a ``RuntimeError`` by the fail-closed handler).

    This test pins the value directly, rather than only observing that the
    end-to-end call stopped raising: it captures the ``intent`` object passed
    to the ANF interpreter and asserts ``scriptCode`` is of type ``bytes`` and
    equals ``varint(len(body)) || body`` -- the same CompactSize-prefixed
    encoding the BIP-143 preimage carries -- independently re-derived from
    the contract's own code part / codesep index using the same
    ``_encode_varint`` helper production uses.

    What this test does NOT prove: that ``_encode_varint`` or
    ``_get_code_part_hex``/``_get_code_sep_index`` are themselves correct (a
    shared bug in those would not be caught here, since the expected value
    reuses them); that the ANF interpreter's ``extractScriptCode`` consumer
    uses this value correctly (covered instead by
    ``test_default_call_path_still_works`` and the N-171 vector-replay
    tests); that this mock value matches the REAL on-chain scriptCode byte
    for byte when the contract carries non-empty state (it used to differ:
    N-189 now cuts it from the spent UTXO script, pinned against the signed
    preimage by the next test); or cross-tier byte parity
    with the other six SDKs' scriptCode construction (each builds it from
    its own codePart logic -- out of scope here, see the N-171-FU brief's
    cross-tier check).
    """
    import runar.sdk.contract as contract_mod
    from runar.sdk.deployment import _encode_varint

    contract, provider, signer = _deploy()
    # N-189: the scriptCode is cut from the SPENT UTXO's locking script (with
    # its state tail), so capture it before call() advances the UTXO.
    spent_script_hex = contract._current_utxo.script

    captured: dict = {}
    original = contract_mod.compute_new_state_and_data_outputs

    def _spy(*args, **kwargs):
        captured["intent"] = kwargs.get("intent")
        return original(*args, **kwargs)

    monkeypatch.setattr(contract_mod, "compute_new_state_and_data_outputs", _spy)

    contract.call("inc", [None], provider, signer)

    intent = captured.get("intent")
    assert intent is not None, "prepare_call must pass an intent to the ANF interpreter"
    script_code = intent.mock_preimage_bytes["scriptCode"]
    assert isinstance(script_code, bytes), (
        f"scriptCode must be bytes (TypeError-causing bug reintroduced), got {type(script_code)}"
    )

    method_index = contract._find_method_index("inc")
    code_sep_idx = contract._get_code_sep_index(method_index)
    body_hex = (
        spent_script_hex[(code_sep_idx + 1) * 2:] if code_sep_idx >= 0 else spent_script_hex
    )
    body = bytes.fromhex(body_hex)
    expected = bytes.fromhex(_encode_varint(len(body))) + body

    assert script_code == expected, (
        "scriptCode must be varint(len(body)) || body, matching the BIP-143 "
        "preimage's CompactSize-prefixed scriptCode encoding"
    )


def test_script_code_intent_equals_signed_preimage_script_code(monkeypatch):
    """N-189: the ``scriptCode`` intent ``prepare_call`` hands the ANF
    interpreter (what ``extractScriptCode(txPreimage)`` returns while the SDK
    predicts the post-state) must equal the scriptCode field of the BIP-143
    preimage the call actually signs. That field is the SPENT UTXO's locking
    script after the OP_CODESEPARATOR -- code AND the ``OP_RETURN <state>``
    tail. R67 built it from the bare template codePart (734 vs 743 bytes for
    SigCounter's count+owner state), so a method whose post-state depends on
    its own scriptCode committed a continuation the covenant rejects (shown on
    @bsv/sdk Spend by
    ``packages/runar-sdk/src/__tests__/n189-scriptcode-intent-includes-state.test.ts``).

    What this proves: byte equality between the intent and
    ``preimage[104:-52]`` (version 4 + hashPrevouts 32 + hashSequence 32 +
    outpoint 36 before; amount 8 + nSequence 4 + hashOutputs 32 + locktime 4
    + sighash type 4 after) for a contract with non-empty state.
    What it does not prove: that the preimage itself is what a node computes
    (covered by the C19 tests above); extra contract inputs of a multi-input
    call (each is spent by its own preimage, not by this prediction).
    """
    import runar.sdk.contract as contract_mod

    contract, provider, signer = _deploy()

    captured: dict = {}
    original = contract_mod.compute_new_state_and_data_outputs

    def _spy(*args, **kwargs):
        captured["intent"] = kwargs.get("intent")
        return original(*args, **kwargs)

    monkeypatch.setattr(contract_mod, "compute_new_state_and_data_outputs", _spy)

    prepared = contract.prepare_call("inc", [None], provider, signer)
    preimage = bytes.fromhex(prepared.preimage)
    signed_script_code = preimage[104:-52]

    intent = captured.get("intent")
    assert intent is not None, "prepare_call must pass an intent to the ANF interpreter"
    assert intent.mock_preimage_bytes["scriptCode"] == signed_script_code, (
        f"scriptCode intent ({len(intent.mock_preimage_bytes['scriptCode'])} bytes) differs "
        f"from the signed preimage's scriptCode field ({len(signed_script_code)} bytes)"
    )
