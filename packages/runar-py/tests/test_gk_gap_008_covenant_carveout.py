"""GK-GAP-008: MockProvider's OP_PUSH_TX carve-out was far wider than disclosed.

``_validate_broadcast`` bucketed ANY ``Spend`` exception whose text contained
``OP_CHECKSIGVERIFY`` as "unvalidatable" and carried on. That covers a plain
wrong-key ``checkSig`` in any contract (stateless included) whenever the check
is compiled as ``OP_CHECKSIGVERIFY``. And non-vacuity was satisfied by
``known_inputs > 0`` alone, so a SINGLE-input transaction spending such a
contract UTXO was accepted as long as the outputs did not exceed the input —
no other validated input needed.

The carve-out exists for one thing only: the OP_PUSH_TX covenant check, whose
``OP_CHECKSIGVERIFY`` verifies against a fixed public key (compressed G, or the
Any-S C=1 key) pushed immediately before it. bsv-sdk recomputes a different
sighash than runar-py signs (see the strict xfail in
``test_g1_raw_outputs_spend.py``), so those inputs cannot be validated here.
The cause is an upstream bsv-sdk defect, pinned by the R2-GAP008 tests at the
end of this module.

Proves: a wrong signature at a CHECKSIGVERIFY against any other key is a
rejection, alone or next to a valid input; a covenant-shaped failure is still
recorded as unvalidatable next to a validated input; and a transaction whose
every known input is unvalidatable is rejected as validating nothing.
R2-GAP008 pins prove: bsv-sdk's Spend sighashes a scriptCode whose OP_RETURN
was re-encoded as a push (rejecting a signature over the real bytes, on every
VM path available); and for a real Counter.inc call runar-py's preimage equals
bsv-sdk's in every field but that one byte, with runar-py's scriptCode being
the locking script's real bytes after OP_CODESEPARATOR.
Does not prove: that a node accepts runar-py's preimage (that is the regtest
integration suite's job), or anything about the other six SDKs.
"""

import pytest

from runar.sdk.errors import BroadcastRejected
from runar.sdk.provider import MockProvider, _bsv_sdk_available
from runar.sdk.types import Utxo

pytestmark = pytest.mark.skipif(
    not _bsv_sdk_available(),
    reason="bsv-sdk not installed: the script-execution layer under test cannot run",
)

ANYONE_CAN_SPEND = '51'
USER_PK = '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
# OP_PUSH_TX verification keys (packages/runar-compiler/src/passes/oppushtx-codegen.ts).
ANYS_C1_PK = '038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218'
G_PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
# A strict-DER, low-S signature over an unrelated message (+ SIGHASH_ALL|FORKID):
# well-encoded, so Spend reaches the verify and fails there (NULLFAIL).
WRONG_SIG = (
    '304402201c48d8ebf847266f50e789c0416f02f165dc01b52df136bb6f6235162205aadb'
    '022000f95241defddb4fc5c566f950085ae3d2aaefbc7359e49e244d4eeea5baea7e' + '41'
)


def _push(hex_data: str) -> str:
    n = len(hex_data) // 2
    assert n < 0x4c
    return f'{n:02x}' + hex_data


def _checksigverify_script(pk_hex: str) -> str:
    """``<pk> OP_CHECKSIGVERIFY OP_1``: a signature gate followed by more script."""
    return _push(pk_hex) + 'ad' + '51'


def _varint(n: int) -> str:
    assert n < 0xFD
    return f'{n:02x}'


def _tx(inputs, outputs) -> str:
    """inputs: [(prev_txid, script_sig_hex)], each spending vout 0."""
    tx = '01000000' + _varint(len(inputs))
    for txid, sig in inputs:
        tx += bytes.fromhex(txid)[::-1].hex() + '00000000'
        tx += _varint(len(sig) // 2) + sig + 'ffffffff'
    tx += _varint(len(outputs))
    for sats, script in outputs:
        tx += int(sats).to_bytes(8, 'little').hex() + _varint(len(script) // 2) + script
    return tx + '00000000'


def _seed(p: MockProvider, txid: str, sats: int, script: str) -> None:
    p.add_utxo('addr', Utxo(txid=txid, output_index=0, satoshis=sats, script=script))


def test_single_input_wrong_sig_at_user_checksigverify_is_rejected():
    p = MockProvider()
    _seed(p, 'a1' * 32, 10_000, _checksigverify_script(USER_PK))
    with pytest.raises(BroadcastRejected, match='input 0'):
        p.broadcast(_tx([('a1' * 32, _push(WRONG_SIG))], [(9_000, ANYONE_CAN_SPEND)]))


def test_wrong_sig_at_user_checksigverify_is_rejected_next_to_a_valid_input():
    p = MockProvider()
    _seed(p, 'a2' * 32, 10_000, _checksigverify_script(USER_PK))
    _seed(p, 'a3' * 32, 10_000, ANYONE_CAN_SPEND)
    with pytest.raises(BroadcastRejected, match='input 0'):
        p.broadcast(_tx(
            [('a2' * 32, _push(WRONG_SIG)), ('a3' * 32, '')],
            [(19_000, ANYONE_CAN_SPEND)],
        ))


@pytest.mark.parametrize('pk', [ANYS_C1_PK, G_PK], ids=['anys-c1', 'generator'])
def test_covenant_shaped_failure_next_to_a_validated_input_is_still_unvalidatable(pk):
    p = MockProvider()
    _seed(p, 'b1' * 32, 10_000, _checksigverify_script(pk))
    _seed(p, 'b2' * 32, 10_000, ANYONE_CAN_SPEND)
    p.broadcast(_tx([('b1' * 32, _push(WRONG_SIG)), ('b2' * 32, '')], [(19_000, ANYONE_CAN_SPEND)]))
    report = p.last_validation_report
    assert report['unvalidatable'] == 1
    assert report['validated'] == 1


def test_a_tx_whose_every_known_input_is_unvalidatable_is_rejected():
    p = MockProvider()
    _seed(p, 'b3' * 32, 10_000, _checksigverify_script(ANYS_C1_PK))
    with pytest.raises(BroadcastRejected, match='no input was validated'):
        p.broadcast(_tx([('b3' * 32, _push(WRONG_SIG))], [(9_000, ANYONE_CAN_SPEND)]))


# --- R2-GAP008: root cause of the incompatibility the carve-out tolerates ------
#
# bsv-sdk (2.4.0, the latest release) parses a top-level OP_RETURN as ONE chunk
# whose ``data`` is every byte after it, and ``Script.from_chunks`` re-encodes
# any chunk that has ``data`` as a data PUSH, dropping the 0x6a opcode.
# ``Spend.subscript_after_code_separator`` builds the BIP-143 scriptCode with
# ``from_chunks``, so for a script carrying ``OP_RETURN <state>`` (every
# stateful Rúnar contract) bsv-sdk sighashes ``... <len> <state>`` instead of
# the locking script's real bytes ``... 6a <state>``. The node, and runar-py,
# use the real bytes. These two tests pin that, and fail once bsv-sdk is fixed:
# then delete the strict xfail in test_g1_raw_outputs_spend.py, the
# carve-out in runar/sdk/provider.py, and these pins.

COUNTER_SRC = '''from runar import StatefulSmartContract, Bigint, public


class Counter(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def inc(self):
        self.count = self.count + 1
'''


def test_bsv_sdk_spend_sighashes_a_reencoded_script_code_after_op_return():
    """Upstream defect, no Rúnar code involved: ``<pk> OP_CHECKSIG OP_RETURN <8 bytes>``.

    A signature over the TRUE scriptCode (the raw locking-script bytes) is
    rejected; one over the ``from_chunks``-re-encoded scriptCode is accepted,
    under every bsv-sdk VM path available here.
    """
    import importlib

    from bsv.constants import SIGHASH
    from bsv.keys import PrivateKey
    from bsv.native import NATIVE_AVAILABLE
    from bsv.script.script import Script
    from bsv.transaction_input import TransactionInput
    from bsv.transaction_output import TransactionOutput
    from bsv.transaction_preimage import tx_preimage

    spend_mod = importlib.import_module('bsv.script.spend')
    key = PrivateKey(7)
    pk = key.public_key().serialize()
    state = bytes.fromhex('0500000000000000')
    raw = bytes([len(pk)]) + pk + b'\xac' + b'\x6a' + state

    reencoded = Script.from_chunks(Script(raw).chunks).serialize()
    # The opcode byte 0x6a is replaced by a push length (8): same size, one byte off.
    assert reencoded == raw[:-len(state) - 1] + bytes([len(state)]) + state

    src_txid = 'aa' * 32
    outputs = [TransactionOutput(locking_script=Script('51'), satoshis=900)]

    def sig_over(script_code: bytes) -> bytes:
        inp = TransactionInput(source_txid=src_txid, source_output_index=0,
                               sequence=0xFFFFFFFF, sighash=SIGHASH.ALL_FORKID)
        inp.locking_script = Script(script_code)
        inp.satoshis = 1000
        return key.sign(tx_preimage(0, [inp], outputs, 1, 0)) + bytes([SIGHASH.ALL_FORKID])

    def spend(sig: bytes):
        return spend_mod.Spend({
            'sourceTXID': src_txid, 'sourceOutputIndex': 0, 'sourceSatoshis': 1000,
            'lockingScript': Script(raw), 'transactionVersion': 1, 'otherInputs': [],
            'outputs': outputs, 'inputIndex': 0,
            'unlockingScript': Script(bytes([len(sig)]) + sig),
            'inputSequence': 0xFFFFFFFF, 'lockTime': 0,
        })

    true_sig, reencoded_sig = sig_over(raw), sig_over(reencoded)
    vms = [False, True] if NATIVE_AVAILABLE else [False]
    for native in vms:
        original = spend_mod._USE_NATIVE_VM
        spend_mod._USE_NATIVE_VM = native
        try:
            with pytest.raises(RuntimeError, match='OP_CHECKSIG failed to verify the signature'):
                spend(true_sig).validate()
            assert spend(reencoded_sig).validate() is True
        finally:
            spend_mod._USE_NATIVE_VM = original


def test_runar_py_covenant_preimage_differs_from_bsv_sdk_only_at_the_op_return_byte(monkeypatch):
    """The real Counter.inc call: runar-py's OP_PUSH_TX preimage and the one
    bsv-sdk's Spend recomputes for the same input agree on every BIP-143 field
    except ONE byte of scriptCode, the OP_RETURN before the state. runar-py's
    scriptCode is the locking script's real bytes after OP_CODESEPARATOR (what
    the node signs); bsv-sdk's has the state's push length there instead.
    """
    import importlib
    import json

    from runar_compiler import compiler

    import runar.sdk.contract as contract_mod
    from runar.sdk.contract import RunarContract
    from runar.sdk.deployment import build_p2pkh_script
    from runar.sdk.local_signer import LocalSigner
    from runar.sdk.types import DeployOptions, RunarArtifact

    result = compiler.compile_from_source_str_with_result(COUNTER_SRC, 'Counter.runar.py')
    assert result.artifact is not None, [d.message for d in result.diagnostics]
    artifact = RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))

    signer = LocalSigner('00' * 31 + '03')
    p = MockProvider()
    p.add_utxo(signer.get_address(), Utxo(
        txid='cc' * 32, output_index=0, satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    c = RunarContract(artifact, [5])
    c.deploy(p, signer, DeployOptions(satoshis=1_000))
    contract_script = bytes.fromhex(c._current_utxo.script)

    ours: list[tuple[bytes, int]] = []
    real_compute = contract_mod.compute_op_push_tx_preimage

    def capture_ours(tx, idx, subscript, sats, code_sep_idx=-1, *rest):
        pre = real_compute(tx, idx, subscript, sats, code_sep_idx, *rest)
        ours.append((bytes.fromhex(pre), code_sep_idx))
        return pre

    spend_mod = importlib.import_module('bsv.script.spend')
    theirs: list[bytes] = []
    real_tx_preimage = spend_mod.tx_preimage

    def capture_theirs(*args):
        pre = bytes(real_tx_preimage(*args))
        theirs.append(pre)
        return pre

    monkeypatch.setattr(contract_mod, 'compute_op_push_tx_preimage', capture_ours)
    monkeypatch.setattr(spend_mod, 'tx_preimage', capture_theirs)
    # Only the pure-Python VM exposes the preimage it computes.
    monkeypatch.setattr(spend_mod, '_USE_NATIVE_VM', False)

    c.call('inc', [], p, signer)
    assert p.last_validation_report['unvalidatable'] == 1, p.last_validation_report

    final, code_sep_idx = ours[-1]
    # bsv-sdk's preimage for the SAME input: same outpoint (bytes 68..104).
    same_input = [t for t in theirs if t[68:104] == final[68:104]]
    assert len(same_input) == 1, f'{len(theirs)} bsv-sdk preimages, {len(same_input)} for the covenant input'
    theirs_final = same_input[0]

    # runar-py's scriptCode is exactly the node's: the real bytes after OP_CODESEPARATOR.
    script_code = contract_script[code_sep_idx + 1:]
    assert code_sep_idx >= 0
    assert final[104:104 + 3] == b'\xfd' + len(script_code).to_bytes(2, 'little')
    assert final[107:107 + len(script_code)] == script_code

    assert len(theirs_final) == len(final)
    diff = [i for i in range(len(final)) if final[i] != theirs_final[i]]
    assert len(diff) == 1, f'expected one differing byte, got {len(diff)} at {diff[:8]}'
    i = diff[0]
    state_len = (len(final) - 52) - (i + 1)  # 52 = amount..sighashType trailer
    assert final[i] == 0x6A
    assert theirs_final[i] == state_len
    assert contract_script.endswith(b'\x6a' + final[i + 1:len(final) - 52])
