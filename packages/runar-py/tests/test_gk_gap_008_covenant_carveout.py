"""GK-GAP-008: MockProvider validates OP_PUSH_TX covenant inputs like any other.

History. ``_validate_broadcast`` used to bucket a failing OP_PUSH_TX covenant
check as "unvalidatable" instead of rejecting it, because bsv-sdk <= 2.4.0
sighashed the wrong scriptCode for any script carrying a top-level
``OP_RETURN <data>``: ``Script.from_chunks`` re-encoded the OP_RETURN chunk as
a data push (dropping the 0x6a) and ``Spend.subscript_after_code_separator``
built the scriptCode with it, so no stateful Rúnar covenant input could be
validated (bsv-blockchain/py-sdk#247, R2-GAP008). The first carve-out matched
any OP_CHECKSIGVERIFY failure (GK-GAP-008); it was later narrowed to the
covenant check. bsv-sdk 2.5.0 fixed #247, the carve-out is gone, and
MockProvider refuses to validate with an older bsv-sdk.

Proves: a wrong signature at an OP_CHECKSIGVERIFY is a rejection whatever key
it checks against, including the fixed OP_PUSH_TX keys, alone or next to a
valid input; the installed bsv-sdk round-trips a top-level OP_RETURN through
``from_chunks`` and accepts a signature over the real scriptCode on every VM
path present; for a real Counter.inc call runar-py's OP_PUSH_TX preimage is
byte-identical to the one bsv-sdk's Spend recomputes, the covenant input is
counted as validated, and a call whose covenant preimage is tampered with is
rejected at input 0; MockProvider refuses to validate under a bsv-sdk older
than 2.5.0 or of unknown version, in CI and out of it.
Does not prove: that a node accepts runar-py's preimage (that is the regtest
integration suite's job), or anything about the other six SDKs.
"""

import json

import pytest

import runar.sdk.provider as provider_mod
from runar.sdk.errors import BroadcastRejected, BroadcastValidationUnavailable
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


ALL_KEYS = pytest.mark.parametrize(
    'pk', [USER_PK, ANYS_C1_PK, G_PK], ids=['user', 'anys-c1', 'generator'],
)


@ALL_KEYS
def test_single_input_wrong_sig_at_checksigverify_is_rejected(pk):
    p = MockProvider()
    _seed(p, 'a1' * 32, 10_000, _checksigverify_script(pk))
    with pytest.raises(BroadcastRejected, match='input 0'):
        p.broadcast(_tx([('a1' * 32, _push(WRONG_SIG))], [(9_000, ANYONE_CAN_SPEND)]))


@ALL_KEYS
def test_wrong_sig_at_checksigverify_is_rejected_next_to_a_valid_input(pk):
    p = MockProvider()
    _seed(p, 'a2' * 32, 10_000, _checksigverify_script(pk))
    _seed(p, 'a3' * 32, 10_000, ANYONE_CAN_SPEND)
    with pytest.raises(BroadcastRejected, match='input 0'):
        p.broadcast(_tx(
            [('a2' * 32, _push(WRONG_SIG)), ('a3' * 32, '')],
            [(19_000, ANYONE_CAN_SPEND)],
        ))


# --- the installed bsv-sdk has the py-sdk#247 fix -----------------------------

def test_bsv_sdk_spend_sighashes_the_real_script_code_after_op_return():
    """No Rúnar code: ``<pk> OP_CHECKSIG OP_RETURN <8 bytes>``.

    ``from_chunks`` keeps the 0x6a, and Spend accepts a signature over the
    locking script's real bytes, under every bsv-sdk VM path available here.
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

    assert Script.from_chunks(Script(raw).chunks).serialize() == raw

    src_txid = 'aa' * 32
    outputs = [TransactionOutput(locking_script=Script('51'), satoshis=900)]

    inp = TransactionInput(source_txid=src_txid, source_output_index=0,
                           sequence=0xFFFFFFFF, sighash=SIGHASH.ALL_FORKID)
    inp.locking_script = Script(raw)
    inp.satoshis = 1000
    sig = key.sign(tx_preimage(0, [inp], outputs, 1, 0)) + bytes([SIGHASH.ALL_FORKID])

    vms = [False, True] if NATIVE_AVAILABLE else [False]
    for native in vms:
        original = spend_mod._USE_NATIVE_VM
        spend_mod._USE_NATIVE_VM = native
        try:
            assert spend_mod.Spend({
                'sourceTXID': src_txid, 'sourceOutputIndex': 0, 'sourceSatoshis': 1000,
                'lockingScript': Script(raw), 'transactionVersion': 1, 'otherInputs': [],
                'outputs': outputs, 'inputIndex': 0,
                'unlockingScript': Script(bytes([len(sig)]) + sig),
                'inputSequence': 0xFFFFFFFF, 'lockTime': 0,
            }).validate() is True
        finally:
            spend_mod._USE_NATIVE_VM = original


# --- a real covenant spend ----------------------------------------------------

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


def _deployed_counter():
    from runar_compiler import compiler

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
    return c, p, signer


def _pushed(ours: list, tx_hex: str) -> tuple[bytes, int]:
    """The last captured preimage that input 0's unlock actually pushes. D25:
    prepare_call also computes the ALL|FORKID preimage of a user Sig's digest
    (PreparedCall.sighash) after the covenant one, so the last capture is not
    necessarily the pushed preimage."""
    return next((pre, cs) for pre, cs in reversed(ours) if pre.hex() in tx_hex)


def _capture_ours(monkeypatch) -> list:
    """Record every OP_PUSH_TX preimage runar-py computes, with its codesep index."""
    import runar.sdk.contract as contract_mod

    ours: list[tuple[bytes, int]] = []
    real_compute = contract_mod.compute_op_push_tx_preimage

    def capture(tx, idx, subscript, sats, code_sep_idx=-1, *rest):
        pre = real_compute(tx, idx, subscript, sats, code_sep_idx, *rest)
        ours.append((bytes.fromhex(pre), code_sep_idx))
        return pre

    monkeypatch.setattr(contract_mod, 'compute_op_push_tx_preimage', capture)
    return ours


def test_covenant_input_is_validated_and_its_preimage_matches_bsv_sdk(monkeypatch):
    """The real Counter.inc call: runar-py's OP_PUSH_TX preimage equals the one
    bsv-sdk's Spend recomputes for the covenant input byte for byte, its
    scriptCode is the locking script's real bytes after OP_CODESEPARATOR, and
    MockProvider counts the covenant input as validated."""
    import importlib

    c, p, signer = _deployed_counter()
    contract_script = bytes.fromhex(c._current_utxo.script)
    ours = _capture_ours(monkeypatch)

    spend_mod = importlib.import_module('bsv.script.spend')
    theirs: list[bytes] = []
    real_tx_preimage = spend_mod.tx_preimage

    def capture_theirs(*args):
        pre = bytes(real_tx_preimage(*args))
        theirs.append(pre)
        return pre

    monkeypatch.setattr(spend_mod, 'tx_preimage', capture_theirs)
    # Only the pure-Python VM exposes the preimage it computes.
    monkeypatch.setattr(spend_mod, '_USE_NATIVE_VM', False)

    c.call('inc', [], p, signer)
    report = p.last_validation_report
    assert report['unvalidatable'] == 0, report
    assert report['unknown'] == 0, report
    # Every input ran through Spend: the covenant input AND the funding input.
    assert report['validated'] == report['total'] == 2, report

    final, code_sep_idx = _pushed(ours, p.get_broadcasted_txs()[-1])
    # bsv-sdk's preimage for the SAME input: same outpoint (bytes 68..104).
    same_input = [t for t in theirs if t[68:104] == final[68:104]]
    assert len(same_input) == 1, f'{len(theirs)} bsv-sdk preimages, {len(same_input)} for the covenant input'
    assert same_input[0] == final

    script_code = contract_script[code_sep_idx + 1:]
    assert code_sep_idx >= 0
    assert final[104:104 + 3] == b'\xfd' + len(script_code).to_bytes(2, 'little')
    assert final[107:107 + len(script_code)] == script_code


def test_tampered_covenant_preimage_is_rejected_at_input_0(monkeypatch):
    """Flip one byte of the OP_PUSH_TX preimage inside input 0's unlocking
    script. Only the covenant input changes (BIP-143 does not sign other
    inputs' scriptSigs, so the P2PKH funding input stays valid), and
    MockProvider must reject the call at input 0."""
    c, p, signer = _deployed_counter()
    ours = _capture_ours(monkeypatch)

    c.call('inc', [], p, signer)
    good = p.get_broadcasted_txs()[-1]
    preimage = _pushed(ours, good)[0].hex()
    assert good.count(preimage) == 1

    # Flip a byte inside hashPrevouts (preimage bytes 4..36).
    at = good.index(preimage) + 2 * 10
    flipped = f'{int(good[at:at + 2], 16) ^ 0x01:02x}'
    tampered = good[:at] + flipped + good[at + 2:]
    assert tampered != good and len(tampered) == len(good)

    with pytest.raises(BroadcastRejected, match='input 0'):
        p.broadcast(tampered)


# --- fail closed on a bsv-sdk without the fix --------------------------------

@pytest.mark.parametrize('version', ['2.4.0', '1.0.0', '2.4.99', None, 'garbage'])
@pytest.mark.parametrize('ci', [True, False], ids=['ci', 'local'])
def test_validation_refuses_a_bsv_sdk_older_than_2_5_0(monkeypatch, version, ci):
    if ci:
        monkeypatch.setenv('CI', '1')
    else:
        monkeypatch.delenv('CI', raising=False)
    monkeypatch.setattr(provider_mod, '_bsv_sdk_version', lambda: version)

    p = MockProvider()
    _seed(p, 'd1' * 32, 10_000, ANYONE_CAN_SPEND)
    with pytest.raises(BroadcastValidationUnavailable, match=r'2\.5\.0'):
        p.broadcast(_tx([('d1' * 32, '')], [(9_000, ANYONE_CAN_SPEND)]))
    assert p.get_broadcasted_txs() == []


@pytest.mark.parametrize('version', ['2.5.0', '2.5.1', '2.10.0', '3.0.0'])
def test_validation_accepts_bsv_sdk_2_5_0_and_later(monkeypatch, version):
    monkeypatch.setattr(provider_mod, '_bsv_sdk_version', lambda: version)
    p = MockProvider()
    _seed(p, 'd2' * 32, 10_000, ANYONE_CAN_SPEND)
    p.broadcast(_tx([('d2' * 32, '')], [(9_000, ANYONE_CAN_SPEND)]))
    assert p.last_validated_input_count == 1
