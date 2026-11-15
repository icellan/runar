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
sighash than runar-py signs (pre-existing; see the strict xfail in
``test_g1_raw_outputs_spend.py``), so those inputs cannot be validated here.

Proves: a wrong signature at a CHECKSIGVERIFY against any other key is a
rejection, alone or next to a valid input; a covenant-shaped failure is still
recorded as unvalidatable next to a validated input; and a transaction whose
every known input is unvalidatable is rejected as validating nothing.
Does not prove: why runar-py's preimage differs from bsv-sdk's (open).
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
