"""MockProvider must refuse a double spend.

A second, DIFFERENT transaction spending an outpoint an earlier accepted
broadcast already spent was acked. A node refuses it, so acking it lets a test
"succeed" at a spend the network rejects.
"""

import pytest

from runar.sdk.errors import BroadcastRejected
from runar.sdk.provider import MockProvider
from runar.sdk.types import Utxo

from test_mock_broadcast_validation import ANYONE_CAN_SPEND, _varint, build_tx

FUND = 'ab' * 32


def deploy(p: MockProvider) -> str:
    p.add_utxo('funder', Utxo(txid=FUND, output_index=0, satoshis=10_000, script=ANYONE_CAN_SPEND))
    return p.broadcast(build_tx(FUND, [(9_000, ANYONE_CAN_SPEND)]))


def test_refuses_a_double_spend():
    p = MockProvider()
    d = deploy(p)
    first = build_tx(d, [(8_000, ANYONE_CAN_SPEND)])
    p.broadcast(first)
    conflicting = build_tx(d, [(7_000, ANYONE_CAN_SPEND)])
    assert conflicting != first
    before = len(p.get_broadcasted_txs())
    with pytest.raises(BroadcastRejected, match='already spent'):
        p.broadcast(conflicting)
    assert len(p.get_broadcasted_txs()) == before


def test_refuses_a_tx_spending_one_outpoint_twice():
    p = MockProvider()
    d = deploy(p)
    outpoint = bytes.fromhex(d)[::-1].hex() + '00000000' + '00' + 'ffffffff'
    tx = '01000000' + '02' + outpoint + outpoint + '01'
    tx += (8_000).to_bytes(8, 'little').hex() + _varint(1) + ANYONE_CAN_SPEND + '00000000'
    with pytest.raises(BroadcastRejected, match='more than once'):
        p.broadcast(tx)


def test_get_utxos_omits_an_outpoint_an_accepted_broadcast_spent():
    p = MockProvider()
    p.add_utxo('funder', Utxo(txid=FUND, output_index=1, satoshis=5_000, script=ANYONE_CAN_SPEND))
    deploy(p)
    assert [u.output_index for u in p.get_utxos('funder')] == [1]


def test_a_refused_broadcast_does_not_spend_its_inputs():
    p = MockProvider()
    d = deploy(p)
    with pytest.raises(BroadcastRejected):
        p.broadcast(build_tx(d, [(50_000, ANYONE_CAN_SPEND)]))
    p.broadcast(build_tx(d, [(8_000, ANYONE_CAN_SPEND)]))


def test_identical_rebroadcast_is_not_a_double_spend():
    p = MockProvider()
    d = deploy(p)
    tx = build_tx(d, [(8_000, ANYONE_CAN_SPEND)])
    first = p.broadcast(tx)
    before = len(p.get_broadcasted_txs())
    assert p.broadcast(tx) == first
    assert len(p.get_broadcasted_txs()) == before
