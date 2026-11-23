# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# MockProvider must refuse a double spend: a second, DIFFERENT transaction
# spending an outpoint an earlier accepted broadcast already spent. A node
# refuses it, so acking it lets a spec "succeed" at a spend the network rejects.
RSpec.describe 'Runar::SDK::MockProvider double spend' do
  OP_TRUE_SCRIPT = '51'
  FUND_TXID = 'ab' * 32

  def le_txid(display)
    [display].pack('H*').bytes.reverse.pack('C*').unpack1('H*')
  end

  def tx_hex(prev_txids, out_sats)
    tx = +'01000000'
    tx << format('%02x', prev_txids.length)
    prev_txids.each { |t| tx << le_txid(t) << '00000000' << '00' << 'ffffffff' }
    tx << '01' << [out_sats & 0xFFFFFFFF, out_sats >> 32].pack('VV').unpack1('H*') << '01' << OP_TRUE_SCRIPT
    tx << '00000000'
  end

  def deploy(provider)
    provider.add_utxo('funder', Runar::SDK::Utxo.new(txid: FUND_TXID, output_index: 0, satoshis: 10_000,
                                                     script: OP_TRUE_SCRIPT))
    provider.broadcast(tx_hex([FUND_TXID], 9_000))
  end

  it 'refuses a different transaction spending an already-spent outpoint' do
    p = Runar::SDK::MockProvider.new
    d = deploy(p)
    first = tx_hex([d], 8_000)
    p.broadcast(first)
    conflicting = tx_hex([d], 7_000)
    expect(conflicting).not_to eq(first)
    before = p.get_broadcasted_txs.length
    expect { p.broadcast(conflicting) }.to raise_error(Runar::SDK::BroadcastRejected, /already spent/)
    expect(p.get_broadcasted_txs.length).to eq(before)
  end

  it 'refuses a transaction spending one outpoint twice' do
    p = Runar::SDK::MockProvider.new
    d = deploy(p)
    expect { p.broadcast(tx_hex([d, d], 8_000)) }
      .to raise_error(Runar::SDK::BroadcastRejected, /more than once/)
  end

  it 'no longer lists an outpoint an accepted broadcast spent' do
    p = Runar::SDK::MockProvider.new
    p.add_utxo('funder', Runar::SDK::Utxo.new(txid: FUND_TXID, output_index: 1, satoshis: 5_000, script: OP_TRUE_SCRIPT))
    deploy(p)
    expect(p.get_utxos('funder').map(&:output_index)).to eq([1])
  end

  it 'lists a new P2PKH output under the address it pays' do
    p = Runar::SDK::MockProvider.new
    pkh = '1111111111111111111111111111111111111111'
    p.add_utxo(pkh, Runar::SDK::Utxo.new(txid: 'cd' * 32, output_index: 0, satoshis: 1, script: OP_TRUE_SCRIPT))
    p.add_utxo('funder', Runar::SDK::Utxo.new(txid: FUND_TXID, output_index: 0, satoshis: 10_000, script: OP_TRUE_SCRIPT))
    raw = tx_hex([FUND_TXID], 9_000).sub(/0151(00000000)\z/, '1976a914111111111111111111111111111111111111111188ac\\1')
    txid = p.broadcast(raw)
    listed = p.get_utxos(pkh).select { |u| u.txid == txid }
    expect(listed.map { |u| [u.output_index, u.satoshis, u.script] }).to eq([[0, 9_000, '76a914111111111111111111111111111111111111111188ac']])
  end

  it 'does not mark the inputs of a refused broadcast spent' do
    p = Runar::SDK::MockProvider.new
    d = deploy(p)
    expect { p.broadcast(tx_hex([d], 50_000)) }.to raise_error(Runar::SDK::BroadcastRejected)
    expect { p.broadcast(tx_hex([d], 8_000)) }.not_to raise_error
  end

  it 'treats re-broadcasting the identical transaction as no double spend' do
    p = Runar::SDK::MockProvider.new
    d = deploy(p)
    tx = tx_hex([d], 8_000)
    first = p.broadcast(tx)
    before = p.get_broadcasted_txs.length
    expect(p.broadcast(tx)).to eq(first)
    expect(p.get_broadcasted_txs.length).to eq(before)
  end
end
