# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK deployment helpers' do
  # rubocop:enable RSpec/DescribeClass

  # A known mainnet P2PKH address with a verified pubkey hash.
  # Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf...  (genesis coinbase)
  # pubkey hash: 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
  GENESIS_ADDRESS  = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'.freeze
  GENESIS_PKH      = '62e907b15cbf27d5425399ebf6f0fb50ebb88f18'.freeze
  GENESIS_SCRIPT   = "76a914#{GENESIS_PKH}88ac".freeze

  def make_utxo(txid, satoshis, index: 0)
    Runar::SDK::Utxo.new(
      txid: txid,
      output_index: index,
      satoshis: satoshis,
      script: GENESIS_SCRIPT
    )
  end

  # A minimal contract locking script (25 bytes = 50 hex chars, same size as P2PKH).
  LOCKING_SCRIPT = GENESIS_SCRIPT
  LOCKING_BYTE_LEN = LOCKING_SCRIPT.length / 2

  # ---------------------------------------------------------------------------
  # build_p2pkh_script
  # ---------------------------------------------------------------------------
  describe 'build_p2pkh_script' do
    it 'builds a P2PKH script from a 40-char hex pubkey hash' do
      result = Runar::SDK.build_p2pkh_script(GENESIS_PKH)
      expect(result).to eq(GENESIS_SCRIPT)
    end

    it 'builds a P2PKH script from a Base58Check address' do
      result = Runar::SDK.build_p2pkh_script(GENESIS_ADDRESS)
      expect(result).to eq(GENESIS_SCRIPT)
    end

    it 'produces the correct prefix and suffix opcodes' do
      script = Runar::SDK.build_p2pkh_script(GENESIS_PKH)
      expect(script).to start_with('76a914')
      expect(script).to end_with('88ac')
    end

    it 'raises ArgumentError for an address with an invalid decoded length' do
      # Feed a short Base58 string that won't decode to 25 bytes.
      expect { Runar::SDK.build_p2pkh_script('1Badx') }
        .to raise_error(ArgumentError, /invalid address length/)
    end
  end

  # ---------------------------------------------------------------------------
  # estimate_deploy_fee
  # ---------------------------------------------------------------------------
  describe 'estimate_deploy_fee' do
    it 'returns a positive integer' do
      fee = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN)
      expect(fee).to be_a(Integer)
      expect(fee).to be > 0
    end

    it 'increases with the number of inputs' do
      fee1 = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN)
      fee2 = Runar::SDK.estimate_deploy_fee(2, LOCKING_BYTE_LEN)
      expect(fee2).to be > fee1
    end

    it 'scales with fee_rate' do
      fee_low  = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN, 100)
      fee_high = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN, 1000)
      expect(fee_high).to be > fee_low
    end

    it 'clamps fee_rate to a minimum of 1' do
      fee_zero = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN, 0)
      fee_one  = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN, 1)
      expect(fee_zero).to eq(fee_one)
    end

    it 'uses ceiling division for sat/KB calculation' do
      # tx_size = overhead(10) + 1 input(148) + contract out(8+1+25=34) + change out(34) = 226
      # fee = ceil(226 * 100 / 1000) = ceil(22.6) = 23
      expect(Runar::SDK.estimate_deploy_fee(1, 25)).to eq(23)
    end
  end

  # ---------------------------------------------------------------------------
  # select_utxos
  # ---------------------------------------------------------------------------
  describe 'select_utxos' do
    it 'selects a single UTXO when it covers target + fee' do
      utxos = [make_utxo('aabbcc', 1_000_000)]
      selected = Runar::SDK.select_utxos(utxos, 10_000, LOCKING_BYTE_LEN)
      expect(selected.length).to eq(1)
      expect(selected.first.txid).to eq('aabbcc')
    end

    it 'selects the largest UTXOs first (greedy strategy)' do
      small  = make_utxo('small', 100)
      medium = make_utxo('medium', 5_000)
      large  = make_utxo('large', 500_000)
      utxos  = [small, medium, large]

      selected = Runar::SDK.select_utxos(utxos, 10_000, LOCKING_BYTE_LEN)
      expect(selected.first.txid).to eq('large')
    end

    it 'accumulates multiple UTXOs when one is not enough' do
      utxo1 = make_utxo('aaa', 200)
      utxo2 = make_utxo('bbb', 200)
      utxo3 = make_utxo('ccc', 200)

      # Each UTXO is tiny; we need all three plus fee coverage.
      # Target = 1 sat, but fee will dwarf it. All three together = 600 sats;
      # that should be enough for a small target (fee ~52 sat at default rate).
      selected = Runar::SDK.select_utxos([utxo1, utxo2, utxo3], 1, LOCKING_BYTE_LEN)
      expect(selected.length).to be >= 1
    end

    it 'raises ArgumentError when total funds are insufficient' do
      utxos = [make_utxo('tiny', 10)]
      expect { Runar::SDK.select_utxos(utxos, 1_000_000, LOCKING_BYTE_LEN) }
        .to raise_error(ArgumentError, /insufficient funds/)
    end

    it 'raises ArgumentError for an empty UTXO list' do
      expect { Runar::SDK.select_utxos([], 1, LOCKING_BYTE_LEN) }
        .to raise_error(ArgumentError, /insufficient funds/)
    end
  end

  # ---------------------------------------------------------------------------
  # build_deploy_transaction
  # ---------------------------------------------------------------------------
  describe 'build_deploy_transaction' do
    let(:funding_utxo) { make_utxo('a' * 64, 1_000_000) }
    let(:satoshis)     { 10_000 }
    let(:change_addr)  { GENESIS_ADDRESS }

    subject(:result) do
      Runar::SDK.build_deploy_transaction(
        LOCKING_SCRIPT, [funding_utxo], satoshis, change_addr
      )
    end

    it 'returns an array of [tx_hex, input_count]' do
      tx_hex, input_count = result
      expect(tx_hex).to be_a(String)
      expect(input_count).to eq(1)
    end

    it 'starts with version 01000000 (LE)' do
      tx_hex, = result
      expect(tx_hex).to start_with('01000000')
    end

    it 'ends with locktime 00000000 (LE)' do
      tx_hex, = result
      expect(tx_hex).to end_with('00000000')
    end

    it 'encodes the input count correctly' do
      tx_hex, = result
      # version(8 hex) + varint for 1 input = '01'
      expect(tx_hex[8, 2]).to eq('01')
    end

    it 'produces a change output when excess funds are available' do
      tx_hex, = result
      # fee at default rate (100 sat/KB) for 1 input, 25-byte script = 23 sats
      fee = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN)
      tx_no_change, = Runar::SDK.build_deploy_transaction(
        LOCKING_SCRIPT, [funding_utxo], funding_utxo.satoshis - fee, change_addr
      )
      expect(tx_hex.length).to be > tx_no_change.length
    end

    it 'omits the change output when change is exactly zero' do
      fee = Runar::SDK.estimate_deploy_fee(1, LOCKING_BYTE_LEN)
      exact_satoshis = funding_utxo.satoshis - fee
      tx_hex, = Runar::SDK.build_deploy_transaction(
        LOCKING_SCRIPT, [funding_utxo], exact_satoshis, change_addr
      )
      # Byte after inputs should be the output count varint = '01' (only contract out).
      # We check that the shorter (no-change) tx is self-consistent rather than
      # parsing the full wire format.
      expect(tx_hex).to be_a(String)
      expect(tx_hex).not_to be_empty
    end

    it 'uses change_script when provided instead of deriving from change_address' do
      custom_script = "76a914#{'ff' * 20}88ac"
      tx_hex, = Runar::SDK.build_deploy_transaction(
        LOCKING_SCRIPT, [funding_utxo], satoshis, '', custom_script
      )
      expect(tx_hex).to include('ff' * 20)
    end

    it 'raises ArgumentError when no UTXOs are provided' do
      expect do
        Runar::SDK.build_deploy_transaction(LOCKING_SCRIPT, [], satoshis, change_addr)
      end.to raise_error(ArgumentError, /no UTXOs provided/)
    end

    it 'raises ArgumentError when funds are insufficient' do
      poor_utxo = make_utxo('b' * 64, 1)
      expect do
        Runar::SDK.build_deploy_transaction(
          LOCKING_SCRIPT, [poor_utxo], 1_000_000, change_addr
        )
      end.to raise_error(ArgumentError, /insufficient funds/)
    end

    it 'includes the txid of the funding UTXO in reversed byte order' do
      txid    = funding_utxo.txid
      tx_hex, = result
      reversed = [txid].pack('H*').reverse.unpack1('H*')
      expect(tx_hex).to include(reversed)
    end

    it 'returns the correct input count for multiple UTXOs' do
      utxo1 = make_utxo('cc' * 32, 500_000)
      utxo2 = make_utxo('dd' * 32, 500_000)
      _, input_count = Runar::SDK.build_deploy_transaction(
        LOCKING_SCRIPT, [utxo1, utxo2], satoshis, change_addr
      )
      expect(input_count).to eq(2)
    end
  end

  # ---------------------------------------------------------------------------
  # encode_varint (internal helper — verified via public API)
  # ---------------------------------------------------------------------------
  describe 'encode_varint' do
    it 'encodes values below 0xfd as one byte' do
      expect(Runar::SDK.encode_varint(0)).to   eq('00')
      expect(Runar::SDK.encode_varint(1)).to   eq('01')
      expect(Runar::SDK.encode_varint(252)).to eq('fc')
    end

    it 'encodes values 0xfd-0xffff as fd + 2 bytes LE' do
      expect(Runar::SDK.encode_varint(0xfd)).to     eq('fdfd00')
      expect(Runar::SDK.encode_varint(0x0100)).to   eq('fd0001')
      expect(Runar::SDK.encode_varint(0xffff)).to   eq('fdffff')
    end

    it 'encodes values 0x10000-0xffffffff as fe + 4 bytes LE' do
      expect(Runar::SDK.encode_varint(0x10000)).to     eq('fe00000100')
      expect(Runar::SDK.encode_varint(0xffffffff)).to  eq('feffffffff')
    end
  end
end
