# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK calling helpers' do
  # rubocop:enable RSpec/DescribeClass

  # Shared address / script fixtures (same as deployment_spec for consistency).
  CALL_ADDRESS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
  CALL_PKH     = '62e907b15cbf27d5425399ebf6f0fb50ebb88f18'
  CALL_SCRIPT  = "76a914#{CALL_PKH}88ac"

  # A minimal contract locking script (P2PKH-sized, 25 bytes).
  CONTRACT_SCRIPT = CALL_SCRIPT

  def make_utxo(txid, satoshis, index: 0)
    Runar::SDK::Utxo.new(
      txid: txid,
      output_index: index,
      satoshis: satoshis,
      script: CALL_SCRIPT
    )
  end

  # Build a plausible contract txid (64 hex chars = 32 bytes).
  CONTRACT_TXID = 'ab' * 32
  FUNDING_TXID  = 'cd' * 32

  # ---------------------------------------------------------------------------
  # build_call_transaction — basic single-output call
  # ---------------------------------------------------------------------------
  describe 'build_call_transaction' do
    let(:contract_utxo)  { make_utxo(CONTRACT_TXID, 10_000) }
    let(:funding_utxo)   { make_utxo(FUNDING_TXID, 1_000_000) }
    let(:new_lock)       { CONTRACT_SCRIPT }
    let(:new_satoshis)   { 10_000 }

    subject(:result) do
      Runar::SDK.build_call_transaction(
        contract_utxo,
        '', # unlocking_script (empty at construction time)
        new_lock,
        new_satoshis,
        CALL_ADDRESS,
        '',
        [funding_utxo]
      )
    end

    it 'returns a three-element array [tx_hex, input_count, change_amount]' do
      tx_hex, input_count, change = result
      expect(tx_hex).to be_a(String)
      expect(tx_hex).not_to be_empty
      expect(input_count).to eq(2)
      expect(change).to be_a(Integer)
      expect(change).to be >= 0
    end

    it 'starts with version 01000000 (LE)' do
      tx_hex, = result
      expect(tx_hex).to start_with('01000000')
    end

    it 'ends with locktime 00000000 (LE)' do
      tx_hex, = result
      expect(tx_hex).to end_with('00000000')
    end

    it 'encodes input count as 2' do
      tx_hex, = result
      # version (8 hex) then varint for input count
      expect(tx_hex[8, 2]).to eq('02')
    end

    it 'includes the contract txid in reversed byte order' do
      tx_hex, = result
      reversed = [CONTRACT_TXID].pack('H*').reverse.unpack1('H*')
      expect(tx_hex).to include(reversed)
    end

    it 'includes the funding txid in reversed byte order' do
      tx_hex, = result
      reversed = [FUNDING_TXID].pack('H*').reverse.unpack1('H*')
      expect(tx_hex).to include(reversed)
    end

    it 'produces a positive change amount when the funding utxo has excess' do
      _, _, change = result
      expect(change).to be > 0
    end

    it 'includes the change address script in the transaction' do
      tx_hex, = result
      expect(tx_hex).to include(CALL_PKH)
    end

    it 'includes the new contract locking script' do
      tx_hex, = result
      expect(tx_hex).to include(CONTRACT_SCRIPT)
    end

    context 'when only the contract utxo covers the output (no additional utxos)' do
      let(:rich_contract_utxo) { make_utxo(CONTRACT_TXID, 1_000_000) }

      subject(:result) do
        Runar::SDK.build_call_transaction(
          rich_contract_utxo,
          '',
          new_lock,
          new_satoshis,
          CALL_ADDRESS
        )
      end

      it 'returns input_count of 1' do
        _, input_count, = result
        expect(input_count).to eq(1)
      end

      it 'produces a positive change' do
        _, _, change = result
        expect(change).to be > 0
      end
    end

    context 'when new_satoshis is 0' do
      it 'carries forward the contract UTXO satoshis' do
        tx_hex, = Runar::SDK.build_call_transaction(
          contract_utxo,
          '',
          new_lock,
          0, # carry-forward
          CALL_ADDRESS,
          '',
          [funding_utxo]
        )
        # The 10_000 satoshis should be encoded in the output — encoded as 8-byte LE.
        expected_sats_hex = [10_000].pack('Q<').unpack1('H*')
        expect(tx_hex).to include(expected_sats_hex)
      end
    end

    context 'when change_script is provided' do
      it 'uses the custom change script instead of deriving from change_address' do
        custom_pkh    = 'ff' * 20
        custom_script = "76a914#{custom_pkh}88ac"
        tx_hex, = Runar::SDK.build_call_transaction(
          contract_utxo,
          '',
          new_lock,
          new_satoshis,
          '', # change_address empty
          custom_script,
          [funding_utxo]
        )
        expect(tx_hex).to include(custom_pkh)
      end
    end

    context 'when no change recipient is provided and change would be positive' do
      # Use a distinct locking script so the change address hash is unambiguous.
      let(:other_pkh)    { 'ee' * 20 }
      let(:other_lock)   { "76a914#{other_pkh}88ac" }
      let(:change_pkh)   { CALL_PKH }

      it 'omits the change output and reports change_amount of 0' do
        tx_hex, _, change = Runar::SDK.build_call_transaction(
          contract_utxo,
          '',
          other_lock,
          new_satoshis,
          '',   # no address
          '',   # no script
          [funding_utxo]
        )
        expect(change).to eq(0)
        # The change address pubkey hash must not appear — only the contract script hash is present.
        expect(tx_hex).not_to include(change_pkh)
      end

      it 'produces a shorter transaction than when a change output is present' do
        tx_with_change, = Runar::SDK.build_call_transaction(
          contract_utxo, '', other_lock, new_satoshis,
          CALL_ADDRESS, '', [funding_utxo]
        )
        tx_no_change, = Runar::SDK.build_call_transaction(
          contract_utxo, '', other_lock, new_satoshis,
          '', '', [funding_utxo]
        )
        expect(tx_no_change.length).to be < tx_with_change.length
      end
    end
  end

  # ---------------------------------------------------------------------------
  # build_call_transaction — multi-output (contract_outputs option)
  # ---------------------------------------------------------------------------
  describe 'build_call_transaction with contract_outputs' do
    let(:contract_utxo) { make_utxo(CONTRACT_TXID, 20_000) }
    let(:funding_utxo)  { make_utxo(FUNDING_TXID, 1_000_000) }

    let(:split_script_a) { "76a914#{'aa' * 20}88ac" }
    let(:split_script_b) { "76a914#{'bb' * 20}88ac" }

    let(:contract_outputs) do
      [
        { script: split_script_a, satoshis: 8_000 },
        { script: split_script_b, satoshis: 8_000 }
      ]
    end

    subject(:result) do
      Runar::SDK.build_call_transaction(
        contract_utxo,
        '',
        '', # new_locking_script ignored when contract_outputs provided
        0,
        CALL_ADDRESS,
        '',
        [funding_utxo],
        options: { contract_outputs: contract_outputs }
      )
    end

    it 'includes both split output scripts' do
      tx_hex, = result
      expect(tx_hex).to include('aa' * 20)
      expect(tx_hex).to include('bb' * 20)
    end

    it 'reports the correct input count' do
      _, input_count, = result
      expect(input_count).to eq(2)
    end

    it 'produces positive change' do
      _, _, change = result
      expect(change).to be > 0
    end
  end

  # ---------------------------------------------------------------------------
  # build_call_transaction — additional contract inputs (merge)
  # ---------------------------------------------------------------------------
  describe 'build_call_transaction with additional_contract_inputs' do
    let(:contract_utxo_a) { make_utxo(CONTRACT_TXID, 10_000, index: 0) }
    let(:contract_utxo_b) { make_utxo('ef' * 32, 10_000, index: 1) }
    let(:funding_utxo)    { make_utxo(FUNDING_TXID, 1_000_000) }

    let(:extra_input) do
      { utxo: contract_utxo_b, unlocking_script: 'deadbeef' }
    end

    subject(:result) do
      Runar::SDK.build_call_transaction(
        contract_utxo_a,
        'cafebabe',
        CONTRACT_SCRIPT,
        15_000,
        CALL_ADDRESS,
        '',
        [funding_utxo],
        options: { additional_contract_inputs: [extra_input] }
      )
    end

    it 'includes three inputs (2 contract + 1 funding)' do
      _, input_count, = result
      expect(input_count).to eq(3)
    end

    it 'encodes the input count as 03' do
      tx_hex, = result
      expect(tx_hex[8, 2]).to eq('03')
    end

    it 'includes the extra contract unlocking script' do
      tx_hex, = result
      expect(tx_hex).to include('deadbeef')
    end
  end

  # ---------------------------------------------------------------------------
  # insert_unlocking_script
  # ---------------------------------------------------------------------------
  describe 'insert_unlocking_script' do
    # Build a reference transaction to operate on.
    let(:contract_utxo) { make_utxo(CONTRACT_TXID, 10_000) }
    let(:funding_utxo)  { make_utxo(FUNDING_TXID, 1_000_000) }

    let(:base_tx) do
      tx_hex, = Runar::SDK.build_call_transaction(
        contract_utxo,
        '',
        CONTRACT_SCRIPT,
        10_000,
        CALL_ADDRESS,
        '',
        [funding_utxo]
      )
      tx_hex
    end

    it 'inserts an unlocking script at input 0 and returns valid hex' do
      unlock = 'aabbccdd'
      updated = Runar::SDK.insert_unlocking_script(base_tx, 0, unlock)
      expect(updated).to be_a(String)
      expect(updated).to include(unlock)
    end

    it 'does not change the length of a same-length replacement' do
      # Original input 0 has empty scriptSig (1 byte varint '00').
      # Replace with a 0-byte script — same effective size.
      updated = Runar::SDK.insert_unlocking_script(base_tx, 0, '')
      expect(updated.length).to eq(base_tx.length)
    end

    it 'increases total hex length when inserting a non-empty script into previously empty input' do
      unlock  = 'deadbeefcafe'
      updated = Runar::SDK.insert_unlocking_script(base_tx, 0, unlock)
      # New length = original + unlock.length + (larger varint diff).
      expect(updated.length).to be > base_tx.length
    end

    it 'can replace the unlocking script at input 1 (funding input)' do
      unlock  = '0102030405'
      updated = Runar::SDK.insert_unlocking_script(base_tx, 1, unlock)
      expect(updated).to include(unlock)
    end

    it 'is idempotent for the same content' do
      unlock   = 'aabbcc'
      once     = Runar::SDK.insert_unlocking_script(base_tx, 0, unlock)
      twice    = Runar::SDK.insert_unlocking_script(once, 0, unlock)
      expect(twice).to eq(once)
    end

    it 'raises ArgumentError when input_index equals input_count' do
      # Two inputs in the base tx, so index 2 is out of range.
      expect do
        Runar::SDK.insert_unlocking_script(base_tx, 2, 'aabb')
      end.to raise_error(ArgumentError, /out of range/)
    end

    it 'raises ArgumentError for a clearly out-of-range index' do
      expect do
        Runar::SDK.insert_unlocking_script(base_tx, 99, 'ff')
      end.to raise_error(ArgumentError, /out of range/)
    end

    context 'with three inputs' do
      let(:extra_input) do
        { utxo: make_utxo('ef' * 32, 10_000, index: 0), unlocking_script: '' }
      end

      let(:three_input_tx) do
        tx_hex, = Runar::SDK.build_call_transaction(
          contract_utxo,
          '',
          CONTRACT_SCRIPT,
          10_000,
          CALL_ADDRESS,
          '',
          [funding_utxo],
          options: { additional_contract_inputs: [extra_input] }
        )
        tx_hex
      end

      it 'can replace the script at index 2 without corrupting the transaction' do
        unlock  = 'beef'
        updated = Runar::SDK.insert_unlocking_script(three_input_tx, 2, unlock)
        expect(updated).to include(unlock)
        # Version and locktime must still be intact.
        expect(updated).to start_with('01000000')
        expect(updated).to end_with('00000000')
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Change output presence / absence
  # ---------------------------------------------------------------------------
  describe 'change output logic' do
    let(:contract_utxo) { make_utxo(CONTRACT_TXID, 10_000) }
    let(:large_funding) { make_utxo(FUNDING_TXID, 1_000_000) }

    it 'includes a change output when there is surplus' do
      tx_hex, _, change = Runar::SDK.build_call_transaction(
        contract_utxo, '', CONTRACT_SCRIPT, 10_000,
        CALL_ADDRESS, '', [large_funding]
      )
      expect(change).to be > 0
      expect(tx_hex).to include(CALL_PKH)
    end

    it 'omits the change output when change would be zero or negative' do
      # Craft a scenario where contract_utxo + tiny_funding == output + fee.
      # Use exact fee so change = 0. We check omission by comparing output
      # lengths rather than parsing byte-for-byte.
      tiny = make_utxo(FUNDING_TXID, 1)
      tx_with_change, = Runar::SDK.build_call_transaction(
        contract_utxo, '', CONTRACT_SCRIPT, 10_000,
        CALL_ADDRESS, '', [large_funding]
      )
      tx_no_change, _, change_no = Runar::SDK.build_call_transaction(
        contract_utxo, '', CONTRACT_SCRIPT, 10_000,
        CALL_ADDRESS, '', [tiny]
      )
      expect(change_no).to eq(0)
      # Transaction without change output should be shorter (no 34-byte P2PKH output).
      expect(tx_no_change.length).to be < tx_with_change.length
    end
  end
end
