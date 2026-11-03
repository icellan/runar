# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# Tests for terminal method call support in RunarContract.
#
# A terminal call consumes the contract UTXO without creating a state
# continuation output. The transaction is built with only the specified
# terminal outputs and no change output.

# ---------------------------------------------------------------------------
# Fixture constants — defined outside describe to satisfy Lint/ConstantDefinitionInBlock
# ---------------------------------------------------------------------------

TERMINAL_PUB_KEY = "02#{'ab' * 32}"
TERMINAL_ADDRESS = ('cd' * 20).freeze
TERMINAL_PKH     = ('ef' * 20).freeze
TERMINAL_SCRIPT_PLACEHOLDER = ('00' * 20).freeze

SIMPLE_TERMINAL_ARTIFACT_JSON = JSON.generate(
  version:         '1.0',
  compilerVersion: '0.1.0',
  contractName:    'Escrow',
  abi:             {
    constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
    methods:     [
      { name: 'settle', params: [], isPublic: true, isTerminal: true }
    ]
  },
  script:           "76a914#{TERMINAL_SCRIPT_PLACEHOLDER}88ac",
  asm:              '',
  stateFields:      [],
  constructorSlots: [{ paramIndex: 0, byteOffset: 2 }]
).freeze

MULTI_METHOD_TERMINAL_ARTIFACT_JSON = JSON.generate(
  version:         '1.0',
  compilerVersion: '0.1.0',
  contractName:    'EscrowMulti',
  abi:             {
    constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
    methods:     [
      { name: 'settle', params: [], isPublic: true, isTerminal: true },
      { name: 'refund', params: [], isPublic: true, isTerminal: false }
    ]
  },
  script:           "76a914#{TERMINAL_SCRIPT_PLACEHOLDER}88ac",
  asm:              '',
  stateFields:      [],
  constructorSlots: [{ paramIndex: 0, byteOffset: 2 }]
).freeze

RSpec.describe Runar::SDK::RunarContract do
  # ---------------------------------------------------------------------------
  # Fixture helpers
  # ---------------------------------------------------------------------------

  def make_artifact(json)
    Runar::SDK::RunarArtifact.from_json(json)
  end

  def make_term_utxo(txid, satoshis, script: "76a914#{TERMINAL_ADDRESS}88ac", index: 0)
    Runar::SDK::Utxo.new(txid: txid, output_index: index, satoshis: satoshis, script: script)
  end

  def make_provider
    Runar::SDK::MockProvider.new
  end

  def make_signer
    Runar::SDK::MockSigner.new(pub_key_hex: TERMINAL_PUB_KEY, address: TERMINAL_ADDRESS)
  end

  def funded_provider
    p = make_provider
    p.add_utxo(TERMINAL_ADDRESS, make_term_utxo('aa' * 32, 1_000_000))
    p
  end

  def sample_terminal_outputs
    [Runar::SDK::TerminalOutput.new(script_hex: "76a914#{TERMINAL_PKH}88ac", satoshis: 5_000)]
  end

  # +provider+ is optional: pass it when the spec actually BROADCASTS, so the
  # fail-closed MockProvider knows the contract outpoint being spent. Injecting
  # @current_utxo directly bypasses the provider, which would otherwise see a
  # transaction none of whose inputs it recognises and refuse to ack it (rather
  # than pass vacuously).
  def contract_with_utxo(artifact, txid_pattern, provider = nil)
    c = described_class.new(artifact, [TERMINAL_PKH])
    utxo = make_term_utxo(txid_pattern * 32, 10_000, script: "76a914#{TERMINAL_PKH}88ac")
    c.instance_variable_set(:@current_utxo, utxo)
    provider&.add_contract_utxo(utxo.script, utxo)
    c
  end

  # ---------------------------------------------------------------------------
  # TerminalOutput struct smoke tests
  # ---------------------------------------------------------------------------

  describe Runar::SDK::TerminalOutput do
    it 'stores script_hex and satoshis' do
      to = described_class.new(script_hex: 'deadbeef', satoshis: 1000)
      expect(to.script_hex).to eq('deadbeef')
      expect(to.satoshis).to eq(1000)
    end
  end

  # ---------------------------------------------------------------------------
  # OutputSpec struct smoke tests
  # ---------------------------------------------------------------------------

  describe Runar::SDK::OutputSpec do
    it 'stores satoshis and state' do
      os = described_class.new(satoshis: 500, state: { 'count' => 1 })
      expect(os.satoshis).to eq(500)
      expect(os.state).to eq('count' => 1)
    end
  end

  # ---------------------------------------------------------------------------
  # CallOptions terminal_outputs field
  # ---------------------------------------------------------------------------

  describe Runar::SDK::CallOptions do
    it 'defaults terminal_outputs to nil' do
      expect(described_class.new.terminal_outputs).to be_nil
    end

    it 'accepts terminal_outputs' do
      outs = [Runar::SDK::TerminalOutput.new(script_hex: 'aabb', satoshis: 100)]
      opts = described_class.new(terminal_outputs: outs)
      expect(opts.terminal_outputs).to eq(outs)
    end
  end

  # ---------------------------------------------------------------------------
  # prepare_call — terminal path returns PreparedCall with is_terminal: true
  # ---------------------------------------------------------------------------

  describe '#prepare_call with terminal_outputs' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer) { make_signer }
    let(:contract) { contract_with_utxo(artifact, 'cc') }
    let(:opts) { Runar::SDK::CallOptions.new(terminal_outputs: sample_terminal_outputs) }

    subject(:prepared) { contract.prepare_call('settle', [], provider, signer, opts) }

    it 'returns a PreparedCall' do
      expect(prepared).to be_a(Runar::SDK::PreparedCall)
    end

    it 'sets is_terminal to true' do
      expect(prepared.is_terminal).to be true
    end

    it 'sets new_locking_script to empty string (no continuation)' do
      expect(prepared.new_locking_script).to eq('')
    end

    it 'sets new_satoshis to 0' do
      expect(prepared.new_satoshis).to eq(0)
    end

    it 'sets change_amount to 0' do
      expect(prepared.change_amount).to eq(0)
    end

    it 'produces a non-empty tx_hex' do
      expect(prepared.tx_hex).not_to be_empty
    end

    it 'returns an empty sighash when there is no preimage' do
      # Stateless method with no Sig/SigHashPreimage params — no OP_PUSH_TX.
      expect(prepared.sighash).to eq('')
    end
  end

  # ---------------------------------------------------------------------------
  # prepare_call — Hash-style terminal outputs (symbol and camelCase string keys)
  # ---------------------------------------------------------------------------

  describe '#prepare_call with Hash terminal_outputs' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer) { make_signer }
    let(:contract) { contract_with_utxo(artifact, 'dd') }

    it 'accepts Hash with symbol keys' do
      hash_outputs = [{ script_hex: "76a914#{TERMINAL_PKH}88ac", satoshis: 5_000 }]
      opts = Runar::SDK::CallOptions.new(terminal_outputs: hash_outputs)
      prepared = contract.prepare_call('settle', [], provider, signer, opts)
      expect(prepared.is_terminal).to be true
    end

    it 'accepts Hash with camelCase string keys' do
      hash_outputs = [{ 'scriptHex' => "76a914#{TERMINAL_PKH}88ac", 'satoshis' => 5_000 }]
      opts = Runar::SDK::CallOptions.new(terminal_outputs: hash_outputs)
      prepared = contract.prepare_call('settle', [], provider, signer, opts)
      expect(prepared.is_terminal).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # call — terminal method nils out @current_utxo
  # ---------------------------------------------------------------------------

  describe '#call with terminal_outputs' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer) { make_signer }
    let(:contract) { contract_with_utxo(artifact, 'ee', provider) }
    let(:opts) { Runar::SDK::CallOptions.new(terminal_outputs: sample_terminal_outputs) }

    it 'returns [txid, transaction]' do
      txid, tx = contract.call('settle', [], provider, signer, opts)
      expect(txid).to be_a(String)
      expect(txid).not_to be_empty
      expect(tx).to be_a(Runar::SDK::TransactionData)
    end

    it 'broadcasts exactly one transaction' do
      contract.call('settle', [], provider, signer, opts)
      expect(provider.get_broadcasted_txs.length).to eq(1)
    end

    it 'sets @current_utxo to nil after a terminal call' do
      contract.call('settle', [], provider, signer, opts)
      expect(contract.get_utxo).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # prepare_call without terminal_outputs follows non-terminal path (regression guard)
  # ---------------------------------------------------------------------------

  describe '#prepare_call without terminal_outputs' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer) { make_signer }
    let(:contract) { contract_with_utxo(artifact, '11') }

    it 'returns PreparedCall with is_terminal: false' do
      prepared = contract.prepare_call('settle', [], provider, signer)
      expect(prepared.is_terminal).to be false
    end
  end

  # ---------------------------------------------------------------------------
  # Terminal fee input (issue #118)
  # ---------------------------------------------------------------------------

  describe '#prepare_call with a fee_utxo (#118)' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer)   { make_signer }
    let(:contract) { contract_with_utxo(artifact, 'cc') }

    let(:fee_utxo) do
      Runar::SDK::Utxo.new(txid: 'fe' * 32, output_index: 3, satoshis: 2_000,
                           script: "76a914#{TERMINAL_ADDRESS}88ac")
    end

    def input_count(tx_hex)
      count, = Runar::SDK.read_varint_hex(tx_hex, 8)
      count
    end

    # Return [scriptSig_hex] for every input of a raw tx.
    def input_scripts(tx_hex)
      pos = 8
      count, ic = Runar::SDK.read_varint_hex(tx_hex, pos)
      pos += ic
      scripts = []
      count.times do
        pos += 72 # prev txid + output index
        len, sl = Runar::SDK.read_varint_hex(tx_hex, pos)
        pos += sl
        scripts << tx_hex[pos, len * 2]
        pos += len * 2 + 8 # scriptSig + sequence
      end
      scripts
    end

    it 'adds the fee input (2 inputs total)' do
      prepared = contract.prepare_call(
        'settle', [], provider, signer,
        Runar::SDK::CallOptions.new(terminal_outputs: sample_terminal_outputs, fee_utxo: fee_utxo)
      )
      expect(input_count(prepared.tx_hex)).to eq(2)
    end

    it 'references the fee UTXO outpoint and signs its input (non-empty scriptSig)' do
      prepared = contract.prepare_call(
        'settle', [], provider, signer,
        Runar::SDK::CallOptions.new(terminal_outputs: sample_terminal_outputs, fee_utxo: fee_utxo)
      )
      # Fee input outpoint (txid little-endian) present in the tx.
      expect(prepared.tx_hex).to include(Runar::SDK.reverse_hex('fe' * 32))
      # The fee input (index 1) carries a signed P2PKH scriptSig (pushes the
      # signer's pubkey), not an empty placeholder.
      scripts = input_scripts(prepared.tx_hex)
      expect(scripts.length).to eq(2)
      expect(scripts[1]).not_to be_empty
      expect(scripts[1]).to include(TERMINAL_PUB_KEY)
    end

    it 'omits the fee input when fee_utxo is unset (back-compatible)' do
      prepared = contract.prepare_call(
        'settle', [], provider, signer,
        Runar::SDK::CallOptions.new(terminal_outputs: sample_terminal_outputs)
      )
      expect(input_count(prepared.tx_hex)).to eq(1)
    end
  end

  # ---------------------------------------------------------------------------
  # N-271: terminal_outputs + additional_contract_inputs must refuse, not drop
  # ---------------------------------------------------------------------------
  #
  # prepare_terminal lays out exactly one contract input (plus an optional
  # fee/funding input) and never reads opts.additional_contract_inputs at
  # all. Before the fix this proves the extra UTXO is silently dropped
  # instead of being rejected or spent -- the call succeeds and returns a
  # PreparedCall, but the built tx has only one input, not two.
  #
  # This does NOT prove additional_contract_inputs could ever be made to
  # work on the terminal path (merging it validly) -- only that dropping it
  # silently is unacceptable and must become a refusal.

  describe '#prepare_call with terminal_outputs and additional_contract_inputs' do
    let(:artifact) { make_artifact(SIMPLE_TERMINAL_ARTIFACT_JSON) }
    let(:provider) { funded_provider }
    let(:signer)   { make_signer }
    let(:contract) { contract_with_utxo(artifact, 'cc') }

    let(:extra_utxo) do
      Runar::SDK::Utxo.new(txid: 'ee' * 32, output_index: 0, satoshis: 1_000,
                           script: '51')
    end

    it 'raises ArgumentError naming additional_contract_inputs instead of dropping it' do
      opts = Runar::SDK::CallOptions.new(
        terminal_outputs: sample_terminal_outputs,
        additional_contract_inputs: [extra_utxo]
      )
      expect do
        contract.prepare_call('settle', [], provider, signer, opts)
      end.to raise_error(ArgumentError, /additional_contract_inputs/)
    end
  end
end
