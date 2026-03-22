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

  def contract_with_utxo(artifact, txid_pattern)
    c = described_class.new(artifact, [TERMINAL_PKH])
    c.instance_variable_set(
      :@current_utxo,
      make_term_utxo(txid_pattern * 32, 10_000, script: "76a914#{TERMINAL_PKH}88ac")
    )
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
    let(:contract) { contract_with_utxo(artifact, 'ee') }
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
end
