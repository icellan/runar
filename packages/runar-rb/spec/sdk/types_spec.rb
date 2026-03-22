# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

MINIMAL_ARTIFACT_HASH = {
  'version' => '1.0.0',
  'compilerVersion' => '0.4.2',
  'contractName' => 'P2PKH',
  'abi' => {
    'constructor' => {
      'params' => [
        { 'name' => 'pubKeyHash', 'type' => 'Ripemd160' }
      ]
    },
    'methods' => [
      {
        'name' => 'unlock',
        'params' => [
          { 'name' => 'sig', 'type' => 'Sig' },
          { 'name' => 'pubKey', 'type' => 'PubKey' }
        ],
        'isPublic' => true
      }
    ]
  },
  'script' => 'deadbeef',
  'asm' => 'OP_DUP OP_HASH160',
  'stateFields' => [],
  'constructorSlots' => [
    { 'paramIndex' => 0, 'byteOffset' => 4 }
  ],
  'buildTimestamp' => '2024-01-01T00:00:00Z',
  'codeSeparatorIndex' => nil,
  'codeSeparatorIndices' => nil
}.freeze

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK types' do
  # rubocop:enable RSpec/DescribeClass

  describe Runar::SDK::Utxo do
    it 'stores all fields' do
      utxo = described_class.new(
        txid: 'abc123',
        output_index: 0,
        satoshis: 10_000,
        script: '76a914deadbeef88ac'
      )
      expect(utxo.txid).to eq('abc123')
      expect(utxo.output_index).to eq(0)
      expect(utxo.satoshis).to eq(10_000)
      expect(utxo.script).to eq('76a914deadbeef88ac')
    end
  end

  describe Runar::SDK::TxInput do
    it 'defaults sequence to 0xFFFFFFFF' do
      input = described_class.new(txid: 'abc', output_index: 1, script: '')
      expect(input.sequence).to eq(0xFFFFFFFF)
    end

    it 'accepts a custom sequence' do
      input = described_class.new(txid: 'abc', output_index: 0, script: '', sequence: 0)
      expect(input.sequence).to eq(0)
    end
  end

  describe Runar::SDK::TxOutput do
    it 'stores script and satoshis' do
      output = described_class.new(script: '76a914ff88ac', satoshis: 5000)
      expect(output.script).to eq('76a914ff88ac')
      expect(output.satoshis).to eq(5000)
    end
  end

  describe Runar::SDK::TransactionData do
    it 'defaults version to 1 and collections to empty' do
      tx = described_class.new(txid: 'deadbeef')
      expect(tx.version).to eq(1)
      expect(tx.inputs).to eq([])
      expect(tx.outputs).to eq([])
      expect(tx.locktime).to eq(0)
      expect(tx.raw).to eq('')
    end

    it 'stores all fields when provided' do
      tx = described_class.new(txid: 'cafe', version: 2, locktime: 1, raw: 'ff')
      expect(tx.txid).to eq('cafe')
      expect(tx.version).to eq(2)
      expect(tx.locktime).to eq(1)
      expect(tx.raw).to eq('ff')
    end
  end

  describe 'Transaction alias' do
    it 'is the same constant as TransactionData' do
      expect(Runar::SDK::Transaction).to be(Runar::SDK::TransactionData)
    end

    it 'can be used to construct TransactionData instances' do
      tx = Runar::SDK::Transaction.new(txid: 'deadbeef')
      expect(tx).to be_a(Runar::SDK::TransactionData)
      expect(tx.version).to eq(1)
    end
  end

  describe Runar::SDK::ABIMethod do
    it 'defaults is_terminal to nil' do
      m = described_class.new(name: 'unlock')
      expect(m.is_terminal).to be_nil
    end

    it 'accepts an explicit is_terminal value' do
      m = described_class.new(name: 'close', is_terminal: true)
      expect(m.is_terminal).to be true
    end

    it 'defaults is_public to true and params to empty' do
      m = described_class.new(name: 'unlock')
      expect(m.is_public).to be true
      expect(m.params).to eq([])
    end
  end

  describe Runar::SDK::RunarArtifact do
    describe '.from_hash' do
      subject(:artifact) { described_class.from_hash(MINIMAL_ARTIFACT_HASH) }

      it 'parses top-level scalar fields' do
        expect(artifact.version).to eq('1.0.0')
        expect(artifact.compiler_version).to eq('0.4.2')
        expect(artifact.contract_name).to eq('P2PKH')
        expect(artifact.script).to eq('deadbeef')
        expect(artifact.asm).to eq('OP_DUP OP_HASH160')
        expect(artifact.build_timestamp).to eq('2024-01-01T00:00:00Z')
      end

      it 'parses constructor params into ABI' do
        expect(artifact.abi.constructor_params.length).to eq(1)
        param = artifact.abi.constructor_params.first
        expect(param.name).to eq('pubKeyHash')
        expect(param.type).to eq('Ripemd160')
      end

      it 'parses ABI methods' do
        expect(artifact.abi.methods.length).to eq(1)
        method = artifact.abi.methods.first
        expect(method.name).to eq('unlock')
        expect(method.is_public).to be true
        expect(method.params.map(&:name)).to eq(%w[sig pubKey])
      end

      it 'sets is_terminal to nil when isTerminal is absent from the artifact' do
        method = artifact.abi.methods.first
        expect(method.is_terminal).to be_nil
      end

      it 'parses isTerminal when present' do
        hash_with_terminal = MINIMAL_ARTIFACT_HASH.dup
        hash_with_terminal['abi'] = MINIMAL_ARTIFACT_HASH['abi'].dup
        hash_with_terminal['abi']['methods'] = [
          {
            'name' => 'close',
            'params' => [],
            'isPublic' => true,
            'isTerminal' => true
          }
        ]
        art = described_class.from_hash(hash_with_terminal)
        expect(art.abi.methods.first.is_terminal).to be true
      end

      it 'parses constructor slots' do
        expect(artifact.constructor_slots.length).to eq(1)
        slot = artifact.constructor_slots.first
        expect(slot.param_index).to eq(0)
        expect(slot.byte_offset).to eq(4)
      end

      it 'parses state fields as empty array' do
        expect(artifact.state_fields).to eq([])
      end

      it 'preserves nil code separator index' do
        expect(artifact.code_separator_index).to be_nil
        expect(artifact.code_separator_indices).to be_nil
      end

      it 'defaults anf to nil when absent from the artifact' do
        expect(artifact.anf).to be_nil
      end

      context 'with an anf field present' do
        let(:anf_data) do
          {
            'contract' => 'Counter',
            'methods' => [
              {
                'name' => 'increment',
                'body' => [{ 'kind' => 'let', 'name' => 't0', 'value' => { 'kind' => 'add', 'left' => 'count', 'right' => 1 } }]
              }
            ]
          }
        end

        subject(:artifact) { described_class.from_hash(MINIMAL_ARTIFACT_HASH.merge('anf' => anf_data)) }

        it 'stores the anf hash' do
          expect(artifact.anf).to eq(anf_data)
        end

        it 'preserves the anf structure without modification' do
          expect(artifact.anf['contract']).to eq('Counter')
          expect(artifact.anf['methods'].length).to eq(1)
          expect(artifact.anf['methods'].first['name']).to eq('increment')
        end
      end

      context 'with a stateful contract hash' do
        let(:stateful_hash) do
          MINIMAL_ARTIFACT_HASH.merge(
            'stateFields' => [
              { 'name' => 'count', 'type' => 'bigint', 'index' => 0, 'initialValue' => '0n' }
            ],
            'codeSeparatorIndex' => 42,
            'codeSeparatorIndices' => [42]
          )
        end

        subject(:artifact) { described_class.from_hash(stateful_hash) }

        it 'parses state fields' do
          expect(artifact.state_fields.length).to eq(1)
          field = artifact.state_fields.first
          expect(field.name).to eq('count')
          expect(field.type).to eq('bigint')
          expect(field.index).to eq(0)
          expect(field.initial_value).to eq('0n')
        end

        it 'parses code separator index' do
          expect(artifact.code_separator_index).to eq(42)
          expect(artifact.code_separator_indices).to eq([42])
        end
      end
    end

    describe '.from_json' do
      it 'parses a JSON string into an artifact' do
        require 'json'
        json = JSON.generate(MINIMAL_ARTIFACT_HASH)
        artifact = described_class.from_json(json)
        expect(artifact.contract_name).to eq('P2PKH')
        expect(artifact.abi.constructor_params.length).to eq(1)
      end

      it 'round-trips the anf field through JSON' do
        require 'json'
        anf_data = { 'contract' => 'P2PKH', 'methods' => [] }
        json = JSON.generate(MINIMAL_ARTIFACT_HASH.merge('anf' => anf_data))
        artifact = described_class.from_json(json)
        expect(artifact.anf).to eq(anf_data)
      end

      it 'produces nil anf when the field is absent from JSON' do
        require 'json'
        json = JSON.generate(MINIMAL_ARTIFACT_HASH)
        artifact = described_class.from_json(json)
        expect(artifact.anf).to be_nil
      end
    end
  end

  describe Runar::SDK::DeployOptions do
    it 'defaults to 10_000 satoshis and empty change address' do
      opts = described_class.new
      expect(opts.satoshis).to eq(10_000)
      expect(opts.change_address).to eq('')
    end

    it 'accepts keyword arguments' do
      opts = described_class.new(satoshis: 50_000, change_address: '1ABC')
      expect(opts.satoshis).to eq(50_000)
      expect(opts.change_address).to eq('1ABC')
    end
  end

  describe Runar::SDK::OutputSpec do
    it 'stores satoshis and state' do
      spec = described_class.new(satoshis: 5000, state: { 'count' => 1 })
      expect(spec.satoshis).to eq(5000)
      expect(spec.state).to eq({ 'count' => 1 })
    end
  end

  describe Runar::SDK::TerminalOutput do
    it 'stores script_hex and satoshis' do
      out = described_class.new(script_hex: 'deadbeef', satoshis: 1000)
      expect(out.script_hex).to eq('deadbeef')
      expect(out.satoshis).to eq(1000)
    end
  end

  describe Runar::SDK::CallOptions do
    it 'defaults to 0 satoshis, empty change address, and nil new_state' do
      opts = described_class.new
      expect(opts.satoshis).to eq(0)
      expect(opts.change_address).to eq('')
      expect(opts.new_state).to be_nil
    end

    it 'accepts a new_state hash' do
      opts = described_class.new(new_state: { 'count' => 5 })
      expect(opts.new_state).to eq({ 'count' => 5 })
    end

    it 'defaults change_pub_key to empty string' do
      opts = described_class.new
      expect(opts.change_pub_key).to eq('')
    end

    it 'defaults outputs to nil' do
      opts = described_class.new
      expect(opts.outputs).to be_nil
    end

    it 'defaults additional_contract_inputs to nil' do
      opts = described_class.new
      expect(opts.additional_contract_inputs).to be_nil
    end

    it 'defaults additional_contract_input_args to nil' do
      opts = described_class.new
      expect(opts.additional_contract_input_args).to be_nil
    end

    it 'defaults terminal_outputs to nil' do
      opts = described_class.new
      expect(opts.terminal_outputs).to be_nil
    end

    it 'accepts all new fields' do
      utxo = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 1000, script: 'aabb')
      term = Runar::SDK::TerminalOutput.new(script_hex: 'cafe', satoshis: 999)
      out  = Runar::SDK::OutputSpec.new(satoshis: 500, state: {})

      opts = described_class.new(
        change_pub_key: 'aabbcc',
        outputs: [out],
        additional_contract_inputs: [utxo],
        additional_contract_input_args: [[1, 2]],
        terminal_outputs: [term]
      )
      expect(opts.change_pub_key).to eq('aabbcc')
      expect(opts.outputs.length).to eq(1)
      expect(opts.additional_contract_inputs.length).to eq(1)
      expect(opts.additional_contract_input_args).to eq([[1, 2]])
      expect(opts.terminal_outputs.length).to eq(1)
    end
  end

  describe Runar::SDK::PreparedCall do
    it 'defaults all fields to sensible zero values' do
      pc = described_class.new
      expect(pc.sighash).to eq('')
      expect(pc.preimage).to eq('')
      expect(pc.op_push_tx_sig).to eq('')
      expect(pc.tx_hex).to eq('')
      expect(pc.sig_indices).to eq([])
      expect(pc.method_name).to eq('')
      expect(pc.resolved_args).to eq([])
      expect(pc.method_selector_hex).to eq('')
      expect(pc.is_stateful).to be false
      expect(pc.is_terminal).to be false
      expect(pc.needs_op_push_tx).to be false
      expect(pc.method_needs_change).to be false
      expect(pc.change_pkh_hex).to eq('')
      expect(pc.change_amount).to eq(0)
      expect(pc.method_needs_new_amount).to be false
      expect(pc.new_amount).to eq(0)
      expect(pc.preimage_index).to eq(-1)
      expect(pc.contract_utxo).to be_nil
      expect(pc.new_locking_script).to eq('')
      expect(pc.new_satoshis).to eq(0)
      expect(pc.has_multi_output).to be false
      expect(pc.contract_outputs).to eq([])
      expect(pc.code_sep_idx).to eq(-1)
    end

    it 'accepts keyword arguments for all fields' do
      utxo = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 1000, script: 'aabb')
      pc = described_class.new(
        sighash: 'abc',
        preimage: 'def',
        tx_hex: 'cafebabe',
        sig_indices: [0],
        method_name: 'increment',
        is_stateful: true,
        is_terminal: true,
        contract_utxo: utxo,
        code_sep_idx: 5
      )
      expect(pc.sighash).to eq('abc')
      expect(pc.preimage).to eq('def')
      expect(pc.tx_hex).to eq('cafebabe')
      expect(pc.sig_indices).to eq([0])
      expect(pc.method_name).to eq('increment')
      expect(pc.is_stateful).to be true
      expect(pc.is_terminal).to be true
      expect(pc.contract_utxo).to be(utxo)
      expect(pc.code_sep_idx).to eq(5)
    end
  end
end
