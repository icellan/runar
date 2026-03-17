# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::RunarContract do
  # ---------------------------------------------------------------------------
  # Fixture helpers
  # ---------------------------------------------------------------------------

  # A minimal stateless artifact (P2PKH-style) with one constructor param and
  # one constructor slot — the pubkey hash placeholder sits at byte offset 3 of
  # the locking script (after OP_DUP OP_HASH160 OP_PUSHDATA1(20)).
  #
  # Script layout (25 bytes):
  #   76          OP_DUP
  #   a9          OP_HASH160
  #   14          push 20 bytes              ← constructor slot placeholder byte
  #   {20 bytes}  pubkey hash               ← replaced by build_code_script
  #   88          OP_EQUALVERIFY
  #   ac          OP_CHECKSIG
  #
  # The artifact's #script contains a single placeholder byte at offset 3
  # (byte_offset: 3).  build_code_script replaces that 1-byte placeholder with
  # the full encoded constructor arg (encode_push_data of the 20-byte hash).
  #
  # NOTE: the real P2PKH script uses a raw push (14 + 20 bytes); here we use
  # OP_PUSHDATA1 style for illustration.  What matters is that the constructor
  # slot mechanics work correctly.
  SAMPLE_PKH       = ('ab' * 20).freeze
  SAMPLE_ADDRESS   = '00' * 20  # used as MockSigner address
  SAMPLE_PUB_KEY   = ('02' + '00' * 32).freeze

  # Minimal stateless artifact JSON.
  STATELESS_ARTIFACT_JSON = JSON.generate(
    version:         '1.0',
    compilerVersion: '0.1.0',
    contractName:    'P2PKH',
    abi:             {
      constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
      methods:     [{ name: 'unlock', params: [{ name: 'sig', type: 'Sig' },
                                               { name: 'pk',  type: 'PubKey' }], isPublic: true }]
    },
    # Script: 76 a9 14 00 00...00 88 ac
    # Byte offset 3 is the push-data placeholder byte (0x00 = 1 null byte).
    # build_code_script replaces the single byte at offset 3 with encode_push_data(pkh).
    script:          '76a9' + '14' + ('00' * 20) + '88ac',
    asm:             '',
    stateFields:     [],
    constructorSlots: [{ paramIndex: 0, byteOffset: 2 }]
  ).freeze

  # Minimal stateful (counter) artifact.
  STATEFUL_ARTIFACT_JSON = JSON.generate(
    version:         '1.0',
    compilerVersion: '0.1.0',
    contractName:    'Counter',
    abi:             {
      constructor: { params: [{ name: 'count', type: 'bigint' }] },
      methods:     [{ name: 'increment', params: [], isPublic: true }]
    },
    # Placeholder script — content is not interpreted by contract.rb unit tests.
    script:          'aabbcc',
    asm:             '',
    stateFields:     [{ name: 'count', type: 'bigint', index: 0 }],
    constructorSlots: [],
    codeSeparatorIndex: 0
  ).freeze

  # Stateful (counter) artifact with ANF IR — used to test auto-computed state.
  #
  # The ANF IR describes an increment() method that adds 1 to the 'count'
  # property via an update_prop node.  It mirrors the minimal Counter contract:
  #
  #   class Counter extends StatefulSmartContract {
  #     count: bigint;
  #     public increment() { this.count += 1n; }
  #   }
  STATEFUL_ANF_ARTIFACT_JSON = JSON.generate(
    version:            '1.0',
    compilerVersion:    '0.1.0',
    contractName:       'Counter',
    abi:                {
      constructor: { params: [{ name: 'count', type: 'bigint' }] },
      methods:     [{ name: 'increment', params: [], isPublic: true }]
    },
    script:             'aabbcc',
    asm:                '',
    stateFields:        [{ name: 'count', type: 'bigint', index: 0 }],
    constructorSlots:   [],
    codeSeparatorIndex: 0,
    anf:                {
      'properties' => [{ 'name' => 'count', 'type' => 'bigint', 'readonly' => false }],
      'methods'    => [
        {
          'name'     => 'increment',
          'isPublic' => true,
          'params'   => [],
          'body'     => [
            # t0 = count  (load current value)
            { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
            # t1 = 1
            { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
            # t2 = t0 + t1
            { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't0', 'right' => 't1' } },
            # update_prop count = t2
            { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't2' } }
          ]
        }
      ]
    }
  ).freeze

  def stateless_artifact
    Runar::SDK::RunarArtifact.from_json(STATELESS_ARTIFACT_JSON)
  end

  def stateful_artifact
    Runar::SDK::RunarArtifact.from_json(STATEFUL_ARTIFACT_JSON)
  end

  def stateful_anf_artifact
    Runar::SDK::RunarArtifact.from_json(STATEFUL_ANF_ARTIFACT_JSON)
  end

  def make_utxo(txid, satoshis, script: 'aabb', index: 0)
    Runar::SDK::Utxo.new(txid: txid, output_index: index, satoshis: satoshis, script: script)
  end

  def mock_provider
    Runar::SDK::MockProvider.new
  end

  def mock_signer
    Runar::SDK::MockSigner.new(pub_key_hex: SAMPLE_PUB_KEY, address: SAMPLE_ADDRESS)
  end

  # ---------------------------------------------------------------------------
  # Constructor validation
  # ---------------------------------------------------------------------------

  describe '#initialize' do
    it 'raises ArgumentError when arg count is wrong (too few)' do
      expect { described_class.new(stateless_artifact, []) }
        .to raise_error(ArgumentError, /expected 1 constructor args.*got 0/i)
    end

    it 'raises ArgumentError when arg count is wrong (too many)' do
      expect { described_class.new(stateless_artifact, [SAMPLE_PKH, 'extra']) }
        .to raise_error(ArgumentError, /expected 1 constructor args.*got 2/i)
    end

    it 'accepts the correct number of args' do
      expect { described_class.new(stateless_artifact, [SAMPLE_PKH]) }.not_to raise_error
    end

    it 'initialises state from constructor args for stateful contracts' do
      contract = described_class.new(stateful_artifact, [42])
      expect(contract.get_state).to eq('count' => 42)
    end

    it 'stores get_utxo as nil before deployment' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      expect(contract.get_utxo).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # build_code_script — constructor slot splicing
  # ---------------------------------------------------------------------------

  describe '#build_code_script' do
    subject(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    it 'returns a String' do
      expect(contract.build_code_script).to be_a(String)
    end

    it 'is not empty' do
      expect(contract.build_code_script).not_to be_empty
    end

    it 'splices the constructor arg into the script at the byte offset' do
      code = contract.build_code_script
      # encode_push_data of a 20-byte value produces 14{40 hex chars} (21 hex pairs = 42 hex chars).
      # Byte offset 2 means hex offset 4. The original script starts with '76a9'.
      # After splicing, those 4 leading chars are preserved, followed by the encoded arg.
      expect(code).to start_with('76a9')
      # The encoded push-data for the 20-byte hash should be present in the result.
      expected_push = Runar::SDK::State.encode_push_data(SAMPLE_PKH)
      expect(code).to include(expected_push)
    end

    it 'preserves the tail of the original script after the splice' do
      code = contract.build_code_script
      expect(code).to end_with('88ac')
    end

    it 'produces the same result on repeated calls' do
      expect(contract.build_code_script).to eq(contract.build_code_script)
    end
  end

  # ---------------------------------------------------------------------------
  # get_locking_script
  # ---------------------------------------------------------------------------

  describe '#get_locking_script' do
    it 'returns a non-empty hex string for stateless contracts' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      script   = contract.get_locking_script
      expect(script).to be_a(String)
      expect(script).not_to be_empty
      expect(script.length).to be_even
    end

    it 'appends OP_RETURN + state hex for stateful contracts' do
      contract = described_class.new(stateful_artifact, [7])
      script   = contract.get_locking_script
      # OP_RETURN = 6a
      expect(script).to include('6a')
    end

    it 'does not include OP_RETURN for stateless contracts' do
      contract = described_class.new(stateless_artifact, [SAMPLE_PKH])
      # Find the op_return at an opcode boundary — stateless scripts should not have one.
      op_return_pos = Runar::SDK::State.find_last_op_return(contract.get_locking_script)
      expect(op_return_pos).to eq(-1)
    end
  end

  # ---------------------------------------------------------------------------
  # build_unlocking_script
  # ---------------------------------------------------------------------------

  describe '#build_unlocking_script' do
    subject(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    let(:sig) { '30' + ('00' * 70) + '41' }

    it 'returns a non-empty hex string' do
      result = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expect(result).to be_a(String)
      expect(result).not_to be_empty
    end

    it 'encodes each arg as push data' do
      result = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expect(result).to include(Runar::SDK::State.encode_push_data(sig))
      expect(result).to include(Runar::SDK::State.encode_push_data(SAMPLE_PUB_KEY))
    end

    it 'does not append a method selector when there is only one public method' do
      # Single public method → no selector suffix needed.
      script_with_args  = contract.build_unlocking_script('unlock', [sig, SAMPLE_PUB_KEY])
      expected_body     = Runar::SDK::State.encode_push_data(sig) + Runar::SDK::State.encode_push_data(SAMPLE_PUB_KEY)
      expect(script_with_args).to eq(expected_body)
    end
  end

  # ---------------------------------------------------------------------------
  # connect / resolve errors
  # ---------------------------------------------------------------------------

  describe '#connect and provider/signer resolution' do
    let(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    it 'raises RuntimeError when deploy is called without provider' do
      expect { contract.deploy }.to raise_error(RuntimeError, /no provider/)
    end

    it 'raises RuntimeError when deploy is called without signer (after connect with only provider)' do
      contract.connect(mock_provider, nil) rescue nil
      # connect stores nil; deploy should raise signer error
      # (We just need a provider-less or signer-less scenario covered.)
      c2 = described_class.new(stateless_artifact, [SAMPLE_PKH])
      c2.instance_variable_set(:@provider, mock_provider)
      expect { c2.deploy }.to raise_error(RuntimeError, /no signer/)
    end

    it 'stores provider and signer via connect' do
      provider = mock_provider
      signer   = mock_signer
      contract.connect(provider, signer)
      expect(contract.instance_variable_get(:@provider)).to be(provider)
      expect(contract.instance_variable_get(:@signer)).to be(signer)
    end
  end

  # ---------------------------------------------------------------------------
  # Deploy lifecycle with MockProvider
  # ---------------------------------------------------------------------------

  describe '#deploy' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateless_artifact, [SAMPLE_PKH]) }

    before do
      # Fund the signer address with a sufficient UTXO.
      provider.add_utxo(SAMPLE_ADDRESS, make_utxo('aa' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac'))
    end

    it 'returns [txid, transaction]' do
      txid, tx = contract.deploy(provider, signer)
      expect(txid).to be_a(String)
      expect(txid).not_to be_empty
      expect(tx).to be_a(Runar::SDK::Transaction)
    end

    it 'broadcasts exactly one transaction' do
      contract.deploy(provider, signer)
      expect(provider.get_broadcasted_txs.length).to eq(1)
    end

    it 'tracks the contract UTXO after deployment' do
      contract.deploy(provider, signer)
      utxo = contract.get_utxo
      expect(utxo).not_to be_nil
      expect(utxo.satoshis).to eq(10_000)
    end

    it 'raises RuntimeError when no UTXOs are available' do
      empty_provider = mock_provider
      expect { contract.deploy(empty_provider, signer) }
        .to raise_error(RuntimeError, /no UTXOs/)
    end

    it 'uses the satoshis value from DeployOptions' do
      opts = Runar::SDK::DeployOptions.new(satoshis: 5_000)
      contract.deploy(provider, signer, opts)
      expect(contract.get_utxo.satoshis).to eq(5_000)
    end
  end

  # ---------------------------------------------------------------------------
  # get_state / set_state
  # ---------------------------------------------------------------------------

  describe '#get_state and #set_state' do
    subject(:contract) { described_class.new(stateful_artifact, [99]) }

    it 'returns a Hash' do
      expect(contract.get_state).to be_a(Hash)
    end

    it 'returns a copy so mutation does not affect internal state' do
      state = contract.get_state
      state['count'] = 0
      expect(contract.get_state['count']).to eq(99)
    end

    it 'updates state with set_state' do
      contract.set_state('count' => 100)
      expect(contract.get_state['count']).to eq(100)
    end

    it 'merges — does not replace the entire state hash' do
      contract.set_state('count' => 50)
      expect(contract.get_state.key?('count')).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # from_txid
  # ---------------------------------------------------------------------------

  describe '.from_txid' do
    let(:artifact)  { stateless_artifact }
    let(:provider)  { mock_provider }
    let(:script)    { described_class.new(artifact, [SAMPLE_PKH]).get_locking_script }
    let(:tx) do
      Runar::SDK::Transaction.new(
        txid: 'beef' * 16,
        outputs: [Runar::SDK::TxOutput.new(script: script, satoshis: 10_000)]
      )
    end

    before { provider.add_transaction(tx) }

    it 'returns a RunarContract instance' do
      contract = described_class.from_txid(artifact, tx.txid, 0, provider)
      expect(contract).to be_a(described_class)
    end

    it 'tracks the UTXO correctly' do
      contract = described_class.from_txid(artifact, tx.txid, 0, provider)
      expect(contract.get_utxo.txid).to eq(tx.txid)
      expect(contract.get_utxo.satoshis).to eq(10_000)
    end

    it 'raises ArgumentError for an out-of-range output index' do
      expect { described_class.from_txid(artifact, tx.txid, 5, provider) }
        .to raise_error(ArgumentError, /out of range/)
    end
  end

  # ---------------------------------------------------------------------------
  # Stateful contract: get_state from locking script
  # ---------------------------------------------------------------------------

  describe 'stateful contract state round-trip' do
    let(:contract) { described_class.new(stateful_artifact, [42]) }

    it 'encodes and decodes state correctly' do
      locking_script = contract.get_locking_script
      decoded = Runar::SDK::State.extract_state_from_script(stateful_artifact, locking_script)
      expect(decoded).to eq('count' => 42)
    end

    it 'reflects set_state changes in the locking script' do
      contract.set_state('count' => 7)
      locking_script = contract.get_locking_script
      decoded = Runar::SDK::State.extract_state_from_script(stateful_artifact, locking_script)
      expect(decoded).to eq('count' => 7)
    end
  end

  # ---------------------------------------------------------------------------
  # ANF interpreter auto-computation of new state
  # ---------------------------------------------------------------------------

  describe 'ANF auto-state in prepare_call' do
    let(:provider) { mock_provider }
    let(:signer)   { mock_signer }
    let(:contract) { described_class.new(stateful_anf_artifact, [5]) }

    before do
      # Deploy the contract so prepare_call has a current UTXO to spend.
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('cc' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      contract.connect(provider, signer)
      contract.deploy
    end

    it 'auto-computes new state from ANF IR when new_state is nil' do
      # count starts at 5; increment() should produce count = 6
      _prepared = contract.prepare_call('increment', [])
      expect(contract.get_state['count']).to eq(6)
    end

    it 'explicit new_state overrides ANF auto-computation' do
      opts = Runar::SDK::CallOptions.new(new_state: { 'count' => 99 })
      _prepared = contract.prepare_call('increment', [], nil, nil, opts)
      expect(contract.get_state['count']).to eq(99)
    end

    it 'prepare_call works normally when artifact has no ANF' do
      # Use the stateful artifact without ANF data — no auto-computation,
      # state should remain unchanged (build_continuation with nil new_state
      # does not modify state).
      no_anf_contract = described_class.new(stateful_artifact, [10])
      provider.add_utxo(
        SAMPLE_ADDRESS,
        make_utxo('dd' * 32, 1_000_000, script: '76a914' + SAMPLE_ADDRESS + '88ac')
      )
      no_anf_contract.connect(provider, signer)
      no_anf_contract.deploy
      _prepared = no_anf_contract.prepare_call('increment', [])
      # Without ANF, state is not mutated by the interpreter.
      expect(no_anf_contract.get_state['count']).to eq(10)
    end
  end
end
